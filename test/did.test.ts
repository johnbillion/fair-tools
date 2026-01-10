import { describe, it } from 'node:test';
import assert from 'node:assert';
import { generateDID } from '../src/did.js';
import {
	generateVerificationKeyId,
	addVerificationKeyToOp,
	addRotationKeyToOp,
	revokeVerificationKeyFromOp,
	revokeRotationKeyFromOp,
	updateServiceUrlInOp,
	replaceServiceUrlInOp,
	removeServiceUrlFromOp,
	addAlsoKnownAsToOp,
	replaceAlsoKnownAsInOp,
	removeAlsoKnownAsFromOp,
	FAIR_SERVICE_ID,
	FAIR_SERVICE_TYPE,
} from '../src/plc.js';
import { generateVerificationKeyPair, generateRotationKeyPair } from '../src/keys.js';

describe('generateDID', () => {
	it('creates a signed operation and returns the DID', async () => {
		const verificationKeys = await generateVerificationKeyPair();
		const rotationKeys = await generateRotationKeyPair();

		const { op, did } = await generateDID({
			verificationKey: verificationKeys.publicKey,
			rotationKey: rotationKeys.publicKey,
			keypair: rotationKeys.keypair,
		});

		assert.ok(op.sig, 'operation should have a signature');
		assert.ok(did.startsWith('did:plc:'), 'should return a valid DID');
		assert.strictEqual(did.length, 32, 'should be 32 characters (did:plc: + 24 char hash)');
	});

	it('generates different DIDs for different keys', async () => {
		const verificationKeys1 = await generateVerificationKeyPair();
		const rotationKeys1 = await generateRotationKeyPair();
		const verificationKeys2 = await generateVerificationKeyPair();
		const rotationKeys2 = await generateRotationKeyPair();

		const { did: did1 } = await generateDID({
			verificationKey: verificationKeys1.publicKey,
			rotationKey: rotationKeys1.publicKey,
			keypair: rotationKeys1.keypair,
		});
		const { did: did2 } = await generateDID({
			verificationKey: verificationKeys2.publicKey,
			rotationKey: rotationKeys2.publicKey,
			keypair: rotationKeys2.keypair,
		});

		assert.notStrictEqual(did1, did2, 'should generate different DIDs');
	});

	it('generates the same DID for the same keys', async () => {
		const verificationKeys = await generateVerificationKeyPair();
		const rotationKeys = await generateRotationKeyPair();

		const { did: did1 } = await generateDID({
			verificationKey: verificationKeys.publicKey,
			rotationKey: rotationKeys.publicKey,
			keypair: rotationKeys.keypair,
		});
		const { did: did2 } = await generateDID({
			verificationKey: verificationKeys.publicKey,
			rotationKey: rotationKeys.publicKey,
			keypair: rotationKeys.keypair,
		});

		assert.strictEqual(did1, did2, 'should generate the same DID for the same keys');
	});
});

describe('generateVerificationKeyId', () => {
	it('returns "fair" when no verification methods exist', () => {
		const keyId = generateVerificationKeyId({});
		assert.strictEqual(keyId, 'fair');
	});

	it('returns "fair" when fair key does not exist', () => {
		const keyId = generateVerificationKeyId({ other: 'did:key:z6Mk...' });
		assert.strictEqual(keyId, 'fair');
	});

	it('returns "fair2" when fair already exists', () => {
		const keyId = generateVerificationKeyId({ fair: 'did:key:z6Mk...' });
		assert.strictEqual(keyId, 'fair2');
	});

	it('returns "fair3" when fair and fair2 exist', () => {
		const keyId = generateVerificationKeyId({
			fair: 'did:key:z6Mk1...',
			fair2: 'did:key:z6Mk2...',
		});
		assert.strictEqual(keyId, 'fair3');
	});

	it('finds gaps in numbering', () => {
		const keyId = generateVerificationKeyId({
			fair: 'did:key:z6Mk1...',
			fair3: 'did:key:z6Mk3...',
		});
		assert.strictEqual(keyId, 'fair2');
	});
});

describe('addVerificationKeyToOp', () => {
	it('adds first key with id "fair"', () => {
		const lastOp = {
			verificationMethods: {},
			rotationKeys: ['did:key:zQ3sh...'],
		};
		const result = addVerificationKeyToOp(lastOp, 'did:key:z6MkNew');

		assert.strictEqual(result.verificationMethods.fair, 'did:key:z6MkNew');
		assert.deepStrictEqual(result.rotationKeys, lastOp.rotationKeys);
	});

	it('adds second key with id "fair2"', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6MkExisting' },
			rotationKeys: ['did:key:zQ3sh...'],
		};
		const result = addVerificationKeyToOp(lastOp, 'did:key:z6MkNew');

		assert.strictEqual(result.verificationMethods.fair, 'did:key:z6MkExisting');
		assert.strictEqual(result.verificationMethods.fair2, 'did:key:z6MkNew');
	});

	it('preserves all existing verification methods', () => {
		const lastOp = {
			verificationMethods: {
				fair: 'did:key:z6Mk1',
				fair2: 'did:key:z6Mk2',
				other: 'did:key:z6Mk3',
			},
			rotationKeys: ['did:key:zQ3sh...'],
		};
		const result = addVerificationKeyToOp(lastOp, 'did:key:z6MkNew');

		assert.strictEqual(result.verificationMethods.fair, 'did:key:z6Mk1');
		assert.strictEqual(result.verificationMethods.fair2, 'did:key:z6Mk2');
		assert.strictEqual(result.verificationMethods.other, 'did:key:z6Mk3');
		assert.strictEqual(result.verificationMethods.fair3, 'did:key:z6MkNew');
	});

	it('preserves other operation properties', () => {
		const lastOp = {
			verificationMethods: {},
			rotationKeys: ['did:key:zQ3sh...'],
			alsoKnownAs: ['fair://example.com'],
			services: { test: { type: 'Test', endpoint: 'https://example.com' } },
		};
		const result = addVerificationKeyToOp(lastOp, 'did:key:z6MkNew');

		assert.deepStrictEqual(result, {
			verificationMethods: { fair: 'did:key:z6MkNew' },
			rotationKeys: ['did:key:zQ3sh...'],
			alsoKnownAs: ['fair://example.com'],
			services: { test: { type: 'Test', endpoint: 'https://example.com' } },
		});
	});
});

describe('addRotationKeyToOp', () => {
	it('appends rotation key to array', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3shExisting'],
		};
		const result = addRotationKeyToOp(lastOp, 'did:key:zQ3shNew');

		assert.deepStrictEqual(result.rotationKeys, ['did:key:zQ3shExisting', 'did:key:zQ3shNew']);
	});

	it('preserves existing rotation keys', () => {
		const lastOp = {
			verificationMethods: {},
			rotationKeys: ['did:key:zQ3sh1', 'did:key:zQ3sh2'],
		};
		const result = addRotationKeyToOp(lastOp, 'did:key:zQ3sh3');

		assert.deepStrictEqual(result.rotationKeys, ['did:key:zQ3sh1', 'did:key:zQ3sh2', 'did:key:zQ3sh3']);
	});

	it('throws if rotation key already exists', () => {
		const lastOp = {
			verificationMethods: {},
			rotationKeys: ['did:key:zQ3shExisting'],
		};

		assert.throws(() => addRotationKeyToOp(lastOp, 'did:key:zQ3shExisting'), /Rotation key already exists/);
	});

	it('preserves other operation properties', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...'],
			alsoKnownAs: ['fair://example.com'],
			services: { test: { type: 'Test', endpoint: 'https://example.com' } },
		};
		const result = addRotationKeyToOp(lastOp, 'did:key:zQ3shNew');

		assert.deepStrictEqual(result, {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...', 'did:key:zQ3shNew'],
			alsoKnownAs: ['fair://example.com'],
			services: { test: { type: 'Test', endpoint: 'https://example.com' } },
		});
	});
});

describe('revokeVerificationKeyFromOp', () => {
	it('removes the specified verification key by public key', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk1', fair2: 'did:key:z6Mk2' },
			rotationKeys: ['did:key:zQ3sh...'],
		};
		const result = revokeVerificationKeyFromOp(lastOp, 'did:key:z6Mk1');

		assert.strictEqual(result.verificationMethods.fair, undefined);
		assert.strictEqual(result.verificationMethods.fair2, 'did:key:z6Mk2');
	});

	it('preserves other verification keys when revoking', () => {
		const lastOp = {
			verificationMethods: {
				fair: 'did:key:z6Mk1',
				fair2: 'did:key:z6Mk2',
				fair3: 'did:key:z6Mk3',
			},
			rotationKeys: ['did:key:zQ3sh...'],
		};
		const result = revokeVerificationKeyFromOp(lastOp, 'did:key:z6Mk2');

		assert.deepStrictEqual(result, {
			verificationMethods: {
				fair: 'did:key:z6Mk1',
				fair3: 'did:key:z6Mk3',
			},
			rotationKeys: ['did:key:zQ3sh...'],
		});
	});

	it('throws if verification key not found', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...'],
		};

		assert.throws(
			() => revokeVerificationKeyFromOp(lastOp, 'did:key:z6MkNotFound'),
			/Verification key did:key:z6MkNotFound not found in DID/,
		);
	});

	it('can remove the last verification key', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...'],
		};
		const result = revokeVerificationKeyFromOp(lastOp, 'did:key:z6Mk...');

		assert.deepStrictEqual(result.verificationMethods, {});
	});

	it('preserves rotation keys, services, and alsoKnownAs', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk1', fair2: 'did:key:z6Mk2' },
			rotationKeys: ['did:key:zQ3sh1', 'did:key:zQ3sh2'],
			alsoKnownAs: ['fair://example.com'],
			services: {
				fairpm_repo: {
					type: 'FairPackageManagementRepo',
					endpoint: 'https://example.com/metadata.json',
				},
			},
		};
		const result = revokeVerificationKeyFromOp(lastOp, 'did:key:z6Mk1');

		assert.deepStrictEqual(result, {
			verificationMethods: { fair2: 'did:key:z6Mk2' },
			rotationKeys: ['did:key:zQ3sh1', 'did:key:zQ3sh2'],
			alsoKnownAs: ['fair://example.com'],
			services: {
				fairpm_repo: {
					type: 'FairPackageManagementRepo',
					endpoint: 'https://example.com/metadata.json',
				},
			},
		});
	});
});

describe('updateServiceUrlInOp', () => {
	it('adds FAIR service when no services exist', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...'],
			services: {},
		};
		const result = updateServiceUrlInOp(lastOp, 'https://example.com/metadata.json');

		assert.deepStrictEqual(result.services[FAIR_SERVICE_ID], {
			type: FAIR_SERVICE_TYPE,
			endpoint: 'https://example.com/metadata.json',
		});
	});

	it('updates existing FAIR service URL', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...'],
			services: {
				[FAIR_SERVICE_ID]: {
					type: FAIR_SERVICE_TYPE,
					endpoint: 'https://old.example.com/metadata.json',
				},
			},
		};
		const result = updateServiceUrlInOp(lastOp, 'https://new.example.com/metadata.json');

		assert.strictEqual(result.services[FAIR_SERVICE_ID].endpoint, 'https://new.example.com/metadata.json');
	});

	it('preserves other services', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...'],
			services: {
				other: { type: 'OtherService', endpoint: 'https://other.example.com' },
			},
		};
		const result = updateServiceUrlInOp(lastOp, 'https://example.com/metadata.json');

		assert.deepStrictEqual(result.services.other, {
			type: 'OtherService',
			endpoint: 'https://other.example.com',
		});
		assert.deepStrictEqual(result.services[FAIR_SERVICE_ID], {
			type: FAIR_SERVICE_TYPE,
			endpoint: 'https://example.com/metadata.json',
		});
	});

	it('preserves other operation properties', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...'],
			alsoKnownAs: ['fair://example.com'],
			services: {},
		};
		const result = updateServiceUrlInOp(lastOp, 'https://example.com/metadata.json');

		assert.deepStrictEqual(result, {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...'],
			alsoKnownAs: ['fair://example.com'],
			services: {
				[FAIR_SERVICE_ID]: {
					type: FAIR_SERVICE_TYPE,
					endpoint: 'https://example.com/metadata.json',
				},
			},
		});
	});
});

describe('replaceServiceUrlInOp', () => {
	it('replaces the FAIR service URL when old URL matches', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...'],
			services: {
				[FAIR_SERVICE_ID]: {
					type: FAIR_SERVICE_TYPE,
					endpoint: 'https://old.example.com/metadata.json',
				},
			},
		};
		const result = replaceServiceUrlInOp(
			lastOp,
			'https://old.example.com/metadata.json',
			'https://new.example.com/metadata.json',
		);

		assert.deepStrictEqual(result.services[FAIR_SERVICE_ID], {
			type: FAIR_SERVICE_TYPE,
			endpoint: 'https://new.example.com/metadata.json',
		});
	});

	it('throws if FAIR service does not exist', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...'],
			services: {},
		};

		assert.throws(
			() =>
				replaceServiceUrlInOp(lastOp, 'https://old.example.com/metadata.json', 'https://new.example.com/metadata.json'),
			/FAIR service not found in DID/,
		);
	});

	it('throws if old URL does not match current URL', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...'],
			services: {
				[FAIR_SERVICE_ID]: {
					type: FAIR_SERVICE_TYPE,
					endpoint: 'https://current.example.com/metadata.json',
				},
			},
		};

		assert.throws(
			() =>
				replaceServiceUrlInOp(
					lastOp,
					'https://wrong.example.com/metadata.json',
					'https://new.example.com/metadata.json',
				),
			/Current service URL does not match: expected "https:\/\/wrong\.example\.com\/metadata\.json", found "https:\/\/current\.example\.com\/metadata\.json"/,
		);
	});

	it('preserves other services', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...'],
			services: {
				[FAIR_SERVICE_ID]: {
					type: FAIR_SERVICE_TYPE,
					endpoint: 'https://old.example.com/metadata.json',
				},
				other: { type: 'OtherService', endpoint: 'https://other.example.com' },
			},
		};
		const result = replaceServiceUrlInOp(
			lastOp,
			'https://old.example.com/metadata.json',
			'https://new.example.com/metadata.json',
		);

		assert.deepStrictEqual(result.services.other, {
			type: 'OtherService',
			endpoint: 'https://other.example.com',
		});
		assert.deepStrictEqual(result.services[FAIR_SERVICE_ID], {
			type: FAIR_SERVICE_TYPE,
			endpoint: 'https://new.example.com/metadata.json',
		});
	});

	it('preserves other operation properties', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...'],
			alsoKnownAs: ['fair://example.com'],
			services: {
				[FAIR_SERVICE_ID]: {
					type: FAIR_SERVICE_TYPE,
					endpoint: 'https://old.example.com/metadata.json',
				},
			},
		};
		const result = replaceServiceUrlInOp(
			lastOp,
			'https://old.example.com/metadata.json',
			'https://new.example.com/metadata.json',
		);

		assert.deepStrictEqual(result, {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...'],
			alsoKnownAs: ['fair://example.com'],
			services: {
				[FAIR_SERVICE_ID]: {
					type: FAIR_SERVICE_TYPE,
					endpoint: 'https://new.example.com/metadata.json',
				},
			},
		});
	});
});

describe('revokeRotationKeyFromOp', () => {
	it('removes the specified rotation key', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh1', 'did:key:zQ3sh2'],
		};
		const result = revokeRotationKeyFromOp(lastOp, 'did:key:zQ3sh1');

		assert.deepStrictEqual(result.rotationKeys, ['did:key:zQ3sh2']);
	});

	it('preserves other rotation keys when revoking', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh1', 'did:key:zQ3sh2', 'did:key:zQ3sh3'],
		};
		const result = revokeRotationKeyFromOp(lastOp, 'did:key:zQ3sh2');

		assert.deepStrictEqual(result.rotationKeys, ['did:key:zQ3sh1', 'did:key:zQ3sh3']);
	});

	it('throws if rotation key not found', () => {
		const lastOp = {
			verificationMethods: {},
			rotationKeys: ['did:key:zQ3sh1'],
		};

		assert.throws(
			() => revokeRotationKeyFromOp(lastOp, 'did:key:zQ3shNotFound'),
			/Rotation key did:key:zQ3shNotFound not found in DID/,
		);
	});

	it('throws if trying to remove the last rotation key', () => {
		const lastOp = {
			verificationMethods: {},
			rotationKeys: ['did:key:zQ3shOnly'],
		};

		assert.throws(() => revokeRotationKeyFromOp(lastOp, 'did:key:zQ3shOnly'), /Cannot revoke the last rotation key/);
	});

	it('preserves verification keys, services, and alsoKnownAs', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk1', fair2: 'did:key:z6Mk2' },
			rotationKeys: ['did:key:zQ3sh1', 'did:key:zQ3sh2'],
			alsoKnownAs: ['fair://example.com'],
			services: {
				fairpm_repo: {
					type: 'FairPackageManagementRepo',
					endpoint: 'https://example.com/metadata.json',
				},
			},
		};
		const result = revokeRotationKeyFromOp(lastOp, 'did:key:zQ3sh1');

		assert.deepStrictEqual(result, {
			verificationMethods: { fair: 'did:key:z6Mk1', fair2: 'did:key:z6Mk2' },
			rotationKeys: ['did:key:zQ3sh2'],
			alsoKnownAs: ['fair://example.com'],
			services: {
				fairpm_repo: {
					type: 'FairPackageManagementRepo',
					endpoint: 'https://example.com/metadata.json',
				},
			},
		});
	});
});

describe('addAlsoKnownAsToOp', () => {
	it('adds URL to empty alsoKnownAs array', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...'],
			alsoKnownAs: [],
		};
		const result = addAlsoKnownAsToOp(lastOp, 'fair://example.com');

		assert.deepStrictEqual(result.alsoKnownAs, ['fair://example.com']);
	});

	it('appends URL to existing alsoKnownAs array', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...'],
			alsoKnownAs: ['fair://existing.com'],
		};
		const result = addAlsoKnownAsToOp(lastOp, 'fair://new.example.com');

		assert.deepStrictEqual(result.alsoKnownAs, ['fair://existing.com', 'fair://new.example.com']);
	});

	it('handles missing alsoKnownAs field', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...'],
		};
		const result = addAlsoKnownAsToOp(lastOp, 'fair://example.com');

		assert.deepStrictEqual(result.alsoKnownAs, ['fair://example.com']);
	});

	it('throws if URL already exists in alsoKnownAs', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...'],
			alsoKnownAs: ['fair://existing.com'],
		};

		assert.throws(() => addAlsoKnownAsToOp(lastOp, 'fair://existing.com'), /URL already exists in alsoKnownAs/);
	});

	it('preserves verification methods, rotation keys, and services', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk1', fair2: 'did:key:z6Mk2' },
			rotationKeys: ['did:key:zQ3sh1', 'did:key:zQ3sh2'],
			alsoKnownAs: ['fair://existing.com'],
			services: {
				fairpm_repo: {
					type: 'FairPackageManagementRepo',
					endpoint: 'https://example.com/metadata.json',
				},
			},
		};
		const result = addAlsoKnownAsToOp(lastOp, 'fair://new.example.com');

		assert.deepStrictEqual(result, {
			verificationMethods: { fair: 'did:key:z6Mk1', fair2: 'did:key:z6Mk2' },
			rotationKeys: ['did:key:zQ3sh1', 'did:key:zQ3sh2'],
			alsoKnownAs: ['fair://existing.com', 'fair://new.example.com'],
			services: {
				fairpm_repo: {
					type: 'FairPackageManagementRepo',
					endpoint: 'https://example.com/metadata.json',
				},
			},
		});
	});
});

describe('replaceAlsoKnownAsInOp', () => {
	it('replaces the alsoKnownAs URL when old URL matches', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...'],
			alsoKnownAs: ['fair://old.example.com'],
		};
		const result = replaceAlsoKnownAsInOp(lastOp, 'fair://old.example.com', 'fair://new.example.com');

		assert.deepStrictEqual(result.alsoKnownAs, ['fair://new.example.com']);
	});

	it('replaces URL at correct index when multiple URLs exist', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...'],
			alsoKnownAs: ['fair://first.com', 'fair://old.example.com', 'fair://third.com'],
		};
		const result = replaceAlsoKnownAsInOp(lastOp, 'fair://old.example.com', 'fair://new.example.com');

		assert.deepStrictEqual(result.alsoKnownAs, ['fair://first.com', 'fair://new.example.com', 'fair://third.com']);
	});

	it('throws if old URL does not exist in alsoKnownAs', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...'],
			alsoKnownAs: ['fair://existing.com'],
		};

		assert.throws(
			() => replaceAlsoKnownAsInOp(lastOp, 'fair://notfound.com', 'fair://new.example.com'),
			/URL not found in alsoKnownAs: fair:\/\/notfound\.com/,
		);
	});

	it('throws if alsoKnownAs is empty', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...'],
			alsoKnownAs: [],
		};

		assert.throws(
			() => replaceAlsoKnownAsInOp(lastOp, 'fair://old.com', 'fair://new.com'),
			/URL not found in alsoKnownAs/,
		);
	});

	it('throws if alsoKnownAs is missing', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...'],
		};

		assert.throws(
			() => replaceAlsoKnownAsInOp(lastOp, 'fair://old.com', 'fair://new.com'),
			/URL not found in alsoKnownAs/,
		);
	});

	it('throws if new URL already exists in alsoKnownAs', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...'],
			alsoKnownAs: ['fair://old.com', 'fair://existing.com'],
		};

		assert.throws(
			() => replaceAlsoKnownAsInOp(lastOp, 'fair://old.com', 'fair://existing.com'),
			/URL already exists in alsoKnownAs: fair:\/\/existing\.com/,
		);
	});

	it('preserves other alsoKnownAs URLs', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...'],
			alsoKnownAs: ['fair://first.com', 'fair://second.com', 'fair://third.com'],
		};
		const result = replaceAlsoKnownAsInOp(lastOp, 'fair://second.com', 'fair://new.com');

		assert.deepStrictEqual(result.alsoKnownAs, ['fair://first.com', 'fair://new.com', 'fair://third.com']);
	});

	it('preserves verification methods, rotation keys, and services', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk1', fair2: 'did:key:z6Mk2' },
			rotationKeys: ['did:key:zQ3sh1', 'did:key:zQ3sh2'],
			alsoKnownAs: ['fair://old.example.com'],
			services: {
				fairpm_repo: {
					type: 'FairPackageManagementRepo',
					endpoint: 'https://example.com/metadata.json',
				},
			},
		};
		const result = replaceAlsoKnownAsInOp(lastOp, 'fair://old.example.com', 'fair://new.example.com');

		assert.deepStrictEqual(result, {
			verificationMethods: { fair: 'did:key:z6Mk1', fair2: 'did:key:z6Mk2' },
			rotationKeys: ['did:key:zQ3sh1', 'did:key:zQ3sh2'],
			alsoKnownAs: ['fair://new.example.com'],
			services: {
				fairpm_repo: {
					type: 'FairPackageManagementRepo',
					endpoint: 'https://example.com/metadata.json',
				},
			},
		});
	});
});

describe('removeServiceUrlFromOp', () => {
	it('removes the FAIR service when URL matches', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...'],
			services: {
				[FAIR_SERVICE_ID]: {
					type: FAIR_SERVICE_TYPE,
					endpoint: 'https://example.com/metadata.json',
				},
			},
		};
		const result = removeServiceUrlFromOp(lastOp, 'https://example.com/metadata.json');

		assert.deepStrictEqual(result.services, {});
	});

	it('removes the last (only) service successfully', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...'],
			services: {
				[FAIR_SERVICE_ID]: {
					type: FAIR_SERVICE_TYPE,
					endpoint: 'https://example.com/metadata.json',
				},
			},
		};
		const result = removeServiceUrlFromOp(lastOp, 'https://example.com/metadata.json');

		assert.deepStrictEqual(result.services, {});
		assert.strictEqual(Object.keys(result.services).length, 0);
	});

	it('throws if FAIR service does not exist', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...'],
			services: {},
		};

		assert.throws(
			() => removeServiceUrlFromOp(lastOp, 'https://example.com/metadata.json'),
			/FAIR service not found in DID/,
		);
	});

	it('throws if URL does not match current URL', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...'],
			services: {
				[FAIR_SERVICE_ID]: {
					type: FAIR_SERVICE_TYPE,
					endpoint: 'https://actual.example.com/metadata.json',
				},
			},
		};

		assert.throws(
			() => removeServiceUrlFromOp(lastOp, 'https://wrong.example.com/metadata.json'),
			/Service URL does not match: expected "https:\/\/wrong\.example\.com\/metadata\.json", found "https:\/\/actual\.example\.com\/metadata\.json"/,
		);
	});

	it('preserves other services', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...'],
			services: {
				[FAIR_SERVICE_ID]: {
					type: FAIR_SERVICE_TYPE,
					endpoint: 'https://example.com/metadata.json',
				},
				other: { type: 'OtherService', endpoint: 'https://other.example.com' },
			},
		};
		const result = removeServiceUrlFromOp(lastOp, 'https://example.com/metadata.json');

		assert.deepStrictEqual(result.services, {
			other: { type: 'OtherService', endpoint: 'https://other.example.com' },
		});
	});

	it('preserves other operation properties', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...'],
			alsoKnownAs: ['fair://example.com'],
			services: {
				[FAIR_SERVICE_ID]: {
					type: FAIR_SERVICE_TYPE,
					endpoint: 'https://example.com/metadata.json',
				},
			},
		};
		const result = removeServiceUrlFromOp(lastOp, 'https://example.com/metadata.json');

		assert.deepStrictEqual(result, {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...'],
			alsoKnownAs: ['fair://example.com'],
			services: {},
		});
	});
});

describe('removeAlsoKnownAsFromOp', () => {
	it('removes the URL from alsoKnownAs', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...'],
			alsoKnownAs: ['fair://example.com'],
		};
		const result = removeAlsoKnownAsFromOp(lastOp, 'fair://example.com');

		assert.deepStrictEqual(result.alsoKnownAs, []);
	});

	it('removes the last (only) URL successfully', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...'],
			alsoKnownAs: ['fair://only.example.com'],
		};
		const result = removeAlsoKnownAsFromOp(lastOp, 'fair://only.example.com');

		assert.deepStrictEqual(result.alsoKnownAs, []);
		assert.strictEqual(result.alsoKnownAs.length, 0);
	});

	it('removes only the specified URL when multiple URLs exist', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...'],
			alsoKnownAs: ['fair://first.com', 'fair://second.com', 'fair://third.com'],
		};
		const result = removeAlsoKnownAsFromOp(lastOp, 'fair://second.com');

		assert.deepStrictEqual(result.alsoKnownAs, ['fair://first.com', 'fair://third.com']);
	});

	it('throws if URL does not exist in alsoKnownAs', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...'],
			alsoKnownAs: ['fair://existing.com'],
		};

		assert.throws(
			() => removeAlsoKnownAsFromOp(lastOp, 'fair://notfound.com'),
			/URL not found in alsoKnownAs: fair:\/\/notfound\.com/,
		);
	});

	it('throws if alsoKnownAs is empty', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...'],
			alsoKnownAs: [],
		};

		assert.throws(() => removeAlsoKnownAsFromOp(lastOp, 'fair://example.com'), /URL not found in alsoKnownAs/);
	});

	it('throws if alsoKnownAs is missing', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...'],
		};

		assert.throws(() => removeAlsoKnownAsFromOp(lastOp, 'fair://example.com'), /URL not found in alsoKnownAs/);
	});

	it('preserves verification methods, rotation keys, and services', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk1', fair2: 'did:key:z6Mk2' },
			rotationKeys: ['did:key:zQ3sh1', 'did:key:zQ3sh2'],
			alsoKnownAs: ['fair://example.com', 'fair://other.com'],
			services: {
				fairpm_repo: {
					type: 'FairPackageManagementRepo',
					endpoint: 'https://example.com/metadata.json',
				},
			},
		};
		const result = removeAlsoKnownAsFromOp(lastOp, 'fair://example.com');

		assert.deepStrictEqual(result, {
			verificationMethods: { fair: 'did:key:z6Mk1', fair2: 'did:key:z6Mk2' },
			rotationKeys: ['did:key:zQ3sh1', 'did:key:zQ3sh2'],
			alsoKnownAs: ['fair://other.com'],
			services: {
				fairpm_repo: {
					type: 'FairPackageManagementRepo',
					endpoint: 'https://example.com/metadata.json',
				},
			},
		});
	});
});
