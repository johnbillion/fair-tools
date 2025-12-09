import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
	generateDID,
	generateVerificationKeyId,
	addVerificationKeyToOp,
	addRotationKeyToOp,
	revokeVerificationKeyFromOp,
	revokeRotationKeyFromOp,
	updateServiceUrlInOp,
	FAIR_SERVICE_ID,
	FAIR_SERVICE_TYPE,
} from '../src/did.js';
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
			alsoKnownAs: ['at://example.com'],
			services: { test: { type: 'Test', endpoint: 'https://example.com' } },
		};
		const result = addVerificationKeyToOp(lastOp, 'did:key:z6MkNew');

		assert.deepStrictEqual(result, {
			verificationMethods: { fair: 'did:key:z6MkNew' },
			rotationKeys: ['did:key:zQ3sh...'],
			alsoKnownAs: ['at://example.com'],
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

		assert.throws(
			() => addRotationKeyToOp(lastOp, 'did:key:zQ3shExisting'),
			/Rotation key already exists/
		);
	});

	it('preserves other operation properties', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...'],
			alsoKnownAs: ['at://example.com'],
			services: { test: { type: 'Test', endpoint: 'https://example.com' } },
		};
		const result = addRotationKeyToOp(lastOp, 'did:key:zQ3shNew');

		assert.deepStrictEqual(result, {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...', 'did:key:zQ3shNew'],
			alsoKnownAs: ['at://example.com'],
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
			/Verification key did:key:z6MkNotFound not found in DID/
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
			alsoKnownAs: ['at://example.com'],
			services: {
				fairpm_repo: { type: 'FairPackageManagementRepo', endpoint: 'https://example.com/metadata.json' },
			},
		};
		const result = revokeVerificationKeyFromOp(lastOp, 'did:key:z6Mk1');

		assert.deepStrictEqual(result, {
			verificationMethods: { fair2: 'did:key:z6Mk2' },
			rotationKeys: ['did:key:zQ3sh1', 'did:key:zQ3sh2'],
			alsoKnownAs: ['at://example.com'],
			services: {
				fairpm_repo: { type: 'FairPackageManagementRepo', endpoint: 'https://example.com/metadata.json' },
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
			alsoKnownAs: ['at://example.com'],
			services: {},
		};
		const result = updateServiceUrlInOp(lastOp, 'https://example.com/metadata.json');

		assert.deepStrictEqual(result, {
			verificationMethods: { fair: 'did:key:z6Mk...' },
			rotationKeys: ['did:key:zQ3sh...'],
			alsoKnownAs: ['at://example.com'],
			services: {
				[FAIR_SERVICE_ID]: {
					type: FAIR_SERVICE_TYPE,
					endpoint: 'https://example.com/metadata.json',
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
			/Rotation key did:key:zQ3shNotFound not found in DID/
		);
	});

	it('throws if trying to remove the last rotation key', () => {
		const lastOp = {
			verificationMethods: {},
			rotationKeys: ['did:key:zQ3shOnly'],
		};

		assert.throws(
			() => revokeRotationKeyFromOp(lastOp, 'did:key:zQ3shOnly'),
			/Cannot revoke the last rotation key/
		);
	});

	it('preserves verification keys, services, and alsoKnownAs', () => {
		const lastOp = {
			verificationMethods: { fair: 'did:key:z6Mk1', fair2: 'did:key:z6Mk2' },
			rotationKeys: ['did:key:zQ3sh1', 'did:key:zQ3sh2'],
			alsoKnownAs: ['at://example.com'],
			services: {
				fairpm_repo: { type: 'FairPackageManagementRepo', endpoint: 'https://example.com/metadata.json' },
			},
		};
		const result = revokeRotationKeyFromOp(lastOp, 'did:key:zQ3sh1');

		assert.deepStrictEqual(result, {
			verificationMethods: { fair: 'did:key:z6Mk1', fair2: 'did:key:z6Mk2' },
			rotationKeys: ['did:key:zQ3sh2'],
			alsoKnownAs: ['at://example.com'],
			services: {
				fairpm_repo: { type: 'FairPackageManagementRepo', endpoint: 'https://example.com/metadata.json' },
			},
		});
		assert.deepStrictEqual(result.alsoKnownAs, ['at://example.com']);
		assert.deepStrictEqual(result.services, {
			fairpm_repo: { type: 'FairPackageManagementRepo', endpoint: 'https://example.com/metadata.json' },
		});
		assert.deepStrictEqual(result.rotationKeys, ['did:key:zQ3sh2']);
	});
});

