import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
	generateDID,
	generateVerificationKeyId,
	addVerificationKeyToOp,
	addRotationKeyToOp,
	updateServiceUrlInOp,
	FAIR_SERVICE_ID,
	FAIR_SERVICE_TYPE,
} from './did.js';
import { generateVerificationKeyPair, generateRotationKeyPair } from './keys.js';

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

		assert.deepStrictEqual(result.rotationKeys, lastOp.rotationKeys);
		assert.deepStrictEqual(result.alsoKnownAs, lastOp.alsoKnownAs);
		assert.deepStrictEqual(result.services, lastOp.services);
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

		assert.deepStrictEqual(result.verificationMethods, lastOp.verificationMethods);
		assert.deepStrictEqual(result.alsoKnownAs, lastOp.alsoKnownAs);
		assert.deepStrictEqual(result.services, lastOp.services);
	});
});
