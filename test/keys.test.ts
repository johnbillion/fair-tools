import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
	generateVerificationKeyPair,
	generateRotationKeyPair,
	importVerificationKeyPair,
	importRotationKeyPair,
	verifyWithVerificationKey,
	verifyWithRotationKey,
	getVerificationPublicKeyMultibase,
	parsePublicKeyOnly,
	getRotationPublicKeyDidKey,
	VerificationKeyInputError,
	RotationKeyInputError,
} from '../src/keys.js';
import { encodeVerificationKey, encodeRotationKey } from '../src/keyfile.js';
import { base58btc } from 'multiformats/bases/base58';

describe('generate verification key pair', () => {
	it('returns an object with publicKey, privateKey, and keypair', async () => {
		const result = await generateVerificationKeyPair();

		assert.ok(result.publicKey, 'publicKey should exist');
		assert.ok(result.privateKey, 'privateKey should exist');
		assert.ok(result.keypair, 'keypair should exist');
	});

	it('returns a valid did:key public key', async () => {
		const result = await generateVerificationKeyPair();

		assert.ok(
			result.publicKey.startsWith('did:key:z6Mk'),
			`publicKey should be an Ed25519 did:key, got ${result.publicKey.slice(0, 15)}`,
		);
	});

	it('returns a 32-byte private key', async () => {
		const result = await generateVerificationKeyPair();

		assert.ok(result.privateKey instanceof Uint8Array, 'privateKey should be a Uint8Array');
		assert.strictEqual(result.privateKey.length, 32, 'privateKey should be 32 bytes');
	});

	it('generates unique keys each call', async () => {
		const result1 = await generateVerificationKeyPair();
		const result2 = await generateVerificationKeyPair();

		assert.notStrictEqual(result1.publicKey, result2.publicKey, 'publicKeys should be different');
	});

	it('keypair can sign and verify', async () => {
		const result = await generateVerificationKeyPair();
		const message = new TextEncoder().encode('test');

		const signature = await result.keypair.sign(message);
		const isValid = await verifyWithVerificationKey(message, signature, result.keypair);

		assert.strictEqual(isValid, true);
	});
});

describe('generate rotation key pair', () => {
	it('returns an object with publicKey, privateKey, and keypair', async () => {
		const result = await generateRotationKeyPair();

		assert.ok(result.publicKey, 'publicKey should exist');
		assert.ok(result.privateKey, 'privateKey should exist');
		assert.ok(result.keypair, 'keypair should exist');
	});

	it('returns a valid did:key public key', async () => {
		const result = await generateRotationKeyPair();

		assert.ok(
			result.publicKey.startsWith('did:key:zQ3sh'),
			`publicKey should be a secp256k1 did:key, got ${result.publicKey.slice(0, 15)}`,
		);
	});

	it('returns a 32-byte private key', async () => {
		const result = await generateRotationKeyPair();

		assert.ok(result.privateKey instanceof Uint8Array, 'privateKey should be a Uint8Array');
		assert.strictEqual(result.privateKey.length, 32, 'privateKey should be 32 bytes');
	});
});

describe('import verification key pair', () => {
	it('imports a private key and produces the same public key', async () => {
		const original = await generateVerificationKeyPair();
		const imported = await importVerificationKeyPair(original.privateKey);

		assert.strictEqual(imported.publicKey, original.publicKey, 'publicKeys should match');
	});

	it('works with hex string input', async () => {
		const original = await generateVerificationKeyPair();
		const hexPrivateKey = Buffer.from(original.privateKey).toString('hex');
		const imported = await importVerificationKeyPair(hexPrivateKey);

		assert.strictEqual(imported.publicKey, original.publicKey, 'publicKeys should match');
	});

	it('imported keypair can sign and verify', async () => {
		const original = await generateVerificationKeyPair();
		const imported = await importVerificationKeyPair(original.privateKey);

		const message = new TextEncoder().encode('test message');
		const signature = await imported.keypair.sign(message);
		const isValid = await verifyWithVerificationKey(message, signature, imported.keypair);

		assert.strictEqual(isValid, true, 'signature should be valid');
	});
});

describe('import rotation key pair', () => {
	it('imports a private key and produces the same public key', async () => {
		const original = await generateRotationKeyPair();
		const imported = await importRotationKeyPair(original.privateKey);

		assert.strictEqual(imported.publicKey, original.publicKey, 'publicKeys should match');
	});

	it('works with hex string input', async () => {
		const original = await generateRotationKeyPair();
		const hexPrivateKey = Buffer.from(original.privateKey).toString('hex');
		const imported = await importRotationKeyPair(hexPrivateKey);

		assert.strictEqual(imported.publicKey, original.publicKey, 'publicKeys should match');
	});
});

describe('verify with verification key', () => {
	it('signature is 64 bytes', async () => {
		const keys = await generateVerificationKeyPair();
		const message = new TextEncoder().encode('Sign this message!');

		const signature = await keys.keypair.sign(message);

		assert.ok(signature instanceof Uint8Array, 'signature should be a Uint8Array');
		assert.strictEqual(signature.length, 64, 'signature should be 64 bytes');
	});

	it('works with Uint8Array messages', async () => {
		const keys = await generateVerificationKeyPair();
		const message = new TextEncoder().encode('binary message');

		const signature = await keys.keypair.sign(message);

		assert.ok(signature instanceof Uint8Array);
		assert.strictEqual(signature.length, 64);
	});

	it('verifies valid signatures', async () => {
		const keys = await generateVerificationKeyPair();
		const message = new TextEncoder().encode('Verify me!');

		const signature = await keys.keypair.sign(message);
		const isValid = await verifyWithVerificationKey(message, signature, keys.keypair);

		assert.strictEqual(isValid, true);
	});

	it('rejects invalid signatures', async () => {
		const keys = await generateVerificationKeyPair();
		const message = new TextEncoder().encode('Original message');
		const wrongMessage = new TextEncoder().encode('Wrong message');

		const signature = await keys.keypair.sign(message);
		const isValid = await verifyWithVerificationKey(wrongMessage, signature, keys.keypair);

		assert.strictEqual(isValid, false);
	});
});

describe('verify with rotation key', () => {
	it('signature is 64 bytes (compact format)', async () => {
		const keys = await generateRotationKeyPair();
		const message = 'Rotate my keys!';

		const signature = await keys.keypair.sign(message);

		assert.ok(signature instanceof Uint8Array, 'signature should be a Uint8Array');
		assert.strictEqual(signature.length, 64, 'signature should be 64 bytes (compact format)');
	});

	it('works with Uint8Array messages', async () => {
		const keys = await generateRotationKeyPair();
		const message = new TextEncoder().encode('binary rotation message');

		const signature = await keys.keypair.sign(message);

		assert.ok(signature instanceof Uint8Array);
		assert.strictEqual(signature.length, 64);
	});

	it('verifies valid signatures', async () => {
		const keys = await generateRotationKeyPair();
		const message = 'Verify rotation!';

		const signature = await keys.keypair.sign(message);
		const isValid = await verifyWithRotationKey(message, signature, keys.publicKey);

		assert.strictEqual(isValid, true);
	});

	it('rejects invalid signatures', async () => {
		const keys = await generateRotationKeyPair();
		const message = 'Original message';
		const wrongMessage = 'Wrong message';

		const signature = await keys.keypair.sign(message);
		const isValid = await verifyWithRotationKey(wrongMessage, signature, keys.publicKey);

		assert.strictEqual(isValid, false);
	});
});

describe('getVerificationPublicKeyMultibase', () => {
	it('extracts multibase from did:key format', async () => {
		const keys = await generateVerificationKeyPair();
		const multibase = keys.keypair.publicKeyStr();

		const result = await getVerificationPublicKeyMultibase(keys.publicKey);

		assert.strictEqual(result, multibase);
	});

	it('returns raw multibase as-is when valid', async () => {
		const keys = await generateVerificationKeyPair();
		const multibase = keys.keypair.publicKeyStr();

		const result = await getVerificationPublicKeyMultibase(multibase);

		assert.strictEqual(result, multibase);
	});

	it('derives public key from hex private key', async () => {
		const keys = await generateVerificationKeyPair();
		const hexPrivateKey = Buffer.from(keys.privateKey).toString('hex');
		const expectedMultibase = keys.keypair.publicKeyStr();

		const result = await getVerificationPublicKeyMultibase(hexPrivateKey);

		assert.strictEqual(result, expectedMultibase);
	});

	it('derives public key from PEM private key', async () => {
		const keys = await generateVerificationKeyPair();
		const pemPrivateKey = encodeVerificationKey(keys.privateKey);
		const expectedMultibase = keys.keypair.publicKeyStr();

		const result = await getVerificationPublicKeyMultibase(pemPrivateKey);

		assert.strictEqual(result, expectedMultibase);
	});

	it('derives public key from multibase private key', async () => {
		const keys = await generateVerificationKeyPair();
		const expectedMultibase = keys.keypair.publicKeyStr();

		// Sodium format: 64 bytes (32-byte seed + 32-byte public key)
		const ED25519_PRIV_PREFIX = new Uint8Array([0x80, 0x26]);
		const sodiumKey = Buffer.concat([
			Buffer.from(ED25519_PRIV_PREFIX),
			Buffer.from(keys.privateKey),
			Buffer.from(keys.keypair.publicKeyBytes()),
		]);
		const multibasePrivateKey = base58btc.encode(sodiumKey);

		const result = await getVerificationPublicKeyMultibase(multibasePrivateKey);

		assert.strictEqual(result, expectedMultibase);
	});

	it('trims whitespace from input', async () => {
		const keys = await generateVerificationKeyPair();
		const multibase = keys.keypair.publicKeyStr();

		const result = await getVerificationPublicKeyMultibase('  ' + keys.publicKey + '\n');

		assert.strictEqual(result, multibase);
	});

	it('throws for invalid did:key format', async () => {
		await assert.rejects(getVerificationPublicKeyMultibase('did:key:invalid'), (err) => {
			assert(err instanceof VerificationKeyInputError);
			assert.match(err.message, /Invalid did:key format/);
			return true;
		});
	});

	it('throws for invalid multibase public key', async () => {
		await assert.rejects(getVerificationPublicKeyMultibase('z6MkInvalidKey'), (err) => {
			assert(err instanceof VerificationKeyInputError);
			assert.match(err.message, /Invalid public key multibase/);
			return true;
		});
	});

	it('throws for unrecognized key format', async () => {
		await assert.rejects(getVerificationPublicKeyMultibase('not-a-valid-key-format'), (err) => {
			assert(err instanceof VerificationKeyInputError);
			assert.match(err.message, /Unrecognized key format/);
			return true;
		});
	});

	it('throws for rotation key (wrong key type)', async () => {
		const rotationKeys = await generateRotationKeyPair();

		await assert.rejects(getVerificationPublicKeyMultibase(rotationKeys.publicKey), (err) => {
			assert(err instanceof VerificationKeyInputError);
			assert.match(err.message, /Invalid did:key format/);
			return true;
		});
	});
});

describe('parsePublicKeyOnly', () => {
	it('extracts multibase from did:key format', async () => {
		const keys = await generateVerificationKeyPair();
		const multibase = keys.keypair.publicKeyStr();

		const result = await parsePublicKeyOnly(keys.publicKey);

		assert.strictEqual(result, multibase);
	});

	it('returns raw multibase as-is when valid', async () => {
		const keys = await generateVerificationKeyPair();
		const multibase = keys.keypair.publicKeyStr();

		const result = await parsePublicKeyOnly(multibase);

		assert.strictEqual(result, multibase);
	});

	it('throws for hex private key', async () => {
		const keys = await generateVerificationKeyPair();
		const hexPrivateKey = Buffer.from(keys.privateKey).toString('hex');

		await assert.rejects(parsePublicKeyOnly(hexPrivateKey), (err) => {
			assert(err instanceof VerificationKeyInputError);
			assert.match(err.message, /Private key provided but only public keys are accepted/);
			return true;
		});
	});

	it('throws for PEM private key', async () => {
		const keys = await generateVerificationKeyPair();
		const pemPrivateKey = encodeVerificationKey(keys.privateKey);

		await assert.rejects(parsePublicKeyOnly(pemPrivateKey), (err) => {
			assert(err instanceof VerificationKeyInputError);
			assert.match(err.message, /Private key provided but only public keys are accepted/);
			return true;
		});
	});

	it('throws for multibase private key', async () => {
		const keys = await generateVerificationKeyPair();

		// Sodium format: 64 bytes (32-byte seed + 32-byte public key)
		const ED25519_PRIV_PREFIX = new Uint8Array([0x80, 0x26]);
		const sodiumKey = Buffer.concat([
			Buffer.from(ED25519_PRIV_PREFIX),
			Buffer.from(keys.privateKey),
			Buffer.from(keys.keypair.publicKeyBytes()),
		]);
		const multibasePrivateKey = base58btc.encode(sodiumKey);

		await assert.rejects(parsePublicKeyOnly(multibasePrivateKey), (err) => {
			assert(err instanceof VerificationKeyInputError);
			assert.match(err.message, /Private key provided but only public keys are accepted/);
			return true;
		});
	});

	it('throws for invalid did:key format', async () => {
		await assert.rejects(parsePublicKeyOnly('did:key:invalid'), (err) => {
			assert(err instanceof VerificationKeyInputError);
			assert.match(err.message, /Invalid did:key format/);
			return true;
		});
	});

	it('throws for invalid multibase public key', async () => {
		await assert.rejects(parsePublicKeyOnly('z6MkInvalidKey'), (err) => {
			assert(err instanceof VerificationKeyInputError);
			assert.match(err.message, /Invalid public key multibase/);
			return true;
		});
	});

	it('throws for unrecognized key format', async () => {
		await assert.rejects(parsePublicKeyOnly('not-a-valid-key-format'), (err) => {
			assert(err instanceof VerificationKeyInputError);
			assert.match(err.message, /Unrecognized key format/);
			return true;
		});
	});

	it('throws for rotation key (wrong key type)', async () => {
		const rotationKeys = await generateRotationKeyPair();

		await assert.rejects(parsePublicKeyOnly(rotationKeys.publicKey), (err) => {
			assert(err instanceof VerificationKeyInputError);
			assert.match(err.message, /Invalid did:key format/);
			return true;
		});
	});
});

describe('getRotationPublicKeyDidKey', () => {
	it('returns did:key format as-is when valid', async () => {
		const keys = await generateRotationKeyPair();

		const result = await getRotationPublicKeyDidKey(keys.publicKey);

		assert.strictEqual(result, keys.publicKey);
	});

	it('converts multibase to did:key format', async () => {
		const keys = await generateRotationKeyPair();
		const multibase = keys.publicKey.replace('did:key:', '');

		const result = await getRotationPublicKeyDidKey(multibase);

		assert.strictEqual(result, keys.publicKey);
	});

	it('derives public key from hex private key', async () => {
		const keys = await generateRotationKeyPair();
		const hexPrivateKey = Buffer.from(keys.privateKey).toString('hex');

		const result = await getRotationPublicKeyDidKey(hexPrivateKey);

		assert.strictEqual(result, keys.publicKey);
	});

	it('derives public key from PEM private key', async () => {
		const keys = await generateRotationKeyPair();
		const pemPrivateKey = encodeRotationKey(keys.privateKey);

		const result = await getRotationPublicKeyDidKey(pemPrivateKey);

		assert.strictEqual(result, keys.publicKey);
	});

	it('derives public key from multibase private key', async () => {
		const keys = await generateRotationKeyPair();

		// secp256k1 multibase format
		const SECP256K1_PRIV_PREFIX = new Uint8Array([0x81, 0x26]);
		const multibaseKey = Buffer.concat([Buffer.from(SECP256K1_PRIV_PREFIX), Buffer.from(keys.privateKey)]);
		const multibasePrivateKey = base58btc.encode(multibaseKey);

		const result = await getRotationPublicKeyDidKey(multibasePrivateKey);

		assert.strictEqual(result, keys.publicKey);
	});

	it('trims whitespace from input', async () => {
		const keys = await generateRotationKeyPair();

		const result = await getRotationPublicKeyDidKey('  ' + keys.publicKey + '\n');

		assert.strictEqual(result, keys.publicKey);
	});

	it('throws for invalid did:key format', async () => {
		await assert.rejects(getRotationPublicKeyDidKey('did:key:invalid'), (err) => {
			assert(err instanceof RotationKeyInputError);
			assert.match(err.message, /Invalid rotation key/);
			return true;
		});
	});

	it('throws for verification key (wrong key type)', async () => {
		const verificationKeys = await generateVerificationKeyPair();

		await assert.rejects(getRotationPublicKeyDidKey(verificationKeys.publicKey), (err) => {
			assert(err instanceof RotationKeyInputError);
			assert.match(err.message, /Wrong key type.*verification key/);
			return true;
		});
	});

	it('throws for verification key multibase (wrong key type)', async () => {
		const verificationKeys = await generateVerificationKeyPair();
		const multibase = verificationKeys.keypair.publicKeyStr();

		await assert.rejects(getRotationPublicKeyDidKey(multibase), (err) => {
			assert(err instanceof RotationKeyInputError);
			assert.match(err.message, /Wrong key type.*verification key/);
			return true;
		});
	});

	it('throws for unrecognized key format', async () => {
		await assert.rejects(getRotationPublicKeyDidKey('not-a-valid-key-format'), (err) => {
			assert(err instanceof RotationKeyInputError);
			assert.match(err.message, /Unrecognized key format/);
			return true;
		});
	});
});
