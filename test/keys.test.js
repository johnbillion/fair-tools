import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
	generateVerificationKeyPair,
	generateRotationKeyPair,
	importVerificationKeyPair,
	importRotationKeyPair,
	verifyWithVerificationKey,
	verifyWithRotationKey,
} from '../src/keys.js';

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
