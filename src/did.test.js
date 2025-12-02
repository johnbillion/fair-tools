import { describe, it } from 'node:test';
import assert from 'node:assert';
import { generateDID } from './did.js';
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

