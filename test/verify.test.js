import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
	extractVerificationKeys,
	verifyArtifactChecksum,
	verifyArtifactSignature,
	validateMetadataStructure,
	ChecksumVerificationError,
	SignatureVerificationError,
} from '../src/verify.js';
import { generateVerificationKeyPair } from '../src/keys.js';
import { Ed25519Keypair } from '../src/Ed25519Keypair.js';
import { signArtifact, METADATA_CONTEXT } from '../src/metadata.js';

describe('extractVerificationKeys', () => {
	it('extracts keys with #fair fragment', () => {
		const didDocument = {
			verificationMethod: [
				{ id: 'did:plc:test#fair', publicKeyMultibase: 'z6MkTest1' },
				{ id: 'did:plc:test#fair2', publicKeyMultibase: 'z6MkTest2' },
				{ id: 'did:plc:test#atproto', publicKeyMultibase: 'z6MkOther' },
			],
		};

		const keys = extractVerificationKeys(didDocument);

		assert.strictEqual(keys.length, 2);
		assert.strictEqual(keys[0].id, 'did:plc:test#fair');
		assert.strictEqual(keys[1].id, 'did:plc:test#fair2');
	});

	it('returns empty array when no fair keys present', () => {
		const didDocument = {
			verificationMethod: [{ id: 'did:plc:test#atproto', publicKeyMultibase: 'z6MkOther' }],
		};

		const keys = extractVerificationKeys(didDocument);

		assert.strictEqual(keys.length, 0);
	});

	it('returns empty array when verificationMethod is missing', () => {
		const didDocument = {};

		const keys = extractVerificationKeys(didDocument);

		assert.strictEqual(keys.length, 0);
	});

	it('handles undefined verificationMethod', () => {
		const didDocument = { verificationMethod: undefined };

		const keys = extractVerificationKeys(didDocument);

		assert.strictEqual(keys.length, 0);
	});
});

describe('verifyArtifactChecksum', () => {
	it('verifies valid sha256 checksum', () => {
		const data = Buffer.from('test data');
		// SHA256 of 'test data'
		const checksum = 'sha256:916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9';

		assert.doesNotThrow(() => verifyArtifactChecksum(data, checksum));
	});

	it('throws ChecksumVerificationError for mismatched checksum', () => {
		const data = Buffer.from('test data');
		const checksum = 'sha256:0000000000000000000000000000000000000000000000000000000000000000';

		assert.throws(() => verifyArtifactChecksum(data, checksum), ChecksumVerificationError);
	});

	it('throws ChecksumVerificationError for unsupported algorithm', () => {
		const data = Buffer.from('test data');
		const checksum = 'md5:abc123';

		assert.throws(
			() => verifyArtifactChecksum(data, checksum),
			(err) => {
				assert.ok(err instanceof ChecksumVerificationError);
				assert.ok(err.message.includes('Unsupported checksum algorithm'));
				return true;
			},
		);
	});
});

describe('validateMetadataStructure', () => {
	it('validates correct metadata structure', () => {
		const metadata = {
			'@context': METADATA_CONTEXT,
			id: 'did:plc:test123456789012345678',
			releases: [],
		};

		const result = validateMetadataStructure(metadata, 'did:plc:test123456789012345678');

		assert.strictEqual(result.valid, true);
		assert.strictEqual(result.errors.length, 0);
	});

	it('fails for wrong @context', () => {
		const metadata = {
			'@context': 'https://wrong.context/v1',
			id: 'did:plc:test123456789012345678',
			releases: [],
		};

		const result = validateMetadataStructure(metadata, 'did:plc:test123456789012345678');

		assert.strictEqual(result.valid, false);
		assert.ok(result.errors.some((e) => e.includes('@context')));
	});

	it('fails for DID mismatch', () => {
		const metadata = {
			'@context': METADATA_CONTEXT,
			id: 'did:plc:wrong12345678901234567',
			releases: [],
		};

		const result = validateMetadataStructure(metadata, 'did:plc:test123456789012345678');

		assert.strictEqual(result.valid, false);
		assert.ok(result.errors.some((e) => e.includes('DID mismatch')));
	});

	it('fails for missing releases array', () => {
		const metadata = {
			'@context': METADATA_CONTEXT,
			id: 'did:plc:test123456789012345678',
		};

		const result = validateMetadataStructure(metadata, 'did:plc:test123456789012345678');

		assert.strictEqual(result.valid, false);
		assert.ok(result.errors.some((e) => e.includes('releases')));
	});

	it('fails for non-array releases', () => {
		const metadata = {
			'@context': METADATA_CONTEXT,
			id: 'did:plc:test123456789012345678',
			releases: 'not an array',
		};

		const result = validateMetadataStructure(metadata, 'did:plc:test123456789012345678');

		assert.strictEqual(result.valid, false);
		assert.ok(result.errors.some((e) => e.includes('releases')));
	});

	it('collects multiple errors', () => {
		const metadata = {
			'@context': 'wrong',
			id: 'wrong-did',
		};

		const result = validateMetadataStructure(metadata, 'did:plc:test123456789012345678');

		assert.strictEqual(result.valid, false);
		assert.ok(result.errors.length >= 2);
	});
});

describe('Ed25519Keypair.fromPublicKeyMultibase', () => {
	it('parses a valid Ed25519 publicKeyMultibase and can verify signatures', async () => {
		// Generate a keypair, get its multibase representation, then parse it back
		const original = await generateVerificationKeyPair();

		// Sign something with the original keypair
		const data = Buffer.from('test artifact data');
		const signature = await signArtifact(data, original.keypair);

		// Get the multibase public key from the did:key
		// did:key:z6Mk... -> z6Mk... (strip 'did:key:' prefix)
		const publicKeyMultibase = original.publicKey.replace('did:key:', '');

		// Parse it back and verify the signature
		const parsed = await Ed25519Keypair.fromPublicKeyMultibase(publicKeyMultibase);
		const { verifyArtifact } = await import('../src/metadata.js');
		const isValid = await verifyArtifact(data, signature, parsed);

		assert.strictEqual(isValid, true);
	});

	it('rejects secp256k1 keys with clear error message', async () => {
		// secp256k1 compressed public key multibase (starts with zQ3sh)
		// This is a valid secp256k1 key format used for rotation keys
		const secp256k1Multibase = 'zQ3shZc2QzJE5VLjPRhMgwg7JXjHKhqLmUxGPGBbhq3yuU3oR';

		await assert.rejects(Ed25519Keypair.fromPublicKeyMultibase(secp256k1Multibase), (err) => {
			assert.ok(err.message.includes('Ed25519'));
			assert.ok(err.message.includes('0xe701')); // secp256k1's multicodec prefix
			return true;
		});
	});

	it('rejects malformed multibase strings', async () => {
		await assert.rejects(Ed25519Keypair.fromPublicKeyMultibase('not-valid-multibase'), (err) => {
			assert.ok(err instanceof Error);
			return true;
		});
	});

	it('round-trips a real public key from querymonitor.com DID document', async () => {
		// Real public key from did:plc:q2afge25l63iz553aumeqi3w#fair
		const publicKeyMultibase = 'z6Mkitp3T2Gk2U4pvuwpy8ygAzxkM6K1Ygoyv1ZgUx3AW9Px';

		const keypair = await Ed25519Keypair.fromPublicKeyMultibase(publicKeyMultibase);

		// Verify it parsed correctly - should be 32 bytes
		assert.strictEqual(keypair.publicKeyBytes().length, 32);

		// Round-trip: publicKeyStr() should return the same multibase
		assert.strictEqual(keypair.publicKeyStr(), publicKeyMultibase);
	});
});

describe('verifyArtifactSignature', () => {
	it('returns the key ID when signature matches', async () => {
		const keys = await generateVerificationKeyPair();
		const data = Buffer.from('artifact content');
		const signature = await signArtifact(data, keys.keypair);

		const verificationKeys = [
			{
				id: 'did:plc:test#fair',
				publicKeyMultibase: keys.publicKey.replace('did:key:', ''),
			},
		];

		const matchedKeyId = await verifyArtifactSignature(data, signature, verificationKeys);

		assert.strictEqual(matchedKeyId, 'did:plc:test#fair');
	});

	it('tries multiple keys and returns the one that matches', async () => {
		const correctKey = await generateVerificationKeyPair();
		const wrongKey = await generateVerificationKeyPair();
		const data = Buffer.from('artifact content');
		const signature = await signArtifact(data, correctKey.keypair);

		const verificationKeys = [
			{
				id: 'did:plc:test#fair-wrong',
				publicKeyMultibase: wrongKey.publicKey.replace('did:key:', ''),
			},
			{
				id: 'did:plc:test#fair-correct',
				publicKeyMultibase: correctKey.publicKey.replace('did:key:', ''),
			},
		];

		const matchedKeyId = await verifyArtifactSignature(data, signature, verificationKeys);

		assert.strictEqual(matchedKeyId, 'did:plc:test#fair-correct');
	});

	it('throws SignatureVerificationError when no key matches', async () => {
		const signingKey = await generateVerificationKeyPair();
		const wrongKey = await generateVerificationKeyPair();
		const data = Buffer.from('artifact content');
		const signature = await signArtifact(data, signingKey.keypair);

		const verificationKeys = [
			{
				id: 'did:plc:test#fair',
				publicKeyMultibase: wrongKey.publicKey.replace('did:key:', ''),
			},
		];

		await assert.rejects(verifyArtifactSignature(data, signature, verificationKeys), (err) => {
			assert.ok(err instanceof SignatureVerificationError);
			assert.ok(err.message.includes('does not match'));
			return true;
		});
	});

	it('includes key parsing errors in the error message', async () => {
		const data = Buffer.from('artifact content');
		const signature = 'some-signature';

		// Use an invalid multibase that will fail to parse
		const verificationKeys = [
			{
				id: 'did:plc:test#fair-bad',
				publicKeyMultibase: 'invalid-not-multibase',
			},
		];

		await assert.rejects(verifyArtifactSignature(data, signature, verificationKeys), (err) => {
			assert.ok(err instanceof SignatureVerificationError);
			assert.ok(err.message.includes('did:plc:test#fair-bad'));
			return true;
		});
	});

	it('rejects non-Ed25519 keys with informative error', async () => {
		const data = Buffer.from('artifact content');
		const signature = 'some-signature';

		// secp256k1 key (rotation key type, not verification key)
		const verificationKeys = [
			{
				id: 'did:plc:test#wrong-type',
				publicKeyMultibase: 'zQ3shZc2QzJE5VLjPRhMgwg7JXjHKhqLmUxGPGBbhq3yuU3oR',
			},
		];

		await assert.rejects(verifyArtifactSignature(data, signature, verificationKeys), (err) => {
			assert.ok(err instanceof SignatureVerificationError);
			assert.ok(err.message.includes('did:plc:test#wrong-type'));
			assert.ok(err.message.includes('Ed25519'));
			return true;
		});
	});
});
