import { describe, it, after, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import { writeFile, rm, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { base58btc } from 'multiformats/bases/base58';
import {
	loadRotationKey,
	loadVerificationKey,
	loadRotationKeyForRevocation,
	SigningKeyError,
} from '../../src/cli/lib/signing.js';

const testDir = join(tmpdir(), 'fair-tools-signing-test-' + Date.now());

// Multicodec prefixes for private keys
const MULTICODEC_SECP256K1_PRIV = new Uint8Array([0x81, 0x26]);
const MULTICODEC_ED25519_PRIV = new Uint8Array([0x80, 0x26]);

/**
 * Create a multibase base58btc encoded private key for testing.
 * @param {string} hexKey - 32-byte key as hex string
 * @param {'rotation'|'verification'} keyType - Key type determines multicodec prefix
 * @returns {string} - Multibase encoded key (starts with 'z')
 */
function createMultibaseKey(hexKey, keyType) {
	const prefix = keyType === 'rotation' ? MULTICODEC_SECP256K1_PRIV : MULTICODEC_ED25519_PRIV;
	const keyBytes = Buffer.from(hexKey, 'hex');
	const combined = new Uint8Array(prefix.length + keyBytes.length);
	combined.set(prefix);
	combined.set(keyBytes, prefix.length);
	return base58btc.encode(combined);
}

// Sample key data - 64 character hex keys (32 bytes)
const sampleKeyFile = {
	did: 'did:plc:test123',
	rotationKeys: {
		'did:key:zQ3shRotation1': 'aabbccdd112233445566778899aabbccddeeff00112233445566778899001122',
		'did:key:zQ3shRotation2': 'eeff0011223344556677889900112233445566778899aabbccddeeff00112233',
	},
	verificationKeys: {
		'did:key:z6MkVerification1': '112233445566778899001122334455667788aabbccddeeff0011223344556677',
		'did:key:z6MkVerification2': '5566778899001122334455667788990011aabbccddeeff00112233445566778899',
	},
};

// Sample hex key (32 bytes)
const sampleHexKey = 'aabbccdd112233445566778899aabbccddeeff00112233445566778899001122';

// Sample multibase keys (encoded from sampleHexKey with appropriate prefix)
const sampleMultibaseRotationKey = createMultibaseKey(sampleHexKey, 'rotation');
const sampleMultibaseVerificationKey = createMultibaseKey(sampleHexKey, 'verification');

describe('signing.js', () => {
	after(async () => {
		await rm(testDir, { recursive: true, force: true });
	});

	describe('loadRotationKey', () => {
		it('throws when --signing-key used without --signing-file', async () => {
			await assert.rejects(
				loadRotationKey({ signingKey: 'did:key:zQ3sh...' }),
				(err) => {
					assert(err instanceof SigningKeyError);
					assert.strictEqual(err.message, 'Cannot specify a signing key without a signing file');
					return true;
				}
			);
		});

		it('throws when key file does not exist', async () => {
			await assert.rejects(
				loadRotationKey({ signingFile: '/nonexistent/path.json' }),
				(err) => {
					assert(err instanceof SigningKeyError);
					assert.match(err.message, /Error reading key file/);
					return true;
				}
			);
		});

		it('throws when key file has no rotation keys', async () => {
			await mkdir(testDir, { recursive: true });
			const filePath = join(testDir, 'empty-rotation.json');
			await writeFile(filePath, JSON.stringify({ did: 'did:plc:test', rotationKeys: {} }));

			await assert.rejects(
				loadRotationKey({ signingFile: filePath }),
				(err) => {
					assert(err instanceof SigningKeyError);
					assert.strictEqual(err.message, 'Key file must contain at least one rotation key');
					return true;
				}
			);
		});

		it('throws when specified signing key not found', async () => {
			await mkdir(testDir, { recursive: true });
			const filePath = join(testDir, 'rotation-keys.json');
			await writeFile(filePath, JSON.stringify(sampleKeyFile));

			await assert.rejects(
				loadRotationKey({ signingFile: filePath, signingKey: 'did:key:nonexistent' }),
				(err) => {
					assert(err instanceof SigningKeyError);
					assert.match(err.message, /not found in key file/);
					assert.match(err.message, /Available keys:/);
					return true;
				}
			);
		});

		it('loads first rotation key when no signing key specified', async () => {
			await mkdir(testDir, { recursive: true });
			const filePath = join(testDir, 'rotation-first.json');
			await writeFile(filePath, JSON.stringify(sampleKeyFile));

			const result = await loadRotationKey({ signingFile: filePath });

			assert.strictEqual(result.privateKeyHex, 'aabbccdd112233445566778899aabbccddeeff00112233445566778899001122');
			assert.deepStrictEqual(result.keyData, sampleKeyFile);
		});

		it('loads specific rotation key when specified', async () => {
			await mkdir(testDir, { recursive: true });
			const filePath = join(testDir, 'rotation-specific.json');
			await writeFile(filePath, JSON.stringify(sampleKeyFile));

			const result = await loadRotationKey({
				signingFile: filePath,
				signingKey: 'did:key:zQ3shRotation2',
			});

			assert.strictEqual(result.privateKeyHex, 'eeff0011223344556677889900112233445566778899aabbccddeeff00112233');
		});

		it('loads multibase key file without trailing newline', async () => {
			await mkdir(testDir, { recursive: true });
			const filePath = join(testDir, 'rotation-multibase.txt');
			await writeFile(filePath, sampleMultibaseRotationKey);

			const result = await loadRotationKey({ signingFile: filePath });

			assert.strictEqual(result.privateKeyHex, sampleHexKey);
			assert.strictEqual(result.keyData, null);
		});

		it('loads multibase key file with trailing newline', async () => {
			await mkdir(testDir, { recursive: true });
			const filePath = join(testDir, 'rotation-multibase-newline.txt');
			await writeFile(filePath, sampleMultibaseRotationKey + '\n');

			const result = await loadRotationKey({ signingFile: filePath });

			assert.strictEqual(result.privateKeyHex, sampleHexKey);
			assert.strictEqual(result.keyData, null);
		});

		it('throws when --signing-key used with multibase key file', async () => {
			await mkdir(testDir, { recursive: true });
			const filePath = join(testDir, 'rotation-multibase-with-key.txt');
			await writeFile(filePath, sampleMultibaseRotationKey);

			await assert.rejects(
				loadRotationKey({ signingFile: filePath, signingKey: 'did:key:zQ3sh...' }),
				(err) => {
					assert(err instanceof SigningKeyError);
					assert.strictEqual(err.message, 'Cannot specify a signing key when using a multibase key file');
					return true;
				}
			);
		});

		it('throws for invalid file content (not JSON or multibase)', async () => {
			await mkdir(testDir, { recursive: true });
			const filePath = join(testDir, 'rotation-invalid.txt');
			await writeFile(filePath, 'this is not valid');

			await assert.rejects(
				loadRotationKey({ signingFile: filePath }),
				(err) => {
					assert(err instanceof SigningKeyError);
					assert.strictEqual(err.message, 'Key file must be valid JSON or a multibase base58btc encoded key (starting with "z")');
					return true;
				}
			);
		});

		it('throws when multibase key has wrong prefix (ed25519 instead of secp256k1)', async () => {
			await mkdir(testDir, { recursive: true });
			const filePath = join(testDir, 'rotation-wrong-prefix.txt');
			// Use a verification key (ed25519) where rotation key (secp256k1) is expected
			await writeFile(filePath, sampleMultibaseVerificationKey);

			await assert.rejects(
				loadRotationKey({ signingFile: filePath }),
				(err) => {
					assert(err instanceof SigningKeyError);
					assert.strictEqual(err.message, 'Wrong key type for this operation. This looks like a verification key, but a rotation key is required.');
					return true;
				}
			);
		});

		it('throws when multibase key has invalid base58btc encoding', async () => {
			await mkdir(testDir, { recursive: true });
			const filePath = join(testDir, 'rotation-bad-base58.txt');
			// 'z' prefix followed by invalid base58 characters (0, O, I, l are invalid)
			await writeFile(filePath, 'zInvalidBase58WithBadChars0OIl');

			await assert.rejects(
				loadRotationKey({ signingFile: filePath }),
				(err) => {
					assert(err instanceof SigningKeyError);
					assert.strictEqual(err.message, 'Invalid key format. The key could not be decoded.');
					return true;
				}
			);
		});

		it('throws when multibase key has wrong length', async () => {
			await mkdir(testDir, { recursive: true });
			const filePath = join(testDir, 'rotation-wrong-length.txt');
			// Create a key with correct secp256k1 prefix but only 8 bytes instead of 32
			const shortKey = Buffer.from('0011223344556677', 'hex');
			const prefix = MULTICODEC_SECP256K1_PRIV;
			const combined = new Uint8Array(prefix.length + shortKey.length);
			combined.set(prefix);
			combined.set(shortKey, prefix.length);
			await writeFile(filePath, base58btc.encode(combined));

			await assert.rejects(
				loadRotationKey({ signingFile: filePath }),
				(err) => {
					assert(err instanceof SigningKeyError);
					assert.strictEqual(err.message, 'Invalid key format. The key has the wrong length.');
					return true;
				}
			);
		});

		it('throws when env var not set and no signing file', async () => {
			const originalEnv = process.env.FAIR_ROTATION_KEY;
			delete process.env.FAIR_ROTATION_KEY;

			try {
				await assert.rejects(
					loadRotationKey({}),
					(err) => {
						assert(err instanceof SigningKeyError);
						assert.strictEqual(err.message, 'No signing key provided. Set the FAIR_ROTATION_KEY environment variable or provide a signing file.');
						return true;
					}
				);
			} finally {
				if (originalEnv !== undefined) {
					process.env.FAIR_ROTATION_KEY = originalEnv;
				}
			}
		});

		it('loads from env var when no signing file', async () => {
			const originalEnv = process.env.FAIR_ROTATION_KEY;
			process.env.FAIR_ROTATION_KEY = 'envkeyvalue';

			try {
				const result = await loadRotationKey({});

				assert.strictEqual(result.privateKeyHex, 'envkeyvalue');
				assert.strictEqual(result.keyData, null);
			} finally {
				if (originalEnv !== undefined) {
					process.env.FAIR_ROTATION_KEY = originalEnv;
				} else {
					delete process.env.FAIR_ROTATION_KEY;
				}
			}
		});

		it('uses custom env var name', async () => {
			const originalEnv = process.env.CUSTOM_KEY;
			process.env.CUSTOM_KEY = 'customvalue';

			try {
				const result = await loadRotationKey({ envVar: 'CUSTOM_KEY' });

				assert.strictEqual(result.privateKeyHex, 'customvalue');
			} finally {
				if (originalEnv !== undefined) {
					process.env.CUSTOM_KEY = originalEnv;
				} else {
					delete process.env.CUSTOM_KEY;
				}
			}
		});
	});

	describe('loadVerificationKey', () => {
		it('throws when --signing-key used without --signing-file', async () => {
			await assert.rejects(
				loadVerificationKey({ signingKey: 'did:key:z6Mk...' }),
				(err) => {
					assert(err instanceof SigningKeyError);
					assert.strictEqual(err.message, 'Cannot specify a signing key without a signing file');
					return true;
				}
			);
		});

		it('throws when key file has no verification keys', async () => {
			await mkdir(testDir, { recursive: true });
			const filePath = join(testDir, 'empty-verification.json');
			await writeFile(filePath, JSON.stringify({ did: 'did:plc:test', verificationKeys: {} }));

			await assert.rejects(
				loadVerificationKey({ signingFile: filePath }),
				(err) => {
					assert(err instanceof SigningKeyError);
					assert.strictEqual(err.message, 'Key file must contain at least one verification key');
					return true;
				}
			);
		});

		it('throws when specified signing key not found', async () => {
			await mkdir(testDir, { recursive: true });
			const filePath = join(testDir, 'verification-keys.json');
			await writeFile(filePath, JSON.stringify(sampleKeyFile));

			await assert.rejects(
				loadVerificationKey({ signingFile: filePath, signingKey: 'did:key:nonexistent' }),
				(err) => {
					assert(err instanceof SigningKeyError);
					assert.match(err.message, /not found in key file/);
					return true;
				}
			);
		});

		it('loads first verification key when no signing key specified', async () => {
			await mkdir(testDir, { recursive: true });
			const filePath = join(testDir, 'verification-first.json');
			await writeFile(filePath, JSON.stringify(sampleKeyFile));

			const result = await loadVerificationKey({ signingFile: filePath });

			assert.strictEqual(result.privateKeyHex, '112233445566778899001122334455667788aabbccddeeff0011223344556677');
		});

		it('loads specific verification key when specified', async () => {
			await mkdir(testDir, { recursive: true });
			const filePath = join(testDir, 'verification-specific.json');
			await writeFile(filePath, JSON.stringify(sampleKeyFile));

			const result = await loadVerificationKey({
				signingFile: filePath,
				signingKey: 'did:key:z6MkVerification2',
			});

			assert.strictEqual(result.privateKeyHex, '5566778899001122334455667788990011aabbccddeeff00112233445566778899');
		});

		it('loads multibase key file without trailing newline', async () => {
			await mkdir(testDir, { recursive: true });
			const filePath = join(testDir, 'verification-multibase.txt');
			await writeFile(filePath, sampleMultibaseVerificationKey);

			const result = await loadVerificationKey({ signingFile: filePath });

			assert.strictEqual(result.privateKeyHex, sampleHexKey);
			assert.strictEqual(result.keyData, null);
		});

		it('loads multibase key file with trailing newline', async () => {
			await mkdir(testDir, { recursive: true });
			const filePath = join(testDir, 'verification-multibase-newline.txt');
			await writeFile(filePath, sampleMultibaseVerificationKey + '\n');

			const result = await loadVerificationKey({ signingFile: filePath });

			assert.strictEqual(result.privateKeyHex, sampleHexKey);
			assert.strictEqual(result.keyData, null);
		});

		it('throws when --signing-key used with multibase key file', async () => {
			await mkdir(testDir, { recursive: true });
			const filePath = join(testDir, 'verification-multibase-with-key.txt');
			await writeFile(filePath, sampleMultibaseVerificationKey);

			await assert.rejects(
				loadVerificationKey({ signingFile: filePath, signingKey: 'did:key:z6Mk...' }),
				(err) => {
					assert(err instanceof SigningKeyError);
					assert.strictEqual(err.message, 'Cannot specify a signing key when using a multibase key file');
					return true;
				}
			);
		});

		it('throws for invalid file content (not JSON or multibase)', async () => {
			await mkdir(testDir, { recursive: true });
			const filePath = join(testDir, 'verification-invalid.txt');
			await writeFile(filePath, 'this is not valid');

			await assert.rejects(
				loadVerificationKey({ signingFile: filePath }),
				(err) => {
					assert(err instanceof SigningKeyError);
					assert.strictEqual(err.message, 'Key file must be valid JSON or a multibase base58btc encoded key (starting with "z")');
					return true;
				}
			);
		});

		it('throws when multibase key has wrong prefix (secp256k1 instead of ed25519)', async () => {
			await mkdir(testDir, { recursive: true });
			const filePath = join(testDir, 'verification-wrong-prefix.txt');
			// Use a rotation key (secp256k1) where verification key (ed25519) is expected
			await writeFile(filePath, sampleMultibaseRotationKey);

			await assert.rejects(
				loadVerificationKey({ signingFile: filePath }),
				(err) => {
					assert(err instanceof SigningKeyError);
					assert.strictEqual(err.message, 'Wrong key type for this operation. This looks like a rotation key, but a verification key is required.');
					return true;
				}
			);
		});

		it('loads from env var when no signing file', async () => {
			const originalEnv = process.env.FAIR_PRIVATE_KEY;
			process.env.FAIR_PRIVATE_KEY = 'verifykeyvalue';

			try {
				const result = await loadVerificationKey({});

				assert.strictEqual(result.privateKeyHex, 'verifykeyvalue');
				assert.strictEqual(result.keyData, null);
			} finally {
				if (originalEnv !== undefined) {
					process.env.FAIR_PRIVATE_KEY = originalEnv;
				} else {
					delete process.env.FAIR_PRIVATE_KEY;
				}
			}
		});
	});

	describe('loadRotationKeyForRevocation', () => {
		it('throws when key file does not exist', async () => {
			await assert.rejects(
				loadRotationKeyForRevocation({
					signingFile: '/nonexistent/path.json',
					revokeKey: 'did:key:zQ3sh...',
				}),
				(err) => {
					assert(err instanceof SigningKeyError);
					assert.match(err.message, /Error reading key file/);
					return true;
				}
			);
		});

		it('throws when key file has no rotation keys', async () => {
			await mkdir(testDir, { recursive: true });
			const filePath = join(testDir, 'revoke-empty.json');
			await writeFile(filePath, JSON.stringify({ did: 'did:plc:test', rotationKeys: {} }));

			await assert.rejects(
				loadRotationKeyForRevocation({ signingFile: filePath, revokeKey: 'did:key:zQ3sh...' }),
				(err) => {
					assert(err instanceof SigningKeyError);
					assert.strictEqual(err.message, 'Key file must contain at least one rotation key');
					return true;
				}
			);
		});

		it('throws when specified signing key not found', async () => {
			await mkdir(testDir, { recursive: true });
			const filePath = join(testDir, 'revoke-notfound.json');
			await writeFile(filePath, JSON.stringify(sampleKeyFile));

			await assert.rejects(
				loadRotationKeyForRevocation({
					signingFile: filePath,
					signingKey: 'did:key:nonexistent',
					revokeKey: 'did:key:zQ3shRotation1',
				}),
				(err) => {
					assert(err instanceof SigningKeyError);
					assert.match(err.message, /not found in key file/);
					return true;
				}
			);
		});

		it('throws when signing key equals revoke key', async () => {
			await mkdir(testDir, { recursive: true });
			const filePath = join(testDir, 'revoke-same.json');
			await writeFile(filePath, JSON.stringify(sampleKeyFile));

			await assert.rejects(
				loadRotationKeyForRevocation({
					signingFile: filePath,
					signingKey: 'did:key:zQ3shRotation1',
					revokeKey: 'did:key:zQ3shRotation1',
				}),
				(err) => {
					assert(err instanceof SigningKeyError);
					assert.strictEqual(err.message, 'Cannot use the key being revoked to sign the operation');
					return true;
				}
			);
		});

		it('throws when only key in file is being revoked', async () => {
			await mkdir(testDir, { recursive: true });
			const filePath = join(testDir, 'revoke-only.json');
			await writeFile(filePath, JSON.stringify({
				did: 'did:plc:test',
				rotationKeys: { 'did:key:zQ3shOnly': 'onlykey' },
			}));

			await assert.rejects(
				loadRotationKeyForRevocation({
					signingFile: filePath,
					revokeKey: 'did:key:zQ3shOnly',
				}),
				(err) => {
					assert(err instanceof SigningKeyError);
					assert.match(err.message, /No signing key available/);
					assert.match(err.message, /only rotation key in the file is the one being revoked/);
					return true;
				}
			);
		});

		it('auto-selects key that is not being revoked', async () => {
			await mkdir(testDir, { recursive: true });
			const filePath = join(testDir, 'revoke-auto.json');
			await writeFile(filePath, JSON.stringify(sampleKeyFile));

			const result = await loadRotationKeyForRevocation({
				signingFile: filePath,
				revokeKey: 'did:key:zQ3shRotation1',
			});

			assert.strictEqual(result.privateKeyHex, 'eeff0011223344556677889900112233445566778899aabbccddeeff00112233');
		});

		it('uses specified signing key when different from revoke key', async () => {
			await mkdir(testDir, { recursive: true });
			const filePath = join(testDir, 'revoke-specified.json');
			await writeFile(filePath, JSON.stringify(sampleKeyFile));

			const result = await loadRotationKeyForRevocation({
				signingFile: filePath,
				signingKey: 'did:key:zQ3shRotation2',
				revokeKey: 'did:key:zQ3shRotation1',
			});

			assert.strictEqual(result.privateKeyHex, 'eeff0011223344556677889900112233445566778899aabbccddeeff00112233');
		});

		it('loads multibase key file without trailing newline', async () => {
			await mkdir(testDir, { recursive: true });
			const filePath = join(testDir, 'revoke-multibase.txt');
			await writeFile(filePath, sampleMultibaseRotationKey);

			const result = await loadRotationKeyForRevocation({
				signingFile: filePath,
				revokeKey: 'did:key:zQ3shSomeKey',
			});

			assert.strictEqual(result.privateKeyHex, sampleHexKey);
			assert.strictEqual(result.keyData, null);
		});

		it('loads multibase key file with trailing newline', async () => {
			await mkdir(testDir, { recursive: true });
			const filePath = join(testDir, 'revoke-multibase-newline.txt');
			await writeFile(filePath, sampleMultibaseRotationKey + '\n');

			const result = await loadRotationKeyForRevocation({
				signingFile: filePath,
				revokeKey: 'did:key:zQ3shSomeKey',
			});

			assert.strictEqual(result.privateKeyHex, sampleHexKey);
			assert.strictEqual(result.keyData, null);
		});

		it('throws when --signing-key used with multibase key file', async () => {
			await mkdir(testDir, { recursive: true });
			const filePath = join(testDir, 'revoke-multibase-with-key.txt');
			await writeFile(filePath, sampleMultibaseRotationKey);

			await assert.rejects(
				loadRotationKeyForRevocation({
					signingFile: filePath,
					signingKey: 'did:key:zQ3sh...',
					revokeKey: 'did:key:zQ3shOther',
				}),
				(err) => {
					assert(err instanceof SigningKeyError);
					assert.strictEqual(err.message, 'Cannot specify a signing key when using a multibase key file');
					return true;
				}
			);
		});

		it('throws for invalid file content (not JSON or multibase)', async () => {
			await mkdir(testDir, { recursive: true });
			const filePath = join(testDir, 'revoke-invalid.txt');
			await writeFile(filePath, 'this is not valid');

			await assert.rejects(
				loadRotationKeyForRevocation({
					signingFile: filePath,
					revokeKey: 'did:key:zQ3shSomeKey',
				}),
				(err) => {
					assert(err instanceof SigningKeyError);
					assert.strictEqual(err.message, 'Key file must be valid JSON or a multibase base58btc encoded key (starting with "z")');
					return true;
				}
			);
		});

		it('throws when multibase key has wrong prefix (ed25519 instead of secp256k1)', async () => {
			await mkdir(testDir, { recursive: true });
			const filePath = join(testDir, 'revoke-wrong-prefix.txt');
			// Use a verification key (ed25519) where rotation key (secp256k1) is expected
			await writeFile(filePath, sampleMultibaseVerificationKey);

			await assert.rejects(
				loadRotationKeyForRevocation({
					signingFile: filePath,
					revokeKey: 'did:key:zQ3shSomeKey',
				}),
				(err) => {
					assert(err instanceof SigningKeyError);
					assert.strictEqual(err.message, 'Wrong key type for this operation. This looks like a verification key, but a rotation key is required.');
					return true;
				}
			);
		});

		it('loads from env var when no signing file', async () => {
			const originalEnv = process.env.FAIR_ROTATION_KEY;
			process.env.FAIR_ROTATION_KEY = 'envrevoke';

			try {
				const result = await loadRotationKeyForRevocation({
					revokeKey: 'did:key:zQ3shSomeKey',
				});

				assert.strictEqual(result.privateKeyHex, 'envrevoke');
				assert.strictEqual(result.keyData, null);
			} finally {
				if (originalEnv !== undefined) {
					process.env.FAIR_ROTATION_KEY = originalEnv;
				} else {
					delete process.env.FAIR_ROTATION_KEY;
				}
			}
		});

		it('throws when env var not set and no signing file', async () => {
			const originalEnv = process.env.FAIR_ROTATION_KEY;
			delete process.env.FAIR_ROTATION_KEY;

			try {
				await assert.rejects(
					loadRotationKeyForRevocation({ revokeKey: 'did:key:zQ3sh...' }),
					(err) => {
						assert(err instanceof SigningKeyError);
						assert.strictEqual(err.message, 'No signing key provided. Set the FAIR_ROTATION_KEY environment variable or provide a signing file.');
						return true;
					}
				);
			} finally {
				if (originalEnv !== undefined) {
					process.env.FAIR_ROTATION_KEY = originalEnv;
				}
			}
		});
	});
});
