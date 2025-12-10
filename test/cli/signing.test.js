import { describe, it, after, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import { writeFile, rm, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
	loadRotationKey,
	loadVerificationKey,
	loadRotationKeyForRevocation,
	SigningKeyError,
} from '../../src/cli/lib/signing.js';

const testDir = join(tmpdir(), 'fair-tools-signing-test-' + Date.now());

// Sample key data
const sampleKeyFile = {
	did: 'did:plc:test123',
	rotationKeys: {
		'did:key:zQ3shRotation1': 'aabbccdd',
		'did:key:zQ3shRotation2': 'eeff0011',
	},
	verificationKeys: {
		'did:key:z6MkVerification1': '11223344',
		'did:key:z6MkVerification2': '55667788',
	},
};

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
					assert.match(err.message, /--signing-key can only be used with --signing-file/);
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
					assert.match(err.message, /must contain at least one rotation key/);
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

			assert.strictEqual(result.privateKeyHex, 'aabbccdd');
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

			assert.strictEqual(result.privateKeyHex, 'eeff0011');
		});

		it('throws when env var not set and no signing file', async () => {
			const originalEnv = process.env.FAIR_ROTATION_KEY;
			delete process.env.FAIR_ROTATION_KEY;

			try {
				await assert.rejects(
					loadRotationKey({}),
					(err) => {
						assert(err instanceof SigningKeyError);
						assert.match(err.message, /FAIR_ROTATION_KEY environment variable is required/);
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
					assert.match(err.message, /--signing-key can only be used with --signing-file/);
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
					assert.match(err.message, /must contain at least one verification key/);
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

			assert.strictEqual(result.privateKeyHex, '11223344');
		});

		it('loads specific verification key when specified', async () => {
			await mkdir(testDir, { recursive: true });
			const filePath = join(testDir, 'verification-specific.json');
			await writeFile(filePath, JSON.stringify(sampleKeyFile));

			const result = await loadVerificationKey({
				signingFile: filePath,
				signingKey: 'did:key:z6MkVerification2',
			});

			assert.strictEqual(result.privateKeyHex, '55667788');
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
					assert.match(err.message, /must contain at least one rotation key/);
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
					assert.match(err.message, /Cannot use the key being revoked to sign/);
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

			assert.strictEqual(result.privateKeyHex, 'eeff0011');
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

			assert.strictEqual(result.privateKeyHex, 'eeff0011');
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
						assert.match(err.message, /No signing key provided/);
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
