import { describe, it, after, beforeEach } from 'node:test';
import assert from 'node:assert';
import crypto from 'node:crypto';
import { stat, rm, mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
	getKeyFilePath,
	formatKeyFileContent,
	writeKeyFile,
	saveRotationKeyToFile,
	saveVerificationKeyToFile,
	SaveKeyError,
	encodeRotationKey,
	encodeVerificationKey,
	convertRotationKeyToPEM,
	convertVerificationKeyToPEM,
	migrateKeysToPEM,
	MigrateKeysError,
} from '../src/keyfile.js';
import { base58btc } from 'multiformats/bases/base58';

// Sample 32-byte private keys for testing
const sampleRotationKey = new Uint8Array(32).fill(0xaa);
const sampleVerificationKey = new Uint8Array(32).fill(0xbb);

describe('getKeyFilePath', () => {
	it('returns path with DID as filename', () => {
		const path = getKeyFilePath('/some/dir', 'did:plc:abc123');
		assert.strictEqual(path, '/some/dir/did:plc:abc123.json');
	});
});

describe('formatKeyFileContent', () => {
	it('formats keys as JSON with PEM-encoded private keys', () => {
		const did = 'did:plc:test123';
		const rotationKey = {
			publicKey: 'did:key:zQ3shRotation',
			privateKey: sampleRotationKey,
		};
		const verificationKey = {
			publicKey: 'did:key:z6MkVerification',
			privateKey: sampleVerificationKey,
		};

		const content = formatKeyFileContent({ did, rotationKey, verificationKey });
		const parsed = JSON.parse(content);

		assert.strictEqual(parsed.did, 'did:plc:test123');

		// Check rotation key is PEM encoded (SEC1 format for secp256k1)
		const rotationKeyValue = parsed.rotationKeys['did:key:zQ3shRotation'];
		assert(rotationKeyValue.startsWith('-----BEGIN EC PRIVATE KEY-----'), 'Rotation key should be SEC1 PEM');
		assert(rotationKeyValue.endsWith('-----END EC PRIVATE KEY-----'), 'Rotation key should end with SEC1 footer');

		// Check verification key is PEM encoded (PKCS#8 format for Ed25519)
		const verificationKeyValue = parsed.verificationKeys['did:key:z6MkVerification'];
		assert(verificationKeyValue.startsWith('-----BEGIN PRIVATE KEY-----'), 'Verification key should be PKCS#8 PEM');
		assert(
			verificationKeyValue.endsWith('-----END PRIVATE KEY-----'),
			'Verification key should end with PKCS#8 footer',
		);
	});

	it('produces valid JSON', () => {
		const content = formatKeyFileContent({
			did: 'did:plc:test',
			rotationKey: { publicKey: 'pub1', privateKey: sampleRotationKey },
			verificationKey: { publicKey: 'pub2', privateKey: sampleVerificationKey },
		});

		assert.doesNotThrow(() => JSON.parse(content));
	});
});

describe('writeKeyFile', () => {
	const testDir = join(tmpdir(), 'fair-tools-keyfile-test-' + Date.now());

	after(async () => {
		await rm(testDir, { recursive: true, force: true });
	});

	it('writes file with mode 0600', async () => {
		await mkdir(testDir, { recursive: true });
		const filePath = join(testDir, 'test-key.json');
		const content = '{"test": true}';

		await writeKeyFile(filePath, content);

		const fileStat = await stat(filePath);
		// mode includes file type bits, so mask to get just permissions
		const permissions = fileStat.mode & 0o777;
		assert.strictEqual(permissions, 0o600, `Expected 0600, got ${permissions.toString(8)}`);
	});

	it('creates file that can be parsed as JSON', async () => {
		await mkdir(testDir, { recursive: true });
		const filePath = join(testDir, 'test-json.json');
		const content = formatKeyFileContent({
			did: 'did:plc:jsontest',
			rotationKey: { publicKey: 'rk', privateKey: sampleRotationKey },
			verificationKey: { publicKey: 'vk', privateKey: sampleVerificationKey },
		});

		await writeKeyFile(filePath, content);

		const written = await readFile(filePath, 'utf-8');
		const parsed = JSON.parse(written);
		assert.strictEqual(parsed.did, 'did:plc:jsontest');
	});
});

describe('encodeRotationKey', () => {
	it('encodes 32-byte key as SEC1 PEM format', () => {
		const encoded = encodeRotationKey(sampleRotationKey);

		assert(encoded.startsWith('-----BEGIN EC PRIVATE KEY-----'), 'Should start with SEC1 header');
		assert(encoded.endsWith('-----END EC PRIVATE KEY-----'), 'Should end with SEC1 footer');
	});

	it('produces a valid PEM that can be parsed by Node.js crypto', () => {
		const encoded = encodeRotationKey(sampleRotationKey);

		// Should be able to import the key
		const keyObject = crypto.createPrivateKey({ key: encoded, format: 'pem' });
		assert.strictEqual(keyObject.type, 'private');
		assert.strictEqual(keyObject.asymmetricKeyType, 'ec');
	});

	it('round-trips through Node.js crypto', () => {
		const encoded = encodeRotationKey(sampleRotationKey);
		const keyObject = crypto.createPrivateKey({ key: encoded, format: 'pem' });
		const jwk = keyObject.export({ format: 'jwk' });
		const recovered = Buffer.from(jwk.d, 'base64url');

		assert.deepStrictEqual(new Uint8Array(recovered), sampleRotationKey);
	});
});

describe('encodeVerificationKey', () => {
	it('encodes 32-byte key as PKCS#8 PEM format', () => {
		const encoded = encodeVerificationKey(sampleVerificationKey);

		assert(encoded.startsWith('-----BEGIN PRIVATE KEY-----'), 'Should start with PKCS#8 header');
		assert(encoded.endsWith('-----END PRIVATE KEY-----'), 'Should end with PKCS#8 footer');
	});

	it('produces a valid PEM that can be parsed by Node.js crypto', () => {
		const encoded = encodeVerificationKey(sampleVerificationKey);

		// Should be able to import the key
		const keyObject = crypto.createPrivateKey({ key: encoded, format: 'pem' });
		assert.strictEqual(keyObject.type, 'private');
		assert.strictEqual(keyObject.asymmetricKeyType, 'ed25519');
	});

	it('round-trips through Node.js crypto', () => {
		const encoded = encodeVerificationKey(sampleVerificationKey);
		const keyObject = crypto.createPrivateKey({ key: encoded, format: 'pem' });
		const jwk = keyObject.export({ format: 'jwk' });
		const recovered = Buffer.from(jwk.d, 'base64url');

		assert.deepStrictEqual(new Uint8Array(recovered), sampleVerificationKey);
	});
});

describe('saveRotationKeyToFile', () => {
	const testDir = join(tmpdir(), 'fair-tools-save-rotation-key-test-' + Date.now());

	// Helper to create a mock key object with a 32-byte key
	function mockKey(publicKey) {
		return {
			publicKey,
			privateKey: sampleRotationKey,
		};
	}

	beforeEach(async () => {
		await mkdir(testDir, { recursive: true });
	});

	after(async () => {
		await rm(testDir, { recursive: true, force: true });
	});

	it('writes PEM key when file does not exist', async () => {
		const outputFile = join(testDir, 'new-key.pem');
		const result = await saveRotationKeyToFile({
			outputFile,
			key: mockKey('did:key:zQ3shTest'),
		});

		assert.strictEqual(result.appended, false);
		const content = await readFile(outputFile, 'utf-8');
		assert(content.startsWith('-----BEGIN EC PRIVATE KEY-----'), 'Should start with PEM header');
		assert(content.endsWith('-----END EC PRIVATE KEY-----\n'), 'Should end with PEM footer and trailing newline');
	});

	it('appends to rotationKeys when file exists with valid JSON', async () => {
		const outputFile = join(testDir, 'existing-rotation.json');
		const existingData = {
			did: 'did:plc:test',
			rotationKeys: {
				'did:key:zQ3shExisting': '11223344',
			},
		};
		await writeFile(outputFile, JSON.stringify(existingData, null, 2));

		const result = await saveRotationKeyToFile({
			outputFile,
			key: mockKey('did:key:zQ3shNew'),
		});

		assert.strictEqual(result.appended, true);
		const content = await readFile(outputFile, 'utf-8');
		const parsed = JSON.parse(content);
		assert.strictEqual(parsed.rotationKeys['did:key:zQ3shExisting'], '11223344');
		// New key should be PEM encoded
		const newKeyValue = parsed.rotationKeys['did:key:zQ3shNew'];
		assert(newKeyValue.startsWith('-----BEGIN EC PRIVATE KEY-----'), 'New key should start with PEM header');
		assert(newKeyValue.endsWith('-----END EC PRIVATE KEY-----'), 'New key should end with PEM footer');
	});

	it('creates rotationKeys object when missing from existing JSON', async () => {
		const outputFile = join(testDir, 'no-keytype.json');
		const existingData = {
			did: 'did:plc:test',
		};
		await writeFile(outputFile, JSON.stringify(existingData, null, 2));

		const result = await saveRotationKeyToFile({
			outputFile,
			key: mockKey('did:key:zQ3shNew'),
		});

		assert.strictEqual(result.appended, true);
		const content = await readFile(outputFile, 'utf-8');
		const parsed = JSON.parse(content);
		assert(
			parsed.rotationKeys['did:key:zQ3shNew'].startsWith('-----BEGIN EC PRIVATE KEY-----'),
			'Should start with PEM header',
		);
		assert(
			parsed.rotationKeys['did:key:zQ3shNew'].endsWith('-----END EC PRIVATE KEY-----'),
			'Should end with PEM footer',
		);
	});

	it('throws SaveKeyError when file exists but is not valid JSON', async () => {
		const outputFile = join(testDir, 'invalid.json');
		await writeFile(outputFile, 'not valid json {{{');

		await assert.rejects(
			saveRotationKeyToFile({
				outputFile,
				key: mockKey('did:key:zQ3shTest'),
			}),
			(err) => {
				assert(err instanceof SaveKeyError);
				assert.match(err.message, /not valid JSON/);
				return true;
			},
		);
	});

	it('throws SaveKeyError when file read fails (not ENOENT)', async () => {
		// Use a directory path instead of a file to trigger a read error
		const outputFile = join(testDir, 'subdir');
		await mkdir(outputFile);

		await assert.rejects(
			saveRotationKeyToFile({
				outputFile,
				key: mockKey('did:key:zQ3shTest'),
			}),
			(err) => {
				assert(err instanceof SaveKeyError);
				assert.match(err.message, /Error reading output file/);
				return true;
			},
		);
	});

	it('throws SaveKeyError when write fails', async () => {
		// Try to write to a path where parent doesn't exist
		const outputFile = join(testDir, 'nonexistent', 'subdir', 'file.json');

		await assert.rejects(
			saveRotationKeyToFile({
				outputFile,
				key: mockKey('did:key:zQ3shTest'),
			}),
			(err) => {
				assert(err instanceof SaveKeyError);
				assert.match(err.message, /Error writing output file/);
				return true;
			},
		);
	});

	it('preserves other properties when appending to existing JSON', async () => {
		const outputFile = join(testDir, 'preserve-props.json');
		const existingData = {
			did: 'did:plc:test',
			rotationKeys: {
				'did:key:zQ3shExisting': '11223344',
			},
			verificationKeys: {
				'did:key:z6MkVerify': '55667788',
			},
			customField: 'should be preserved',
		};
		await writeFile(outputFile, JSON.stringify(existingData, null, 2));

		await saveRotationKeyToFile({
			outputFile,
			key: mockKey('did:key:zQ3shNew'),
		});

		const content = await readFile(outputFile, 'utf-8');
		const parsed = JSON.parse(content);
		assert.strictEqual(parsed.did, 'did:plc:test');
		assert.strictEqual(parsed.customField, 'should be preserved');
		assert.strictEqual(parsed.verificationKeys['did:key:z6MkVerify'], '55667788');
		assert(
			parsed.rotationKeys['did:key:zQ3shNew'].startsWith('-----BEGIN EC PRIVATE KEY-----'),
			'Should start with PEM header',
		);
		assert(
			parsed.rotationKeys['did:key:zQ3shNew'].endsWith('-----END EC PRIVATE KEY-----'),
			'Should end with PEM footer',
		);
	});

	it('throws SaveKeyError when key already exists in file', async () => {
		const outputFile = join(testDir, 'duplicate.json');
		const existingData = {
			did: 'did:plc:test',
			rotationKeys: {
				'did:key:zQ3shSame': 'oldvalue',
			},
		};
		await writeFile(outputFile, JSON.stringify(existingData, null, 2));

		await assert.rejects(
			saveRotationKeyToFile({
				outputFile,
				key: mockKey('did:key:zQ3shSame'),
			}),
			(err) => {
				assert(err instanceof SaveKeyError);
				assert.strictEqual(err.message, 'Key already exists in file: did:key:zQ3shSame');
				return true;
			},
		);
	});
});

describe('saveVerificationKeyToFile', () => {
	const testDir = join(tmpdir(), 'fair-tools-save-verification-key-test-' + Date.now());

	// Helper to create a mock key object with a 32-byte key
	function mockKey(publicKey) {
		return {
			publicKey,
			privateKey: sampleVerificationKey,
		};
	}

	beforeEach(async () => {
		await mkdir(testDir, { recursive: true });
	});

	after(async () => {
		await rm(testDir, { recursive: true, force: true });
	});

	it('writes PEM key when file does not exist', async () => {
		const outputFile = join(testDir, 'new-key.pem');
		const result = await saveVerificationKeyToFile({
			outputFile,
			key: mockKey('did:key:z6MkTest'),
		});

		assert.strictEqual(result.appended, false);
		const content = await readFile(outputFile, 'utf-8');
		assert(content.startsWith('-----BEGIN PRIVATE KEY-----'), 'Should start with PEM header');
		assert(content.endsWith('-----END PRIVATE KEY-----\n'), 'Should end with PEM footer and trailing newline');
	});

	it('appends to verificationKeys when file exists with valid JSON', async () => {
		const outputFile = join(testDir, 'existing-verification.json');
		const existingData = {
			did: 'did:plc:test',
			verificationKeys: {
				'did:key:z6MkExisting': '11223344',
			},
		};
		await writeFile(outputFile, JSON.stringify(existingData, null, 2));

		const result = await saveVerificationKeyToFile({
			outputFile,
			key: mockKey('did:key:z6MkNew'),
		});

		assert.strictEqual(result.appended, true);
		const content = await readFile(outputFile, 'utf-8');
		const parsed = JSON.parse(content);
		assert.strictEqual(parsed.verificationKeys['did:key:z6MkExisting'], '11223344');
		// New key should be PEM encoded
		const newKeyValue = parsed.verificationKeys['did:key:z6MkNew'];
		assert(newKeyValue.startsWith('-----BEGIN PRIVATE KEY-----'), 'New key should start with PEM header');
		assert(newKeyValue.endsWith('-----END PRIVATE KEY-----'), 'New key should end with PEM footer');
	});

	it('creates verificationKeys object when missing from existing JSON', async () => {
		const outputFile = join(testDir, 'no-keytype.json');
		const existingData = {
			did: 'did:plc:test',
		};
		await writeFile(outputFile, JSON.stringify(existingData, null, 2));

		const result = await saveVerificationKeyToFile({
			outputFile,
			key: mockKey('did:key:z6MkNew'),
		});

		assert.strictEqual(result.appended, true);
		const content = await readFile(outputFile, 'utf-8');
		const parsed = JSON.parse(content);
		assert(
			parsed.verificationKeys['did:key:z6MkNew'].startsWith('-----BEGIN PRIVATE KEY-----'),
			'Should start with PEM header',
		);
		assert(
			parsed.verificationKeys['did:key:z6MkNew'].endsWith('-----END PRIVATE KEY-----'),
			'Should end with PEM footer',
		);
	});

	it('throws SaveKeyError when key already exists in file', async () => {
		const outputFile = join(testDir, 'duplicate.json');
		const existingData = {
			did: 'did:plc:test',
			verificationKeys: {
				'did:key:z6MkSame': 'oldvalue',
			},
		};
		await writeFile(outputFile, JSON.stringify(existingData, null, 2));

		await assert.rejects(
			saveVerificationKeyToFile({
				outputFile,
				key: mockKey('did:key:z6MkSame'),
			}),
			(err) => {
				assert(err instanceof SaveKeyError);
				assert.strictEqual(err.message, 'Key already exists in file: did:key:z6MkSame');
				return true;
			},
		);
	});
});

// Multicodec prefixes for test data generation
const SECP256K1_PRIV_PREFIX = new Uint8Array([0x81, 0x26]);
const ED25519_PRIV_PREFIX = new Uint8Array([0x80, 0x26]);

// Sample hex key (32 bytes)
const sampleHexKey = 'aabbccdd112233445566778899aabbccddeeff00112233445566778899001122';
const sampleKeyBytes = Buffer.from(sampleHexKey, 'hex');

// Sample PEM keys (encoded from sampleKeyBytes)
const samplePemRotationKey = encodeRotationKey(sampleKeyBytes);
const samplePemVerificationKey = encodeVerificationKey(sampleKeyBytes);

// Sample multibase keys (encoded from sampleKeyBytes with appropriate prefix)
const sampleMultibaseRotationKey = base58btc.encode(Buffer.concat([SECP256K1_PRIV_PREFIX, sampleKeyBytes]));
// Sodium format verification key: 64 bytes (32-byte seed + 32-byte public key)
const sodiumPublicKeyPortion = Buffer.alloc(32, 0xff);
const sampleMultibaseVerificationKey = base58btc.encode(
	Buffer.concat([ED25519_PRIV_PREFIX, sampleKeyBytes, sodiumPublicKeyPortion]),
);

describe('convertRotationKeyToPEM', () => {
	it('converts hex to PEM', () => {
		const pem = convertRotationKeyToPEM(sampleHexKey);
		assert(pem.startsWith('-----BEGIN EC PRIVATE KEY-----'), 'Should start with PEM header');
		assert(pem.endsWith('-----END EC PRIVATE KEY-----'), 'Should end with PEM footer');

		// Verify it round-trips correctly
		const keyObject = crypto.createPrivateKey({ key: pem, format: 'pem' });
		const jwk = keyObject.export({ format: 'jwk' });
		const recovered = Buffer.from(jwk.d, 'base64url').toString('hex');
		assert.strictEqual(recovered, sampleHexKey);
	});

	it('converts multibase to PEM', () => {
		const pem = convertRotationKeyToPEM(sampleMultibaseRotationKey);
		assert(pem.startsWith('-----BEGIN EC PRIVATE KEY-----'), 'Should start with PEM header');

		// Verify it round-trips correctly
		const keyObject = crypto.createPrivateKey({ key: pem, format: 'pem' });
		const jwk = keyObject.export({ format: 'jwk' });
		const recovered = Buffer.from(jwk.d, 'base64url').toString('hex');
		assert.strictEqual(recovered, sampleHexKey);
	});

	it('throws for unrecognized format', () => {
		assert.throws(() => convertRotationKeyToPEM('not a key'), /Unrecognized rotation key format/);
	});
});

describe('convertVerificationKeyToPEM', () => {
	it('converts hex to PEM', () => {
		const pem = convertVerificationKeyToPEM(sampleHexKey);
		assert(pem.startsWith('-----BEGIN PRIVATE KEY-----'), 'Should start with PEM header');
		assert(pem.endsWith('-----END PRIVATE KEY-----'), 'Should end with PEM footer');

		// Verify it round-trips correctly
		const keyObject = crypto.createPrivateKey({ key: pem, format: 'pem' });
		const jwk = keyObject.export({ format: 'jwk' });
		const recovered = Buffer.from(jwk.d, 'base64url').toString('hex');
		assert.strictEqual(recovered, sampleHexKey);
	});

	it('converts multibase to PEM', () => {
		const pem = convertVerificationKeyToPEM(sampleMultibaseVerificationKey);
		assert(pem.startsWith('-----BEGIN PRIVATE KEY-----'), 'Should start with PEM header');

		// Verify it round-trips correctly
		const keyObject = crypto.createPrivateKey({ key: pem, format: 'pem' });
		const jwk = keyObject.export({ format: 'jwk' });
		const recovered = Buffer.from(jwk.d, 'base64url').toString('hex');
		assert.strictEqual(recovered, sampleHexKey);
	});

	it('throws for unrecognized format', () => {
		assert.throws(() => convertVerificationKeyToPEM('not a key'), /Unrecognized verification key format/);
	});
});

describe('migrateKeysToPEM', () => {
	const testDir = join(tmpdir(), 'fair-tools-migrate-keys-test-' + Date.now());

	beforeEach(async () => {
		await mkdir(testDir, { recursive: true });
	});

	after(async () => {
		await rm(testDir, { recursive: true, force: true });
	});

	it('migrates hex rotation keys to PEM', async () => {
		const keyFile = join(testDir, 'hex-rotation.json');
		const keyData = {
			did: 'did:plc:test',
			rotationKeys: {
				'did:key:zQ3shTest': sampleHexKey,
			},
		};
		await writeFile(keyFile, JSON.stringify(keyData, null, 2));

		const result = await migrateKeysToPEM({ keyFile });

		assert.strictEqual(result.rotationKeysMigrated, 1);
		assert.strictEqual(result.verificationKeysMigrated, 0);
		assert.strictEqual(result.rotationKeysAlreadyPEM, 0);
		assert.strictEqual(result.verificationKeysAlreadyPEM, 0);
		assert.strictEqual(result.backupPath, keyFile + '.bak');

		// Verify backup was created
		const backup = await readFile(keyFile + '.bak', 'utf-8');
		const backupData = JSON.parse(backup);
		assert.strictEqual(backupData.rotationKeys['did:key:zQ3shTest'], sampleHexKey);

		// Verify file was updated
		const updated = await readFile(keyFile, 'utf-8');
		const updatedData = JSON.parse(updated);
		assert(
			updatedData.rotationKeys['did:key:zQ3shTest'].startsWith('-----BEGIN EC PRIVATE KEY-----'),
			'Should be converted to PEM',
		);
	});

	it('migrates multibase rotation keys to PEM', async () => {
		const keyFile = join(testDir, 'multibase-rotation.json');
		const keyData = {
			did: 'did:plc:test',
			rotationKeys: {
				'did:key:zQ3shTest': sampleMultibaseRotationKey,
			},
		};
		await writeFile(keyFile, JSON.stringify(keyData, null, 2));

		const result = await migrateKeysToPEM({ keyFile });

		assert.strictEqual(result.rotationKeysMigrated, 1);
		assert.strictEqual(result.backupPath, keyFile + '.bak');

		// Verify file was updated
		const updated = await readFile(keyFile, 'utf-8');
		const updatedData = JSON.parse(updated);
		assert(
			updatedData.rotationKeys['did:key:zQ3shTest'].startsWith('-----BEGIN EC PRIVATE KEY-----'),
			'Should be converted to PEM',
		);
	});

	it('migrates hex verification keys to PEM', async () => {
		const keyFile = join(testDir, 'hex-verification.json');
		const keyData = {
			did: 'did:plc:test',
			verificationKeys: {
				'did:key:z6MkTest': sampleHexKey,
			},
		};
		await writeFile(keyFile, JSON.stringify(keyData, null, 2));

		const result = await migrateKeysToPEM({ keyFile });

		assert.strictEqual(result.rotationKeysMigrated, 0);
		assert.strictEqual(result.verificationKeysMigrated, 1);
		assert.strictEqual(result.backupPath, keyFile + '.bak');

		// Verify file was updated
		const updated = await readFile(keyFile, 'utf-8');
		const updatedData = JSON.parse(updated);
		assert(
			updatedData.verificationKeys['did:key:z6MkTest'].startsWith('-----BEGIN PRIVATE KEY-----'),
			'Should be converted to PEM',
		);
	});

	it('migrates multibase verification keys to PEM', async () => {
		const keyFile = join(testDir, 'multibase-verification.json');
		const keyData = {
			did: 'did:plc:test',
			verificationKeys: {
				'did:key:z6MkTest': sampleMultibaseVerificationKey,
			},
		};
		await writeFile(keyFile, JSON.stringify(keyData, null, 2));

		const result = await migrateKeysToPEM({ keyFile });

		assert.strictEqual(result.verificationKeysMigrated, 1);
		assert.strictEqual(result.backupPath, keyFile + '.bak');

		// Verify file was updated
		const updated = await readFile(keyFile, 'utf-8');
		const updatedData = JSON.parse(updated);
		assert(
			updatedData.verificationKeys['did:key:z6MkTest'].startsWith('-----BEGIN PRIVATE KEY-----'),
			'Should be converted to PEM',
		);
	});

	it('migrates mixed format keys', async () => {
		const keyFile = join(testDir, 'mixed-formats.json');
		const keyData = {
			did: 'did:plc:test',
			rotationKeys: {
				'did:key:zQ3shHex': sampleHexKey,
				'did:key:zQ3shMultibase': sampleMultibaseRotationKey,
				'did:key:zQ3shPEM': samplePemRotationKey,
			},
			verificationKeys: {
				'did:key:z6MkHex': sampleHexKey,
				'did:key:z6MkPEM': samplePemVerificationKey,
			},
		};
		await writeFile(keyFile, JSON.stringify(keyData, null, 2));

		const result = await migrateKeysToPEM({ keyFile });

		assert.strictEqual(result.rotationKeysMigrated, 2);
		assert.strictEqual(result.verificationKeysMigrated, 1);
		assert.strictEqual(result.rotationKeysAlreadyPEM, 1);
		assert.strictEqual(result.verificationKeysAlreadyPEM, 1);
	});

	it('does not modify file when all keys are already PEM', async () => {
		const keyFile = join(testDir, 'all-pem.json');
		const keyData = {
			did: 'did:plc:test',
			rotationKeys: {
				'did:key:zQ3shPEM': samplePemRotationKey,
			},
			verificationKeys: {
				'did:key:z6MkPEM': samplePemVerificationKey,
			},
		};
		await writeFile(keyFile, JSON.stringify(keyData, null, 2));

		const result = await migrateKeysToPEM({ keyFile });

		assert.strictEqual(result.rotationKeysMigrated, 0);
		assert.strictEqual(result.verificationKeysMigrated, 0);
		assert.strictEqual(result.rotationKeysAlreadyPEM, 1);
		assert.strictEqual(result.verificationKeysAlreadyPEM, 1);
		assert.strictEqual(result.backupPath, null);

		// Verify no backup was created
		await assert.rejects(readFile(keyFile + '.bak', 'utf-8'), {
			code: 'ENOENT',
		});
	});

	it('throws for non-existent file', async () => {
		await assert.rejects(migrateKeysToPEM({ keyFile: '/nonexistent/file.json' }), (err) => {
			assert(err instanceof MigrateKeysError);
			assert.match(err.message, /Error reading key file/);
			return true;
		});
	});

	it('throws for unrecognized standalone file format', async () => {
		const keyFile = join(testDir, 'not-json.txt');
		await writeFile(keyFile, 'not valid json or key');

		await assert.rejects(migrateKeysToPEM({ keyFile }), (err) => {
			assert(err instanceof MigrateKeysError);
			assert.strictEqual(err.message, 'Key file must be valid JSON or a standalone multibase-encoded key.');
			return true;
		});
	});

	it('migrates standalone multibase rotation key to PEM', async () => {
		const keyFile = join(testDir, 'standalone-multibase-rotation.key');
		await writeFile(keyFile, sampleMultibaseRotationKey);

		const result = await migrateKeysToPEM({ keyFile });

		assert.strictEqual(result.rotationKeysMigrated, 1);
		assert.strictEqual(result.verificationKeysMigrated, 0);
		assert.strictEqual(result.backupPath, keyFile + '.bak');

		// Verify file was updated to PEM
		const updated = await readFile(keyFile, 'utf-8');
		assert(updated.startsWith('-----BEGIN EC PRIVATE KEY-----'));
	});

	it('migrates standalone multibase verification key to PEM', async () => {
		const keyFile = join(testDir, 'standalone-multibase-verification.key');
		await writeFile(keyFile, sampleMultibaseVerificationKey);

		const result = await migrateKeysToPEM({ keyFile });

		assert.strictEqual(result.rotationKeysMigrated, 0);
		assert.strictEqual(result.verificationKeysMigrated, 1);
		assert.strictEqual(result.backupPath, keyFile + '.bak');

		// Verify file was updated to PEM
		const updated = await readFile(keyFile, 'utf-8');
		assert(updated.startsWith('-----BEGIN PRIVATE KEY-----'));
	});

	it('reports standalone PEM rotation key as already migrated', async () => {
		const keyFile = join(testDir, 'standalone-pem-rotation.key');
		await writeFile(keyFile, samplePemRotationKey);

		const result = await migrateKeysToPEM({ keyFile });

		assert.strictEqual(result.rotationKeysMigrated, 0);
		assert.strictEqual(result.rotationKeysAlreadyPEM, 1);
		assert.strictEqual(result.backupPath, null);
	});

	it('reports standalone PEM verification key as already migrated', async () => {
		const keyFile = join(testDir, 'standalone-pem-verification.key');
		await writeFile(keyFile, samplePemVerificationKey);

		const result = await migrateKeysToPEM({ keyFile });

		assert.strictEqual(result.verificationKeysMigrated, 0);
		assert.strictEqual(result.verificationKeysAlreadyPEM, 1);
		assert.strictEqual(result.backupPath, null);
	});

	it('throws for unrecognized key format', async () => {
		const keyFile = join(testDir, 'bad-format.json');
		const keyData = {
			did: 'did:plc:test',
			rotationKeys: {
				'did:key:zQ3shTest': 'not a valid key format',
			},
		};
		await writeFile(keyFile, JSON.stringify(keyData, null, 2));

		await assert.rejects(migrateKeysToPEM({ keyFile }), (err) => {
			assert(err instanceof MigrateKeysError);
			assert.match(err.message, /Failed to convert rotation key.*Unrecognized rotation key format/);
			return true;
		});
	});

	it('handles empty rotationKeys and verificationKeys', async () => {
		const keyFile = join(testDir, 'empty-keys.json');
		const keyData = {
			did: 'did:plc:test',
			rotationKeys: {},
			verificationKeys: {},
		};
		await writeFile(keyFile, JSON.stringify(keyData, null, 2));

		const result = await migrateKeysToPEM({ keyFile });

		assert.strictEqual(result.rotationKeysMigrated, 0);
		assert.strictEqual(result.verificationKeysMigrated, 0);
		assert.strictEqual(result.backupPath, null);
	});

	it('handles file with only did field', async () => {
		const keyFile = join(testDir, 'only-did.json');
		const keyData = {
			did: 'did:plc:test',
		};
		await writeFile(keyFile, JSON.stringify(keyData, null, 2));

		const result = await migrateKeysToPEM({ keyFile });

		assert.strictEqual(result.rotationKeysMigrated, 0);
		assert.strictEqual(result.verificationKeysMigrated, 0);
		assert.strictEqual(result.backupPath, null);
	});

	it('preserves other properties in the file', async () => {
		const keyFile = join(testDir, 'preserve-props.json');
		const keyData = {
			did: 'did:plc:test',
			rotationKeys: {
				'did:key:zQ3shTest': sampleHexKey,
			},
			customField: 'should be preserved',
			anotherField: { nested: true },
		};
		await writeFile(keyFile, JSON.stringify(keyData, null, 2));

		await migrateKeysToPEM({ keyFile });

		const updated = await readFile(keyFile, 'utf-8');
		const updatedData = JSON.parse(updated);
		assert.strictEqual(updatedData.customField, 'should be preserved');
		assert.deepStrictEqual(updatedData.anotherField, { nested: true });
	});
});
