import { describe, it, after, beforeEach } from 'node:test';
import assert from 'node:assert';
import { stat, rm, mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { base58btc } from 'multiformats/bases/base58';
import {
	getKeyFilePath,
	formatKeyFileContent,
	writeKeyFile,
	saveRotationKeyToFile,
	saveVerificationKeyToFile,
	SaveKeyError,
	encodeRotationKey,
	encodeVerificationKey,
} from '../src/keyfile.js';

describe('getKeyFilePath', () => {
	it('returns path with DID as filename', () => {
		const path = getKeyFilePath('/some/dir', 'did:plc:abc123');
		assert.strictEqual(path, '/some/dir/did:plc:abc123.json');
	});
});

describe('formatKeyFileContent', () => {
	it('formats keys as JSON with multibase-encoded private keys', () => {
		const did = 'did:plc:test123';
		const rotationKey = {
			publicKey: 'did:key:zQ3shRotation',
			privateKey: new Uint8Array([0x01, 0x02, 0x03, 0x04]),
		};
		const verificationKey = {
			publicKey: 'did:key:z6MkVerification',
			privateKey: new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]),
		};

		const content = formatKeyFileContent({ did, rotationKey, verificationKey });
		const parsed = JSON.parse(content);

		assert.strictEqual(parsed.did, 'did:plc:test123');

		// Check rotation key is multibase encoded with secp256k1-priv prefix (0x8126)
		const rotationKeyValue = parsed.rotationKeys['did:key:zQ3shRotation'];
		assert(rotationKeyValue.startsWith('z'), 'Rotation key should be multibase base58btc');
		const decodedRotation = base58btc.decode(rotationKeyValue);
		assert.strictEqual(decodedRotation[0], 0x81);
		assert.strictEqual(decodedRotation[1], 0x26);
		assert.deepStrictEqual(Array.from(decodedRotation.slice(2)), [0x01, 0x02, 0x03, 0x04]);

		// Check verification key is multibase encoded with ed25519-priv prefix (0x8026)
		const verificationKeyValue = parsed.verificationKeys['did:key:z6MkVerification'];
		assert(verificationKeyValue.startsWith('z'), 'Verification key should be multibase base58btc');
		const decodedVerification = base58btc.decode(verificationKeyValue);
		assert.strictEqual(decodedVerification[0], 0x80);
		assert.strictEqual(decodedVerification[1], 0x26);
		assert.deepStrictEqual(Array.from(decodedVerification.slice(2)), [0xaa, 0xbb, 0xcc, 0xdd]);
	});

	it('produces valid JSON', () => {
		const content = formatKeyFileContent({
			did: 'did:plc:test',
			rotationKey: { publicKey: 'pub1', privateKey: new Uint8Array([1]) },
			verificationKey: { publicKey: 'pub2', privateKey: new Uint8Array([2]) },
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
			rotationKey: { publicKey: 'rk', privateKey: new Uint8Array([1, 2, 3]) },
			verificationKey: { publicKey: 'vk', privateKey: new Uint8Array([4, 5, 6]) },
		});

		await writeKeyFile(filePath, content);

		const written = await readFile(filePath, 'utf-8');
		const parsed = JSON.parse(written);
		assert.strictEqual(parsed.did, 'did:plc:jsontest');
	});
});

describe('encodeRotationKey', () => {
	it('encodes Uint8Array as multibase base58btc with secp256k1-priv prefix', () => {
		const key = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
		const encoded = encodeRotationKey(key);

		assert(encoded.startsWith('z'), 'Should start with z (base58btc multibase prefix)');
		const decoded = base58btc.decode(encoded);
		assert.strictEqual(decoded[0], 0x81);
		assert.strictEqual(decoded[1], 0x26);
		assert.deepStrictEqual(Array.from(decoded.slice(2)), [0x01, 0x02, 0x03, 0x04]);
	});

	it('encodes 32-byte key correctly', () => {
		const key = new Uint8Array(32).fill(0xaa);
		const encoded = encodeRotationKey(key);
		const decoded = base58btc.decode(encoded);

		assert.strictEqual(decoded.length, 34); // 2 prefix + 32 key
		assert.strictEqual(decoded[0], 0x81);
		assert.strictEqual(decoded[1], 0x26);
	});
});

describe('encodeVerificationKey', () => {
	it('encodes Uint8Array as multibase base58btc with ed25519-priv prefix', () => {
		const key = new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]);
		const encoded = encodeVerificationKey(key);

		assert(encoded.startsWith('z'), 'Should start with z (base58btc multibase prefix)');
		const decoded = base58btc.decode(encoded);
		assert.strictEqual(decoded[0], 0x80);
		assert.strictEqual(decoded[1], 0x26);
		assert.deepStrictEqual(Array.from(decoded.slice(2)), [0xaa, 0xbb, 0xcc, 0xdd]);
	});

	it('encodes 32-byte key correctly', () => {
		const key = new Uint8Array(32).fill(0xbb);
		const encoded = encodeVerificationKey(key);
		const decoded = base58btc.decode(encoded);

		assert.strictEqual(decoded.length, 34); // 2 prefix + 32 key
		assert.strictEqual(decoded[0], 0x80);
		assert.strictEqual(decoded[1], 0x26);
	});
});

describe('saveRotationKeyToFile', () => {
	const testDir = join(tmpdir(), 'fair-tools-save-rotation-key-test-' + Date.now());

	// Helper to create a mock key object from hex string
	function mockKey(publicKey, hexPrivateKey) {
		return {
			publicKey,
			privateKey: Buffer.from(hexPrivateKey, 'hex'),
		};
	}

	beforeEach(async () => {
		await mkdir(testDir, { recursive: true });
	});

	after(async () => {
		await rm(testDir, { recursive: true, force: true });
	});

	it('writes multibase key when file does not exist', async () => {
		const outputFile = join(testDir, 'new-key.txt');
		const result = await saveRotationKeyToFile({
			outputFile,
			key: mockKey('did:key:zQ3shTest', 'aabbccdd'),
		});

		assert.strictEqual(result.appended, false);
		const content = await readFile(outputFile, 'utf-8');
		assert(content.trim().startsWith('z'), 'Should write multibase key');
		// Verify it decodes correctly
		const decoded = base58btc.decode(content.trim());
		assert.strictEqual(decoded[0], 0x81);
		assert.strictEqual(decoded[1], 0x26);
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
			key: mockKey('did:key:zQ3shNew', 'aabbccdd'),
		});

		assert.strictEqual(result.appended, true);
		const content = await readFile(outputFile, 'utf-8');
		const parsed = JSON.parse(content);
		assert.strictEqual(parsed.rotationKeys['did:key:zQ3shExisting'], '11223344');
		// New key should be multibase encoded
		const newKeyValue = parsed.rotationKeys['did:key:zQ3shNew'];
		assert(newKeyValue.startsWith('z'), 'New key should be multibase encoded');
	});

	it('creates rotationKeys object when missing from existing JSON', async () => {
		const outputFile = join(testDir, 'no-keytype.json');
		const existingData = {
			did: 'did:plc:test',
		};
		await writeFile(outputFile, JSON.stringify(existingData, null, 2));

		const result = await saveRotationKeyToFile({
			outputFile,
			key: mockKey('did:key:zQ3shNew', 'aabbccdd'),
		});

		assert.strictEqual(result.appended, true);
		const content = await readFile(outputFile, 'utf-8');
		const parsed = JSON.parse(content);
		assert(parsed.rotationKeys['did:key:zQ3shNew'].startsWith('z'));
	});

	it('throws SaveKeyError when file exists but is not valid JSON', async () => {
		const outputFile = join(testDir, 'invalid.json');
		await writeFile(outputFile, 'not valid json {{{');

		await assert.rejects(
			saveRotationKeyToFile({
				outputFile,
				key: mockKey('did:key:zQ3shTest', 'aabbccdd'),
			}),
			(err) => {
				assert(err instanceof SaveKeyError);
				assert.match(err.message, /not valid JSON/);
				return true;
			}
		);
	});

	it('throws SaveKeyError when file read fails (not ENOENT)', async () => {
		// Use a directory path instead of a file to trigger a read error
		const outputFile = join(testDir, 'subdir');
		await mkdir(outputFile);

		await assert.rejects(
			saveRotationKeyToFile({
				outputFile,
				key: mockKey('did:key:zQ3shTest', 'aabbccdd'),
			}),
			(err) => {
				assert(err instanceof SaveKeyError);
				assert.match(err.message, /Error reading output file/);
				return true;
			}
		);
	});

	it('throws SaveKeyError when write fails', async () => {
		// Try to write to a path where parent doesn't exist
		const outputFile = join(testDir, 'nonexistent', 'subdir', 'file.json');

		await assert.rejects(
			saveRotationKeyToFile({
				outputFile,
				key: mockKey('did:key:zQ3shTest', 'aabbccdd'),
			}),
			(err) => {
				assert(err instanceof SaveKeyError);
				assert.match(err.message, /Error writing output file/);
				return true;
			}
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
			key: mockKey('did:key:zQ3shNew', 'aabbccdd'),
		});

		const content = await readFile(outputFile, 'utf-8');
		const parsed = JSON.parse(content);
		assert.strictEqual(parsed.did, 'did:plc:test');
		assert.strictEqual(parsed.customField, 'should be preserved');
		assert.strictEqual(parsed.verificationKeys['did:key:z6MkVerify'], '55667788');
		assert(parsed.rotationKeys['did:key:zQ3shNew'].startsWith('z'));
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
				key: mockKey('did:key:zQ3shSame', 'newvalue'),
			}),
			(err) => {
				assert(err instanceof SaveKeyError);
				assert.match(err.message, /Key already exists in file/);
				return true;
			}
		);
	});
});

describe('saveVerificationKeyToFile', () => {
	const testDir = join(tmpdir(), 'fair-tools-save-verification-key-test-' + Date.now());

	// Helper to create a mock key object from hex string
	function mockKey(publicKey, hexPrivateKey) {
		return {
			publicKey,
			privateKey: Buffer.from(hexPrivateKey, 'hex'),
		};
	}

	beforeEach(async () => {
		await mkdir(testDir, { recursive: true });
	});

	after(async () => {
		await rm(testDir, { recursive: true, force: true });
	});

	it('writes multibase key when file does not exist', async () => {
		const outputFile = join(testDir, 'new-key.txt');
		const result = await saveVerificationKeyToFile({
			outputFile,
			key: mockKey('did:key:z6MkTest', 'aabbccdd'),
		});

		assert.strictEqual(result.appended, false);
		const content = await readFile(outputFile, 'utf-8');
		assert(content.trim().startsWith('z'), 'Should write multibase key');
		// Verify it decodes correctly with ed25519 prefix
		const decoded = base58btc.decode(content.trim());
		assert.strictEqual(decoded[0], 0x80);
		assert.strictEqual(decoded[1], 0x26);
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
			key: mockKey('did:key:z6MkNew', 'aabbccdd'),
		});

		assert.strictEqual(result.appended, true);
		const content = await readFile(outputFile, 'utf-8');
		const parsed = JSON.parse(content);
		assert.strictEqual(parsed.verificationKeys['did:key:z6MkExisting'], '11223344');
		// New key should be multibase encoded
		const newKeyValue = parsed.verificationKeys['did:key:z6MkNew'];
		assert(newKeyValue.startsWith('z'), 'New key should be multibase encoded');
	});

	it('creates verificationKeys object when missing from existing JSON', async () => {
		const outputFile = join(testDir, 'no-keytype.json');
		const existingData = {
			did: 'did:plc:test',
		};
		await writeFile(outputFile, JSON.stringify(existingData, null, 2));

		const result = await saveVerificationKeyToFile({
			outputFile,
			key: mockKey('did:key:z6MkNew', 'aabbccdd'),
		});

		assert.strictEqual(result.appended, true);
		const content = await readFile(outputFile, 'utf-8');
		const parsed = JSON.parse(content);
		assert(parsed.verificationKeys['did:key:z6MkNew'].startsWith('z'));
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
				key: mockKey('did:key:z6MkSame', 'newvalue'),
			}),
			(err) => {
				assert(err instanceof SaveKeyError);
				assert.match(err.message, /Key already exists in file/);
				return true;
			}
		);
	});
});
