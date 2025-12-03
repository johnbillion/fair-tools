import { describe, it, after } from 'node:test';
import assert from 'node:assert';
import { stat, rm, mkdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
	getKeyFilePath,
	formatKeyFileContent,
	writeKeyFile,
} from '../src/keyfile.js';

describe('getKeyFilePath', () => {
	it('returns path with DID as filename', () => {
		const path = getKeyFilePath('/some/dir', 'did:plc:abc123');
		assert.strictEqual(path, '/some/dir/did:plc:abc123.json');
	});
});

describe('formatKeyFileContent', () => {
	it('formats keys as JSON with hex-encoded private keys', () => {
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
		assert.deepStrictEqual(parsed.rotationKeys, { 'did:key:zQ3shRotation': '01020304' });
		assert.deepStrictEqual(parsed.verificationKeys, { 'did:key:z6MkVerification': 'aabbccdd' });
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
