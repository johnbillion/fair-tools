import { describe, it, after, beforeEach } from 'node:test';
import assert from 'node:assert';
import { readFile, writeFile, rm, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { saveKeyToFile, SaveKeyError } from '../../src/cli/lib/save-key.js';

const testDir = join(tmpdir(), 'fair-tools-save-key-test-' + Date.now());

// Helper to create a mock key object from hex string
function mockKey(publicKey, hexPrivateKey) {
	return {
		publicKey,
		privateKey: Buffer.from(hexPrivateKey, 'hex'),
	};
}

describe('save-key.js', () => {
	beforeEach(async () => {
		await mkdir(testDir, { recursive: true });
	});

	after(async () => {
		await rm(testDir, { recursive: true, force: true });
	});

	describe('save key to file', () => {
		it('writes raw hex when file does not exist', async () => {
			const outputFile = join(testDir, 'new-key.txt');
			const result = await saveKeyToFile({
				outputFile,
				key: mockKey('did:key:zQ3shTest', 'aabbccdd'),
				keyType: 'rotationKeys',
			});

			assert.strictEqual(result.appended, false);
			const content = await readFile(outputFile, 'utf-8');
			assert.strictEqual(content, 'aabbccdd\n');
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

			const result = await saveKeyToFile({
				outputFile,
				key: mockKey('did:key:zQ3shNew', 'aabbccdd'),
				keyType: 'rotationKeys',
			});

			assert.strictEqual(result.appended, true);
			const content = await readFile(outputFile, 'utf-8');
			const parsed = JSON.parse(content);
			assert.strictEqual(parsed.rotationKeys['did:key:zQ3shExisting'], '11223344');
			assert.strictEqual(parsed.rotationKeys['did:key:zQ3shNew'], 'aabbccdd');
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

			const result = await saveKeyToFile({
				outputFile,
				key: mockKey('did:key:z6MkNew', 'aabbccdd'),
				keyType: 'verificationKeys',
			});

			assert.strictEqual(result.appended, true);
			const content = await readFile(outputFile, 'utf-8');
			const parsed = JSON.parse(content);
			assert.strictEqual(parsed.verificationKeys['did:key:z6MkExisting'], '11223344');
			assert.strictEqual(parsed.verificationKeys['did:key:z6MkNew'], 'aabbccdd');
		});

		it('creates keyType object when missing from existing JSON', async () => {
			const outputFile = join(testDir, 'no-keytype.json');
			const existingData = {
				did: 'did:plc:test',
			};
			await writeFile(outputFile, JSON.stringify(existingData, null, 2));

			const result = await saveKeyToFile({
				outputFile,
				key: mockKey('did:key:zQ3shNew', 'aabbccdd'),
				keyType: 'rotationKeys',
			});

			assert.strictEqual(result.appended, true);
			const content = await readFile(outputFile, 'utf-8');
			const parsed = JSON.parse(content);
			assert.strictEqual(parsed.rotationKeys['did:key:zQ3shNew'], 'aabbccdd');
		});

		it('throws SaveKeyError when file exists but is not valid JSON', async () => {
			const outputFile = join(testDir, 'invalid.json');
			await writeFile(outputFile, 'not valid json {{{');

			await assert.rejects(
				saveKeyToFile({
					outputFile,
					key: mockKey('did:key:zQ3shTest', 'aabbccdd'),
					keyType: 'rotationKeys',
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
				saveKeyToFile({
					outputFile,
					key: mockKey('did:key:zQ3shTest', 'aabbccdd'),
					keyType: 'rotationKeys',
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
				saveKeyToFile({
					outputFile,
					key: mockKey('did:key:zQ3shTest', 'aabbccdd'),
					keyType: 'rotationKeys',
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

			await saveKeyToFile({
				outputFile,
				key: mockKey('did:key:zQ3shNew', 'aabbccdd'),
				keyType: 'rotationKeys',
			});

			const content = await readFile(outputFile, 'utf-8');
			const parsed = JSON.parse(content);
			assert.strictEqual(parsed.did, 'did:plc:test');
			assert.strictEqual(parsed.customField, 'should be preserved');
			assert.strictEqual(parsed.verificationKeys['did:key:z6MkVerify'], '55667788');
			assert.strictEqual(parsed.rotationKeys['did:key:zQ3shNew'], 'aabbccdd');
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
				saveKeyToFile({
					outputFile,
					key: mockKey('did:key:zQ3shSame', 'newvalue'),
					keyType: 'rotationKeys',
				}),
				(err) => {
					assert(err instanceof SaveKeyError);
					assert.match(err.message, /Key already exists in file/);
					return true;
				}
			);
		});
	});
});
