import { readFile, writeFile } from 'node:fs/promises';

export class SaveKeyError extends Error {
	constructor(message) {
		super(message);
		this.name = 'SaveKeyError';
	}
}

/**
 * Save a new key to a file.
 *
 * If the file exists and is valid JSON, appends the key to the specified keys object.
 * If the file doesn't exist, writes just the raw hex value.
 *
 * @param {object} opts
 * @param {string} opts.outputFile - Path to output file
 * @param {{publicKey: string, privateKey: Uint8Array}} opts.key - The key pair to save
 * @param {'rotationKeys'|'verificationKeys'} opts.keyType - Which key collection to add to
 * @returns {Promise<{appended: boolean}>} Whether the key was appended to existing file
 * @throws {SaveKeyError} If reading or writing fails, or if key already exists
 */
export async function saveKeyToFile({ outputFile, key, keyType }) {
	const publicKey = key.publicKey;
	const privateKeyHex = Buffer.from(key.privateKey).toString('hex');
	let outputData = null;

	try {
		const content = await readFile(outputFile, 'utf-8');
		outputData = JSON.parse(content);
	} catch (err) {
		if (err.code !== 'ENOENT') {
			if (err instanceof SyntaxError) {
				throw new SaveKeyError(`Output file is not valid JSON: ${outputFile}`);
			}
			throw new SaveKeyError(`Error reading output file: ${err.message}`);
		}
		// File doesn't exist - will write raw hex
	}

	try {
		if (outputData) {
			// File exists and is valid JSON - append to keys
			if (!outputData[keyType]) {
				outputData[keyType] = {};
			}
			if (outputData[keyType][publicKey]) {
				throw new SaveKeyError(`Key already exists in file: ${publicKey}`);
			}
			outputData[keyType][publicKey] = privateKeyHex;
			await writeFile(outputFile, JSON.stringify(outputData, null, 2) + '\n', { mode: 0o600 });
			return { appended: true };
		} else {
			// File doesn't exist - write raw hex
			await writeFile(outputFile, privateKeyHex + '\n', { mode: 0o600 });
			return { appended: false };
		}
	} catch (err) {
		throw new SaveKeyError(`Error writing output file: ${err.message}`);
	}
}
