/**
 * Key file utilities for DID key storage.
 *
 * Provides functions for formatting and writing DID key files
 * with secure permissions.
 */

import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

/**
 * Error thrown when saving a key to a file fails.
 */
export class SaveKeyError extends Error {
	constructor(message) {
		super(message);
		this.name = 'SaveKeyError';
	}
}

/**
 * Encodes a private key as a hex string.
 *
 * @param {Uint8Array} privateKey - The private key bytes
 * @returns {string} The hex-encoded private key
 */
export function encodePrivateKey(privateKey) {
	return Buffer.from(privateKey).toString('hex');
}

/**
 * File mode for DID key files (owner read/write only).
 */
export const KEY_FILE_MODE = 0o600;

/**
 * Directory mode for DID key directories (owner only).
 */
export const KEY_DIR_MODE = 0o700;

/**
 * Generates the output file path for a DID key file.
 *
 * @param {string} directory - The directory to write to
 * @param {string} did - The DID
 * @returns {string} The full path to the key file
 */
export function getKeyFilePath(directory, did) {
	return join(directory, `${did}.json`);
}

/**
 * Formats the DID key file content.
 *
 * Keys are stored as objects keyed by public key.
 *
 * @param {object} options
 * @param {string} options.did - The DID
 * @param {object} options.rotationKey - The rotation key pair
 * @param {string} options.rotationKey.publicKey - The public key
 * @param {Uint8Array} options.rotationKey.privateKey - The private key
 * @param {object} options.verificationKey - The verification key pair
 * @param {string} options.verificationKey.publicKey - The public key
 * @param {Uint8Array} options.verificationKey.privateKey - The private key
 * @returns {string} The JSON content to write
 */
export function formatKeyFileContent({ did, rotationKey, verificationKey }) {
	return JSON.stringify({
		did,
		rotationKeys: {
			[rotationKey.publicKey]: encodePrivateKey(rotationKey.privateKey),
		},
		verificationKeys: {
			[verificationKey.publicKey]: encodePrivateKey(verificationKey.privateKey),
		},
	}, null, 2);
}

/**
 * Writes DID keys to a file with secure permissions.
 *
 * @param {string} path - The file path
 * @param {string} content - The content to write
 * @returns {Promise<void>}
 */
export async function writeKeyFile(path, content) {
	await writeFile(path, content + '\n', { mode: KEY_FILE_MODE });
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
	const privateKeyHex = encodePrivateKey(key.privateKey);
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
			await writeFile(outputFile, JSON.stringify(outputData, null, 2) + '\n', { mode: KEY_FILE_MODE });
			return { appended: true };
		} else {
			// File doesn't exist - write raw hex
			await writeFile(outputFile, privateKeyHex + '\n', { mode: KEY_FILE_MODE });
			return { appended: false };
		}
	} catch (err) {
		if (err instanceof SaveKeyError) {
			throw err;
		}
		throw new SaveKeyError(`Error writing output file: ${err.message}`);
	}
}
