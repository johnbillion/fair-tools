/**
 * Key file utilities for DID key storage.
 *
 * Provides functions for formatting and writing DID key files
 * with secure permissions.
 */

import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { base58btc } from 'multiformats/bases/base58';

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
 * Multicodec prefix for secp256k1 private keys (rotation keys).
 * Used when reading multibase-encoded keys for interoperability with FAIR Beacon.
 */
export const SECP256K1_PRIV_PREFIX = new Uint8Array([0x81, 0x26]);

/**
 * Multicodec prefix for ed25519 private keys (verification keys).
 * Used when reading multibase-encoded keys for interoperability with FAIR Beacon.
 */
export const ED25519_PRIV_PREFIX = new Uint8Array([0x80, 0x26]);

/**
 * Encodes a rotation key (secp256k1) as a multibase base58btc string.
 *
 * @param {Uint8Array} privateKey - The 32-byte private key
 * @returns {string} The PEM-encoded private key (-----BEGIN EC PRIVATE KEY-----)
 */
export function encodeRotationKey(privateKey) {
	const combined = new Uint8Array(SECP256K1_PRIV_PREFIX.length + privateKey.length);
	combined.set(SECP256K1_PRIV_PREFIX);
	combined.set(privateKey, SECP256K1_PRIV_PREFIX.length);
	return base58btc.encode(combined);
}

/**
 * Encodes a verification key (ed25519) as a PEM string in PKCS#8 format.
 *
 * @param {Uint8Array} privateKey - The 32-byte private key
 * @returns {string} The PEM-encoded private key (-----BEGIN PRIVATE KEY-----)
 */
export function encodeVerificationKey(privateKey) {
	const combined = new Uint8Array(ED25519_PRIV_PREFIX.length + privateKey.length);
	combined.set(ED25519_PRIV_PREFIX);
	combined.set(privateKey, ED25519_PRIV_PREFIX.length);
	return base58btc.encode(combined);
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
 * Keys are stored as objects keyed by public key, with values encoded as
 * PEM strings:
 * - Rotation keys: SEC1 format (-----BEGIN EC PRIVATE KEY-----)
 * - Verification keys: PKCS#8 format (-----BEGIN PRIVATE KEY-----)
 *
 * @param {{
 *   did: string, // did:plc:...
 *   rotationKey: {
 *     publicKey: string, // did:key:zQ3sh...
 *     privateKey: Uint8Array
 *   },
 *   verificationKey: {
 *     publicKey: string, // did:key:z6Mk...
 *     privateKey: Uint8Array
 *   }
 * }} options
 * @returns {string} The JSON content to write
 */
export function formatKeyFileContent({ did, rotationKey, verificationKey }) {
	return JSON.stringify({
		did,
		rotationKeys: {
			[rotationKey.publicKey]: encodeRotationKey(rotationKey.privateKey),
		},
		verificationKeys: {
			[verificationKey.publicKey]: encodeVerificationKey(verificationKey.privateKey),
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
 * Save a new rotation key to a file.
 *
 * If the file exists and is valid JSON, appends the key to the rotationKeys object.
 * If the file doesn't exist, writes the PEM-encoded key as a standalone file.
 *
 * @param {{
 *   outputFile: string,
 *   key: {
 *     publicKey: string, // did:key:zQ3sh...
 *     privateKey: Uint8Array
 *   }
 * }} opts
 * @returns {Promise<{appended: boolean}>} Whether the key was appended to existing file
 * @throws {SaveKeyError} If reading or writing fails, or if key already exists
 */
export async function saveRotationKeyToFile({ outputFile, key }) {
	const publicKey = key.publicKey;
	const encodedKey = encodeRotationKey(key.privateKey);
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
		// File doesn't exist - will write PEM key
	}

	try {
		if (outputData) {
			// File exists and is valid JSON - append to keys
			if (!outputData.rotationKeys) {
				outputData.rotationKeys = {};
			}
			if (outputData.rotationKeys[publicKey]) {
				throw new SaveKeyError(`Key already exists in file: ${publicKey}`);
			}
			outputData.rotationKeys[publicKey] = encodedKey;
			await writeFile(outputFile, JSON.stringify(outputData, null, 2) + '\n', { mode: KEY_FILE_MODE });
			return { appended: true };
		} else {
			// File doesn't exist - write PEM key with proper multiline format
			await writeFile(outputFile, encodedKey + '\n', { mode: KEY_FILE_MODE });
			return { appended: false };
		}
	} catch (err) {
		if (err instanceof SaveKeyError) {
			throw err;
		}
		throw new SaveKeyError(`Error writing output file: ${err.message}`);
	}
}

/**
 * Save a new verification key to a file.
 *
 * If the file exists and is valid JSON, appends the key to the verificationKeys object.
 * If the file doesn't exist, writes the PEM-encoded key as a standalone file.
 *
 * @param {{
 *   outputFile: string,
 *   key: {
 *     publicKey: string, // did:key:z6Mk...
 *     privateKey: Uint8Array
 *   }
 * }} opts
 * @returns {Promise<{appended: boolean}>} Whether the key was appended to existing file
 * @throws {SaveKeyError} If reading or writing fails, or if key already exists
 */
export async function saveVerificationKeyToFile({ outputFile, key }) {
	const publicKey = key.publicKey;
	const encodedKey = encodeVerificationKey(key.privateKey);
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
		// File doesn't exist - will write PEM key
	}

	try {
		if (outputData) {
			// File exists and is valid JSON - append to keys
			if (!outputData.verificationKeys) {
				outputData.verificationKeys = {};
			}
			if (outputData.verificationKeys[publicKey]) {
				throw new SaveKeyError(`Key already exists in file: ${publicKey}`);
			}
			outputData.verificationKeys[publicKey] = encodedKey;
			await writeFile(outputFile, JSON.stringify(outputData, null, 2) + '\n', { mode: KEY_FILE_MODE });
			return { appended: true };
		} else {
			// File doesn't exist - write PEM key with proper multiline format
			await writeFile(outputFile, encodedKey + '\n', { mode: KEY_FILE_MODE });
			return { appended: false };
		}
	} catch (err) {
		if (err instanceof SaveKeyError) {
			throw err;
		}
		throw new SaveKeyError(`Error writing output file: ${err.message}`);
	}
}
