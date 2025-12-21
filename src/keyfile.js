/**
 * Key file utilities for DID key storage.
 *
 * Provides functions for formatting and writing DID key files
 * with secure permissions.
 */

import crypto from 'node:crypto';
import { chmod, copyFile, readFile, writeFile, constants } from 'node:fs/promises';
import { join } from 'node:path';
import { secp256k1 } from '@noble/curves/secp256k1';
import { ed25519 } from '@noble/curves/ed25519';
import {
	isECPrivateKeyPEM,
	isPKCS8PrivateKeyPEM,
	isHexPrivateKey,
	isMultibaseRotationKey,
	isMultibaseVerificationKey,
	decodeMultibaseRotationKey,
	decodeMultibaseVerificationKey,
} from './signing.js';

/**
 * Error thrown when saving a key to a file fails.
 */
export class SaveKeyError extends Error {}

/**
 * Encodes a rotation key (secp256k1) as a PEM string in SEC1 format.
 *
 * @param {Uint8Array} privateKey - The 32-byte private key
 * @returns {string} The PEM-encoded private key (-----BEGIN EC PRIVATE KEY-----)
 */
export function encodeRotationKey(privateKey) {
	const uncompressedPublicKey = secp256k1.getPublicKey(privateKey, false);
	const publicKeyX = uncompressedPublicKey.slice(1, 33);
	const publicKeyY = uncompressedPublicKey.slice(33, 65);

	const keyObject = crypto.createPrivateKey({
		key: {
			kty: 'EC',
			crv: 'secp256k1',
			d: Buffer.from(privateKey).toString('base64url'),
			x: Buffer.from(publicKeyX).toString('base64url'),
			y: Buffer.from(publicKeyY).toString('base64url'),
		},
		format: 'jwk',
	});

	return keyObject
		.export({
			type: 'sec1',
			format: 'pem',
		})
		.trim();
}

/**
 * Encodes a verification key (ed25519) as a PEM string in PKCS#8 format.
 *
 * @param {Uint8Array} privateKey - The 32-byte private key
 * @returns {string} The PEM-encoded private key (-----BEGIN PRIVATE KEY-----)
 */
export function encodeVerificationKey(privateKey) {
	const publicKey = ed25519.getPublicKey(privateKey);
	const keyObject = crypto.createPrivateKey({
		key: {
			kty: 'OKP',
			crv: 'Ed25519',
			d: Buffer.from(privateKey).toString('base64url'),
			x: Buffer.from(publicKey).toString('base64url'),
		},
		format: 'jwk',
	});

	return keyObject
		.export({
			type: 'pkcs8',
			format: 'pem',
		})
		.trim();
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
	return JSON.stringify(
		{
			did,
			rotationKeys: {
				[rotationKey.publicKey]: encodeRotationKey(rotationKey.privateKey),
			},
			verificationKeys: {
				[verificationKey.publicKey]: encodeVerificationKey(verificationKey.privateKey),
			},
		},
		null,
		2,
	);
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
 * @returns {Promise<{
 *   appended: boolean
 * }>} Whether the key was appended to existing file
 * @throws {SaveKeyError} If reading or writing fails, or if key already exists
 */
export async function saveRotationKeyToFile({ outputFile, key }) {
	const publicKey = key.publicKey;
	let encodedKey;
	try {
		encodedKey = encodeRotationKey(key.privateKey);
	} catch (err) {
		throw new SaveKeyError(`Invalid private key: ${err.message}`);
	}
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
			await writeFile(outputFile, JSON.stringify(outputData, null, 2) + '\n', {
				mode: KEY_FILE_MODE,
			});
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
 * @returns {Promise<{
 *   appended: boolean
 * }>} Whether the key was appended to existing file
 * @throws {SaveKeyError} If reading or writing fails, or if key already exists
 */
export async function saveVerificationKeyToFile({ outputFile, key }) {
	const publicKey = key.publicKey;
	let encodedKey;
	try {
		encodedKey = encodeVerificationKey(key.privateKey);
	} catch (err) {
		throw new SaveKeyError(`Invalid private key: ${err.message}`);
	}
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
			await writeFile(outputFile, JSON.stringify(outputData, null, 2) + '\n', {
				mode: KEY_FILE_MODE,
			});
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
 * Convert a rotation key from hex or multibase format to PEM.
 *
 * @param {string} value - The key value (hex or multibase)
 * @returns {string} The PEM-encoded key
 * @throws {Error} If the format is unrecognized
 */
export function convertRotationKeyToPEM(value) {
	const trimmed = value.trim();

	if (isMultibaseRotationKey(trimmed)) {
		return encodeRotationKey(decodeMultibaseRotationKey(trimmed));
	}
	if (isHexPrivateKey(trimmed)) {
		return encodeRotationKey(Buffer.from(trimmed, 'hex'));
	}

	throw new Error('Unrecognized rotation key format');
}

/**
 * Convert a verification key from hex or multibase format to PEM.
 *
 * @param {string} value - The key value (hex or multibase)
 * @returns {string} The PEM-encoded key
 * @throws {Error} If the format is unrecognized
 */
export function convertVerificationKeyToPEM(value) {
	const trimmed = value.trim();

	if (isMultibaseVerificationKey(trimmed)) {
		return encodeVerificationKey(decodeMultibaseVerificationKey(trimmed));
	}
	if (isHexPrivateKey(trimmed)) {
		return encodeVerificationKey(Buffer.from(trimmed, 'hex'));
	}

	throw new Error('Unrecognized verification key format');
}

/**
 * Error thrown when migrating keys fails.
 */
export class MigrateKeysError extends Error {}

/**
 * Result of a key migration operation.
 * @typedef {{
 *   rotationKeysMigrated: number,
 *   verificationKeysMigrated: number,
 *   rotationKeysAlreadyPEM: number,
 *   verificationKeysAlreadyPEM: number,
 *   backupPath: string | null
 * }} MigrateKeysResult
 */

/**
 * Migrate a standalone multibase rotation key file to PEM.
 *
 * @param {string} keyFile - Path to the key file
 * @param {string} content - The key content (trimmed)
 * @returns {Promise<MigrateKeysResult>}
 */
async function migrateStandaloneRotationKey(keyFile, content) {
	const backupPath = keyFile + '.bak';
	try {
		await copyFile(keyFile, backupPath, constants.COPYFILE_EXCL);
		await chmod(backupPath, KEY_FILE_MODE);
	} catch (err) {
		throw new MigrateKeysError(`Error creating backup: ${err.message}`);
	}

	let pemKey;
	try {
		pemKey = convertRotationKeyToPEM(content);
	} catch (err) {
		throw new MigrateKeysError(`Failed to convert key: ${err.message}`);
	}

	try {
		await writeFile(keyFile, pemKey + '\n');
		await chmod(keyFile, KEY_FILE_MODE);
	} catch (err) {
		throw new MigrateKeysError(`Error writing migrated file: ${err.message}`);
	}

	return {
		rotationKeysMigrated: 1,
		verificationKeysMigrated: 0,
		rotationKeysAlreadyPEM: 0,
		verificationKeysAlreadyPEM: 0,
		backupPath,
	};
}

/**
 * Migrate a standalone multibase verification key file to PEM.
 *
 * @param {string} keyFile - Path to the key file
 * @param {string} content - The key content (trimmed)
 * @returns {Promise<MigrateKeysResult>}
 */
async function migrateStandaloneVerificationKey(keyFile, content) {
	const backupPath = keyFile + '.bak';
	try {
		await copyFile(keyFile, backupPath, constants.COPYFILE_EXCL);
		await chmod(backupPath, KEY_FILE_MODE);
	} catch (err) {
		throw new MigrateKeysError(`Error creating backup: ${err.message}`);
	}

	let pemKey;
	try {
		pemKey = convertVerificationKeyToPEM(content);
	} catch (err) {
		throw new MigrateKeysError(`Failed to convert key: ${err.message}`);
	}

	try {
		await writeFile(keyFile, pemKey + '\n');
		await chmod(keyFile, KEY_FILE_MODE);
	} catch (err) {
		throw new MigrateKeysError(`Error writing migrated file: ${err.message}`);
	}

	return {
		rotationKeysMigrated: 0,
		verificationKeysMigrated: 1,
		rotationKeysAlreadyPEM: 0,
		verificationKeysAlreadyPEM: 0,
		backupPath,
	};
}

/**
 * Migrate a JSON key file from hex or multibase format to PEM.
 *
 * @param {string} keyFile - Path to the key file
 * @param {object} keyData - The parsed JSON data
 * @returns {Promise<MigrateKeysResult>}
 */
async function migrateJsonKeyFile(keyFile, keyData) {
	const rotationKeys = keyData.rotationKeys || {};
	const verificationKeys = keyData.verificationKeys || {};

	let rotationKeysMigrated = 0;
	let verificationKeysMigrated = 0;
	let rotationKeysAlreadyPEM = 0;
	let verificationKeysAlreadyPEM = 0;

	// Process rotation keys
	for (const [publicKey, privateKey] of Object.entries(rotationKeys)) {
		if (isECPrivateKeyPEM(privateKey)) {
			rotationKeysAlreadyPEM++;
		} else {
			try {
				keyData.rotationKeys[publicKey] = convertRotationKeyToPEM(privateKey);
				rotationKeysMigrated++;
			} catch (err) {
				throw new MigrateKeysError(`Failed to convert rotation key ${publicKey}: ${err.message}`);
			}
		}
	}

	// Process verification keys
	for (const [publicKey, privateKey] of Object.entries(verificationKeys)) {
		if (isPKCS8PrivateKeyPEM(privateKey)) {
			verificationKeysAlreadyPEM++;
		} else {
			try {
				keyData.verificationKeys[publicKey] = convertVerificationKeyToPEM(privateKey);
				verificationKeysMigrated++;
			} catch (err) {
				throw new MigrateKeysError(`Failed to convert verification key ${publicKey}: ${err.message}`);
			}
		}
	}

	const totalMigrated = rotationKeysMigrated + verificationKeysMigrated;
	let backupPath = null;

	if (totalMigrated > 0) {
		backupPath = keyFile + '.bak';
		try {
			await copyFile(keyFile, backupPath, constants.COPYFILE_EXCL);
			await chmod(backupPath, KEY_FILE_MODE);
		} catch (err) {
			throw new MigrateKeysError(`Error creating backup: ${err.message}`);
		}

		try {
			await writeFile(keyFile, JSON.stringify(keyData, null, 2) + '\n');
			await chmod(keyFile, KEY_FILE_MODE);
		} catch (err) {
			throw new MigrateKeysError(`Error writing migrated file: ${err.message}`);
		}
	}

	return {
		rotationKeysMigrated,
		verificationKeysMigrated,
		rotationKeysAlreadyPEM,
		verificationKeysAlreadyPEM,
		backupPath,
	};
}

/**
 * Migrate keys in a key file from hex or multibase format to PEM format.
 *
 * Supports JSON key files with rotationKeys/verificationKeys objects,
 * as well as standalone key files containing a single key.
 *
 * Creates a backup of the original file before modifying it.
 *
 * @param {{
 *   keyFile: string,
 * }} opts
 * @returns {Promise<MigrateKeysResult>}
 * @throws {MigrateKeysError} If migration fails
 */
export async function migrateKeysToPEM({ keyFile }) {
	let keyContent;
	try {
		keyContent = await readFile(keyFile, 'utf-8');
	} catch (err) {
		throw new MigrateKeysError(`Error reading key file: ${err.message}`);
	}

	const trimmedContent = keyContent.trim();

	// Try to parse as JSON first
	try {
		const keyData = JSON.parse(trimmedContent);
		return migrateJsonKeyFile(keyFile, keyData);
	} catch {
		// Not JSON - check if it's a standalone key file
	}

	// Check for standalone multibase rotation key
	if (isMultibaseRotationKey(trimmedContent)) {
		return migrateStandaloneRotationKey(keyFile, trimmedContent);
	}

	// Check for standalone multibase verification key
	if (isMultibaseVerificationKey(trimmedContent)) {
		return migrateStandaloneVerificationKey(keyFile, trimmedContent);
	}

	// Check for standalone PEM keys (already migrated)
	if (isECPrivateKeyPEM(trimmedContent)) {
		return {
			rotationKeysMigrated: 0,
			verificationKeysMigrated: 0,
			rotationKeysAlreadyPEM: 1,
			verificationKeysAlreadyPEM: 0,
			backupPath: null,
		};
	}
	if (isPKCS8PrivateKeyPEM(trimmedContent)) {
		return {
			rotationKeysMigrated: 0,
			verificationKeysMigrated: 0,
			rotationKeysAlreadyPEM: 0,
			verificationKeysAlreadyPEM: 1,
			backupPath: null,
		};
	}

	throw new MigrateKeysError('Key file must be valid JSON or a standalone multibase-encoded key.');
}
