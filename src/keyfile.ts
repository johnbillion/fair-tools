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

interface KeyData {
	did?: string;
	rotationKeys?: Record<string, string>;
	verificationKeys?: Record<string, string>;
}

interface KeyPair {
	/** did:key:... */
	publicKey: string;
	privateKey: Uint8Array;
}

interface FormatKeyFileContentOptions {
	did: string;
	rotationKey: KeyPair;
	verificationKey: KeyPair;
}

/**
 * Error thrown when saving a key to a file fails.
 */
export class SaveKeyError extends Error {}

/**
 * Size of the uncompressed public key prefix byte (0x04).
 */
const UNCOMPRESSED_KEY_PREFIX_SIZE = 1;

/**
 * Size of a secp256k1 coordinate (X or Y) in bytes.
 */
const SECP256K1_COORDINATE_SIZE = 32;

/**
 * Encodes a rotation key (secp256k1) as a PEM string in SEC1 format.
 *
 * @param {Uint8Array} privateKey - The 32-byte private key
 * @returns {string} The PEM-encoded private key (-----BEGIN EC PRIVATE KEY-----)
 */
export function encodeRotationKey(privateKey: Uint8Array): string {
	const uncompressedPublicKey = secp256k1.getPublicKey(privateKey, false);
	// Uncompressed format: 0x04 prefix + 32-byte X + 32-byte Y
	const xStart = UNCOMPRESSED_KEY_PREFIX_SIZE;
	const xEnd = xStart + SECP256K1_COORDINATE_SIZE;
	const yEnd = xEnd + SECP256K1_COORDINATE_SIZE;
	const publicKeyX = uncompressedPublicKey.slice(xStart, xEnd);
	const publicKeyY = uncompressedPublicKey.slice(xEnd, yEnd);

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

	return (
		keyObject.export({
			type: 'sec1',
			format: 'pem',
		}) as string
	).trim();
}

/**
 * Encodes a verification key (ed25519) as a PEM string in PKCS#8 format.
 *
 * @param {Uint8Array} privateKey - The 32-byte private key
 * @returns {string} The PEM-encoded private key (-----BEGIN PRIVATE KEY-----)
 */
export function encodeVerificationKey(privateKey: Uint8Array): string {
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

	return (
		keyObject.export({
			type: 'pkcs8',
			format: 'pem',
		}) as string
	).trim();
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
export function getKeyFilePath(directory: string, did: string): string {
	return join(directory, `${did}.json`);
}

/**
 * Formats the DID key file content.
 *
 * Keys are stored as objects keyed by public key, with values encoded as
 * PEM strings:
 * - Rotation keys: SEC1 format (-----BEGIN EC PRIVATE KEY-----)
 * - Verification keys: PKCS#8 format (-----BEGIN PRIVATE KEY-----)
 * @returns {string} The JSON content to write
 */
export function formatKeyFileContent({ did, rotationKey, verificationKey }: FormatKeyFileContentOptions): string {
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
		'\t',
	);
}

/**
 * Writes DID keys to a file with secure permissions.
 *
 * @param {string} path - The file path
 * @param {string} content - The content to write
 * @returns {Promise<void>}
 */
export async function writeKeyFile(path: string, content: string): Promise<void> {
	await writeFile(path, content + '\n', { mode: KEY_FILE_MODE });
}

/**
 * Save a new rotation key to a file.
 *
 * If the file exists and is valid JSON, appends the key to the rotationKeys object.
 * If the file doesn't exist, writes the PEM-encoded key as a standalone file.
 * @returns {Promise<{
 *   appended: boolean
 * }>} Whether the key was appended to existing file
 * @throws {SaveKeyError} If reading or writing fails, or if key already exists
 */
export async function saveRotationKeyToFile({
	outputFile,
	key,
}: {
	outputFile: string;
	key: KeyPair;
}): Promise<{ appended: boolean }> {
	const publicKey = key.publicKey;
	let encodedKey: string;
	try {
		encodedKey = encodeRotationKey(key.privateKey);
	} catch (err) {
		throw new SaveKeyError(`Invalid private key: ${(err as Error).message}`);
	}
	let outputData: unknown = null;

	try {
		const content = await readFile(outputFile, 'utf-8');
		outputData = JSON.parse(content);
	} catch (err) {
		const error = err as NodeJS.ErrnoException;
		if (error.code !== 'ENOENT') {
			if (err instanceof SyntaxError) {
				throw new SaveKeyError(`Output file is not valid JSON: ${outputFile}`);
			}
			throw new SaveKeyError(`Error reading output file: ${error.message}`);
		}
		// File doesn't exist - will write PEM key
	}

	try {
		if (outputData !== null && typeof outputData === 'object') {
			// File exists and is valid JSON - append to keys
			const data = outputData as KeyData;
			if (!data.rotationKeys) {
				data.rotationKeys = {};
			}
			if (data.rotationKeys[publicKey]) {
				throw new SaveKeyError(`Key already exists in file: ${publicKey}`);
			}
			data.rotationKeys[publicKey] = encodedKey;
			await writeFile(outputFile, JSON.stringify(outputData, null, '\t') + '\n', {
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
		throw new SaveKeyError(`Error writing output file: ${(err as Error).message}`);
	}
}

/**
 * Save a new verification key to a file.
 *
 * If the file exists and is valid JSON, appends the key to the verificationKeys object.
 * If the file doesn't exist, writes the PEM-encoded key as a standalone file.
 * @returns {Promise<{
 *   appended: boolean
 * }>} Whether the key was appended to existing file
 * @throws {SaveKeyError} If reading or writing fails, or if key already exists
 */
export async function saveVerificationKeyToFile({
	outputFile,
	key,
}: {
	outputFile: string;
	key: KeyPair;
}): Promise<{ appended: boolean }> {
	const publicKey = key.publicKey;
	let encodedKey: string;
	try {
		encodedKey = encodeVerificationKey(key.privateKey);
	} catch (err) {
		throw new SaveKeyError(`Invalid private key: ${(err as Error).message}`);
	}
	let outputData: unknown = null;

	try {
		const content = await readFile(outputFile, 'utf-8');
		outputData = JSON.parse(content);
	} catch (err) {
		const error = err as NodeJS.ErrnoException;
		if (error.code !== 'ENOENT') {
			if (err instanceof SyntaxError) {
				throw new SaveKeyError(`Output file is not valid JSON: ${outputFile}`);
			}
			throw new SaveKeyError(`Error reading output file: ${error.message}`);
		}
		// File doesn't exist - will write PEM key
	}

	try {
		if (outputData !== null && typeof outputData === 'object') {
			// File exists and is valid JSON - append to keys
			const data = outputData as KeyData;
			if (!data.verificationKeys) {
				data.verificationKeys = {};
			}
			if (data.verificationKeys[publicKey]) {
				throw new SaveKeyError(`Key already exists in file: ${publicKey}`);
			}
			data.verificationKeys[publicKey] = encodedKey;
			await writeFile(outputFile, JSON.stringify(outputData, null, '\t') + '\n', {
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
		throw new SaveKeyError(`Error writing output file: ${(err as Error).message}`);
	}
}

/**
 * Convert a rotation key from hex or multibase format to PEM.
 *
 * @param {string} value - The key value (hex or multibase)
 * @returns {string} The PEM-encoded key
 * @throws {Error} If the format is unrecognized
 */
export function convertRotationKeyToPEM(value: string): string {
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
export function convertVerificationKeyToPEM(value: string): string {
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
 */
interface MigrateKeysResult {
	rotationKeysMigrated: number;
	verificationKeysMigrated: number;
	rotationKeysAlreadyPEM: number;
	verificationKeysAlreadyPEM: number;
	backupPath: string | null;
}

/**
 * Migrate a standalone multibase rotation key file to PEM.
 *
 * @param {string} keyFile - Path to the key file
 * @param {string} content - The key content (trimmed)
 * @returns {Promise<MigrateKeysResult>}
 */
async function migrateStandaloneRotationKey(keyFile: string, content: string): Promise<MigrateKeysResult> {
	const backupPath = keyFile + '.bak';
	try {
		await copyFile(keyFile, backupPath, constants.COPYFILE_EXCL);
		await chmod(backupPath, KEY_FILE_MODE);
	} catch (err) {
		throw new MigrateKeysError(`Error creating backup: ${(err as Error).message}`);
	}

	let pemKey: string;
	try {
		pemKey = convertRotationKeyToPEM(content);
	} catch (err) {
		throw new MigrateKeysError(`Failed to convert key: ${(err as Error).message}`);
	}

	try {
		await writeFile(keyFile, pemKey + '\n');
		await chmod(keyFile, KEY_FILE_MODE);
	} catch (err) {
		throw new MigrateKeysError(`Error writing migrated file: ${(err as Error).message}`);
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
async function migrateStandaloneVerificationKey(keyFile: string, content: string): Promise<MigrateKeysResult> {
	const backupPath = keyFile + '.bak';
	try {
		await copyFile(keyFile, backupPath, constants.COPYFILE_EXCL);
		await chmod(backupPath, KEY_FILE_MODE);
	} catch (err) {
		throw new MigrateKeysError(`Error creating backup: ${(err as Error).message}`);
	}

	let pemKey: string;
	try {
		pemKey = convertVerificationKeyToPEM(content);
	} catch (err) {
		throw new MigrateKeysError(`Failed to convert key: ${(err as Error).message}`);
	}

	try {
		await writeFile(keyFile, pemKey + '\n');
		await chmod(keyFile, KEY_FILE_MODE);
	} catch (err) {
		throw new MigrateKeysError(`Error writing migrated file: ${(err as Error).message}`);
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
async function migrateJsonKeyFile(keyFile: string, keyData: KeyData): Promise<MigrateKeysResult> {
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
				keyData.rotationKeys![publicKey] = convertRotationKeyToPEM(privateKey);
				rotationKeysMigrated++;
			} catch (err) {
				throw new MigrateKeysError(`Failed to convert rotation key ${publicKey}: ${(err as Error).message}`);
			}
		}
	}

	// Process verification keys
	for (const [publicKey, privateKey] of Object.entries(verificationKeys)) {
		if (isPKCS8PrivateKeyPEM(privateKey)) {
			verificationKeysAlreadyPEM++;
		} else {
			try {
				keyData.verificationKeys![publicKey] = convertVerificationKeyToPEM(privateKey);
				verificationKeysMigrated++;
			} catch (err) {
				throw new MigrateKeysError(`Failed to convert verification key ${publicKey}: ${(err as Error).message}`);
			}
		}
	}

	const totalMigrated = rotationKeysMigrated + verificationKeysMigrated;
	let backupPath: string | null = null;

	if (totalMigrated > 0) {
		backupPath = keyFile + '.bak';
		try {
			await copyFile(keyFile, backupPath, constants.COPYFILE_EXCL);
			await chmod(backupPath, KEY_FILE_MODE);
		} catch (err) {
			throw new MigrateKeysError(`Error creating backup: ${(err as Error).message}`);
		}

		try {
			await writeFile(keyFile, JSON.stringify(keyData, null, '\t') + '\n');
			await chmod(keyFile, KEY_FILE_MODE);
		} catch (err) {
			throw new MigrateKeysError(`Error writing migrated file: ${(err as Error).message}`);
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
 * @throws {MigrateKeysError} If migration fails
 */
export async function migrateKeysToPEM({ keyFile }: { keyFile: string }): Promise<MigrateKeysResult> {
	let keyContent: string;
	try {
		keyContent = await readFile(keyFile, 'utf-8');
	} catch (err) {
		throw new MigrateKeysError(`Error reading key file: ${(err as Error).message}`);
	}

	const trimmedContent = keyContent.trim();

	// Try to parse as JSON first
	try {
		const keyData = JSON.parse(trimmedContent) as KeyData;
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
