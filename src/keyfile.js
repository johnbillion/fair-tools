/**
 * Key file utilities for DID key storage.
 *
 * Provides functions for formatting and writing DID key files
 * with secure permissions.
 */

import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';

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
		rotationKey: {
			publicKey: rotationKey.publicKey,
			privateKey: Buffer.from(rotationKey.privateKey).toString('hex'),
		},
		verificationKey: {
			publicKey: verificationKey.publicKey,
			privateKey: Buffer.from(verificationKey.privateKey).toString('hex'),
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
