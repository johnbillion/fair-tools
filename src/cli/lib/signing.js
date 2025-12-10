import { readFile } from 'node:fs/promises';
import { base58btc } from 'multiformats/bases/base58';
import {
	SECP256K1_PRIV_PREFIX,
	ED25519_PRIV_PREFIX,
} from '../../keyfile.js';

const SECP256K1_PRIV_PREFIX_HEX = Buffer.from(SECP256K1_PRIV_PREFIX).toString('hex');
const ED25519_PRIV_PREFIX_HEX = Buffer.from(ED25519_PRIV_PREFIX).toString('hex');

export class SigningKeyError extends Error {
	constructor(message) {
		super(message);
		this.name = 'SigningKeyError';
	}
}

/**
 * Decode a multibase base58btc private key string.
 *
 * @param {string} key - The multibase key (starts with 'z3vL' or 'z3u2')
 * @returns {{prefixHex: string, rawKey: Uint8Array}} - The decoded prefix (hex) and raw key
 * @throws {SigningKeyError} If the key format is invalid
 */
function decodeMultibasePrivateKey(key) {
	let decoded;
	try {
		decoded = base58btc.decode(key);
	} catch (err) {
		throw new SigningKeyError('Invalid key format. The key could not be decoded.');
	}

	if (decoded.length < 2) {
		throw new SigningKeyError('Invalid key format. The key is too short.');
	}

	const prefixHex = Buffer.from(decoded.slice(0, 2)).toString('hex');
	const rawKey = decoded.slice(2);

	if (rawKey.length !== 32) {
		throw new SigningKeyError('Invalid key format. The key has the wrong length.');
	}

	return { prefixHex, rawKey };
}

/**
 * Try to parse content as a multibase base58btc rotation private key.
 *
 * @param {string} content - The file content to check
 * @returns {string|null} - The hex key if valid multibase, null otherwise
 * @throws {SigningKeyError} If it looks like multibase but is invalid
 */
function parseAsMultibaseRotationKey(content) {
	const trimmed = content.trim();
	if (!trimmed.startsWith('z')) {
		return null;
	}

	const { prefixHex, rawKey } = decodeMultibasePrivateKey(trimmed);

	if (prefixHex === ED25519_PRIV_PREFIX_HEX) {
		throw new SigningKeyError('Wrong key type for this operation. This looks like a verification key, but a rotation key is required.');
	}

	if (prefixHex !== SECP256K1_PRIV_PREFIX_HEX) {
		throw new SigningKeyError(`Unrecognized key type (prefix: ${prefixHex}). Expected a rotation key.`);
	}

	return Buffer.from(rawKey).toString('hex');
}

/**
 * Try to parse content as a multibase base58btc verification private key.
 *
 * @param {string} content - The file content to check
 * @returns {string|null} - The hex key if valid multibase, null otherwise
 * @throws {SigningKeyError} If it looks like multibase but is invalid
 */
function parseAsMultibaseVerificationKey(content) {
	const trimmed = content.trim();
	if (!trimmed.startsWith('z')) {
		return null;
	}

	const { prefixHex, rawKey } = decodeMultibasePrivateKey(trimmed);

	if (prefixHex === SECP256K1_PRIV_PREFIX_HEX) {
		throw new SigningKeyError('Wrong key type for this operation. This looks like a rotation key, but a verification key is required.');
	}

	if (prefixHex !== ED25519_PRIV_PREFIX_HEX) {
		throw new SigningKeyError(`Unrecognized key type (prefix: ${prefixHex}). Expected a verification key.`);
	}

	return Buffer.from(rawKey).toString('hex');
}

/**
 * Parse a rotation key value from JSON (could be multibase or hex for backwards compatibility).
 *
 * @param {string} value - The key value from JSON
 * @returns {string} - The hex key
 * @throws {SigningKeyError} If the value is invalid
 */
function parseRotationKeyValue(value) {
	const multibaseKey = parseAsMultibaseRotationKey(value);
	if (multibaseKey) {
		return multibaseKey;
	}
	// Assume hex for backwards compatibility
	return value;
}

/**
 * Parse a verification key value from JSON (could be multibase or hex for backwards compatibility).
 *
 * @param {string} value - The key value from JSON
 * @returns {string} - The hex key
 * @throws {SigningKeyError} If the value is invalid
 */
function parseVerificationKeyValue(value) {
	const multibaseKey = parseAsMultibaseVerificationKey(value);
	if (multibaseKey) {
		return multibaseKey;
	}
	// Assume hex for backwards compatibility
	return value;
}

/**
 * Load a rotation key from a key file or environment variable.
 *
 * The key file can be either:
 * - A multibase base58btc encoded private key (starts with 'z3vL')
 * - A JSON file with a `rotationKeys` object mapping public keys to private keys
 *
 * @param {{
 *   signingFile?: string,
 *   signingKey?: string, // ignored for multibase files
 *   envVar?: string // defaults to 'FAIR_ROTATION_KEY'
 * }} opts
 * @returns {Promise<{privateKeyHex: string, keyData: object|null}>}
 * @throws {SigningKeyError} If key cannot be loaded
 */
export async function loadRotationKey({ signingFile, signingKey, envVar = 'FAIR_ROTATION_KEY' }) {
	if (signingKey && !signingFile) {
		throw new SigningKeyError('Cannot specify a signing key without a signing file');
	}

	if (signingFile) {
		let keyContent;
		try {
			keyContent = await readFile(signingFile, 'utf-8');
		} catch (err) {
			throw new SigningKeyError(`Error reading key file: ${err.message}`);
		}

		// Try multibase first
		const multibaseKey = parseAsMultibaseRotationKey(keyContent);
		if (multibaseKey) {
			if (signingKey) {
				throw new SigningKeyError('Cannot specify a signing key when using a multibase key file');
			}
			return { privateKeyHex: multibaseKey, keyData: null };
		}

		// Try JSON
		let keyData;
		try {
			keyData = JSON.parse(keyContent);
		} catch {
			throw new SigningKeyError('Key file must be valid JSON or a multibase base58btc encoded rotation key (starting with "z3vL")');
		}

		const rotationKeys = keyData.rotationKeys || {};
		const publicKeys = Object.keys(rotationKeys);

		if (publicKeys.length === 0) {
			throw new SigningKeyError('Key file must contain at least one rotation key');
		}

		let privateKeyHex;
		if (signingKey) {
			const rawValue = rotationKeys[signingKey];
			if (!rawValue) {
				throw new SigningKeyError(`Rotation key ${signingKey} not found in key file. Available keys: ${publicKeys.join(', ')}`);
			}
			privateKeyHex = parseRotationKeyValue(rawValue);
		} else {
			privateKeyHex = parseRotationKeyValue(rotationKeys[publicKeys[0]]);
		}

		return { privateKeyHex, keyData };
	}

	const privateKeyHex = process.env[envVar];
	if (!privateKeyHex) {
		throw new SigningKeyError(`No signing key provided. Set the ${envVar} environment variable or provide a signing file.`);
	}

	return { privateKeyHex, keyData: null };
}

/**
 * Load a verification key from a key file or environment variable.
 *
 * The key file can be either:
 * - A multibase base58btc encoded private key (starts with 'z3u2')
 * - A JSON file with a `verificationKeys` object mapping public keys to private keys
 *
 * @param {{
 *   signingFile?: string,
 *   signingKey?: string, // ignored for multibase files
 *   envVar?: string // defaults to 'FAIR_VERIFICATION_KEY'
 * }} opts
 * @returns {Promise<{privateKeyHex: string, keyData: object|null}>}
 * @throws {SigningKeyError} If key cannot be loaded
 */
export async function loadVerificationKey({ signingFile, signingKey, envVar = 'FAIR_VERIFICATION_KEY' }) {
	if (signingKey && !signingFile) {
		throw new SigningKeyError('Cannot specify a signing key without a signing file');
	}

	if (signingFile) {
		let keyContent;
		try {
			keyContent = await readFile(signingFile, 'utf-8');
		} catch (err) {
			throw new SigningKeyError(`Error reading key file: ${err.message}`);
		}

		// Try multibase first
		const multibaseKey = parseAsMultibaseVerificationKey(keyContent);
		if (multibaseKey) {
			if (signingKey) {
				throw new SigningKeyError('Cannot specify a signing key when using a multibase key file');
			}
			return { privateKeyHex: multibaseKey, keyData: null };
		}

		// Try JSON
		let keyData;
		try {
			keyData = JSON.parse(keyContent);
		} catch {
			throw new SigningKeyError('Key file must be valid JSON or a multibase base58btc encoded verification key (starting with "z3u2")');
		}

		const verificationKeys = keyData.verificationKeys || {};
		const publicKeys = Object.keys(verificationKeys);

		if (publicKeys.length === 0) {
			throw new SigningKeyError('Key file must contain at least one verification key');
		}

		let privateKeyHex;
		if (signingKey) {
			const rawValue = verificationKeys[signingKey];
			if (!rawValue) {
				throw new SigningKeyError(`Verification key ${signingKey} not found in key file. Available keys: ${publicKeys.join(', ')}`);
			}
			privateKeyHex = parseVerificationKeyValue(rawValue);
		} else {
			privateKeyHex = parseVerificationKeyValue(verificationKeys[publicKeys[0]]);
		}

		return { privateKeyHex, keyData };
	}

	const privateKeyHex = process.env[envVar];
	if (!privateKeyHex) {
		throw new SigningKeyError(`No signing key provided. Set the ${envVar} environment variable or provide a signing file.`);
	}

	return { privateKeyHex, keyData: null };
}

/**
 * Load a rotation key for revoking another rotation key.
 * Auto-selects a key that isn't the one being revoked (for JSON files only).
 *
 * The key file can be either:
 * - A multibase base58btc encoded private key (starts with 'z3vL')
 * - A JSON file with a `rotationKeys` object mapping public keys to private keys
 *
 * @param {{
 *   signingFile?: string,
 *   signingKey?: string, // ignored for multibase files
 *   revokeKey: string, // the key being revoked (to avoid using it for signing)
 *   envVar?: string // defaults to 'FAIR_ROTATION_KEY'
 * }} opts
 * @returns {Promise<{privateKeyHex: string, keyData: object|null}>}
 * @throws {SigningKeyError} If key cannot be loaded
 */
export async function loadRotationKeyForRevocation({ signingFile, signingKey, revokeKey, envVar = 'FAIR_ROTATION_KEY' }) {
	if (signingFile) {
		let keyContent;
		try {
			keyContent = await readFile(signingFile, 'utf-8');
		} catch (err) {
			throw new SigningKeyError(`Error reading key file: ${err.message}`);
		}

		// Try multibase first
		const multibaseKey = parseAsMultibaseRotationKey(keyContent);
		if (multibaseKey) {
			if (signingKey) {
				throw new SigningKeyError('Cannot specify a signing key when using a multibase key file');
			}
			return { privateKeyHex: multibaseKey, keyData: null };
		}

		// Try JSON
		let keyData;
		try {
			keyData = JSON.parse(keyContent);
		} catch {
			throw new SigningKeyError('Key file must be valid JSON or a multibase base58btc encoded rotation key (starting with "z3vL")');
		}

		const rotationKeys = keyData.rotationKeys || {};
		const publicKeys = Object.keys(rotationKeys);

		if (publicKeys.length === 0) {
			throw new SigningKeyError('Key file must contain at least one rotation key');
		}

		let signerPublicKey;
		if (signingKey) {
			if (!rotationKeys[signingKey]) {
				throw new SigningKeyError(`Signing key ${signingKey} not found in key file`);
			}
			if (signingKey === revokeKey) {
				throw new SigningKeyError('Cannot use the key being revoked to sign the operation');
			}
			signerPublicKey = signingKey;
		} else {
			// Auto-select: use first key that isn't the one being revoked
			signerPublicKey = publicKeys.find((k) => k !== revokeKey);
			if (!signerPublicKey) {
				throw new SigningKeyError(`No signing key available. The only rotation key in the file is the one being revoked. Use ${envVar} environment variable to provide a different signing key.`);
			}
		}

		const privateKeyHex = parseRotationKeyValue(rotationKeys[signerPublicKey]);
		return { privateKeyHex, keyData };
	}

	// @TODO convert this to a guard condition near the start of the function
	const privateKeyHex = process.env[envVar];
	if (!privateKeyHex) {
		throw new SigningKeyError(`No signing key provided. Set the ${envVar} environment variable or provide a signing file.`);
	}

	return { privateKeyHex, keyData: null };
}
