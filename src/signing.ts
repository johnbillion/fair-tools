import crypto from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { base58btc } from 'multiformats/bases/base58';

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

const SECP256K1_PRIV_PREFIX_HEX = Buffer.from(SECP256K1_PRIV_PREFIX).toString('hex');
const ED25519_PRIV_PREFIX_HEX = Buffer.from(ED25519_PRIV_PREFIX).toString('hex');

/**
 * PEM header for EC private keys (SEC1 format, used for secp256k1 rotation keys).
 */
const EC_PRIVATE_KEY_HEADER = '-----BEGIN EC PRIVATE KEY-----';

/**
 * PEM header for PKCS#8 private keys (used for Ed25519 verification keys).
 */
const PKCS8_PRIVATE_KEY_HEADER = '-----BEGIN PRIVATE KEY-----';

export class SigningKeyError extends Error {}

export interface KeyData {
	rotationKeys?: Record<string, string>;
	verificationKeys?: Record<string, string>;
}

interface LoadKeyResult {
	privateKeyHex: string;
	keyData: KeyData | null;
}

/**
 * Decode a multibase base58btc rotation private key string (32-byte key).
 *
 * @param {string} key - The multibase key (starts with 'z3vL')
 * @returns {Uint8Array} - The 32-byte private key
 * @throws {SigningKeyError} If the key format is invalid
 */
export function decodeMultibaseRotationKey(key: string): Uint8Array {
	let decoded: Uint8Array;
	try {
		decoded = base58btc.decode(key);
	} catch {
		throw new SigningKeyError('Invalid key format. The key could not be decoded.');
	}

	if (decoded.length < 2) {
		throw new SigningKeyError('Invalid key format. The key is too short.');
	}

	const prefixHex = Buffer.from(decoded.slice(0, 2)).toString('hex');

	if (prefixHex === ED25519_PRIV_PREFIX_HEX) {
		throw new SigningKeyError(
			'Wrong key type for this operation. This looks like a verification key, but a rotation key is required.',
		);
	}

	if (prefixHex !== SECP256K1_PRIV_PREFIX_HEX) {
		throw new SigningKeyError(`Unrecognized key type (prefix: ${prefixHex}). Expected a rotation key.`);
	}

	const rawKey = decoded.slice(2);

	if (rawKey.length !== 32) {
		throw new SigningKeyError('Invalid key format. The key has the wrong length.');
	}

	return rawKey;
}

/**
 * Decode a multibase base58btc verification private key string (Sodium 64-byte format).
 *
 * Sodium stores Ed25519 secret keys as 64 bytes: the 32-byte seed concatenated with
 * the 32-byte public key. This function extracts just the 32-byte seed.
 *
 * @param {string} key - The multibase key (starts with 'zru' or 'zrv')
 * @returns {Uint8Array} - The 32-byte private key seed
 * @throws {SigningKeyError} If the key format is invalid
 */
export function decodeMultibaseVerificationKey(key: string): Uint8Array {
	let decoded: Uint8Array;
	try {
		decoded = base58btc.decode(key);
	} catch {
		throw new SigningKeyError('Invalid key format. The key could not be decoded.');
	}

	if (decoded.length < 2) {
		throw new SigningKeyError('Invalid key format. The key is too short.');
	}

	const prefixHex = Buffer.from(decoded.slice(0, 2)).toString('hex');

	if (prefixHex === SECP256K1_PRIV_PREFIX_HEX) {
		throw new SigningKeyError(
			'Wrong key type for this operation. This looks like a rotation key, but a verification key is required.',
		);
	}

	if (prefixHex !== ED25519_PRIV_PREFIX_HEX) {
		throw new SigningKeyError(`Unrecognized key type (prefix: ${prefixHex}). Expected a verification key.`);
	}

	const rawKey = decoded.slice(2);

	// Sodium format: 64 bytes (32-byte seed + 32-byte public key)
	if (rawKey.length === 64) {
		return rawKey.slice(0, 32);
	}

	throw new SigningKeyError('Invalid key format. Expected a 64-byte Sodium-format Ed25519 key.');
}

/**
 * Decode a PEM-encoded EC private key (SEC1 format) to raw bytes.
 *
 * @param {string} key - The PEM string (-----BEGIN EC PRIVATE KEY-----)
 * @returns {Uint8Array} - The 32-byte raw private key
 * @throws {SigningKeyError} If the PEM format is invalid
 */
function decodeECPrivateKeyPEM(key: string): Uint8Array {
	let keyObject: crypto.KeyObject;
	try {
		keyObject = crypto.createPrivateKey({
			key,
			format: 'pem',
		});
	} catch {
		throw new SigningKeyError('Invalid rotation key. The PEM file could not be parsed.');
	}

	// Export as JWK to get the raw 'd' parameter (private key)
	const jwk = keyObject.export({
		format: 'jwk',
	});
	if (!jwk.d) {
		throw new SigningKeyError('Invalid rotation key. The PEM file is missing private key data.');
	}

	// JWK 'd' is base64url-encoded
	const rawKey = Buffer.from(jwk.d, 'base64url');
	if (rawKey.length !== 32) {
		throw new SigningKeyError('Invalid rotation key. The key has the wrong length.');
	}

	return new Uint8Array(rawKey);
}

/**
 * Decode a PEM-encoded PKCS#8 private key (Ed25519) to raw bytes.
 *
 * @param {string} key - The PEM string (-----BEGIN PRIVATE KEY-----)
 * @returns {Uint8Array} - The 32-byte raw private key
 * @throws {SigningKeyError} If the PEM format is invalid
 */
function decodePKCS8PrivateKeyPEM(key: string): Uint8Array {
	let keyObject: crypto.KeyObject;
	try {
		keyObject = crypto.createPrivateKey({
			key,
			format: 'pem',
		});
	} catch {
		throw new SigningKeyError('Invalid verification key. The PEM file could not be parsed.');
	}

	// Export as JWK to get the raw 'd' parameter (private key)
	const jwk = keyObject.export({
		format: 'jwk',
	});
	if (!jwk.d) {
		throw new SigningKeyError('Invalid verification key. The PEM file is missing private key data.');
	}

	// JWK 'd' is base64url-encoded
	const rawKey = Buffer.from(jwk.d, 'base64url');
	if (rawKey.length !== 32) {
		throw new SigningKeyError('Invalid verification key. The key has the wrong length.');
	}

	return new Uint8Array(rawKey);
}

/**
 * Check if content looks like a PEM-encoded EC private key (rotation key).
 */
export function isECPrivateKeyPEM(content: string): boolean {
	return content.startsWith(EC_PRIVATE_KEY_HEADER);
}

/**
 * Check if content looks like a PEM-encoded PKCS#8 private key (verification key).
 */
export function isPKCS8PrivateKeyPEM(content: string): boolean {
	return content.startsWith(PKCS8_PRIVATE_KEY_HEADER);
}

/**
 * Check if content looks like a 32-byte hex-encoded private key.
 */
export function isHexPrivateKey(content: string): boolean {
	return /^[a-f0-9]{64}$/i.test(content);
}

/**
 * Check if content looks like a multibase-encoded rotation key (secp256k1).
 */
export function isMultibaseRotationKey(content: string): boolean {
	if (!content.startsWith('z')) {
		return false;
	}
	try {
		const decoded = base58btc.decode(content);
		if (decoded.length < 2) {
			return false;
		}
		const prefixHex = Buffer.from(decoded.slice(0, 2)).toString('hex');
		return prefixHex === SECP256K1_PRIV_PREFIX_HEX;
	} catch {
		return false;
	}
}

/**
 * Check if content looks like a multibase-encoded verification key (Ed25519).
 */
export function isMultibaseVerificationKey(content: string): boolean {
	if (!content.startsWith('z')) {
		return false;
	}
	try {
		const decoded = base58btc.decode(content);
		if (decoded.length < 2) {
			return false;
		}
		const prefixHex = Buffer.from(decoded.slice(0, 2)).toString('hex');
		return prefixHex === ED25519_PRIV_PREFIX_HEX;
	} catch {
		return false;
	}
}

/**
 * Parse content as a rotation private key (PEM, multibase, or hex).
 *
 * @param {string} content - The file content to parse
 * @returns {string} - The hex key
 * @throws {SigningKeyError} If the format is invalid or unrecognized
 */
function parseAsRotationKey(content: string): string {
	const trimmed = content.trim();

	// Try PEM format first (EC PRIVATE KEY for secp256k1)
	if (isECPrivateKeyPEM(trimmed)) {
		const rawKey = decodeECPrivateKeyPEM(trimmed);
		return Buffer.from(rawKey).toString('hex');
	}

	// Check if it's a PKCS#8 PEM (wrong type for rotation key)
	if (isPKCS8PrivateKeyPEM(trimmed)) {
		throw new SigningKeyError(
			'Wrong key type for this operation. This looks like a verification key, but a rotation key is required.',
		);
	}

	// Try multibase format
	if (trimmed.startsWith('z')) {
		const rawKey = decodeMultibaseRotationKey(trimmed);
		return Buffer.from(rawKey).toString('hex');
	}

	// Try raw hex format
	if (isHexPrivateKey(trimmed)) {
		return trimmed.toLowerCase();
	}

	throw new SigningKeyError('Unrecognized key format. Expected a PEM, multibase, or hex encoded rotation key.');
}

/**
 * Parse content as a verification private key (PEM, multibase, or hex).
 *
 * @param {string} content - The file content to parse
 * @returns {string} - The hex key
 * @throws {SigningKeyError} If the format is invalid or unrecognized
 */
function parseAsVerificationKey(content: string): string {
	const trimmed = content.trim();

	// Try PEM format first (PKCS#8 for Ed25519)
	if (isPKCS8PrivateKeyPEM(trimmed)) {
		const rawKey = decodePKCS8PrivateKeyPEM(trimmed);
		return Buffer.from(rawKey).toString('hex');
	}

	// Check if it's an EC PEM (wrong type for verification key)
	if (isECPrivateKeyPEM(trimmed)) {
		throw new SigningKeyError(
			'Wrong key type for this operation. This looks like a rotation key, but a verification key is required.',
		);
	}

	// Try multibase format
	if (trimmed.startsWith('z')) {
		const rawKey = decodeMultibaseVerificationKey(trimmed);
		return Buffer.from(rawKey).toString('hex');
	}

	// Try raw hex format
	if (isHexPrivateKey(trimmed)) {
		return trimmed.toLowerCase();
	}

	throw new SigningKeyError('Unrecognized key format. Expected a PEM, multibase, or hex encoded verification key.');
}

interface LoadRotationKeyOptions {
	signingFile?: string;
	signingKey?: string;
	envVar?: string;
}

/**
 * Load a rotation key from a key file or environment variable.
 *
 * The key file can contain one of:
 * - A single PEM-encoded EC private key (-----BEGIN EC PRIVATE KEY-----)
 * - A single multibase base58btc encoded private key (starts with 'z3vL')
 * - A single 64-character hex string (32-byte private key)
 * - A JSON-encoded string containing a `rotationKeys` object mapping public keys to private keys
 *
 * @param {{
 *   signingFile?: string,
 *   signingKey?: string, // ignored for standalone key files
 *   envVar?: string // defaults to 'FAIR_ROTATION_KEY'
 * }} opts
 * @throws {SigningKeyError} If key cannot be loaded
 */
export async function loadRotationKey({
	signingFile,
	signingKey,
	envVar = 'FAIR_ROTATION_KEY',
}: LoadRotationKeyOptions): Promise<LoadKeyResult> {
	if (signingKey && !signingFile) {
		throw new SigningKeyError('Cannot specify a signing key without a signing file');
	}

	if (signingFile) {
		let keyContent: string;
		try {
			keyContent = await readFile(signingFile, 'utf-8');
		} catch (err) {
			throw new SigningKeyError(`Error reading key file: ${(err as Error).message}`);
		}

		// Try PEM, multibase, or hex format first (standalone key file)
		const trimmed = keyContent.trim();
		if (trimmed.startsWith('-----BEGIN') || trimmed.startsWith('z') || isHexPrivateKey(trimmed)) {
			const standaloneKey = parseAsRotationKey(keyContent);
			if (signingKey) {
				throw new SigningKeyError('Cannot specify a signing key when using a standalone key file');
			}
			return { privateKeyHex: standaloneKey, keyData: null };
		}

		// Try JSON
		let keyData: KeyData;
		try {
			keyData = JSON.parse(keyContent) as KeyData;
		} catch {
			throw new SigningKeyError('Key file must be valid JSON or a standalone key (PEM, multibase, or hex)');
		}

		const rotationKeys = keyData.rotationKeys || {};
		const publicKeys = Object.keys(rotationKeys);

		if (publicKeys.length === 0) {
			throw new SigningKeyError('Key file must contain at least one rotation key');
		}

		let privateKeyHex: string;
		if (signingKey) {
			const rawValue = rotationKeys[signingKey];
			if (!rawValue) {
				throw new SigningKeyError(
					`Rotation key ${signingKey} not found in key file. Available keys: ${publicKeys.join(', ')}`,
				);
			}
			privateKeyHex = parseAsRotationKey(rawValue);
		} else {
			privateKeyHex = parseAsRotationKey(rotationKeys[publicKeys[0]]);
		}

		return { privateKeyHex, keyData };
	}

	const privateKeyHex = process.env[envVar];
	if (!privateKeyHex) {
		throw new SigningKeyError(
			`No signing key provided. Set the ${envVar} environment variable or provide a signing file.`,
		);
	}

	return { privateKeyHex, keyData: null };
}

interface LoadVerificationKeyOptions {
	signingFile?: string;
	signingKey?: string;
	envVar?: string;
}

/**
 * Load a verification key from a key file or environment variable.
 *
 * The key file can contain one of:
 * - A single PEM-encoded PKCS#8 private key (-----BEGIN PRIVATE KEY-----)
 * - A single multibase base58btc encoded private key in Sodium 64-byte format (starts with 'zru' or 'zrv')
 * - A single 64-character hex string (32-byte private key)
 * - A JSON-encoded string containing a `verificationKeys` object mapping public keys to private keys
 *
 * @param {{
 *   signingFile?: string,
 *   signingKey?: string, // ignored for standalone key files
 *   envVar?: string // defaults to 'FAIR_VERIFICATION_KEY'
 * }} opts
 * @throws {SigningKeyError} If key cannot be loaded
 */
export async function loadVerificationKey({
	signingFile,
	signingKey,
	envVar = 'FAIR_VERIFICATION_KEY',
}: LoadVerificationKeyOptions): Promise<LoadKeyResult> {
	if (signingKey && !signingFile) {
		throw new SigningKeyError('Cannot specify a signing key without a signing file');
	}

	if (signingFile) {
		let keyContent: string;
		try {
			keyContent = await readFile(signingFile, 'utf-8');
		} catch (err) {
			throw new SigningKeyError(`Error reading key file: ${(err as Error).message}`);
		}

		// Try PEM, multibase, or hex format first (standalone key file)
		const trimmed = keyContent.trim();
		if (trimmed.startsWith('-----BEGIN') || trimmed.startsWith('z') || isHexPrivateKey(trimmed)) {
			const standaloneKey = parseAsVerificationKey(keyContent);
			if (signingKey) {
				throw new SigningKeyError('Cannot specify a signing key when using a standalone key file');
			}
			return { privateKeyHex: standaloneKey, keyData: null };
		}

		// Try JSON
		let keyData: KeyData;
		try {
			keyData = JSON.parse(keyContent) as KeyData;
		} catch {
			throw new SigningKeyError('Key file must be valid JSON or a standalone key (PEM, multibase, or hex)');
		}

		const verificationKeys = keyData.verificationKeys || {};
		const publicKeys = Object.keys(verificationKeys);

		if (publicKeys.length === 0) {
			throw new SigningKeyError('Key file must contain at least one verification key');
		}

		let privateKeyHex: string;
		if (signingKey) {
			const rawValue = verificationKeys[signingKey];
			if (!rawValue) {
				throw new SigningKeyError(
					`Verification key ${signingKey} not found in key file. Available keys: ${publicKeys.join(', ')}`,
				);
			}
			privateKeyHex = parseAsVerificationKey(rawValue);
		} else {
			privateKeyHex = parseAsVerificationKey(verificationKeys[publicKeys[0]]);
		}

		return { privateKeyHex, keyData };
	}

	const privateKeyHex = process.env[envVar];
	if (!privateKeyHex) {
		throw new SigningKeyError(
			`No signing key provided. Set the ${envVar} environment variable or provide a signing file.`,
		);
	}

	return { privateKeyHex, keyData: null };
}

interface LoadRotationKeyForRevocationOptions {
	signingFile?: string;
	signingKey?: string;
	revokeKey: string;
	envVar?: string;
}

/**
 * Load a rotation key for revoking another rotation key.
 * Auto-selects a key that isn't the one being revoked (for JSON files only).
 *
 * The key file can contain one of:
 * - A single PEM-encoded EC private key (-----BEGIN EC PRIVATE KEY-----)
 * - A single multibase base58btc encoded private key (starts with 'z3vL')
 * - A single 64-character hex string (32-byte private key)
 * - A JSON-encoded string containing a `rotationKeys` object mapping public keys to private keys
 *
 * @param {{
 *   signingFile?: string,
 *   signingKey?: string, // ignored for standalone key files
 *   revokeKey: string, // the key being revoked (to avoid using it for signing)
 *   envVar?: string // defaults to 'FAIR_ROTATION_KEY'
 * }} opts
 * @throws {SigningKeyError} If key cannot be loaded
 */
export async function loadRotationKeyForRevocation({
	signingFile,
	signingKey,
	revokeKey,
	envVar = 'FAIR_ROTATION_KEY',
}: LoadRotationKeyForRevocationOptions): Promise<LoadKeyResult> {
	if (signingFile) {
		let keyContent: string;
		try {
			keyContent = await readFile(signingFile, 'utf-8');
		} catch (err) {
			throw new SigningKeyError(`Error reading key file: ${(err as Error).message}`);
		}

		// Try PEM, multibase, or hex format first (standalone key file)
		const trimmed = keyContent.trim();
		if (trimmed.startsWith('-----BEGIN') || trimmed.startsWith('z') || isHexPrivateKey(trimmed)) {
			const standaloneKey = parseAsRotationKey(keyContent);
			if (signingKey) {
				throw new SigningKeyError('Cannot specify a signing key when using a standalone key file');
			}
			return { privateKeyHex: standaloneKey, keyData: null };
		}

		// Try JSON
		let keyData: KeyData;
		try {
			keyData = JSON.parse(keyContent) as KeyData;
		} catch {
			throw new SigningKeyError('Key file must be valid JSON or a standalone key (PEM, multibase, or hex)');
		}

		const rotationKeys = keyData.rotationKeys || {};
		const publicKeys = Object.keys(rotationKeys);

		if (publicKeys.length === 0) {
			throw new SigningKeyError('Key file must contain at least one rotation key');
		}

		let signerPublicKey: string | undefined;
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
				throw new SigningKeyError(
					`No signing key available. The only rotation key in the file is the one being revoked. Use ${envVar} environment variable to provide a different signing key.`,
				);
			}
		}

		const privateKeyHex = parseAsRotationKey(rotationKeys[signerPublicKey]);
		return { privateKeyHex, keyData };
	}

	// @TODO convert this to a guard condition near the start of the function
	const privateKeyHex = process.env[envVar];
	if (!privateKeyHex) {
		throw new SigningKeyError(
			`No signing key provided. Set the ${envVar} environment variable or provide a signing file.`,
		);
	}

	return { privateKeyHex, keyData: null };
}
