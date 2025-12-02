import {
	Secp256k1Keypair,
	verifySignature,
} from '@atproto/crypto';

/**
 * did:key prefix for secp256k1 compressed public keys.
 *
 * All secp256k1 public keys in did:key format start with this prefix,
 * which encodes the multibase (z = Base58BTC) and multicodec (0xe701 = secp256k1-pub).
 *
 * @type {string}
 */
export const SECP256K1_DID_PREFIX = 'did:key:zQ3sh';

/**
 * Generates a verification key pair.
 *
 * Used for signing and verifying messages in the FAIR protocol.
 *
 * @returns {Promise<{ publicKey: string, privateKey: Uint8Array, keypair: Secp256k1Keypair }>}
 */
export async function generateVerificationKeyPair() {
	const keypair = await Secp256k1Keypair.create({ exportable: true });
	const privateKey = await keypair.export();
	const publicKey = keypair.did();

	return {
		publicKey,
		privateKey,
		keypair,
	};
}

/**
 * Generates a rotation key pair.
 *
 * Used for key rotation operations in the FAIR protocol.
 *
 * @returns {Promise<{ publicKey: string, privateKey: Uint8Array, keypair: Secp256k1Keypair }>}
 */
export async function generateRotationKeyPair() {
	return generateVerificationKeyPair();
}

/**
 * Imports a verification key pair from a private key.
 *
 * @param {Uint8Array|string} privateKey - The private key (raw bytes or hex string)
 * @returns {Promise<{ publicKey: string, privateKey: Uint8Array, keypair: Secp256k1Keypair }>}
 */
export async function importVerificationKeyPair(privateKey) {
	const keypair = await Secp256k1Keypair.import(privateKey, { exportable: true });
	const exportedKey = await keypair.export();
	const publicKey = keypair.did();

	return {
		publicKey,
		privateKey: exportedKey,
		keypair,
	};
}

/**
 * Imports a rotation key pair from a private key.
 *
 * @param {Uint8Array|string} privateKey - The private key (raw bytes or hex string)
 * @returns {Promise<{ publicKey: string, privateKey: Uint8Array, keypair: Secp256k1Keypair }>}
 */
export async function importRotationKeyPair(privateKey) {
	return importVerificationKeyPair(privateKey);
}

/**
 * Signs a message.
 *
 * Returns a 64-byte signature in IEEE-P1363 compact format (r || s),
 * with low-S normalization as required by the FAIR protocol.
 *
 * @param {Uint8Array|string} message - The message to sign
 * @param {Secp256k1Keypair} keypair - The keypair to sign with
 * @returns {Promise<Uint8Array>} The signature
 */
async function sign(message, keypair) {
	const messageBytes = typeof message === 'string'
		? new TextEncoder().encode(message)
		: message;

	return keypair.sign(messageBytes);
}

/**
 * Verifies a signature.
 *
 * Expects a 64-byte signature in IEEE-P1363 compact format (r || s).
 *
 * @param {Uint8Array|string} message - The original message
 * @param {Uint8Array} signature - The signature to verify
 * @param {string} publicKey - The did:key formatted public key
 * @returns {Promise<boolean>} Whether the signature is valid
 */
async function verify(message, signature, publicKey) {
	const messageBytes = typeof message === 'string'
		? new TextEncoder().encode(message)
		: message;

	return verifySignature(publicKey, messageBytes, signature);
}

/**
 * Signs a message using a verification key.
 *
 * Returns a 64-byte signature in IEEE-P1363 compact format (r || s),
 * with low-S normalization as required by the FAIR protocol.
 *
 * @param {Uint8Array|string} message - The message to sign
 * @param {Secp256k1Keypair} keypair - The keypair to sign with
 * @returns {Promise<Uint8Array>} The signature
 */
export async function signWithVerificationKey(message, keypair) {
	return sign(message, keypair);
}

/**
 * Signs a message using a rotation key.
 *
 * Returns a 64-byte signature in IEEE-P1363 compact format (r || s),
 * with low-S normalization as required by the FAIR protocol.
 *
 * @param {Uint8Array|string} message - The message to sign
 * @param {Secp256k1Keypair} keypair - The keypair to sign with
 * @returns {Promise<Uint8Array>} The signature
 */
export async function signWithRotationKey(message, keypair) {
	return sign(message, keypair);
}

/**
 * Verifies a signature using a verification key.
 *
 * Expects a 64-byte signature in IEEE-P1363 compact format (r || s).
 *
 * @param {Uint8Array|string} message - The original message
 * @param {Uint8Array} signature - The signature to verify
 * @param {string} publicKey - The did:key formatted public key
 * @returns {Promise<boolean>} Whether the signature is valid
 */
export async function verifyWithVerificationKey(message, signature, publicKey) {
	return verify(message, signature, publicKey);
}

/**
 * Verifies a signature using a rotation key.
 *
 * Expects a 64-byte signature in IEEE-P1363 compact format (r || s).
 *
 * @param {Uint8Array|string} message - The original message
 * @param {Uint8Array} signature - The signature to verify
 * @param {string} publicKey - The did:key formatted public key
 * @returns {Promise<boolean>} Whether the signature is valid
 */
export async function verifyWithRotationKey(message, signature, publicKey) {
	return verify(message, signature, publicKey);
}
