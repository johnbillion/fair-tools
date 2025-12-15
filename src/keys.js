import { Secp256k1Keypair, verifySignature } from '@atproto/crypto';
import { ed25519 } from '@noble/curves/ed25519';
import { Ed25519Keypair } from './Ed25519Keypair.js';

/**
 * Generates a verification key pair.
 *
 * Used for signing and verifying messages in the FAIR protocol.
 *
 * @returns {Promise<{
 *   publicKey: string,
 *   privateKey: Uint8Array,
 *   keypair: Ed25519Keypair
 * }>}
 */
export async function generateVerificationKeyPair() {
	const keypair = await Ed25519Keypair.create({ exportable: true });
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
 * @returns {Promise<{
 *   publicKey: string,
 *   privateKey: Uint8Array,
 *   keypair: Secp256k1Keypair
 * }>}
 */
export async function generateRotationKeyPair() {
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
 * Imports a verification key pair from a private key.
 *
 * @param {Uint8Array|string} privateKey - The private key (raw bytes or hex string)
 * @returns {Promise<{
 *   publicKey: string,
 *   privateKey: Uint8Array,
 *   keypair: Ed25519Keypair
 * }>}
 */
export async function importVerificationKeyPair(privateKey) {
	const keypair = await Ed25519Keypair.import(privateKey, { exportable: true });
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
 * @returns {Promise<{
 *   publicKey: string,
 *   privateKey: Uint8Array,
 *   keypair: Secp256k1Keypair
 * }>}
 */
export async function importRotationKeyPair(privateKey) {
	const keypair = await Secp256k1Keypair.import(privateKey, {
		exportable: true,
	});
	const exportedKey = await keypair.export();
	const publicKey = keypair.did();

	return {
		publicKey,
		privateKey: exportedKey,
		keypair,
	};
}

/**
 * Signs a message using a verification key.
 *
 * @param {Uint8Array|string} message - The message to sign
 * @param {Ed25519Keypair} keypair - The keypair to sign with
 * @returns {Promise<Uint8Array>} 64-byte signature
 */
export async function signWithVerificationKey(message, keypair) {
	const messageBytes =
		typeof message === 'string' ? new TextEncoder().encode(message) : message;

	return keypair.sign(messageBytes);
}

/**
 * Signs a message using a rotation key.
 *
 * @param {Uint8Array|string} message - The message to sign
 * @param {Secp256k1Keypair} keypair - The keypair to sign with
 * @returns {Promise<Uint8Array>} The signature
 */
export async function signWithRotationKey(message, keypair) {
	const messageBytes =
		typeof message === 'string' ? new TextEncoder().encode(message) : message;

	return keypair.sign(messageBytes);
}

/**
 * Verifies a signature using a verification key.
 *
 * @param {Uint8Array|string} message - The original message
 * @param {Uint8Array} signature - The signature to verify
 * @param {Ed25519Keypair} keypair - The keypair to verify with
 * @returns {Promise<boolean>} Whether the signature is valid
 */
export async function verifyWithVerificationKey(message, signature, keypair) {
	const messageBytes =
		typeof message === 'string' ? new TextEncoder().encode(message) : message;

	return ed25519.verify(signature, messageBytes, keypair.publicKeyBytes());
}

/**
 * Verifies a signature using a rotation key.
 *
 * @param {Uint8Array|string} message - The original message
 * @param {Uint8Array} signature - The signature to verify
 * @param {string} publicKey - The did:key formatted public key
 * @returns {Promise<boolean>} Whether the signature is valid
 */
export async function verifyWithRotationKey(message, signature, publicKey) {
	const messageBytes =
		typeof message === 'string' ? new TextEncoder().encode(message) : message;

	return verifySignature(publicKey, messageBytes, signature);
}
