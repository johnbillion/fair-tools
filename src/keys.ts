import { Keypair, Secp256k1Keypair, verifySignature } from '@atproto/crypto';
import { ed25519 } from '@noble/curves/ed25519';
import { Ed25519Keypair } from './Ed25519Keypair.js';

export interface KeyPairBundle<T extends Keypair = Keypair> {
	publicKey: string;
	privateKey: Uint8Array;
	keypair: T;
}

export type VerificationKeyPair = KeyPairBundle<Ed25519Keypair>;
export type RotationKeyPair = KeyPairBundle<Secp256k1Keypair>;

/**
 * Generates a verification key pair.
 *
 * Used for signing and verifying messages in the FAIR protocol.
 */
export async function generateVerificationKeyPair(): Promise<VerificationKeyPair> {
	const keypair = await Ed25519Keypair.create({ exportable: true });
	const privateKey = (await keypair.export())!;
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
 */
export async function generateRotationKeyPair(): Promise<RotationKeyPair> {
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
 */
export async function importVerificationKeyPair(privateKey: Uint8Array | string): Promise<VerificationKeyPair> {
	const keypair = await Ed25519Keypair.import(privateKey, { exportable: true });
	const exportedKey = (await keypair.export())!;
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
 */
export async function importRotationKeyPair(privateKey: Uint8Array | string): Promise<RotationKeyPair> {
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
 * Verifies a signature using a verification key.
 *
 * @param {Uint8Array} message - The original message
 * @param {Uint8Array} signature - The signature to verify
 * @param {Ed25519Keypair} keypair - The keypair to verify with
 * @returns {Promise<boolean>} Whether the signature is valid
 */
export async function verifyWithVerificationKey(
	message: Uint8Array,
	signature: Uint8Array,
	keypair: Ed25519Keypair,
): Promise<boolean> {
	return ed25519.verify(signature, message, keypair.publicKeyBytes());
}

/**
 * Verifies a signature using a rotation key.
 *
 * @param {Uint8Array} message - The original message
 * @param {Uint8Array} signature - The signature to verify
 * @param {string} publicKey - The did:key formatted public key
 * @returns {Promise<boolean>} Whether the signature is valid
 */
export async function verifyWithRotationKey(
	message: Uint8Array,
	signature: Uint8Array,
	publicKey: string,
): Promise<boolean> {
	return verifySignature(publicKey, message, signature);
}
