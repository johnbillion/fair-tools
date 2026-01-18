import { Keypair, Secp256k1Keypair, verifySignature } from '@atproto/crypto';
import { ed25519 } from '@noble/curves/ed25519';
import {
	Ed25519Keypair,
	ED25519_PUBLIC_MULTIBASE_PREFIX as ED25519_MULTIBASE_PREFIX,
	DID_KEY_PREFIX,
} from './Ed25519Keypair.js';
import {
	SECP256K1_DID_KEY_PREFIX,
	SECP256K1_DID_KEY_LENGTH,
	SECP256K1_PUBLIC_MULTIBASE_PREFIX,
	SECP256K1_PUBLIC_MULTIBASE_LENGTH,
	ED25519_DID_KEY_PREFIX,
	ED25519_PUBLIC_MULTIBASE_PREFIX,
} from './did-validation.js';

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

/**
 * Error thrown when a verification key input is invalid.
 */
export class VerificationKeyInputError extends Error {}

/**
 * Error thrown when a rotation key input is invalid.
 */
export class RotationKeyInputError extends Error {}

/**
 * Parses a public key input and returns the multibase format.
 *
 * Only accepts public keys:
 * - did:key format (did:key:z6Mk...)
 * - Multibase format (z6Mk...)
 *
 * @param keyInput - The public key input string
 * @returns The public key multibase (z6Mk...)
 * @throws {VerificationKeyInputError} If the key format is unrecognized, invalid, or a private key
 */
export async function parsePublicKeyOnly(keyInput: string): Promise<string> {
	const { isMultibaseVerificationKey, isPKCS8PrivateKeyPEM, isHexPrivateKey } = await import('./signing.js');

	const trimmed = keyInput.trim();

	// Check if it looks like a private key and reject with a specific error
	if (isPKCS8PrivateKeyPEM(trimmed) || isMultibaseVerificationKey(trimmed) || isHexPrivateKey(trimmed)) {
		throw new VerificationKeyInputError(
			'Private key provided but only public keys are accepted. Use --key-file to provide a private key from a file.',
		);
	}

	// Delegate to getVerificationPublicKeyMultibase for public key parsing
	return getVerificationPublicKeyMultibase(trimmed);
}

/**
 * Extracts the public key multibase from a verification key input.
 *
 * Accepts:
 * - Public key in did:key format (did:key:z6Mk...)
 * - Public key multibase (z6Mk...)
 * - Private key in PEM, multibase, or hex format (derives the public key)
 *
 * @param keyInput - The key input string
 * @returns The public key multibase (z6Mk...)
 * @throws {VerificationKeyInputError} If the key format is unrecognized or invalid
 */
export async function getVerificationPublicKeyMultibase(keyInput: string): Promise<string> {
	const { isMultibaseVerificationKey, isPKCS8PrivateKeyPEM, isHexPrivateKey, parseAsVerificationKey } =
		await import('./signing.js');

	const trimmed = keyInput.trim();

	if (trimmed.startsWith(DID_KEY_PREFIX)) {
		const multibase = trimmed.slice(DID_KEY_PREFIX.length);
		try {
			await Ed25519Keypair.fromPublicKeyMultibase(multibase);
		} catch (err) {
			throw new VerificationKeyInputError(`Invalid did:key format: ${(err as Error).message}`);
		}
		return multibase;
	}

	if (trimmed.startsWith(ED25519_MULTIBASE_PREFIX)) {
		try {
			await Ed25519Keypair.fromPublicKeyMultibase(trimmed);
		} catch (err) {
			throw new VerificationKeyInputError(`Invalid public key multibase: ${(err as Error).message}`);
		}
		return trimmed;
	}

	if (isPKCS8PrivateKeyPEM(trimmed) || isMultibaseVerificationKey(trimmed) || isHexPrivateKey(trimmed)) {
		try {
			const privateKeyHex = parseAsVerificationKey(trimmed);
			const { keypair } = await importVerificationKeyPair(privateKeyHex);
			return keypair.publicKeyStr();
		} catch (err) {
			throw new VerificationKeyInputError(`Invalid private key: ${(err as Error).message}`);
		}
	}

	throw new VerificationKeyInputError(
		'Unrecognized key format. Expected a public key (did:key:z6Mk...) or private key (PEM, multibase, or hex)',
	);
}

/**
 * Extracts the public key did:key from a rotation key input.
 *
 * Accepts:
 * - Public key in did:key format (did:key:zQ3sh...)
 * - Public key multibase (zQ3sh...)
 * - Private key in PEM, multibase, or hex format (derives the public key)
 *
 * @param keyInput - The key input string
 * @returns The public key in did:key format (did:key:zQ3sh...)
 * @throws {RotationKeyInputError} If the key format is unrecognized or invalid
 */
export async function getRotationPublicKeyDidKey(keyInput: string): Promise<string> {
	const { isMultibaseRotationKey, isECPrivateKeyPEM, isHexPrivateKey, parseAsRotationKey } =
		await import('./signing.js');

	const trimmed = keyInput.trim();

	// Check if it's already in did:key format
	if (trimmed.startsWith(DID_KEY_PREFIX)) {
		// Validate it's a rotation key, not a verification key
		if (trimmed.startsWith(ED25519_DID_KEY_PREFIX)) {
			throw new RotationKeyInputError(
				'Wrong key type. This looks like a verification key, but a rotation key is required.',
			);
		}
		if (!trimmed.startsWith(SECP256K1_DID_KEY_PREFIX)) {
			throw new RotationKeyInputError(
				`Invalid rotation key format. Key must start with '${SECP256K1_DID_KEY_PREFIX}'.`,
			);
		}
		// Validate length
		if (trimmed.length !== SECP256K1_DID_KEY_LENGTH) {
			throw new RotationKeyInputError('Invalid rotation key length.');
		}
		return trimmed;
	}

	// Check if it's a multibase public key
	if (trimmed.startsWith(SECP256K1_PUBLIC_MULTIBASE_PREFIX)) {
		// Validate length
		if (trimmed.length !== SECP256K1_PUBLIC_MULTIBASE_LENGTH) {
			throw new RotationKeyInputError('Invalid rotation key multibase length.');
		}
		return DID_KEY_PREFIX + trimmed;
	}

	// Check if it's a verification key multibase (wrong type)
	if (trimmed.startsWith(ED25519_PUBLIC_MULTIBASE_PREFIX)) {
		throw new RotationKeyInputError(
			'Wrong key type. This looks like a verification key, but a rotation key is required.',
		);
	}

	// Try to parse as private key and derive public key
	if (isECPrivateKeyPEM(trimmed) || isMultibaseRotationKey(trimmed) || isHexPrivateKey(trimmed)) {
		try {
			const privateKeyHex = parseAsRotationKey(trimmed);
			const { keypair } = await importRotationKeyPair(privateKeyHex);
			return keypair.did();
		} catch (err) {
			throw new RotationKeyInputError(`Invalid private key: ${(err as Error).message}`);
		}
	}

	throw new RotationKeyInputError(
		'Unrecognized key format. Expected a public key (did:key:zQ3sh...) or private key (PEM, multibase, or hex)',
	);
}
