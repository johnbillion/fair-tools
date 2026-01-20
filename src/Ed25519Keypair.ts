import { bytesToMultibase, multibaseToBytes, Keypair } from '@atproto/crypto';
import { DID_KEY_PREFIX } from './did-validation.js';
import { ed25519 } from '@noble/curves/ed25519';
import * as uint8arrays from 'uint8arrays';

/**
 * Multicodec prefix for Ed25519 public keys.
 */
export const ED25519_PUBLIC_PREFIX = new Uint8Array([0xed, 0x01]);

/**
 * Length of an Ed25519 public key in bytes.
 */
const ED25519_PUBLIC_KEY_SIZE = 32;

/**
 * Ed25519 verification keypair.
 */
export class Ed25519Keypair implements Keypair {
	jwtAlg = 'EdDSA';
	#privateKey: Uint8Array | null;
	#publicKey: Uint8Array;

	constructor(privateKey: Uint8Array | null, publicKey: Uint8Array) {
		this.#privateKey = privateKey;
		this.#publicKey = publicKey;
	}

	/**
	 * Create a new Ed25519 keypair.
	 */
	static async create(_options?: object): Promise<Ed25519Keypair> {
		const privateKey = ed25519.utils.randomSecretKey();
		const publicKey = ed25519.getPublicKey(privateKey);
		return new Ed25519Keypair(privateKey, publicKey);
	}

	/**
	 * Import an Ed25519 keypair from a private key.
	 */
	static async import(privateKey: Uint8Array | string, _options?: object): Promise<Ed25519Keypair> {
		const privBytes = typeof privateKey === 'string' ? uint8arrays.fromString(privateKey, 'hex') : privateKey;
		const publicKey = ed25519.getPublicKey(privBytes);
		return new Ed25519Keypair(privBytes, publicKey);
	}

	/**
	 * Create a verification-only keypair from a public key.
	 */
	static async fromPublicKey(publicKey: Uint8Array): Promise<Ed25519Keypair> {
		return new Ed25519Keypair(null, publicKey);
	}

	/**
	 * Create a verification-only keypair from a multibase-encoded public key.
	 */
	static async fromPublicKeyMultibase(publicKeyMultibase: string): Promise<Ed25519Keypair> {
		const decoded = multibaseToBytes(publicKeyMultibase);
		const expectedLength = ED25519_PUBLIC_PREFIX.length + ED25519_PUBLIC_KEY_SIZE;

		// Validate minimum length before accessing array indices
		if (decoded.length < ED25519_PUBLIC_PREFIX.length) {
			throw new Error(
				`Invalid key length: expected ${expectedLength} bytes for Ed25519 public key, got ${decoded.length} bytes`,
			);
		}

		// Check for Ed25519 multicodec prefix
		if (decoded[0] !== ED25519_PUBLIC_PREFIX[0] || decoded[1] !== ED25519_PUBLIC_PREFIX[1]) {
			throw new Error(
				`Unsupported key type: expected Ed25519 multicodec prefix (0xed01), ` +
					`got 0x${decoded[0].toString(16).padStart(2, '0')}${decoded[1].toString(16).padStart(2, '0')}`,
			);
		}

		// Validate total length (2-byte prefix + 32-byte public key = 34 bytes)
		if (decoded.length !== expectedLength) {
			throw new Error(
				`Invalid key length: expected ${expectedLength} bytes (2-byte prefix + 32-byte key), ` +
					`got ${decoded.length} bytes`,
			);
		}

		const publicKeyBytes = decoded.slice(ED25519_PUBLIC_PREFIX.length);
		return new Ed25519Keypair(null, publicKeyBytes);
	}

	/**
	 * Get the public key as raw bytes.
	 */
	publicKeyBytes(): Uint8Array {
		return this.#publicKey;
	}

	/**
	 * Get the public key as a multibase string (z6Mk...).
	 */
	publicKeyStr(): string {
		const prefixed = new Uint8Array(ED25519_PUBLIC_PREFIX.length + this.#publicKey.length);
		prefixed.set(ED25519_PUBLIC_PREFIX, 0);
		prefixed.set(this.#publicKey, ED25519_PUBLIC_PREFIX.length);
		return bytesToMultibase(prefixed, 'base58btc');
	}

	/**
	 * Get the public key as a did:key string.
	 */
	did(): string {
		return `${DID_KEY_PREFIX}${this.publicKeyStr()}`;
	}

	/**
	 * Sign a message.
	 */
	async sign(message: Uint8Array): Promise<Uint8Array> {
		if (!this.#privateKey) {
			throw new Error('Cannot sign: no private key available');
		}
		return ed25519.sign(message, this.#privateKey);
	}

	/**
	 * Export the private key as raw bytes.
	 */
	async export(): Promise<Uint8Array | null> {
		return this.#privateKey;
	}
}
