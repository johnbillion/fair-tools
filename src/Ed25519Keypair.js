import { bytesToMultibase } from '@atproto/crypto';
import { ed25519 } from '@noble/curves/ed25519';
import * as uint8arrays from 'uint8arrays';

/**
 * Multicodec prefix for Ed25519 public keys.
 *
 * @type {Uint8Array}
 */
export const ED25519_PUBLIC_PREFIX = new Uint8Array([0xed, 0x01]);

/**
 * Multicodec prefix for Ed25519 private keys.
 *
 * @type {Uint8Array}
 */
export const ED25519_PRIVATE_PREFIX = new Uint8Array([0x80, 0x26]);

/**
 * Ed25519 verification keypair.
 *
 * Provides the same interface as Secp256k1Keypair for Ed25519 keys used for artifact signing.
 */
export class Ed25519Keypair {
	#privateKey;
	#publicKey;

	/**
	 * @param {Uint8Array} privateKey - 32-byte private key
	 * @param {Uint8Array} publicKey - 32-byte public key
	 */
	constructor(privateKey, publicKey) {
		this.#privateKey = privateKey;
		this.#publicKey = publicKey;
	}

	/**
	 * Create a new Ed25519 keypair.
	 *
	 * @param {object} [_options] - Options (ignored, for API compatibility with Secp256k1Keypair)
	 * @returns {Promise<Ed25519Keypair>}
	 */
	static async create(_options) {
		const privateKey = ed25519.utils.randomSecretKey();
		const publicKey = ed25519.getPublicKey(privateKey);
		return new Ed25519Keypair(privateKey, publicKey);
	}

	/**
	 * Import an Ed25519 keypair from a private key.
	 *
	 * @param {Uint8Array|string} privateKey - 32-byte private key or hex string
	 * @param {object} [_options] - Options (ignored, for API compatibility with Secp256k1Keypair)
	 * @returns {Promise<Ed25519Keypair>}
	 */
	static async import(privateKey, _options) {
		const privBytes = typeof privateKey === 'string' ? uint8arrays.fromString(privateKey, 'hex') : privateKey;
		const publicKey = ed25519.getPublicKey(privBytes);
		return new Ed25519Keypair(privBytes, publicKey);
	}

	/**
	 * Get the public key as raw bytes.
	 *
	 * @returns {Uint8Array} 32-byte public key
	 */
	publicKeyBytes() {
		return this.#publicKey;
	}

	/**
	 * Get the public key as a multibase string (z6Mk...).
	 *
	 * @returns {string} Base58BTC-encoded public key with Ed25519 multicodec prefix
	 */
	publicKeyStr() {
		const prefixed = new Uint8Array(ED25519_PUBLIC_PREFIX.length + this.#publicKey.length);
		prefixed.set(ED25519_PUBLIC_PREFIX, 0);
		prefixed.set(this.#publicKey, ED25519_PUBLIC_PREFIX.length);
		return bytesToMultibase(prefixed, 'base58btc');
	}

	/**
	 * Get the public key as a did:key string.
	 *
	 * @returns {string} did:key formatted public key (did:key:z6Mk...)
	 */
	did() {
		return `did:key:${this.publicKeyStr()}`;
	}

	/**
	 * Sign a message.
	 *
	 * @param {Uint8Array} message - The message to sign
	 * @returns {Promise<Uint8Array>} 64-byte signature
	 */
	async sign(message) {
		return ed25519.sign(message, this.#privateKey);
	}

	/**
	 * Export the private key as raw bytes.
	 *
	 * @returns {Promise<Uint8Array>} 32-byte private key
	 */
	async export() {
		return this.#privateKey;
	}
}
