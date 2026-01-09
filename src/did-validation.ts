/**
 * Error thrown when a DID validation fails.
 */
export class DidValidationError extends Error {}

/**
 * Error thrown when a public key validation fails.
 */
export class PublicKeyValidationError extends Error {}

/**
 * Expected length of a valid did:plc: identifier.
 * Format: did:plc: (8 chars) + 24 character base32 hash = 32 characters total.
 */
const DID_PLC_LENGTH = 32;

/**
 * Prefix for Ed25519 public keys in did:key format (verification keys).
 * Format: did:key:z6Mk...
 */
const ED25519_DID_KEY_PREFIX = 'did:key:z6Mk';

/**
 * Prefix for Secp256k1 public keys in did:key format (rotation keys).
 * Format: did:key:zQ3sh...
 */
const SECP256K1_DID_KEY_PREFIX = 'did:key:zQ3sh';

/**
 * Expected length of a did:key Ed25519 public key.
 * Format: did:key: (8 chars) + multibase 'z' (1 char) + base58btc encoded (multicodec prefix + 32-byte key) = 56 characters total.
 */
const ED25519_DID_KEY_LENGTH = 56;

/**
 * Expected length of a did:key Secp256k1 compressed public key.
 * Format: did:key: (8 chars) + multibase 'z' (1 char) + base58btc encoded (multicodec prefix + 33-byte compressed key) = 57 characters total.
 */
const SECP256K1_DID_KEY_LENGTH = 57;

/**
 * Validates that a DID has the required did:plc: prefix and correct length.
 *
 * @param {string} did - The DID to validate
 * @throws {DidValidationError} If the DID doesn't start with 'did:plc:' or has incorrect length
 */
export function validatePlcDid(did: string): void {
	if (!did.startsWith('did:plc:')) {
		throw new DidValidationError(`Invalid DID format. DID must have the prefix 'did:plc:'.`);
	}
	if (did.length !== DID_PLC_LENGTH) {
		throw new DidValidationError(`Invalid DID format. DID must be ${DID_PLC_LENGTH} characters in length.`);
	}
}

/**
 * Validates that a verification key has the required did:key: format with Ed25519 prefix and correct length.
 *
 * @param {string} key - The verification key to validate (did:key:z6Mk...)
 * @throws {PublicKeyValidationError} If the key format is invalid
 */
export function validateVerificationKey(key: string): void {
	if (!key.startsWith('did:key:')) {
		throw new PublicKeyValidationError(`Invalid verification key format. Key must start with 'did:key:' prefix.`);
	}

	if (key.startsWith(SECP256K1_DID_KEY_PREFIX)) {
		throw new PublicKeyValidationError(
			`Wrong key type. This looks like a rotation key but a verification key is required. Verification keys start with '${ED25519_DID_KEY_PREFIX}'.`,
		);
	}

	if (!key.startsWith(ED25519_DID_KEY_PREFIX)) {
		throw new PublicKeyValidationError(
			`Invalid verification key format. Key must start with '${ED25519_DID_KEY_PREFIX}'.`,
		);
	}

	if (key.length !== ED25519_DID_KEY_LENGTH) {
		throw new PublicKeyValidationError(
			`Invalid verification key format. Key must be ${ED25519_DID_KEY_LENGTH} characters in length.`,
		);
	}
}

/**
 * Validates that a rotation key has the required did:key: format with Secp256k1 prefix and correct length.
 *
 * @param {string} key - The rotation key to validate (did:key:zQ3sh...)
 * @throws {PublicKeyValidationError} If the key format is invalid
 */
export function validateRotationKey(key: string): void {
	if (!key.startsWith('did:key:')) {
		throw new PublicKeyValidationError(`Invalid rotation key format. Key must start with 'did:key:' prefix.`);
	}

	if (key.startsWith(ED25519_DID_KEY_PREFIX)) {
		throw new PublicKeyValidationError(
			`Wrong key type. This looks like a verification key but a rotation key is required. Rotation keys start with '${SECP256K1_DID_KEY_PREFIX}'.`,
		);
	}

	if (!key.startsWith(SECP256K1_DID_KEY_PREFIX)) {
		throw new PublicKeyValidationError(
			`Invalid rotation key format. Key must start with '${SECP256K1_DID_KEY_PREFIX}'.`,
		);
	}

	if (key.length !== SECP256K1_DID_KEY_LENGTH) {
		throw new PublicKeyValidationError(
			`Invalid rotation key format. Key must be ${SECP256K1_DID_KEY_LENGTH} characters in length.`,
		);
	}
}
