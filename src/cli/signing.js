import { readFile } from 'node:fs/promises';

export class SigningKeyError extends Error {
	constructor(message) {
		super(message);
		this.name = 'SigningKeyError';
	}
}

/**
 * Load a rotation key from a key file or environment variable.
 *
 * @param {object} opts
 * @param {string} [opts.signingFile] - Path to key file
 * @param {string} [opts.signingKey] - Specific key to use from file
 * @param {string} [opts.envVar='FAIR_ROTATION_KEY'] - Environment variable name
 * @returns {Promise<{privateKeyHex: string, keyData: object|null}>}
 * @throws {SigningKeyError} If key cannot be loaded
 */
export async function loadRotationKey({ signingFile, signingKey, envVar = 'FAIR_ROTATION_KEY' }) {
	if (signingKey && !signingFile) {
		throw new SigningKeyError('--signing-key can only be used with --signing-file');
	}

	if (signingFile) {
		let keyData;
		try {
			const keyContent = await readFile(signingFile, 'utf-8');
			keyData = JSON.parse(keyContent);
		} catch (err) {
			throw new SigningKeyError(`Error reading key file: ${err.message}`);
		}

		const rotationKeys = keyData.rotationKeys || {};
		const publicKeys = Object.keys(rotationKeys);

		if (publicKeys.length === 0) {
			throw new SigningKeyError('Key file must contain at least one rotation key');
		}

		let privateKeyHex;
		if (signingKey) {
			privateKeyHex = rotationKeys[signingKey];
			if (!privateKeyHex) {
				throw new SigningKeyError(`Rotation key ${signingKey} not found in key file. Available keys: ${publicKeys.join(', ')}`);
			}
		} else {
			privateKeyHex = rotationKeys[publicKeys[0]];
		}

		return { privateKeyHex, keyData };
	}

	const privateKeyHex = process.env[envVar];
	if (!privateKeyHex) {
		throw new SigningKeyError(`Either --signing-file or ${envVar} environment variable is required`);
	}

	return { privateKeyHex, keyData: null };
}

/**
 * Load a verification key from a key file or environment variable.
 *
 * @param {object} opts
 * @param {string} [opts.signingFile] - Path to key file
 * @param {string} [opts.signingKey] - Specific key to use from file
 * @param {string} [opts.envVar='FAIR_PRIVATE_KEY'] - Environment variable name
 * @returns {Promise<{privateKeyHex: string, keyData: object|null}>}
 * @throws {SigningKeyError} If key cannot be loaded
 */
export async function loadVerificationKey({ signingFile, signingKey, envVar = 'FAIR_PRIVATE_KEY' }) {
	if (signingKey && !signingFile) {
		throw new SigningKeyError('--signing-key can only be used with --signing-file');
	}

	if (signingFile) {
		let keyData;
		try {
			const keyContent = await readFile(signingFile, 'utf-8');
			keyData = JSON.parse(keyContent);
		} catch (err) {
			throw new SigningKeyError(`Error reading key file: ${err.message}`);
		}

		const verificationKeys = keyData.verificationKeys || {};
		const publicKeys = Object.keys(verificationKeys);

		if (publicKeys.length === 0) {
			throw new SigningKeyError('Key file must contain at least one verification key');
		}

		let privateKeyHex;
		if (signingKey) {
			privateKeyHex = verificationKeys[signingKey];
			if (!privateKeyHex) {
				throw new SigningKeyError(`Verification key ${signingKey} not found in key file. Available keys: ${publicKeys.join(', ')}`);
			}
		} else {
			privateKeyHex = verificationKeys[publicKeys[0]];
		}

		return { privateKeyHex, keyData };
	}

	const privateKeyHex = process.env[envVar];
	if (!privateKeyHex) {
		throw new SigningKeyError(`Either --signing-file or ${envVar} environment variable is required`);
	}

	return { privateKeyHex, keyData: null };
}

/**
 * Load a rotation key for revoking another rotation key.
 * Auto-selects a key that isn't the one being revoked.
 *
 * @param {object} opts
 * @param {string} [opts.signingFile] - Path to key file
 * @param {string} [opts.signingKey] - Specific key to use from file
 * @param {string} opts.revokeKey - The key being revoked (to avoid using it for signing)
 * @param {string} [opts.envVar='FAIR_ROTATION_KEY'] - Environment variable name
 * @returns {Promise<{privateKeyHex: string, signerPublicKey: string|null, keyData: object|null}>}
 * @throws {SigningKeyError} If key cannot be loaded
 */
export async function loadRotationKeyForRevocation({ signingFile, signingKey, revokeKey, envVar = 'FAIR_ROTATION_KEY' }) {
	if (signingFile) {
		let keyData;
		try {
			const keyContent = await readFile(signingFile, 'utf-8');
			keyData = JSON.parse(keyContent);
		} catch (err) {
			throw new SigningKeyError(`Error reading key file: ${err.message}`);
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

		const privateKeyHex = rotationKeys[signerPublicKey];
		return { privateKeyHex, signerPublicKey, keyData };
	}

	const privateKeyHex = process.env[envVar];
	if (!privateKeyHex) {
		throw new SigningKeyError(`No signing key provided. Use --signing-file <file> or set ${envVar} environment variable.`);
	}

	// For env var, we'll return null for signerPublicKey - caller must derive it
	return { privateKeyHex, signerPublicKey: null, keyData: null };
}
