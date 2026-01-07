/**
 * FAIR Protocol verification functions.
 *
 * Verifies metadata documents, release signatures, and checksums.
 */

/**
 * @typedef {{
 *   url: string,
 *   keyId: string|null,
 *   signatureValid: boolean,
 *   checksumValid: boolean
 * }} ArtifactVerificationResult
 */

/**
 * @typedef {{
 *   version: string,
 *   artifacts: ArtifactVerificationResult[]
 * }} ReleaseVerificationResult
 */

/**
 * @typedef {{
 *   did: string,
 *   allReleases?: boolean,
 *   plcUrl?: string
 * }} VerificationOptions
 */

import { createHash, timingSafeEqual } from 'node:crypto';
import { Ed25519Keypair } from './Ed25519Keypair.js';
import { METADATA_CONTEXT, verifyArtifact } from './metadata.js';
import { PLC_DIRECTORY_URL } from './did.js';

/**
 * Error thrown when metadata verification fails.
 * @property {ReleaseVerificationResult[]} [result] - Detailed verification result when available
 */
export class MetadataVerificationError extends Error {
	/**
	 * @param {string} message
	 * @param {ReleaseVerificationResult[]} [result]
	 */
	constructor(message, result) {
		super(message);
		this.result = result;
	}
}

/**
 * Error thrown when release verification fails.
 * @property {ReleaseVerificationResult} [result] - Detailed verification result when available
 */
export class ReleaseVerificationError extends Error {
	/**
	 * @param {string} message
	 * @param {ReleaseVerificationResult} [result]
	 */
	constructor(message, result) {
		super(message);
		this.result = result;
	}
}

/**
 * Error thrown when metadata cannot be fetched.
 */
export class MetadataFetchError extends Error {}

/**
 * Error thrown when an artifact cannot be fetched.
 */
export class ArtifactFetchError extends Error {}

/**
 * Error thrown when an artifact signature is invalid or missing.
 */
export class SignatureVerificationError extends Error {}

/**
 * Error thrown when an artifact checksum doesn't match.
 */
export class ChecksumVerificationError extends Error {}

/**
 * Fetches a DID document from the PLC directory.
 *
 * @param {string} did - The DID to fetch
 * @param {string} [plcUrl] - The PLC directory URL
 * @returns {Promise<object>} The DID document
 * @throws {MetadataFetchError} If the document cannot be fetched
 */
export async function fetchDidDocument(did, plcUrl = PLC_DIRECTORY_URL) {
	const url = `${plcUrl}/${did}`;

	let response;
	try {
		response = await fetch(url);
	} catch (err) {
		throw new MetadataFetchError(`Failed to fetch DID document: ${err.message}`);
	}

	if (!response.ok) {
		throw new MetadataFetchError(`Failed to fetch DID document: HTTP ${response.status} ${response.statusText}`);
	}

	try {
		return await response.json();
	} catch (err) {
		throw new MetadataFetchError(`Failed to parse DID document: ${err.message}`);
	}
}

/**
 * Extracts verification keys from a DID document.
 *
 * Looks for verification methods with IDs containing 'fair' (e.g., #fair, #fair2).
 *
 * @param {object} didDocument - The DID document
 * @returns {Array<{id: string, publicKeyMultibase: string}>} The verification keys
 */
export function extractVerificationKeys(didDocument) {
	const verificationMethods = didDocument.verificationMethod || [];
	return verificationMethods.filter((vm) => vm.id && vm.id.includes('#fair'));
}

/**
 * Fetches verification keys for a DID.
 *
 * @param {string} did - The DID to get keys for
 * @param {string} [plcUrl] - The PLC directory URL
 * @returns {Promise<Array<{id: string, publicKeyMultibase: string}>>} The verification keys
 * @throws {MetadataFetchError} If keys cannot be fetched
 * @throws {MetadataVerificationError} If no verification keys are found
 */
export async function getVerificationKeys(did, plcUrl = PLC_DIRECTORY_URL) {
	const document = await fetchDidDocument(did, plcUrl);
	const keys = extractVerificationKeys(document);

	if (keys.length === 0) {
		throw new MetadataVerificationError(`No verification keys found for DID: ${did}`);
	}

	return keys;
}

/**
 * Verifies an artifact signature against verification keys.
 *
 * @param {Buffer|Uint8Array} data - The artifact data
 * @param {string} signature - The base64url-encoded signature
 * @param {Array<{id: string, publicKeyMultibase: string}>} verificationKeys - Keys to verify against
 * @returns {Promise<string>} The key ID that verified the signature
 * @throws {SignatureVerificationError} If signature doesn't match any key
 */
export async function verifyArtifactSignature(data, signature, verificationKeys) {
	const errors = [];

	for (const key of verificationKeys) {
		try {
			const keypair = await Ed25519Keypair.fromPublicKeyMultibase(key.publicKeyMultibase);
			const valid = await verifyArtifact(data, signature, keypair);
			if (valid) {
				return key.id;
			}
		} catch (err) {
			errors.push(`${key.id}: ${err.message}`);
		}
	}

	if (errors.length > 0) {
		throw new SignatureVerificationError(`Signature verification failed: ${errors.join('; ')}`);
	}

	throw new SignatureVerificationError('Signature does not match any verification key');
}

/**
 * Verifies an artifact checksum.
 *
 * @param {Buffer|Uint8Array} data - The artifact data
 * @param {string} checksum - The checksum in format 'algorithm:hash'
 * @throws {ChecksumVerificationError} If checksum doesn't match
 */
export function verifyArtifactChecksum(data, checksum) {
	const [algorithm, expectedHash] = checksum.split(':');

	if (algorithm !== 'sha256') {
		throw new ChecksumVerificationError(`Unsupported checksum algorithm: ${algorithm}`);
	}

	const actualHashBuffer = createHash(algorithm).update(data).digest();
	const expectedHashBuffer = Buffer.from(expectedHash, 'hex');

	let match;
	try {
		match = timingSafeEqual(actualHashBuffer, expectedHashBuffer);
	} catch {
		match = false;
	}

	if (!match) {
		throw new ChecksumVerificationError(
			`Checksum mismatch: expected ${expectedHash}, got ${actualHashBuffer.toString('hex')}`,
		);
	}
}

/**
 * Fetches artifact data from a URL.
 *
 * @param {string} url - The artifact URL
 * @returns {Promise<Buffer>} The artifact data
 * @throws {ArtifactFetchError} If the artifact cannot be fetched
 */
export async function fetchArtifact(url) {
	let response;
	try {
		response = await fetch(url);
	} catch (err) {
		throw new ArtifactFetchError(`Failed to fetch artifact: ${err.message}`);
	}

	if (!response.ok) {
		throw new ArtifactFetchError(`Failed to fetch artifact: HTTP ${response.status}`);
	}

	try {
		const arrayBuffer = await response.arrayBuffer();
		return Buffer.from(arrayBuffer);
	} catch (err) {
		throw new ArtifactFetchError(`Failed to read artifact data: ${err.message}`);
	}
}

/**
 * Verifies all package artifacts in a release.
 *
 * Only 'package' type artifacts require signature verification.
 * Other artifact types (banner, icon, screenshot) are not verified.
 *
 * @param {object} release - The release object from metadata
 * @param {Array<{id: string, publicKeyMultibase: string}>} verificationKeys - Keys to verify against
 * @returns {Promise<ReleaseVerificationResult>}
 * @throws {ReleaseVerificationError} If verification fails (includes result with details)
 */
export async function verifyRelease(release, verificationKeys) {
	const artifacts = [];
	const errors = [];

	// Only verify 'package' artifacts - other types don't require signatures
	const packageArtifacts = release.artifacts?.package || [];

	if (packageArtifacts.length === 0) {
		throw new ReleaseVerificationError('No package artifacts to verify', {
			version: release.version,
			artifacts: [],
		});
	}

	// Verify each package artifact
	for (const artifact of packageArtifacts) {
		// Signature is required
		if (!artifact.signature) {
			errors.push(`Missing signature for ${artifact.url}`);
			artifacts.push({
				url: artifact.url,
				keyId: null,
				signatureValid: false,
				checksumValid: false,
			});
			continue;
		}

		// Checksum is required
		if (!artifact.checksum) {
			errors.push(`Missing checksum for ${artifact.url}`);
			artifacts.push({
				url: artifact.url,
				keyId: null,
				signatureValid: false,
				checksumValid: false,
			});
			continue;
		}

		// Fetch the artifact
		let data;
		try {
			data = await fetchArtifact(artifact.url);
		} catch (err) {
			errors.push(`Failed to fetch ${artifact.url}: ${err.message}`);
			artifacts.push({
				url: artifact.url,
				keyId: null,
				signatureValid: false,
				checksumValid: false,
			});
			continue;
		}

		// Verify signature and checksum
		let signatureValid = false;
		let checksumValid = false;
		let keyId = null;

		try {
			keyId = await verifyArtifactSignature(data, artifact.signature, verificationKeys);
			signatureValid = true;
		} catch (err) {
			errors.push(err.message);
		}

		try {
			verifyArtifactChecksum(data, artifact.checksum);
			checksumValid = true;
		} catch (err) {
			errors.push(err.message);
		}

		artifacts.push({
			url: artifact.url,
			keyId,
			signatureValid,
			checksumValid,
		});
	}

	const result = { version: release.version, artifacts };

	if (errors.length > 0) {
		throw new ReleaseVerificationError(errors.join('; '), result);
	}

	return result;
}

/**
 * Fetches FAIR metadata from a URL.
 *
 * @param {string} url - The metadata URL (must be HTTPS)
 * @returns {Promise<object>} The metadata document
 * @throws {MetadataFetchError} If the URL is not HTTPS or the metadata cannot be fetched
 */
export async function fetchFairMetadata(url) {
	if (!url.startsWith('https://')) {
		throw new MetadataFetchError('Metadata URL must use HTTPS');
	}

	let response;
	try {
		response = await fetch(url);
	} catch (err) {
		throw new MetadataFetchError(`Failed to fetch metadata: ${err.message}`);
	}

	if (!response.ok) {
		throw new MetadataFetchError(`Failed to fetch metadata: HTTP ${response.status} ${response.statusText}`);
	}

	try {
		return await response.json();
	} catch (err) {
		throw new MetadataFetchError(`Failed to parse metadata: ${err.message}`);
	}
}

/**
 * Validates the structure of a FAIR metadata document.
 *
 * @param {object} metadata - The metadata document
 * @param {string} expectedDid - The expected DID
 * @returns {{valid: boolean, errors: string[]}} Validation result
 */
export function validateMetadataStructure(metadata, expectedDid) {
	const errors = [];

	// Check context
	if (metadata['@context'] !== METADATA_CONTEXT) {
		errors.push(`Invalid @context: expected "${METADATA_CONTEXT}", got "${metadata['@context']}"`);
	}

	// Check DID matches
	if (metadata.id !== expectedDid) {
		errors.push(`DID mismatch: expected "${expectedDid}", got "${metadata.id}"`);
	}

	// Check required fields
	if (!metadata.releases || !Array.isArray(metadata.releases)) {
		errors.push('Missing or invalid releases array');
	}

	return {
		valid: errors.length === 0,
		errors,
	};
}

/**
 * Verifies a FAIR metadata document.
 *
 * @param {object} metadata - The metadata document
 * @param {VerificationOptions} options - Verification options
 * @returns {Promise<ReleaseVerificationResult[]>}
 * @throws {MetadataVerificationError} If verification fails (includes result with details)
 * @throws {MetadataFetchError} If verification keys cannot be fetched
 */
export async function verifyMetadata(metadata, options) {
	const { did, allReleases = false, plcUrl = PLC_DIRECTORY_URL } = options;

	// Validate metadata structure
	const structureResult = validateMetadataStructure(metadata, did);
	if (!structureResult.valid) {
		throw new MetadataVerificationError(structureResult.errors.join('; '));
	}

	// Get verification keys (throws MetadataFetchError on failure)
	const verificationKeys = await getVerificationKeys(did, plcUrl);

	// Determine which releases to verify
	const metadataReleases = metadata.releases || [];
	const releasesToVerify = allReleases ? metadataReleases : metadataReleases.slice(0, 1);

	if (releasesToVerify.length === 0) {
		throw new MetadataVerificationError('No releases to verify');
	}

	const releaseResults = [];
	const errors = [];

	// Verify releases
	for (const release of releasesToVerify) {
		try {
			const releaseResult = await verifyRelease(release, verificationKeys);
			releaseResults.push(releaseResult);
		} catch (err) {
			if (err instanceof ReleaseVerificationError) {
				releaseResults.push(err.result);
				errors.push(`v${release.version}: ${err.message}`);
			} else {
				throw err;
			}
		}
	}

	if (errors.length > 0) {
		throw new MetadataVerificationError(errors.join('; '), releaseResults);
	}

	return releaseResults;
}

/**
 * Verifies a specific release version from metadata.
 *
 * @param {object} metadata - The metadata document
 * @param {string} version - The version to verify
 * @param {VerificationOptions} options - Verification options
 * @returns {Promise<ReleaseVerificationResult[]>}
 * @throws {MetadataVerificationError} If verification fails (includes result with details)
 * @throws {MetadataFetchError} If verification keys cannot be fetched
 */
export async function verifyMetadataRelease(metadata, version, options) {
	const { did, plcUrl = PLC_DIRECTORY_URL } = options;

	// Validate metadata structure
	const structureResult = validateMetadataStructure(metadata, did);
	if (!structureResult.valid) {
		throw new MetadataVerificationError(structureResult.errors.join('; '));
	}

	// Find the specified release
	const metadataReleases = metadata.releases || [];
	const release = metadataReleases.find((r) => r.version === version);

	if (!release) {
		throw new MetadataVerificationError(`Release version "${version}" not found in metadata`);
	}

	// Get verification keys (throws MetadataFetchError on failure)
	const verificationKeys = await getVerificationKeys(did, plcUrl);

	// Verify the release
	try {
		const releaseResult = await verifyRelease(release, verificationKeys);
		return [releaseResult];
	} catch (err) {
		if (err instanceof ReleaseVerificationError) {
			throw new MetadataVerificationError(`v${version}: ${err.message}`, [err.result]);
		}
		throw err;
	}
}

/**
 * Verifies a service endpoint URL.
 *
 * Fetches metadata from the URL and verifies it matches the expected DID.
 *
 * @param {string} url - The service endpoint URL (must be HTTPS)
 * @param {VerificationOptions} options - Verification options
 * @returns {Promise<ReleaseVerificationResult[]>}
 * @throws {MetadataFetchError} If metadata cannot be fetched
 */
export async function verifyServiceEndpoint(url, options) {
	const { did, allReleases = false, plcUrl = PLC_DIRECTORY_URL } = options;

	const metadata = await fetchFairMetadata(url);

	return verifyMetadata(metadata, {
		did,
		allReleases,
		plcUrl,
	});
}
