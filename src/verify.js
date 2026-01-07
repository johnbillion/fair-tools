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
 *   checksumValid: boolean,
 *   checksumMissing: boolean
 * }} ArtifactVerificationResult
 */

/**
 * @typedef {{
 *   version: string,
 *   valid: boolean,
 *   artifacts: ArtifactVerificationResult[],
 *   warnings: string[],
 *   errors: string[]
 * }} ReleaseVerificationResult
 */

/**
 * @typedef {{
 *   valid: boolean,
 *   did: string,
 *   source?: string,
 *   releases: ReleaseVerificationResult[],
 *   warnings: string[],
 *   errors: string[]
 * }} MetadataVerificationResult
 */

/**
 * @typedef {{
 *   did: string,
 *   allReleases?: boolean,
 *   source?: string,
 *   plcUrl?: string
 * }} VerificationOptions
 */

import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import * as uint8arrays from 'uint8arrays';
import { Ed25519Keypair } from './Ed25519Keypair.js';
import { METADATA_CONTEXT, verifyArtifact } from './metadata.js';
import { PLC_DIRECTORY_URL } from './did.js';

/**
 * Error thrown when metadata verification fails.
 */
export class MetadataVerificationError extends Error {}

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
		if (response.status === 404) {
			throw new MetadataFetchError(`DID not found: ${did}`);
		}
		throw new MetadataFetchError(`Failed to fetch DID document: HTTP ${response.status}`);
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
 * Creates an Ed25519Keypair from a publicKeyMultibase value.
 *
 * @param {string} publicKeyMultibase - The multibase-encoded public key
 * @returns {Promise<Ed25519Keypair>} The keypair (public key only)
 */
async function keypairFromMultibase(publicKeyMultibase) {
	// publicKeyMultibase is in format: z + base58btc(multicodec_prefix + public_key)
	// For Ed25519, the multicodec prefix is 0xed01
	const decoded = uint8arrays.fromString(publicKeyMultibase.slice(1), 'base58btc');
	// Skip the 2-byte multicodec prefix (0xed, 0x01)
	const publicKeyBytes = decoded.slice(2);
	return Ed25519Keypair.fromPublicKey(publicKeyBytes);
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
			const keypair = await keypairFromMultibase(key.publicKeyMultibase);
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

	const actualHash = createHash('sha256').update(data).digest('hex');

	if (actualHash !== expectedHash) {
		throw new ChecksumVerificationError(`Checksum mismatch: expected ${expectedHash}, got ${actualHash}`);
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
 */
export async function verifyRelease(release, verificationKeys) {
	const result = {
		version: release.version,
		valid: true,
		artifacts: [],
		warnings: [],
		errors: [],
	};

	// Only verify 'package' artifacts - other types don't require signatures
	const packageArtifacts = release.artifacts?.package || [];

	if (packageArtifacts.length === 0) {
		result.warnings.push('No package artifacts to verify');
		return result;
	}

	// Verify each package artifact
	for (const artifact of packageArtifacts) {
		// Signature is required
		if (!artifact.signature) {
			result.valid = false;
			result.errors.push(`package: Missing signature for ${artifact.url}`);
			continue;
		}

		// Fetch the artifact
		let data;
		try {
			data = await fetchArtifact(artifact.url);
		} catch (err) {
			result.valid = false;
			result.errors.push(`package: Failed to fetch ${artifact.url}: ${err.message}`);
			continue;
		}

		// Track results for this artifact
		let signatureValid = false;
		let checksumValid = false;
		let keyId = null;
		const checksumMissing = !artifact.checksum;

		// Verify signature
		try {
			keyId = await verifyArtifactSignature(data, artifact.signature, verificationKeys);
			signatureValid = true;
		} catch (err) {
			result.valid = false;
			result.errors.push(`package: ${err.message}`);
		}

		// Verify checksum if present (warn if missing, fail if mismatch)
		if (artifact.checksum) {
			try {
				verifyArtifactChecksum(data, artifact.checksum);
				checksumValid = true;
			} catch (err) {
				result.valid = false;
				result.errors.push(`package: ${err.message}`);
			}
		} else {
			result.warnings.push(`package: Missing checksum for ${artifact.url}`);
		}

		// Add artifact result with both check statuses
		result.artifacts.push({
			url: artifact.url,
			keyId,
			signatureValid,
			checksumValid,
			checksumMissing,
		});
	}

	return result;
}

/**
 * Fetches FAIR metadata from a URL.
 *
 * @param {string} url - The metadata URL (must be HTTPS)
 * @returns {Promise<object>} The metadata document
 * @throws {MetadataFetchError} If the metadata cannot be fetched
 * @throws {MetadataVerificationError} If the URL is not HTTPS
 */
export async function fetchFairMetadata(url) {
	if (!url.startsWith('https://')) {
		throw new MetadataVerificationError('Metadata URL must use HTTPS');
	}

	let response;
	try {
		response = await fetch(url);
	} catch (err) {
		throw new MetadataFetchError(`Failed to fetch metadata: ${err.message}`);
	}

	if (!response.ok) {
		if (response.status === 404) {
			throw new MetadataFetchError(`Metadata not found at URL: ${url}`);
		}
		throw new MetadataFetchError(`Failed to fetch metadata: HTTP ${response.status}`);
	}

	try {
		return await response.json();
	} catch (err) {
		throw new MetadataFetchError(`Failed to parse metadata: ${err.message}`);
	}
}

/**
 * Loads FAIR metadata from a local file.
 *
 * @param {string} filePath - Path to the metadata file
 * @returns {Promise<object>} The metadata document
 * @throws {MetadataFetchError} If the file cannot be read
 */
export async function loadFairMetadata(filePath) {
	try {
		const content = await readFile(filePath, 'utf-8');
		return JSON.parse(content);
	} catch (err) {
		throw new MetadataFetchError(`Failed to load metadata from file: ${err.message}`);
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
 * @returns {Promise<MetadataVerificationResult>}
 */
export async function verifyMetadata(metadata, options) {
	const { did, allReleases = false, source, plcUrl = PLC_DIRECTORY_URL } = options;

	const result = {
		valid: true,
		did,
		source,
		releases: [],
		warnings: [],
		errors: [],
	};

	// Validate metadata structure
	const structureResult = validateMetadataStructure(metadata, did);
	if (!structureResult.valid) {
		result.valid = false;
		result.errors.push(...structureResult.errors);
		return result;
	}

	// Get verification keys
	let verificationKeys;
	try {
		verificationKeys = await getVerificationKeys(did, plcUrl);
	} catch (err) {
		result.valid = false;
		result.errors.push(err.message);
		return result;
	}

	// Determine which releases to verify
	const releases = metadata.releases || [];
	const releasesToVerify = allReleases ? releases : releases.slice(0, 1);

	if (releasesToVerify.length === 0) {
		result.warnings.push('No releases to verify');
		return result;
	}

	// Verify releases
	for (const release of releasesToVerify) {
		const releaseResult = await verifyRelease(release, verificationKeys);
		result.releases.push(releaseResult);

		if (!releaseResult.valid) {
			result.valid = false;
			result.errors.push(...releaseResult.errors.map((e) => `v${release.version}: ${e}`));
		}
		result.warnings.push(...releaseResult.warnings.map((w) => `v${release.version}: ${w}`));
	}

	return result;
}

/**
 * Verifies a specific release version from metadata.
 *
 * @param {object} metadata - The metadata document
 * @param {string} version - The version to verify
 * @param {VerificationOptions} options - Verification options
 * @returns {Promise<MetadataVerificationResult>}
 */
export async function verifyMetadataRelease(metadata, version, options) {
	const { did, source, plcUrl = PLC_DIRECTORY_URL } = options;

	const result = {
		valid: true,
		did,
		source,
		releases: [],
		warnings: [],
		errors: [],
	};

	// Validate metadata structure
	const structureResult = validateMetadataStructure(metadata, did);
	if (!structureResult.valid) {
		result.valid = false;
		result.errors.push(...structureResult.errors);
		return result;
	}

	// Find the specified release
	const releases = metadata.releases || [];
	const release = releases.find((r) => r.version === version);

	if (!release) {
		result.valid = false;
		result.errors.push(`Release version "${version}" not found in metadata`);
		return result;
	}

	// Get verification keys
	let verificationKeys;
	try {
		verificationKeys = await getVerificationKeys(did, plcUrl);
	} catch (err) {
		result.valid = false;
		result.errors.push(err.message);
		return result;
	}

	// Verify the release
	const releaseResult = await verifyRelease(release, verificationKeys);
	result.releases.push(releaseResult);

	if (!releaseResult.valid) {
		result.valid = false;
		result.errors.push(...releaseResult.errors.map((e) => `v${version}: ${e}`));
	}
	result.warnings.push(...releaseResult.warnings.map((w) => `v${version}: ${w}`));

	return result;
}

/**
 * Verifies a service endpoint URL.
 *
 * Fetches metadata from the URL and verifies it matches the expected DID.
 *
 * @param {string} url - The service endpoint URL (must be HTTPS)
 * @param {VerificationOptions} options - Verification options
 * @returns {Promise<MetadataVerificationResult>}
 */
export async function verifyServiceEndpoint(url, options) {
	const { did, allReleases = false, plcUrl = PLC_DIRECTORY_URL } = options;

	// Fetch metadata from the URL
	let metadata;
	try {
		metadata = await fetchFairMetadata(url);
	} catch (err) {
		return {
			valid: false,
			did,
			source: url,
			releases: [],
			warnings: [],
			errors: [err.message],
		};
	}

	// Verify the metadata
	return verifyMetadata(metadata, {
		did,
		allReleases,
		source: url,
		plcUrl,
	});
}
