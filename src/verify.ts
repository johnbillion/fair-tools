/**
 * FAIR Protocol verification functions.
 *
 * Verifies metadata documents, release signatures, and checksums.
 */

interface VerificationKey {
	id: string;
	publicKeyMultibase: string;
}

interface Artifact {
	url: string;
	signature?: string;
	checksum?: string;
}

interface Release {
	version: string;
	artifacts?: {
		package?: Artifact[];
	};
}

export interface Metadata {
	'@context'?: string;
	id?: string;
	releases?: Release[];
}

interface VerificationOptions {
	did: string;
	allReleases?: boolean;
	plcUrl?: string;
}

interface ArtifactVerificationResult {
	url: string;
	keyId: string | null;
	signatureValid: boolean;
	checksumValid: boolean;
}

interface ReleaseVerificationResult {
	version: string;
	artifacts: ArtifactVerificationResult[];
}

import { createHash, timingSafeEqual } from 'node:crypto';
import { Ed25519Keypair } from './Ed25519Keypair.js';
import { fetchOptions } from './utils.js';
import { METADATA_CONTEXT, verifyArtifact } from './metadata.js';
import { PLC_DIRECTORY_URL } from './did.js';

/**
 * Error thrown when metadata verification fails.
 */
export class MetadataVerificationError extends Error {
	result?: ReleaseVerificationResult[];
	constructor(message: string, result?: ReleaseVerificationResult[]) {
		super(message);
		this.result = result;
	}
}

/**
 * Error thrown when release verification fails.
 */
export class ReleaseVerificationError extends Error {
	result?: ReleaseVerificationResult;
	constructor(message: string, result?: ReleaseVerificationResult) {
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
 * Partial DID document type containing only the fields we use.
 * The actual API response includes many more fields.
 */
interface PartialDidDocument {
	verificationMethod?: VerificationKey[];
	[key: string]: unknown;
}

/**
 * Fetches a DID document from the PLC directory.
 * @throws {MetadataFetchError} If the document cannot be fetched
 */
async function fetchDidDocument(did: string, plcUrl = PLC_DIRECTORY_URL): Promise<PartialDidDocument> {
	const url = `${plcUrl}/${did}`;

	let response: Response;
	try {
		response = await fetch(url, fetchOptions);
	} catch (err) {
		throw new MetadataFetchError(`Failed to fetch DID document: ${(err as Error).message}`);
	}

	if (!response.ok) {
		throw new MetadataFetchError(`Failed to fetch DID document: HTTP ${response.status} ${response.statusText}`);
	}

	try {
		return (await response.json()) as PartialDidDocument;
	} catch (err) {
		throw new MetadataFetchError(`Failed to parse DID document: ${(err as Error).message}`);
	}
}

/**
 * Extracts verification keys from a DID document.
 *
 * Looks for verification methods with IDs containing 'fair' (e.g., #fair, #fair2).
 */
export function extractVerificationKeys(didDocument: PartialDidDocument): VerificationKey[] {
	const verificationMethods = didDocument.verificationMethod || [];
	return verificationMethods.filter((vm) => vm.id && vm.id.includes('#fair'));
}

/**
 * Fetches verification keys for a DID.
 * @throws {MetadataFetchError} If keys cannot be fetched
 * @throws {MetadataVerificationError} If no verification keys are found
 */
export async function getVerificationKeys(did: string, plcUrl = PLC_DIRECTORY_URL): Promise<VerificationKey[]> {
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
 * @throws {SignatureVerificationError} If signature doesn't match any key
 */
export async function verifyArtifactSignature(
	data: Buffer | Uint8Array,
	signature: string,
	verificationKeys: VerificationKey[],
): Promise<string> {
	const errors: string[] = [];

	for (const key of verificationKeys) {
		try {
			const keypair = await Ed25519Keypair.fromPublicKeyMultibase(key.publicKeyMultibase);
			const valid = await verifyArtifact(data, signature, keypair);
			if (valid) {
				return key.id;
			}
		} catch (err) {
			errors.push(`${key.id}: ${(err as Error).message}`);
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
export function verifyArtifactChecksum(data: Buffer | Uint8Array, checksum: string): void {
	const [algorithm, expectedHash] = checksum.split(':');

	if (algorithm !== 'sha256') {
		throw new ChecksumVerificationError(`Unsupported checksum algorithm: ${algorithm}`);
	}

	const actualHashBuffer = createHash(algorithm).update(data).digest();
	const expectedHashBuffer = Buffer.from(expectedHash, 'hex');

	let match: boolean;
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
 * GitHub API release asset URLs require an Accept header to download
 * the actual binary content instead of JSON metadata.
 *
 * @param {string} url - The artifact URL
 * @throws {ArtifactFetchError} If the artifact cannot be fetched
 */
export async function fetchArtifact(url: string): Promise<Buffer> {
	const options: RequestInit = {
		...fetchOptions,
		headers: {
			...fetchOptions.headers,
			// Required for GitHub API to return binary content instead of JSON
			Accept: 'application/octet-stream',
		},
	};

	let response: Response;
	try {
		response = await fetch(url, options);
	} catch (err) {
		throw new ArtifactFetchError(`Failed to fetch artifact: ${(err as Error).message}`);
	}

	if (!response.ok) {
		throw new ArtifactFetchError(`Failed to fetch artifact: HTTP ${response.status}`);
	}

	try {
		const arrayBuffer = await response.arrayBuffer();
		return Buffer.from(arrayBuffer);
	} catch (err) {
		throw new ArtifactFetchError(`Failed to read artifact data: ${(err as Error).message}`);
	}
}

/**
 * Verifies all package artifacts in a release.
 *
 * Only 'package' type artifacts require signature verification.
 * Other artifact types (banner, icon, screenshot) are not verified.
 * @throws {ReleaseVerificationError} If verification fails (includes result with details)
 */
export async function verifyRelease(
	release: Release,
	verificationKeys: VerificationKey[],
): Promise<ReleaseVerificationResult> {
	const artifacts: ArtifactVerificationResult[] = [];
	const errors: string[] = [];

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
		let data: Buffer;
		try {
			data = await fetchArtifact(artifact.url);
		} catch (err) {
			errors.push(`Failed to fetch ${artifact.url}: ${(err as Error).message}`);
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
		let keyId: string | null = null;

		try {
			keyId = await verifyArtifactSignature(data, artifact.signature, verificationKeys);
			signatureValid = true;
		} catch (err) {
			errors.push((err as Error).message);
		}

		try {
			verifyArtifactChecksum(data, artifact.checksum);
			checksumValid = true;
		} catch (err) {
			errors.push((err as Error).message);
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
 * @throws {MetadataFetchError} If the URL is not HTTPS or the metadata cannot be fetched
 */
export async function fetchFairMetadata(url: string): Promise<Metadata> {
	if (!url.startsWith('https://')) {
		throw new MetadataFetchError('Metadata URL must use HTTPS');
	}

	let response: Response;
	try {
		response = await fetch(url, fetchOptions);
	} catch (err) {
		throw new MetadataFetchError(`Failed to fetch metadata: ${(err as Error).message}`);
	}

	if (!response.ok) {
		throw new MetadataFetchError(`Failed to fetch metadata: HTTP ${response.status} ${response.statusText}`);
	}

	try {
		return (await response.json()) as Metadata;
	} catch (err) {
		throw new MetadataFetchError(`Failed to parse metadata: ${(err as Error).message}`);
	}
}

/**
 * Validates the structure of a FAIR metadata document.
 * @throws {MetadataVerificationError} If validation fails
 */
export function validateMetadataStructure(metadata: Metadata, expectedDid: string): void {
	const errors: string[] = [];

	// Check context
	if (!('@context' in metadata)) {
		errors.push('Missing @context');
	} else if (metadata['@context'] !== METADATA_CONTEXT) {
		errors.push(`Invalid @context: expected "${METADATA_CONTEXT}", got "${metadata['@context']}"`);
	}

	// Check DID matches
	if (!('id' in metadata)) {
		errors.push('Missing id');
	} else if (metadata.id !== expectedDid) {
		errors.push(`DID mismatch: expected "${expectedDid}", got "${metadata.id}"`);
	}

	// Check required fields
	if (!('releases' in metadata)) {
		errors.push('Missing releases');
	} else if (!Array.isArray(metadata.releases)) {
		errors.push('Invalid releases: expected array');
	}

	if (errors.length > 0) {
		throw new MetadataVerificationError(errors.join('; '));
	}
}

/**
 * Verifies a FAIR metadata document.
 * @throws {MetadataVerificationError} If verification fails (includes result with details)
 * @throws {MetadataFetchError} If verification keys cannot be fetched
 */
export async function verifyMetadata(
	metadata: Metadata,
	options: VerificationOptions,
): Promise<ReleaseVerificationResult[]> {
	const { did, allReleases = false, plcUrl = PLC_DIRECTORY_URL } = options;

	// Validate metadata structure
	validateMetadataStructure(metadata, did);

	// Get verification keys (throws MetadataFetchError on failure)
	const verificationKeys = await getVerificationKeys(did, plcUrl);

	// Determine which releases to verify
	const metadataReleases = metadata.releases || [];
	const releasesToVerify = allReleases ? metadataReleases : metadataReleases.slice(0, 1);

	if (releasesToVerify.length === 0) {
		throw new MetadataVerificationError('No releases to verify');
	}

	const releaseResults: ReleaseVerificationResult[] = [];
	const errors: string[] = [];

	// Verify releases
	for (const release of releasesToVerify) {
		try {
			const releaseResult = await verifyRelease(release, verificationKeys);
			releaseResults.push(releaseResult);
		} catch (err) {
			if (err instanceof ReleaseVerificationError) {
				if (err.result) {
					releaseResults.push(err.result);
				}
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
 * @throws {MetadataVerificationError} If verification fails (includes result with details)
 * @throws {MetadataFetchError} If verification keys cannot be fetched
 */
export async function verifyMetadataRelease(
	metadata: Metadata,
	version: string,
	options: VerificationOptions,
): Promise<ReleaseVerificationResult[]> {
	const { did, plcUrl = PLC_DIRECTORY_URL } = options;

	// Validate metadata structure
	validateMetadataStructure(metadata, did);

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
			throw new MetadataVerificationError(`v${version}: ${err.message}`, err.result ? [err.result] : undefined);
		}
		throw err;
	}
}

/**
 * Verifies a service endpoint URL.
 *
 * Fetches metadata from the URL and verifies it matches the expected DID.
 * @throws {MetadataFetchError} If metadata cannot be fetched
 */
export async function verifyServiceEndpoint(
	url: string,
	options: VerificationOptions,
): Promise<ReleaseVerificationResult[]> {
	const { did, allReleases = false, plcUrl = PLC_DIRECTORY_URL } = options;

	const metadata = await fetchFairMetadata(url);

	return verifyMetadata(metadata, {
		did,
		allReleases,
		plcUrl,
	});
}
