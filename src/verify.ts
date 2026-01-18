/**
 * FAIR Protocol verification functions.
 *
 * Verifies metadata documents, release signatures, and checksums.
 */

import { createHash, timingSafeEqual } from 'node:crypto';
import { DidDocument } from '@did-plc/lib';
import { Ed25519Keypair } from './Ed25519Keypair.js';
import { fetchOptions } from './utils.js';
import { METADATA_CONTEXT, verifyArtifact } from './metadata.js';
import { FAIR_SERVICE_TYPE, PLC_DIRECTORY_URL, createPlcClient } from './plc.js';
import { validateDidLog, DidLogFetchError, DidLogValidationError, fetchDidLog } from './plc-log.js';
import {
	getFairAlias,
	verifyDomainDid,
	NoAliasError,
	MultipleAliasesError,
	DnsRecordNotFoundError,
	DnsRecordInvalidError,
	DidMismatchError,
} from './domain.js';

interface VerificationKey {
	id: string;
	publicKeyMultibase: string;
}

interface Artifact {
	url: string;
	signature?: string;
	checksum?: string;
	'content-type'?: string;
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
 * Error thrown when no FAIR service endpoints are found.
 */
export class NoServicesError extends Error {}

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
 * @param {string} [contentType] - Optional content type
 * @throws {ArtifactFetchError} If the artifact cannot be fetched
 */
export async function fetchArtifact(url: string, contentType?: string): Promise<Buffer> {
	const options: RequestInit = {
		...fetchOptions,
		headers: {
			...fetchOptions.headers,
			// Required for GitHub API to return binary content instead of JSON
			Accept: contentType || 'application/octet-stream',
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
			data = await fetchArtifact(artifact.url, artifact['content-type']);
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

interface ServiceResult {
	url: string;
	valid: boolean;
	releases?: ReleaseVerificationResult[];
	error?: string;
}

interface AliasResult {
	url?: string;
	domain?: string;
	valid: boolean;
	error?: string;
	note?: string;
}

interface LogResult {
	valid: boolean;
	operationCount?: number;
	error?: string;
}

export interface DidVerificationResult {
	valid: boolean;
	did: string;
	log: LogResult;
	services: ServiceResult[];
	alias: AliasResult | null;
	errors: string[];
}

export interface VerifyDidOptions {
	did: string;
	allReleases?: boolean;
	plcUrl?: string;
}

/**
 * Gets FAIR service endpoints from a DID document.
 */
export function getFairServices(didDocument: DidDocument): Array<{ type: string; serviceEndpoint: string }> {
	return (didDocument.service || []).filter((s) => s.type === FAIR_SERVICE_TYPE);
}

/**
 * Validates that a DID document has at least one FAIR service endpoint.
 * Throws NoServicesError if none are found.
 */
export function requireFairServices(didDocument: DidDocument): Array<{ type: string; serviceEndpoint: string }> {
	const services = getFairServices(didDocument);
	if (services.length === 0) {
		throw new NoServicesError('No FairPackageManagementRepo service endpoints found');
	}
	return services;
}

/**
 * Verifies all FAIR service endpoints for a DID.
 * Throws NoServicesError if no FAIR services are found.
 */
export async function verifyFairServices(
	didDocument: DidDocument,
	did: string,
	allReleases = false,
): Promise<ServiceResult[]> {
	const fairServices = requireFairServices(didDocument);
	const results: ServiceResult[] = [];

	for (const service of fairServices) {
		const serviceUrl = service.serviceEndpoint;
		try {
			const releases = await verifyServiceEndpoint(serviceUrl, {
				did,
				allReleases,
			});

			results.push({
				url: serviceUrl,
				valid: true,
				releases,
			});
		} catch (err) {
			if (err instanceof MetadataFetchError) {
				results.push({
					url: serviceUrl,
					valid: false,
					error: err.message,
				});
			} else if (err instanceof MetadataVerificationError) {
				results.push({
					url: serviceUrl,
					valid: false,
					releases: err.result,
					error: err.message,
				});
			} else {
				throw err;
			}
		}
	}

	return results;
}

/**
 * Extracts domain from a fair:// alias URL.
 */
export function extractDomainFromAlias(alias: string): string {
	return alias.replace(/^fair:\/\//, '').replace(/\/$/, '');
}

/**
 * Result of fetching the fair:// alias for a DID.
 */
export type FetchAliasResult =
	| { type: 'alias'; alias: string }
	| { type: 'no-alias' }
	| { type: 'multiple-aliases'; error: string };

/**
 * Result of verifying a domain's DNS record.
 */
export type VerifyDomainResult = { valid: true } | { valid: false; error: string };

/**
 * Builds an AliasResult from fetch and verification results.
 * This is a pure function.
 */
export function buildAliasResult(fetchResult: FetchAliasResult, verifyResult: VerifyDomainResult | null): AliasResult {
	if (fetchResult.type === 'no-alias') {
		return { valid: true, note: 'No fair:// alias configured' };
	}

	if (fetchResult.type === 'multiple-aliases') {
		return { valid: false, error: fetchResult.error };
	}

	const domain = extractDomainFromAlias(fetchResult.alias);

	if (!verifyResult) {
		return { url: fetchResult.alias, domain, valid: false, error: 'Verification not performed' };
	}

	if (verifyResult.valid) {
		return { url: fetchResult.alias, domain, valid: true };
	}

	return { url: fetchResult.alias, domain, valid: false, error: verifyResult.error };
}

/**
 * Verifies domain aliases for a DID.
 */
export async function verifyDomainAlias(did: string): Promise<AliasResult> {
	let fetchResult: FetchAliasResult;
	try {
		const alias = await getFairAlias(did);
		fetchResult = { type: 'alias', alias };
	} catch (err) {
		if (err instanceof NoAliasError) {
			fetchResult = { type: 'no-alias' };
		} else if (err instanceof MultipleAliasesError) {
			fetchResult = { type: 'multiple-aliases', error: err.message };
		} else {
			throw err;
		}
	}

	if (fetchResult.type !== 'alias') {
		return buildAliasResult(fetchResult, null);
	}

	const domain = extractDomainFromAlias(fetchResult.alias);

	let verifyResult: VerifyDomainResult;
	try {
		await verifyDomainDid(domain, did);
		verifyResult = { valid: true };
	} catch (err) {
		const errorMsg =
			err instanceof DnsRecordNotFoundError || err instanceof DnsRecordInvalidError || err instanceof DidMismatchError
				? err.message
				: `DNS verification failed: ${(err as Error).message}`;
		verifyResult = { valid: false, error: errorMsg };
	}

	return buildAliasResult(fetchResult, verifyResult);
}

/**
 * Performs comprehensive verification of a DID.
 *
 * This verifies:
 * 1. DID log validation - Verifies the complete operation history from genesis
 * 2. DID document validation - Ensures computed state matches current document
 * 3. Service endpoint verification - Validates FAIR metadata at each service URL
 * 4. Domain alias verification - Checks fair:// aliases resolve correctly
 */
export async function verifyDid(options: VerifyDidOptions): Promise<DidVerificationResult> {
	const { did, allReleases = false, plcUrl = PLC_DIRECTORY_URL } = options;

	const result: DidVerificationResult = {
		valid: true,
		did,
		log: { valid: false },
		services: [],
		alias: null,
		errors: [],
	};

	// 1. Validate DID log
	try {
		const logResult = await validateDidLog(did);
		result.log = {
			valid: true,
			operationCount: logResult.operations.length,
		};
	} catch (err) {
		if (err instanceof DidLogFetchError || err instanceof DidLogValidationError) {
			result.log = {
				valid: false,
				error: err.message,
			};
			result.valid = false;
			result.errors.push(`DID log: ${err.message}`);
		} else {
			throw err;
		}
	}

	// 2. Fetch DID document
	let didDocument: DidDocument;
	try {
		const client = createPlcClient(plcUrl);
		didDocument = await client.getDocument(did);
	} catch (err) {
		result.valid = false;
		result.errors.push(`Could not fetch DID document: ${(err as Error).message}`);
		return result;
	}

	// 3. Verify service endpoints
	try {
		const serviceResults = await verifyFairServices(didDocument, did, allReleases);
		result.services = serviceResults;

		for (const service of serviceResults) {
			if (!service.valid) {
				result.valid = false;
				result.errors.push(`${service.url}: ${service.error}`);
			}
		}
	} catch (err) {
		if (err instanceof NoServicesError) {
			result.valid = false;
			result.errors.push(err.message);
		} else {
			throw err;
		}
	}

	// 4. Verify domain aliases
	result.alias = await verifyDomainAlias(did);
	if (!result.alias.valid && result.alias.error) {
		result.valid = false;
		result.errors.push(`Domain alias: ${result.alias.error}`);
	}

	return result;
}

/**
 * Result of checking if a verification key is valid for a DID.
 */
export interface CheckVerificationKeyResult {
	valid: boolean;
	publicKeyMultibase: string;
	matchingKeyId: string | null;
	allKeys: Array<{ id: string; publicKeyMultibase: string }>;
}

/**
 * Checks if a verification key is valid for a DID.
 *
 * A verification key is valid if it's present in the DID document's verification methods.
 *
 * @param did - The DID to check (did:plc:...)
 * @param publicKeyMultibase - The public key multibase to check (z6Mk...)
 * @param plcUrl - Optional PLC directory URL
 * @returns Result indicating if the key is valid and details about the match
 * @throws {MetadataFetchError} If the DID document cannot be fetched
 */
export async function checkVerificationKey(
	did: string,
	publicKeyMultibase: string,
	plcUrl = PLC_DIRECTORY_URL,
): Promise<CheckVerificationKeyResult> {
	const verificationKeys = await getVerificationKeys(did, plcUrl);

	const matchingKey = verificationKeys.find((vk) => vk.publicKeyMultibase === publicKeyMultibase);

	return {
		valid: !!matchingKey,
		publicKeyMultibase,
		matchingKeyId: matchingKey?.id ?? null,
		allKeys: verificationKeys,
	};
}

/**
 * Result of checking if a rotation key is valid for a DID.
 */
export interface CheckRotationKeyResult {
	valid: boolean;
	publicKeyDidKey: string;
	allKeys: string[];
}

/**
 * Checks if a rotation key is valid for a DID.
 *
 * A rotation key is valid if it's present in the latest operation in the DID log,
 * not in the DID document.
 *
 * @param did - The DID to check (did:plc:...)
 * @param publicKeyDidKey - The public key in did:key format to check (did:key:zQ3sh...)
 * @param plcUrl - Optional PLC directory URL
 * @returns Result indicating if the key is valid and all rotation keys in the latest operation
 * @throws {DidLogFetchError} If the DID log cannot be fetched
 */
export async function checkRotationKey(
	did: string,
	publicKeyDidKey: string,
	plcUrl = PLC_DIRECTORY_URL,
): Promise<CheckRotationKeyResult> {
	// Fetch the DID operation log
	const ops = await fetchDidLog(did, plcUrl);

	if (ops.length === 0) {
		throw new DidLogFetchError('DID log is empty');
	}

	// Get rotation keys from the latest operation
	const latestOp = ops[ops.length - 1];
	const rotationKeys = latestOp.rotationKeys || [];

	const isValid = rotationKeys.includes(publicKeyDidKey);

	return {
		valid: isValid,
		publicKeyDidKey,
		allKeys: rotationKeys,
	};
}

// Re-export error types for consumers
export { DidLogFetchError, DidLogValidationError } from './plc-log.js';
export {
	NoAliasError,
	MultipleAliasesError,
	DnsRecordNotFoundError,
	DnsRecordInvalidError,
	DidMismatchError,
} from './domain.js';
