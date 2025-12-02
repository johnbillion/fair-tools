/**
 * FAIR Protocol metadata document generation.
 *
 * Generates JSON-LD metadata and accompanying release documents,
 * with support for WordPress plugins and themes.
 */

import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { basename, dirname, join } from 'node:path';
import * as uint8arrays from 'uint8arrays';
import { signWithVerificationKey, verifyWithVerificationKey } from './keys.js';

/**
 * @typedef {import('@atproto/crypto').Secp256k1Keypair} Secp256k1Keypair
 */

/**
 * JSON-LD context for metadata documents.
 *
 * @type {string}
 */
export const METADATA_CONTEXT = 'https://fair.pm/ns/metadata/v1';

/**
 * JSON-LD context for release documents.
 *
 * @type {string}
 */
export const RELEASE_CONTEXT = 'https://fair.pm/ns/release/v1';

/**
 * Calculate SHA-256 checksum of data.
 *
 * @param {Buffer|Uint8Array|string} data - File contents or path to file
 * @returns {Promise<string>} Checksum in format 'sha256:...'
 */
export async function calculateChecksum(data) {
	let buffer = data;
	if (typeof data === 'string') {
		buffer = await readFile(data);
	}
	const hash = createHash('sha256').update(buffer).digest('hex');
	return `sha256:${hash}`;
}

/**
 * Sign an artifact checksum.
 *
 * Signs the checksum string with a secp256k1 verification key.
 *
 * @param {string} checksum - Checksum string (e.g., 'sha256:abc123...')
 * @param {Secp256k1Keypair} keypair - The keypair to sign with
 * @returns {Promise<string>} Base64url-encoded signature
 */
export async function signArtifact(checksum, keypair) {
	const sig = await signWithVerificationKey(checksum, keypair);
	return uint8arrays.toString(sig, 'base64url');
}

/**
 * Verify an artifact signature.
 *
 * @param {string} checksum - Checksum string (e.g., 'sha256:abc123...')
 * @param {string} signature - Base64url-encoded signature
 * @param {string} publicKey - The did:key formatted public key
 * @returns {Promise<boolean>} True if signature is valid
 */
export async function verifyArtifact(checksum, signature, publicKey) {
	const sig = uint8arrays.fromString(signature, 'base64url');
	return verifyWithVerificationKey(checksum, sig, publicKey);
}

/**
 * Parse WordPress plugin headers from PHP file content.
 *
 * @param {string} content - PHP file content
 * @returns {object} Parsed headers
 */
export function parsePluginHeaders(content) {
	const headers = {};
	const headerMap = {
		'Plugin Name': 'name',
		'Plugin URI': 'pluginUri',
		Description: 'description',
		Version: 'version',
		Author: 'author',
		'Author URI': 'authorUri',
		License: 'license',
		'License URI': 'licenseUri',
		'Text Domain': 'textDomain',
		'Domain Path': 'domainPath',
		'Requires at least': 'requiresWp',
		'Requires PHP': 'requiresPhp',
		'Update URI': 'updateUri',
	};

	for (const [phpHeader, jsKey] of Object.entries(headerMap)) {
		const regex = new RegExp(`^\\s*\\*?\\s*${phpHeader}:\\s*(.+)$`, 'mi');
		const match = content.match(regex);
		if (match) {
			headers[jsKey] = match[1].trim();
		}
	}

	return headers;
}

/**
 * Parse WordPress readme.txt file content.
 *
 * Extracts license, keywords, and short description.
 *
 * @param {string} content - readme.txt file content
 * @returns {object} Parsed readme data
 */
export function parseReadmeFile(content) {
	const data = {};

	// Parse license
	const licenseMatch = content.match(/^License:\s*(.+)$/mi);
	if (licenseMatch) {
		data.license = licenseMatch[1].trim();
	}

	// Parse tags into keywords array
	const tagsMatch = content.match(/^Tags:\s*(.+)$/mi);
	data.keywords = tagsMatch
		? tagsMatch[1].split(',').map((tag) => tag.trim()).filter(Boolean)
		: [];

	// Extract short description (first non-empty line after header fields)
	const lines = content.split('\n');
	let foundHeaders = false;
	for (const line of lines) {
		const trimmed = line.trim();
		// Skip the title line
		if (trimmed.startsWith('===') && trimmed.endsWith('===')) {
			foundHeaders = true;
			continue;
		}
		// Skip header fields (Key: Value format)
		if (foundHeaders && /^[A-Za-z][A-Za-z\s]+:/.test(trimmed)) {
			continue;
		}
		// Skip empty lines
		if (!trimmed) {
			continue;
		}
		// Skip section headings
		if (trimmed.startsWith('==') && trimmed.endsWith('==')) {
			break;
		}
		// This is the short description
		if (foundHeaders) {
			data.shortDescription = trimmed;
			break;
		}
	}

	return data;
}

/**
 * Try to find SPDX license from package.json or composer.json.
 *
 * @param {string} pluginDir - Plugin directory path
 * @returns {Promise<string|null>} SPDX license identifier or null
 */
async function findSpdxLicense(pluginDir) {
	// Try composer.json first
	try {
		const composerJson = await readFile(join(pluginDir, 'composer.json'), 'utf-8');
		const composer = JSON.parse(composerJson);
		if (composer.license) {
			return composer.license;
		}
	} catch {
		// File doesn't exist or isn't valid JSON
	}

	// Try package.json
	try {
		const packageJson = await readFile(join(pluginDir, 'package.json'), 'utf-8');
		const pkg = JSON.parse(packageJson);
		if (pkg.license) {
			return pkg.license;
		}
	} catch {
		// File doesn't exist or isn't valid JSON
	}

	return null;
}

/**
 * Create a metadata document for a package.
 *
 * @param {object} options
 * @param {string} options.id - Package DID (did:plc:... or did:web:...)
 * @param {string} options.type - Package type (e.g., 'wp-plugin' or 'wp-theme')
 * @param {string} options.name - Human-readable name
 * @param {string} [options.slug] - URL-safe slug
 * @param {string} [options.description] - Package description
 * @param {Array} [options.authors] - Array of {name, url?, email?} objects
 * @param {string} [options.license] - License identifier (e.g., 'GPL-2.0-or-later')
 * @param {Array} [options.keywords] - Search keywords (max 5)
 * @param {object} [options.sections] - Additional info sections
 * @param {Array} [options.security] - Security contact info
 * @param {Array} [options.releases] - Array of release documents
 * @returns {object} Metadata document
 */
export function createMetadataDocument(options) {
	const {
		id,
		type,
		name,
		slug,
		description,
		authors = [],
		license = '',
		keywords = [],
		sections = {},
		security = [],
		releases = [],
	} = options;

	const doc = {
		'@context': METADATA_CONTEXT,
		id,
		type,
		name,
		license,
		authors,
		security,
		releases,
	};

	// Optional properties
	if (slug) doc.slug = slug;
	if (description) doc.description = description;
	if (keywords.length > 0) doc.keywords = keywords.slice(0, 5);
	if (Object.keys(sections).length > 0) doc.sections = sections;

	return doc;
}

/**
 * Create a release document for a specific version.
 *
 * @param {object} options
 * @param {string} options.version - Semantic version string
 * @param {object} options.artifacts - Artifact objects keyed by type
 * @param {object} [options.requires] - Requirements (e.g., {'env:wp': '>=6.0'})
 * @param {object} [options.suggests] - Suggested packages
 * @param {object} [options.provides] - Provided capabilities
 * @returns {object} Release document
 */
export function createReleaseDocument(options) {
	const {
		version,
		artifacts,
		requires,
		suggests,
		provides,
	} = options;

	const doc = {
		version,
		artifacts,
	};

	// Optional properties - only include if non-empty
	if (requires && Object.keys(requires).length > 0) doc.requires = requires;
	if (suggests && Object.keys(suggests).length > 0) doc.suggests = suggests;
	if (provides && Object.keys(provides).length > 0) doc.provides = provides;

	return doc;
}

/**
 * Create an artifact entry for a release.
 *
 * @param {object} options
 * @param {string} options.url - Download URL
 * @param {string} options.checksum - Checksum in format 'algorithm:hash'
 * @param {string} [options.signature] - Base64url-encoded signature
 * @returns {object} Artifact object
 */
export function createArtifact(options) {
	const { url, checksum, signature } = options;

	const artifact = { url, checksum };
	if (signature) {
		artifact.signature = signature;
	}
	return artifact;
}

/**
 * Create a signed artifact entry.
 *
 * @param {object} options
 * @param {string} options.url - Download URL
 * @param {Buffer|Uint8Array} options.data - File contents to checksum and sign
 * @param {Secp256k1Keypair} options.keypair - Keypair for signing
 * @returns {Promise<object>} Artifact with url, checksum, and signature
 */
export async function createSignedArtifact(options) {
	const { url, data, keypair } = options;

	const checksum = await calculateChecksum(data);
	const signature = await signArtifact(checksum, keypair);

	return createArtifact({ url, checksum, signature });
}

/**
 * Build complete FAIR metadata for a WordPress plugin release.
 *
 * @param {object} options
 * @param {string} options.did - Package DID
 * @param {Secp256k1Keypair} options.keypair - Keypair for signing artifacts
 * @param {string} options.pluginFile - Path to main plugin PHP file
 * @param {string} options.zipFile - Path to zip file
 * @param {string} options.downloadUrl - Public download URL for the zip
 * @param {Array} [options.existingReleases] - Existing releases to preserve
 * @returns {Promise<object>} Complete metadata document with release
 */
export async function buildMetadata(options) {
	const {
		did,
		keypair,
		pluginFile,
		zipFile,
		downloadUrl,
		existingReleases = [],
	} = options;

	// Determine slug from directory or filename
	const pluginDir = dirname(pluginFile);
	const slug = basename(pluginDir) !== '.' ? basename(pluginDir) : basename(pluginFile, '.php');

	// Read and parse plugin headers
	const pluginContent = await readFile(pluginFile, 'utf-8');
	const headers = parsePluginHeaders(pluginContent);

	// Try to find readme.txt
	let readmeData = {};
	try {
		const readmePath = join(pluginDir, 'readme.txt');
		const readmeContent = await readFile(readmePath, 'utf-8');
		readmeData = parseReadmeFile(readmeContent);
	} catch {
		// No readme.txt found
	}

	// Determine license
	let license = await findSpdxLicense(pluginDir);
	if (!license) {
		license = headers.license || readmeData.license || '';
	}

	// Build authors array
	const authors = [];
	if (headers.author) {
		const author = { name: headers.author };
		if (headers.authorUri) author.url = headers.authorUri;
		authors.push(author);
	}

	// Read zip and create signed artifact
	const zipData = await readFile(zipFile);
	const artifact = await createSignedArtifact({
		url: downloadUrl,
		data: zipData,
		keypair,
	});

	// Parse requirements
	const requires = {};
	if (headers.requiresWp) {
		requires['env:wp'] = `>=${headers.requiresWp}`;
	}
	if (headers.requiresPhp) {
		requires['env:php'] = `>=${headers.requiresPhp}`;
	}

	// Create release
	const release = createReleaseDocument({
		version: headers.version || '1.0.0',
		artifacts: {
			package: [artifact],
		},
		requires,
	});

	// Create metadata document with new release prepended to existing ones
	return createMetadataDocument({
		id: did,
		type: 'wp-plugin',
		name: headers.name || slug,
		slug,
		description: headers.description || readmeData.shortDescription || '',
		authors,
		license,
		keywords: (readmeData.keywords || []).slice(0, 5),
		security: [],
		releases: [release, ...existingReleases],
	});
}
