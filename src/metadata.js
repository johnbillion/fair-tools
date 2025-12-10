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
 * Calculates SHA-256 checksum of data.
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
 * Signs artifact data using the verification keypair.
 *
 * Signs the SHA-384 hash of the raw artifact data, matching the format
 * expected by WordPress's verify_file_signature() function.
 *
 * @param {Buffer|Uint8Array} data - Raw artifact data (e.g., zip file contents)
 * @param {object} keypair - The verification keypair to sign with
 * @returns {Promise<string>} Base64url-encoded signature
 */
export async function signArtifact(data, keypair) {
	const hash = createHash('sha384').update(data).digest();
	const sig = await signWithVerificationKey(hash, keypair);
	return uint8arrays.toString(sig, 'base64url');
}

/**
 * Verifies an artifact signature.
 *
 * Verifies the Ed25519 signature against the SHA-384 hash of the data.
 *
 * @param {Buffer|Uint8Array} data - Raw artifact data
 * @param {string} signature - Base64url-encoded signature
 * @param {object} keypair - The verification keypair (public key) to verify with
 * @returns {Promise<boolean>} True if signature is valid
 */
export async function verifyArtifact(data, signature, keypair) {
	const hash = createHash('sha384').update(data).digest();
	const sig = uint8arrays.fromString(signature, 'base64url');
	return verifyWithVerificationKey(hash, sig, keypair);
}

/**
 * Parses WordPress plugin headers from PHP file content.
 *
 * @param {string} content - PHP file content
 * @returns {object} Parsed headers
 */
export function parsePluginHeaders(content) {
	const headers = {};
	const headerMap = {
		'Plugin Name': 'name',
		'Plugin URI': 'pluginUri',
		'Plugin ID': 'pluginId',
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
		Security: 'security',
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
 * Parses WordPress readme.txt file content.
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
 * Parses composer.json content and extracts relevant fields.
 *
 * @param {string} content - Content of composer.json file
 * @returns {object} Parsed data with license and securityContact fields
 */
export function parseComposerJson(content) {
	const data = {};

	try {
		const composer = JSON.parse(content);
		if (composer.license) {
			data.license = composer.license;
		}
		if (composer.support?.security) {
			data.securityContact = composer.support.security;
		}
	} catch {
		// Invalid JSON
	}

	return data;
}

/**
 * Parses package.json content and extracts relevant fields.
 *
 * @param {string} content - Content of package.json file
 * @returns {object} Parsed data with license field
 */
export function parsePackageJson(content) {
	const data = {};

	try {
		const pkg = JSON.parse(content);
		if (pkg.license) {
			data.license = pkg.license;
		}
	} catch {
		// Invalid JSON
	}

	return data;
}

/**
 * Creates a metadata document for a package.
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
 * Creates a release document for a specific version.
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
 * Creates an artifact entry for a release.
 *
 * @param {object} options
 * @param {string} options.url - Download URL
 * @param {string} options.checksum - Checksum in format 'algorithm:hash'
 * @param {string} [options.signature] - Base64url-encoded signature
 * @param {string} [options.contentType] - MIME type of the artifact
 * @returns {object} Artifact object
 */
export function createArtifact(options) {
	const { url, checksum, signature, contentType } = options;

	const artifact = { url, checksum };
	if (contentType) {
		artifact['content-type'] = contentType;
	}
	if (signature) {
		artifact.signature = signature;
	}
	return artifact;
}

/**
 * Creates a signed artifact entry.
 *
 * Signs the artifact data using Ed25519 over the SHA-384 hash, matching the
 * format expected by the verify_file_signature() function in WordPress.
 *
 * @param {object} options
 * @param {string} options.url - Download URL
 * @param {Buffer|Uint8Array} options.data - File contents to checksum and sign
 * @param {object} options.keypair - Verification keypair for signing
 * @param {string} [options.contentType] - MIME type of the artifact
 * @returns {Promise<object>} Artifact with url, checksum, signature, and content-type
 */
export async function createSignedArtifact(options) {
	const { url, data, keypair, contentType } = options;

	const checksum = await calculateChecksum(data);
	const signature = await signArtifact(data, keypair);

	return createArtifact({ url, checksum, signature, contentType });
}

/**
 * Formats a security contact value into the schema format.
 *
 * @param {string} value - Email address or URL
 * @returns {object} Object with either {email} or {url} property
 */
function formatSecurityContact(value) {
	// Check if it's a URL (has scheme) or plain email address
	if (/^[a-z][a-z0-9+.-]*:/i.test(value)) {
		return { url: value };
	}
	return { email: value };
}

/**
 * Builds complete FAIR metadata for a WordPress plugin release.
 *
 * This is the core metadata building function that accepts pre-resolved final values.
 * Use buildMetadata() for a file-based wrapper that handles parsing and priority resolution.
 *
 * @param {object} options
 * @param {string} options.did - Package DID
 * @param {object} options.keypair - Verification keypair for signing artifacts
 * @param {string} options.slug - Plugin slug
 * @param {string} options.version - Version string (required)
 * @param {string} [options.name] - Plugin name (defaults to slug)
 * @param {string} [options.description] - Plugin description
 * @param {object} [options.author] - Author object {name, url?}
 * @param {string} [options.license] - License identifier
 * @param {Array<string>} [options.keywords] - Search keywords
 * @param {string} [options.securityContact] - Security contact (email or URL)
 * @param {string} [options.requiresWp] - Minimum WordPress version
 * @param {string} [options.requiresPhp] - Minimum PHP version
 * @param {Buffer|Uint8Array} options.zipData - Plugin zip file contents
 * @param {string} options.downloadUrl - Public download URL for the zip
 * @param {Array} [options.existingReleases] - Existing releases to preserve
 * @returns {Promise<object>} Complete metadata document with release
 */
export async function buildMetadataFromContent(options) {
	const {
		did,
		keypair,
		slug,
		version,
		name,
		description,
		author,
		license,
		keywords,
		securityContact,
		requiresWp,
		requiresPhp,
		zipData,
		downloadUrl,
		existingReleases = [],
	} = options;

	// Validate required fields
	if (!version) {
		throw new Error('Plugin file is missing required "Version:" header');
	}

	// Build authors array
	const authors = author ? [author] : [];

	// Create signed artifact
	const artifact = await createSignedArtifact({
		url: downloadUrl,
		data: zipData,
		keypair,
		contentType: 'application/zip',
	});

	// Build requirements
	const requires = {};
	if (requiresWp) {
		requires['env:wp'] = `>=${requiresWp}`;
	}
	if (requiresPhp) {
		requires['env:php'] = `>=${requiresPhp}`;
	}

	// Create release
	const release = createReleaseDocument({
		version,
		artifacts: {
			package: [artifact],
		},
		requires,
	});

	// Build security contacts array
	const security = securityContact ? [formatSecurityContact(securityContact)] : [];

	// Create metadata document with new release prepended to existing ones
	return createMetadataDocument({
		id: did,
		type: 'wp-plugin',
		name: name || slug,
		slug,
		description: description || '',
		authors,
		license: license || '',
		keywords: (keywords || []).slice(0, 5),
		security,
		releases: [release, ...existingReleases],
	});
}

/**
 * Builds complete FAIR metadata for a WordPress plugin release.
 *
 * File-based wrapper that handles all file reading, parsing, and priority resolution,
 * then delegates to buildMetadataFromContent() with final values.
 *
 * @param {object} options
 * @param {string} options.did - Package DID
 * @param {object} options.keypair - Verification keypair for signing artifacts
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

	// Parse all source files
	const pluginContent = await readFile(pluginFile, 'utf-8');
	const pluginData = parsePluginHeaders(pluginContent);

	// Validate plugin ID matches
	if (!pluginData.pluginId) {
		throw new Error('Plugin file is missing required "Plugin ID:" header');
	}
	if (pluginData.pluginId !== did) {
		throw new Error(`Plugin ID mismatch: plugin file has "${pluginData.pluginId}" but DID "${did}" was provided`);
	}

	let readmeData = {};
	try {
		const readmeContent = await readFile(join(pluginDir, 'readme.txt'), 'utf-8');
		readmeData = parseReadmeFile(readmeContent);
	} catch {
		// No readme.txt found
	}

	let composerData = {};
	try {
		const composerContent = await readFile(join(pluginDir, 'composer.json'), 'utf-8');
		composerData = parseComposerJson(composerContent);
	} catch {
		// No composer.json found
	}

	let packageData = {};
	try {
		const packageContent = await readFile(join(pluginDir, 'package.json'), 'utf-8');
		packageData = parsePackageJson(packageContent);
	} catch {
		// No package.json found
	}

	// Resolve values by priority
	const license = composerData.license || packageData.license || pluginData.license || readmeData.license || '';
	const securityContact = pluginData.security || composerData.securityContact;
	const description = pluginData.description || readmeData.shortDescription;

	// Build author object
	let author;
	if (pluginData.author) {
		author = { name: pluginData.author };
		if (pluginData.authorUri) {
			author.url = pluginData.authorUri;
		}
	}

	// Read zip data
	const zipData = await readFile(zipFile);

	return buildMetadataFromContent({
		did,
		keypair,
		slug,
		version: pluginData.version,
		name: pluginData.name,
		description,
		author,
		license,
		keywords: readmeData.keywords,
		securityContact,
		requiresWp: pluginData.requiresWp,
		requiresPhp: pluginData.requiresPhp,
		zipData,
		downloadUrl,
		existingReleases,
	});
}
