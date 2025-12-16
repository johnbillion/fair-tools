/**
 * FAIR Protocol metadata document generation.
 *
 * Generates JSON-LD metadata and accompanying release documents,
 * with support for plugins and themes for WordPress.
 */

import { readFile, realpath } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { basename, dirname, join } from 'node:path';
import * as uint8arrays from 'uint8arrays';
import { verifyWithVerificationKey } from './keys.js';
import { parseReadmeFile } from './readme-parser.js';

/**
 * @typedef {import('./Ed25519Keypair.js').Ed25519Keypair} Ed25519Keypair
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
 * @param {Ed25519Keypair} keypair - The verification keypair to sign with
 * @returns {Promise<string>} Base64url-encoded signature
 */
export async function signArtifact(data, keypair) {
	const hash = createHash('sha384').update(data).digest();
	const sig = await keypair.sign(hash);
	return uint8arrays.toString(sig, 'base64url');
}

/**
 * Verifies an artifact signature.
 *
 * Verifies the Ed25519 signature against the SHA-384 hash of the data.
 *
 * @param {Buffer|Uint8Array} data - Raw artifact data
 * @param {string} signature - Base64url-encoded signature
 * @param {Ed25519Keypair} keypair - The verification keypair (public key) to verify with
 * @returns {Promise<boolean>} True if signature is valid
 */
export async function verifyArtifact(data, signature, keypair) {
	const hash = createHash('sha384').update(data).digest();
	const sig = uint8arrays.fromString(signature, 'base64url');
	return verifyWithVerificationKey(hash, sig, keypair);
}

/**
 * Parses plugin headers from PHP file content.
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
 * Parses composer.json content and extracts relevant fields.
 *
 * @param {string} content - Content of composer.json file
 * @returns {{
 *   license?: string,
 *   securityContact?: string
 * }} Parsed data
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
 * @returns {{
 *   license?: string
 * }} Parsed data
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
 * @param {{
 *   id: string, // did:plc:... or did:web:...
 *   type: string, // e.g., 'wp-plugin' or 'wp-theme'
 *   name: string,
 *   slug: string,
 *   filename: string, // e.g., 'query-monitor/query-monitor.php'
 *   description: string,
 *   authors: Array<{name: string, url?: string, email?: string}>,
 *   license: string, // e.g., 'GPL-2.0-or-later'
 *   security?: Array,
 *   keywords?: Array<string>, // max 5
 *   sections?: object,
 *   releases?: Array
 * }} options
 * @returns {object} Metadata document
 */
export function createMetadataDocument(options) {
	const {
		id,
		type,
		name,
		slug,
		filename,
		description,
		authors,
		license,
		security = [],
		keywords = [],
		sections = {},
		releases = [],
	} = options;

	const doc = {
		'@context': METADATA_CONTEXT,
		id,
		type,
		name,
		slug,
		filename,
		description,
		authors,
		license,
		security,
		keywords,
		sections,
		releases,
	};

	return doc;
}

/**
 * Creates a release document for a specific version.
 *
 * @param {{
 *   version: string,
 *   artifacts: object, // keyed by type
 *   requires?: object, // e.g., {'env:wp': '>=6.0'}
 *   suggests?: object,
 *   provides?: object
 * }} options
 * @returns {object} Release document
 */
export function createReleaseDocument(options) {
	const { version, artifacts, requires, suggests, provides } = options;

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
 * @param {{
 *   url: string,
 *   checksum: string, // format 'algorithm:hash'
 *   signature?: string, // base64url-encoded
 *   contentType?: string // MIME type
 * }} options
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
 * @param {{
 *   url: string,
 *   data: Buffer|Uint8Array,
 *   keypair: Ed25519Keypair, // verification keypair for signing
 *   contentType?: string // MIME type
 * }} options
 * @returns {Promise<{
 *   url: string,
 *   checksum: string,
 *   'content-type'?: string,
 *   signature?: string
 * }>} Artifact with url, checksum, signature, and content-type
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
 * @returns {{ email: string } | { url: string }}
 */
function formatSecurityContact(value) {
	// Check if it's a URL (has scheme) or plain email address
	if (/^[a-z][a-z0-9+.-]*:/i.test(value)) {
		return { url: value };
	}
	return { email: value };
}

/**
 * Builds complete FAIR metadata for a release of a plugin for WordPress.
 *
 * This is the core metadata building function that accepts pre-resolved final values.
 * Use buildMetadata() for a file-based wrapper that handles parsing and priority resolution.
 *
 * @param {{
 *   keypair: Ed25519Keypair,
 *   did: string, // did:plc:...
 *   name: string,
 *   slug: string,
 *   filename: string, // e.g., 'query-monitor/query-monitor.php'
 *   description: string,
 *   author: {name: string, url?: string},
 *   license: string,
 *   securityContact?: string, // email or URL
 *   keywords?: Array<string>,
 *   existingReleases?: Array,
 *   version: string,
 *   requiresWp?: string,
 *   requiresPhp?: string,
 *   zipData: Buffer|Uint8Array,
 *   downloadUrl: string
 * }} options
 * @returns {Promise<{metadata: object, overwrittenVersion: string|null}>} Complete metadata document with release and overwrite info
 */
export async function buildMetadataFromContent(options) {
	const {
		// Keys
		keypair,

		// Metadata
		did,
		name,
		slug,
		filename,
		description,
		author,
		license,
		securityContact,
		keywords,

		// Existing releases
		existingReleases = [],

		// Release
		version,
		requiresWp,
		requiresPhp,
		zipData,
		downloadUrl,
	} = options;

	// Validate required fields
	if (!version) {
		throw new Error('Plugin file is missing required "Version:" header');
	}

	// Build authors array
	const authors = [author];

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
	const security = securityContact
		? [formatSecurityContact(securityContact)]
		: [];

	// Check if this version already exists in existing releases
	const existingVersionIndex = existingReleases.findIndex(
		(r) => r.version === version,
	);
	const overwrittenVersion = existingVersionIndex !== -1 ? version : null;

	// Filter out any existing release with the same version
	const filteredReleases = existingReleases.filter(
		(r) => r.version !== version,
	);

	// Create metadata document with new release prepended to existing ones
	const metadata = createMetadataDocument({
		id: did,
		type: 'wp-plugin',
		name,
		slug,
		filename,
		description,
		authors,
		license,
		security,
		keywords: (keywords || []).slice(0, 5),
		releases: [release, ...filteredReleases],
	});

	return { metadata, overwrittenVersion };
}

/**
 * Builds complete FAIR metadata for a release of a plugin for WordPress.
 *
 * File-based wrapper that handles all file reading, parsing, and priority resolution,
 * then delegates to buildMetadataFromContent() with final values.
 *
 * @param {{
 *   did: string, // did:plc:...
 *   keypair: Ed25519Keypair, // verification keypair for signing artifacts
 *   pluginFile: string, // path to main plugin PHP file
 *   zipFile: string,
 *   downloadUrl: string,
 *   existingReleases?: Array
 * }} options
 * @returns {Promise<{metadata: object, overwrittenVersion: string|null}>} Complete metadata document with release and overwrite info
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

	// Resolve to absolute path to handle relative paths like "plugin.php"
	const resolvedPluginFile = await realpath(pluginFile);

	// Determine slug and filename from resolved path
	const pluginDir = dirname(resolvedPluginFile);
	const pluginBasename = basename(resolvedPluginFile);
	const dirBasename = basename(pluginDir);
	const slug = dirBasename;
	const filename = `${dirBasename}/${pluginBasename}`;

	// Parse all source files
	const pluginContent = await readFile(pluginFile, 'utf-8');
	const pluginData = parsePluginHeaders(pluginContent);

	// Validate plugin ID matches
	if (!pluginData.pluginId) {
		throw new Error('Plugin file is missing required "Plugin ID:" header');
	}
	if (pluginData.pluginId !== did) {
		throw new Error(
			`Plugin ID mismatch: plugin file has "${pluginData.pluginId}" but DID "${did}" was provided`,
		);
	}

	let readmeData = {};
	try {
		const readmeContent = await readFile(
			join(pluginDir, 'readme.txt'),
			'utf-8',
		);
		readmeData = parseReadmeFile(readmeContent);
	} catch {
		// No readme.txt found
	}

	let composerData = {};
	try {
		const composerContent = await readFile(
			join(pluginDir, 'composer.json'),
			'utf-8',
		);
		composerData = parseComposerJson(composerContent);
	} catch {
		// No composer.json found
	}

	let packageData = {};
	try {
		const packageContent = await readFile(
			join(pluginDir, 'package.json'),
			'utf-8',
		);
		packageData = parsePackageJson(packageContent);
	} catch {
		// No package.json found
	}

	// Resolve values by priority
	const license =
		composerData.license ||
		packageData.license ||
		pluginData.license ||
		readmeData.license ||
		'';
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
		// Keys
		keypair,

		// Metadata
		did,
		name: pluginData.name,
		slug,
		filename,
		description,
		author,
		license,
		securityContact,
		keywords: readmeData.keywords,

		// Existing releases
		existingReleases,

		// Release
		version: pluginData.version,
		requiresWp: pluginData.requiresWp,
		requiresPhp: pluginData.requiresPhp,
		zipData,
		downloadUrl,
	});
}
