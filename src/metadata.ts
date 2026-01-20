/**
 * FAIR Protocol metadata document generation.
 *
 * Generates JSON-LD metadata and accompanying release documents,
 * with support for plugins and themes for WordPress.
 */

import { readFile, readdir, realpath } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { basename, dirname, join } from 'node:path';
import * as uint8arrays from 'uint8arrays';
import { imageSize } from 'image-size';
import { marked } from 'marked';
import { verifyWithVerificationKey } from './keys.js';
import { parseReadmeFile } from './readme-parser.js';
import type { Ed25519Keypair } from './Ed25519Keypair.js';
export { parseReadmeFile } from './readme-parser.js';

/**
 * JSON-LD context for metadata documents.
 */
export const METADATA_CONTEXT = 'https://fair.pm/ns/metadata/v1';

/**
 * JSON-LD context for release documents.
 */
export const RELEASE_CONTEXT = 'https://fair.pm/ns/release/v1';

/**
 * Calculates SHA-256 checksum of data.
 *
 * @param {Buffer|Uint8Array|string} data - File contents or path to file
 * @returns {Promise<string>} Checksum in format 'sha256:...'
 */
export async function calculateChecksum(data: Buffer | Uint8Array | string): Promise<string> {
	const buffer: Buffer | Uint8Array = typeof data === 'string' ? await readFile(data) : data;
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
export async function signArtifact(data: Buffer | Uint8Array, keypair: Ed25519Keypair): Promise<string> {
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
export async function verifyArtifact(
	data: Buffer | Uint8Array,
	signature: string,
	keypair: Ed25519Keypair,
): Promise<boolean> {
	const hash = createHash('sha384').update(data).digest();
	const sig = uint8arrays.fromString(signature, 'base64url');
	return verifyWithVerificationKey(hash, sig, keypair);
}

interface PluginHeaders {
	name?: string;
	pluginUri?: string;
	pluginId?: string;
	description?: string;
	version?: string;
	author?: string;
	authorUri?: string;
	license?: string;
	licenseUri?: string;
	textDomain?: string;
	domainPath?: string;
	requiresWp?: string;
	requiresPhp?: string;
	updateUri?: string;
	security?: string;
}

/**
 * Parses plugin headers from PHP file content.
 */
export function parsePluginHeaders(content: string): PluginHeaders {
	const headers: PluginHeaders = {};
	const headerMap: Record<string, keyof PluginHeaders> = {
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
 */
export function parseComposerJson(content: string): { license?: string; securityContact?: string } {
	const data: { license?: string; securityContact?: string } = {};

	try {
		const composer = JSON.parse(content) as { license?: string; support?: { security?: string } };
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
 */
export function parsePackageJson(content: string): { license?: string } {
	const data: { license?: string } = {};

	try {
		const pkg = JSON.parse(content) as { license?: string };
		if (pkg.license) {
			data.license = pkg.license;
		}
	} catch {
		// Invalid JSON
	}

	return data;
}

interface Author {
	name: string;
	url?: string;
	email?: string;
}

interface ReadmeSections {
	description?: string;
	installation?: string;
	changelog?: string;
	faq?: string;
	screenshots?: string;
	security?: string;
	otherNotes?: string;
	upgradeNotice?: string;
	[key: string]: string | undefined;
}

export interface Release {
	version: string;
	artifacts: Record<string, unknown[]>;
	suggests: Record<string, unknown>;
	requires?: Record<string, unknown>;
	provides?: Record<string, unknown>;
}

interface MetadataDocumentOptions {
	id: string;
	type: string;
	name?: string;
	slug: string;
	filename: string;
	description?: string;
	authors: Author[];
	license: string;
	security?: Array<{ email: string } | { url: string }>;
	keywords?: string[];
	sections?: ReadmeSections;
	releases?: Release[];
}

export interface MetadataDocument {
	'@context': string;
	id: string;
	type: string;
	name?: string;
	slug: string;
	filename: string;
	description?: string;
	authors: Author[];
	license: string;
	security: Array<{ email: string } | { url: string }>;
	keywords: string[];
	sections: ReadmeSections;
	releases: Release[];
}

/**
 * Creates a metadata document for a package.
 */
export function createMetadataDocument(options: MetadataDocumentOptions): MetadataDocument {
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

	const doc: MetadataDocument = {
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

interface ReleaseDocumentOptions {
	version: string;
	artifacts: Record<string, unknown[]>;
	requires?: Record<string, unknown>;
	suggests?: Record<string, unknown>;
	provides?: Record<string, unknown>;
}

/**
 * Creates a release document for a specific version.
 */
export function createReleaseDocument(options: ReleaseDocumentOptions): Release {
	const { version, artifacts, requires, suggests, provides } = options;

	const doc: Release = {
		version,
		artifacts,
		suggests: suggests || {},
	};

	// Optional properties - only include if non-empty
	if (requires && Object.keys(requires).length > 0) doc.requires = requires;
	if (provides && Object.keys(provides).length > 0) doc.provides = provides;

	return doc;
}

interface ArtifactOptions {
	url: string;
	checksum: string;
	signature?: string;
	contentType?: string;
}

interface Artifact {
	url: string;
	checksum: string;
	'content-type'?: string;
	signature?: string;
}

/**
 * Creates an artifact entry for a release.
 */
export function createArtifact(options: ArtifactOptions): Artifact {
	const { url, checksum, signature, contentType } = options;

	const artifact: Artifact = { url, checksum };
	if (contentType) {
		artifact['content-type'] = contentType;
	}
	if (signature) {
		artifact.signature = signature;
	}
	return artifact;
}

interface SignedArtifactOptions {
	url: string;
	data: Buffer | Uint8Array;
	keypair: Ed25519Keypair;
	contentType?: string;
}

/**
 * Creates a signed artifact entry.
 *
 * Signs the artifact data using Ed25519 over the SHA-384 hash, matching the
 * format expected by the verify_file_signature() function in WordPress.
 */
export async function createSignedArtifact(options: SignedArtifactOptions): Promise<Artifact> {
	const { url, data, keypair, contentType } = options;

	const checksum = await calculateChecksum(data);
	const signature = await signArtifact(data, keypair);

	return createArtifact({ url, checksum, signature, contentType });
}

/**
 * Formats a security contact value into the schema format.
 *
 * @param {string} value - Email address or URL
 */
function formatSecurityContact(value: string): { email: string } | { url: string } {
	// Check if it's a URL (has scheme) or plain email address
	if (/^[a-z][a-z0-9+.-]*:/i.test(value)) {
		return { url: value };
	}
	return { email: value };
}

interface AssetArtifact {
	url: string;
	'content-type': string;
	height: number | null;
	width: number | null;
}

interface AssetPattern {
	pattern: RegExp;
	type: 'banner' | 'icon';
	width: number | null;
	height: number | null;
}

/**
 * WordPress plugin banner dimensions.
 */
const BANNER_SMALL_WIDTH = 772;
const BANNER_SMALL_HEIGHT = 250;
const BANNER_LARGE_WIDTH = 1544;
const BANNER_LARGE_HEIGHT = 500;

/**
 * WordPress plugin icon dimensions.
 */
const ICON_SMALL_SIZE = 128;
const ICON_LARGE_SIZE = 256;

/**
 * Maximum number of keywords allowed in metadata.
 */
const MAX_KEYWORDS = 5;

/**
 * Asset file patterns for WordPress plugins.
 *
 * See https://developer.wordpress.org/plugins/wordpress-org/plugin-assets/
 */
const ASSET_PATTERNS: AssetPattern[] = [
	// Banners
	{
		pattern: new RegExp(`^banner-${BANNER_SMALL_WIDTH}x${BANNER_SMALL_HEIGHT}\\.(png|jpe?g|gif)$`, 'i'),
		type: 'banner',
		width: BANNER_SMALL_WIDTH,
		height: BANNER_SMALL_HEIGHT,
	},
	{
		pattern: new RegExp(`^banner-${BANNER_LARGE_WIDTH}x${BANNER_LARGE_HEIGHT}\\.(png|jpe?g|gif)$`, 'i'),
		type: 'banner',
		width: BANNER_LARGE_WIDTH,
		height: BANNER_LARGE_HEIGHT,
	},
	// Icons
	{
		pattern: /^icon\.svg$/i,
		type: 'icon',
		width: null,
		height: null,
	},
	{
		pattern: new RegExp(`^icon-${ICON_SMALL_SIZE}x${ICON_SMALL_SIZE}\\.(png|jpe?g|gif)$`, 'i'),
		type: 'icon',
		width: ICON_SMALL_SIZE,
		height: ICON_SMALL_SIZE,
	},
	{
		pattern: new RegExp(`^icon-${ICON_LARGE_SIZE}x${ICON_LARGE_SIZE}\\.(png|jpe?g|gif)$`, 'i'),
		type: 'icon',
		width: ICON_LARGE_SIZE,
		height: ICON_LARGE_SIZE,
	},
];

/**
 * Pattern for screenshot files: screenshot-{n}.(png|jpg)
 * Captures the screenshot number for sorting.
 */
const SCREENSHOT_PATTERN = /^screenshot-(\d+)\.(png|jpe?g)$/i;

/**
 * Maps file extensions to MIME types for assets.
 */
function getAssetContentType(filename: string): string {
	const ext = filename.split('.').pop()?.toLowerCase();
	switch (ext) {
		case 'png':
			return 'image/png';
		case 'jpg':
		case 'jpeg':
			return 'image/jpeg';
		case 'gif':
			return 'image/gif';
		case 'svg':
			return 'image/svg+xml';
		default:
			return 'application/octet-stream';
	}
}

interface FileDimensions {
	width: number;
	height: number;
}

/**
 * Matches filenames against asset patterns and constructs artifact entries.
 *
 * Pure function that processes a map of files and returns categorized
 * asset artifacts ready for inclusion in release documents.
 * @param {string} baseUrl - Base URL for assets (must end with /)
 */
export function matchAssetFiles(
	files: Record<string, FileDimensions | null>,
	baseUrl: string,
): { banners: AssetArtifact[]; icons: AssetArtifact[]; screenshots: AssetArtifact[] } {
	const filenames = Object.keys(files);
	const banners: AssetArtifact[] = [];
	const icons: AssetArtifact[] = [];

	// Iterate patterns and find matching files for banners and icons
	for (const assetPattern of ASSET_PATTERNS) {
		const file = filenames.find((f) => assetPattern.pattern.test(f));
		if (file) {
			const artifact: AssetArtifact = {
				url: `${baseUrl}${file}`,
				'content-type': getAssetContentType(file),
				height: assetPattern.height,
				width: assetPattern.width,
			};

			if (assetPattern.type === 'banner') {
				banners.push(artifact);
			} else {
				icons.push(artifact);
			}
		}
	}

	// Screenshots: find all matches and sort by number
	const screenshotMatches: Array<{ file: string; number: number }> = [];
	for (const file of filenames) {
		const match = SCREENSHOT_PATTERN.exec(file);
		if (match) {
			screenshotMatches.push({ file, number: parseInt(match[1], 10) });
		}
	}
	screenshotMatches.sort((a, b) => a.number - b.number);
	const screenshots: AssetArtifact[] = screenshotMatches.map(({ file }) => {
		const dim = files[file];
		return {
			url: `${baseUrl}${file}`,
			'content-type': getAssetContentType(file),
			height: dim?.height ?? null,
			width: dim?.width ?? null,
		};
	});

	return { banners, icons, screenshots };
}

interface DiscoverAssetsOptions {
	assetsDir: string;
	assetsUrl: string;
}

/**
 * Discovers asset files in a directory and constructs artifact entries.
 *
 * Scans for WordPress plugin asset files (banners, icons, and screenshots) and returns
 * arrays of artifact objects ready for inclusion in release documents.
 * @throws {Error} If directory doesn't exist or no assets found
 */
export async function discoverAssets(
	options: DiscoverAssetsOptions,
): Promise<{ banners: AssetArtifact[]; icons: AssetArtifact[]; screenshots: AssetArtifact[] }> {
	const { assetsDir, assetsUrl } = options;

	let filenames: string[];
	try {
		filenames = await readdir(assetsDir);
	} catch {
		throw new Error(`Assets directory not found: ${assetsDir}`);
	}

	// Ensure assetsUrl ends with /
	const baseUrl = assetsUrl.endsWith('/') ? assetsUrl : `${assetsUrl}/`;

	// Build files map with dimensions for screenshots
	const files: Record<string, FileDimensions | null> = {};
	for (const file of filenames) {
		if (SCREENSHOT_PATTERN.test(file)) {
			try {
				const buffer = readFileSync(join(assetsDir, file));
				const result = imageSize(buffer);
				if (result.width && result.height) {
					files[file] = { width: result.width, height: result.height };
				} else {
					files[file] = null;
				}
			} catch {
				// Ignore errors reading dimensions, will use null
				files[file] = null;
			}
		} else {
			files[file] = null;
		}
	}

	const { banners, icons, screenshots } = matchAssetFiles(files, baseUrl);

	if (banners.length === 0 && icons.length === 0 && screenshots.length === 0) {
		throw new Error(`No asset files found in directory: ${assetsDir}`);
	}

	return { banners, icons, screenshots };
}

interface BuildMetadataFromContentOptions {
	keypair: Ed25519Keypair;
	did: string;
	name?: string;
	slug: string;
	filename: string;
	description?: string;
	author?: { name: string; url?: string };
	license: string;
	securityContact?: string;
	keywords?: string[];
	sections?: ReadmeSections;
	existingReleases?: Release[];
	version?: string;
	requiresWp?: string;
	requiresPhp?: string;
	testedUpTo?: string;
	zipData: Buffer | Uint8Array;
	downloadUrl: string;
	banners?: AssetArtifact[];
	icons?: AssetArtifact[];
	screenshots?: AssetArtifact[];
}

/**
 * Builds complete FAIR metadata for a release of a plugin for WordPress.
 *
 * This is the core metadata building function that accepts pre-resolved final values.
 * Use buildMetadata() for a file-based wrapper that handles parsing and priority resolution.
 */
export async function buildMetadataFromContent(
	options: BuildMetadataFromContentOptions,
): Promise<{ metadata: MetadataDocument; overwrittenVersion: string | null }> {
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
		sections,

		// Existing releases
		existingReleases = [],

		// Release
		version,
		requiresWp,
		requiresPhp,
		testedUpTo,
		zipData,
		downloadUrl,

		// Assets
		banners = [],
		icons = [],
		screenshots = [],
	} = options;

	// Validate required fields
	if (!version) {
		throw new Error('Plugin file is missing required "Version:" header');
	}

	// Build authors array
	const authors: Author[] = author ? [author] : [];

	// Create signed artifact
	const artifact = await createSignedArtifact({
		url: downloadUrl,
		data: zipData,
		keypair,
		contentType: 'application/zip',
	});

	// Build requirements
	const requires: Record<string, string> = {};
	if (requiresWp) {
		requires['env:wp'] = `>=${requiresWp}`;
	}
	if (requiresPhp) {
		requires['env:php'] = `>=${requiresPhp}`;
	}

	// Build suggests (testedUpTo takes priority, fallback to requiresWp)
	const suggests: Record<string, string> = {};
	const suggestedWp = testedUpTo || requiresWp;
	if (suggestedWp) {
		suggests['env:wp'] = `>=${suggestedWp}`;
	}

	// Build artifacts object (order: banner, icon, screenshot, package)
	const artifacts: Record<string, unknown[]> = {};
	if (banners.length > 0) {
		artifacts.banner = banners;
	}
	if (icons.length > 0) {
		artifacts.icon = icons;
	}
	if (screenshots.length > 0) {
		artifacts.screenshot = screenshots;
	}
	artifacts.package = [artifact];

	// Create release
	const release = createReleaseDocument({
		version,
		artifacts,
		requires,
		suggests,
	});

	// Build security contacts array
	const security = securityContact ? [formatSecurityContact(securityContact)] : [];

	// Check if this version already exists in existing releases
	const existingVersionIndex = existingReleases.findIndex((r) => r.version === version);
	const overwrittenVersion = existingVersionIndex !== -1 ? version : null;

	// Filter out any existing release with the same version
	const filteredReleases = existingReleases.filter((r) => r.version !== version);

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
		keywords: (keywords || []).slice(0, MAX_KEYWORDS),
		sections,
		releases: [release, ...filteredReleases],
	});

	return { metadata, overwrittenVersion };
}

interface BuildMetadataOptions {
	did: string;
	keypair: Ed25519Keypair;
	pluginFile: string;
	zipFile: string;
	downloadUrl: string;
	existingReleases?: Release[];
	assetsDir?: string;
	assetsUrl?: string;
}

/**
 * Builds complete FAIR metadata for a release of a plugin for WordPress.
 *
 * File-based wrapper that handles all file reading, parsing, and priority resolution,
 * then delegates to buildMetadataFromContent() with final values.
 */
export async function buildMetadata(
	options: BuildMetadataOptions,
): Promise<{ metadata: MetadataDocument; overwrittenVersion: string | null }> {
	const { did, keypair, pluginFile, zipFile, downloadUrl, existingReleases = [], assetsDir, assetsUrl } = options;

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
		throw new Error(`Plugin ID mismatch: plugin file has "${pluginData.pluginId}" but DID "${did}" was provided`);
	}

	let readmeData: Partial<ReturnType<typeof parseReadmeFile>> = {};
	try {
		const readmeContent = await readFile(join(pluginDir, 'readme.txt'), 'utf-8');
		readmeData = parseReadmeFile(readmeContent);
	} catch {
		// No readme.txt found
	}

	let composerData: ReturnType<typeof parseComposerJson> = {};
	try {
		const composerContent = await readFile(join(pluginDir, 'composer.json'), 'utf-8');
		composerData = parseComposerJson(composerContent);
	} catch {
		// No composer.json found
	}

	let packageData: ReturnType<typeof parsePackageJson> = {};
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
	let author: { name: string; url?: string } | undefined;
	if (pluginData.author) {
		author = {
			name: pluginData.author,
			...(pluginData.authorUri && { url: pluginData.authorUri }),
		};
	}

	// Read zip data
	const zipData = await readFile(zipFile);

	// Discover assets if directory provided
	let banners: AssetArtifact[] = [];
	let icons: AssetArtifact[] = [];
	let screenshots: AssetArtifact[] = [];
	if (assetsDir && assetsUrl) {
		({ banners, icons, screenshots } = await discoverAssets({
			assetsDir,
			assetsUrl,
		}));
	}

	// Reconstruct screenshots section HTML using discovered screenshot assets
	// and descriptions from readme.txt
	const sections: ReadmeSections = { ...readmeData.sections };
	if (screenshots.length > 0) {
		const screenshotDescriptions = readmeData.screenshots || [];
		const items = screenshots
			.map((screenshot, index) => {
				const desc = screenshotDescriptions[index]?.description || '';
				const alt = desc ? desc.replace(/"/g, '&quot;') : '';
				const caption = desc ? marked.parse(desc) : '';
				return `<li><a href="${screenshot.url}"><img src="${screenshot.url}" alt="${alt}"></a>${caption}</li>`;
			})
			.join('\n');
		sections.screenshots = `<ol>\n${items}\n</ol>\n`;
	}

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
		sections,

		// Existing releases
		existingReleases,

		// Release
		version: pluginData.version,
		requiresWp: pluginData.requiresWp,
		requiresPhp: pluginData.requiresPhp,
		testedUpTo: readmeData.testedUpTo,
		zipData,
		downloadUrl,

		// Assets
		banners,
		icons,
		screenshots,
	});
}
