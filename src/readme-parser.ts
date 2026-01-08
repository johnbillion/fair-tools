/**
 * WordPress readme.txt parser.
 *
 * Parses WordPress plugin/theme readme.txt files into structured data.
 * Based on the WordPress readme.txt specification.
 *
 * @see https://developer.wordpress.org/plugins/wordpress-org/how-your-readme-txt-works/
 */

import { marked } from 'marked';

/**
 * Readme sections structure.
 *
 * @typedef {{
 *   description?: string,
 *   installation?: string,
 *   changelog?: string,
 *   faq?: string,
 *   screenshots?: string,
 *   security?: string,
 *   otherNotes?: string,
 *   upgradeNotice?: string
 * }} ReadmeSections
 */

/**
 * Normalizes a section name to camelCase.
 *
 * - "frequently asked questions" -> "faq"
 * - "upgrade notice" -> "upgradeNotice"
 * - "wp cli commands" -> "wpCliCommands"
 *
 * @param {string} name - Section name (already lowercase)
 * @returns {string} Normalized name in camelCase
 */
function normalizeSectionName(name) {
	// Special case mappings
	if (name === 'frequently asked questions') {
		return 'faq';
	}
	// Convert spaces to camelCase
	return name.replace(/\s+([a-z])/g, (_, c) => c.toUpperCase());
}

/**
 * Tokenizes WordPress readme.txt into header block and named sections.
 *
 * Supports both WordPress-flavour (== Section ==) and Markdown-flavour (## Section).
 *
 * @param {string} content - readme.txt file content
 * @returns {{ headerBlock: string, sections: Map<string, { content: string, originalTitle: string }> }}
 */
function tokenizeReadme(content) {
	const sections = new Map();

	// Match both WordPress-flavour (== Section ==) and Markdown-flavour (## Section)
	// Some readmes mix both styles, so we need to find all of them
	const wpSectionRegex = /^==(?!=)\s*(.+?)\s*==(?!=)\s*$/gm;
	const mdSectionRegex = /^##\s+(.+?)(?:\s*##)?\s*$/gm;

	const wpMatches = [...content.matchAll(wpSectionRegex)];
	const mdMatches = [...content.matchAll(mdSectionRegex)];

	// Combine and sort by position in the document
	const allMatches = [...wpMatches, ...mdMatches].sort((a, b) => a.index - b.index);

	if (allMatches.length === 0) {
		return { headerBlock: content, sections };
	}

	// Everything before the first section is the header block
	const headerBlock = content.slice(0, allMatches[0].index).trim();

	// Extract each section's content, preserving original title for unsupported sections
	for (let i = 0; i < allMatches.length; i++) {
		const originalTitle = allMatches[i][1].trim();
		const name = normalizeSectionName(originalTitle.toLowerCase());
		const start = allMatches[i].index + allMatches[i][0].length;
		const end = allMatches[i + 1]?.index ?? content.length;
		sections.set(name, {
			content: content.slice(start, end).trim(),
			originalTitle,
		});
	}

	return { headerBlock, sections };
}

/**
 * Parses header fields from the header block.
 *
 * @param {string} headerBlock - The header portion of readme.txt
 * @returns {Record<string, string>}
 */
function parseHeaderFields(headerBlock) {
	const fields = {};
	const lines = headerBlock.split('\n');

	for (const line of lines) {
		const match = line.match(/^([A-Za-z][A-Za-z\s]+):\s*(.+)$/);
		if (match) {
			const key = match[1].trim().toLowerCase().replace(/\s+/g, '_');
			fields[key] = match[2].trim();
		}
	}

	return fields;
}

/**
 * Extracts short description from header block.
 *
 * The short description is the first non-empty line after the header fields
 * that isn't a title or field definition.
 *
 * Supports both WordPress-flavour (=== Title ===) and Markdown-flavour (# Title).
 *
 * @param {string} headerBlock
 * @returns {string|undefined}
 */
function parseShortDescription(headerBlock) {
	const lines = headerBlock.split('\n');
	let pastTitle = false;

	for (const line of lines) {
		const trimmed = line.trim();
		// Skip WordPress-flavour title line (=== Title ===)
		if (trimmed.startsWith('===') && trimmed.endsWith('===')) {
			pastTitle = true;
			continue;
		}
		// Skip Markdown-flavour title line (# Title)
		if (/^#\s+/.test(trimmed)) {
			pastTitle = true;
			continue;
		}
		// Skip header fields
		if (/^[A-Za-z][A-Za-z\s]+:/.test(trimmed)) {
			pastTitle = true; // Header fields also indicate we're past the title
			continue;
		}
		// Skip empty lines
		if (!trimmed) {
			continue;
		}
		// Found it (must be after title or header fields)
		if (pastTitle) {
			return trimmed;
		}
	}
	return undefined;
}

/**
 * Parses Screenshots section into array of objects.
 *
 * Screenshots use the format:
 * 1. Description of first screenshot
 * 2. Description of second screenshot
 *
 * @param {string} content - Screenshots section content
 * @returns {Array<{ description: string }>}
 */
function parseScreenshotsSection(content) {
	const screenshots = [];
	const lines = content.split('\n');

	for (const line of lines) {
		const match = line.match(/^\s*\d+\.\s*(.+)$/);
		if (match) {
			screenshots.push({ description: match[1].trim() });
		}
	}

	return screenshots;
}

/**
 * Parses WordPress readme.txt file content.
 *
 * Extracts all header fields, short description, and parses
 * structured sections like FAQ and Screenshots.
 *
 * @param {string} content - readme.txt file content
 * @returns {{
 *   name: string | undefined,
 *   license: string | undefined,
 *   licenseUri: string | undefined,
 *   keywords: string[],
 *   shortDescription: string | undefined,
 *   contributors: string[] | undefined,
 *   requires: string | undefined,
 *   testedUpTo: string | undefined,
 *   requiresPhp: string | undefined,
 *   stableTag: string | undefined,
 *   donateLink: string | undefined,
 *   sections: ReadmeSections,
 *   screenshots?: Array<{ description: string }>
 * }}
 */
export function parseReadmeFile(content) {
	// Normalize line endings to Unix-style
	content = content.replace(/\r\n/g, '\n');

	const { headerBlock, sections: rawSections } = tokenizeReadme(content);
	const fields = parseHeaderFields(headerBlock);

	// Extract plugin name from === Plugin Name === or # Plugin Name
	const wpTitleMatch = headerBlock.match(/^===\s*(.+?)\s*===\s*$/m);
	const mdTitleMatch = headerBlock.match(/^#\s+(.+?)\s*$/m);
	const titleMatch = wpTitleMatch || mdTitleMatch;

	// Build sections object with just content (originalTitle used later for unsupported sections)
	/** @type {Record<string, string>} */
	const sectionsContent = {};
	for (const [key, { content }] of rawSections) {
		sectionsContent[key] = content;
	}

	// Build result with normalized field names
	const result = {
		name: titleMatch?.[1],
		license: fields.license,
		licenseUri: fields.license_uri,
		keywords: fields.tags
			? fields.tags
					.split(',')
					.map((t) => t.trim())
					.filter(Boolean)
			: [],
		shortDescription: parseShortDescription(headerBlock),
		contributors: fields.contributors
			? fields.contributors
					.split(',')
					.map((c) => c.trim())
					.filter(Boolean)
			: undefined,
		requires: fields.requires_at_least,
		testedUpTo: fields.tested_up_to,
		requiresPhp: fields.requires_php,
		stableTag: fields.stable_tag,
		donateLink: fields.donate_link,
		sections: sectionsContent,
	};

	// Parse screenshots section into structured data
	if (rawSections.has('screenshots')) {
		result.screenshots = parseScreenshotsSection(rawSections.get('screenshots').content);
	}

	// Supported sections per FAIR spec (plus upgradeNotice for WordPress compatibility)
	const supportedSections = [
		'description',
		'installation',
		'changelog',
		'faq',
		'screenshots',
		'security',
		'otherNotes',
		'upgradeNotice',
	];

	// Append unsupported sections to description (WordPress.org behavior)
	// Process in original order from the readme, using original title to preserve casing
	for (const [key, { content, originalTitle }] of rawSections) {
		if (!supportedSections.includes(key)) {
			const descriptionContent = result.sections.description || '';
			result.sections.description = descriptionContent + `\n\n### ${originalTitle}\n\n${content}`;
			delete result.sections[key];
		}
	}

	// Trim leading whitespace from description if it was empty before
	if (result.sections.description) {
		result.sections.description = result.sections.description.trim();
	}

	// Convert markdown sections to HTML
	for (const section of Object.keys(result.sections)) {
		// Convert WordPress-flavour subheadings to markdown before parsing
		// Handles 1-3 equals signs: = Heading =, == Heading ==, === Heading ===
		// All become #### Heading (h4) as they're subheadings within sections
		let markdown = result.sections[section].replace(/^={1,3}\s*(.+?)\s*={0,3}\s*$/gm, '#### $1');
		// Strip trailing hashes from markdown headings (e.g., "### Heading ###" -> "### Heading")
		// Some readmes use ATX-style closing hashes which marked doesn't handle
		markdown = markdown.replace(/^(#{1,6}\s+.+?)\s*#{1,6}\s*$/gm, '$1');
		result.sections[section] = marked.parse(markdown, {
			async: false,
			breaks: true, // WordPress readme uses single newlines for <br>
		});
	}

	// Reorder sections per FAIR spec order
	/** @type {Record<string, string>} */
	const orderedSections = {};
	for (const key of supportedSections) {
		if (result.sections[key] !== undefined) {
			orderedSections[key] = result.sections[key];
		}
	}
	result.sections = orderedSections;

	return result;
}
