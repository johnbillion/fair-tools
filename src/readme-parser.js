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
 * Tokenizes WordPress readme.txt into header block and named sections.
 *
 * Supports both WordPress-flavour (== Section ==) and Markdown-flavour (## Section).
 *
 * @param {string} content - readme.txt file content
 * @returns {{ headerBlock: string, sections: Map<string, string> }}
 */
function tokenizeReadme(content) {
	const sections = new Map();

	// Try WordPress-flavour first: == Section == (but not === Title ===)
	let sectionRegex = /^==(?!=)\s*(.+?)\s*==(?!=)$/gm;
	let matches = [...content.matchAll(sectionRegex)];

	// If no WordPress-flavour sections, try Markdown-flavour: ## Section
	if (matches.length === 0) {
		sectionRegex = /^##\s+(.+)$/gm;
		matches = [...content.matchAll(sectionRegex)];
	}

	if (matches.length === 0) {
		return { headerBlock: content, sections };
	}

	// Everything before the first section is the header block
	const headerBlock = content.slice(0, matches[0].index).trim();

	// Extract each section's content
	for (let i = 0; i < matches.length; i++) {
		const name = matches[i][1].toLowerCase();
		const start = matches[i].index + matches[i][0].length;
		const end = matches[i + 1]?.index ?? content.length;
		sections.set(name, content.slice(start, end).trim());
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
 * Parses FAQ section into Q&A pairs.
 *
 * Supports both formats:
 * - WordPress-flavour: = Question here =
 * - Markdown-flavour: ### Question here
 *
 * @param {string} content - FAQ section content
 * @returns {Array<{ question: string, answer: string }>}
 */
function parseFaqSection(content) {
	const faq = [];

	// Try WordPress-flavour first: = Question =
	let questionRegex = /^=\s*(.+?)\s*=$/gm;
	let matches = [...content.matchAll(questionRegex)];

	// If no WordPress-flavour questions, try Markdown-flavour: ### Question
	if (matches.length === 0) {
		questionRegex = /^###\s+(.+)$/gm;
		matches = [...content.matchAll(questionRegex)];
	}

	for (let i = 0; i < matches.length; i++) {
		const question = matches[i][1];
		const start = matches[i].index + matches[i][0].length;
		const end = matches[i + 1]?.index ?? content.length;
		const answer = content.slice(start, end).trim();
		faq.push({ question, answer });
	}

	return faq;
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
 *   sections: Record<string, string>,
 *   faq?: Array<{ question: string, answer: string }>,
 *   screenshots?: Array<{ description: string }>
 * }}
 */
export function parseReadmeFile(content) {
	// Normalize line endings to Unix-style
	content = content.replace(/\r\n/g, '\n');

	const { headerBlock, sections } = tokenizeReadme(content);
	const fields = parseHeaderFields(headerBlock);

	// Extract plugin name from === Plugin Name === or # Plugin Name
	const wpTitleMatch = headerBlock.match(/^===\s*(.+?)\s*===$/m);
	const mdTitleMatch = headerBlock.match(/^#\s+(.+)$/m);
	const titleMatch = wpTitleMatch || mdTitleMatch;

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
		sections: Object.fromEntries(sections),
	};

	// Parse structured sections (check common variations of section names)
	const faqSection =
		sections.get('faq') || sections.get('frequently asked questions');
	if (faqSection) {
		result.faq = parseFaqSection(faqSection);
	}
	if (sections.has('screenshots')) {
		result.screenshots = parseScreenshotsSection(sections.get('screenshots'));
	}

	// Convert markdown sections to HTML
	for (const section of ['description', 'installation']) {
		if (result.sections[section]) {
			// Convert WordPress-flavour subheadings to markdown before parsing
			// = Heading = -> #### Heading (h4)
			const markdown = result.sections[section].replace(
				/^=\s*(.+?)\s*=$/gm,
				'#### $1',
			);
			result.sections[section] = marked.parse(markdown, {
				async: false,
			});
		}
	}

	return result;
}
