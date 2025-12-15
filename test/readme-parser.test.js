import { describe, it } from 'node:test';
import assert from 'node:assert';
import { readFile, readdir, writeFile, mkdir } from 'node:fs/promises';
import { basename } from 'node:path';
import { parseReadmeFile } from '../src/readme-parser.js';

const RESULTS_DIR = 'test/results';

// Load all fixtures dynamically
const fixtures = {};

async function loadFixtures() {
	if (Object.keys(fixtures).length > 0) return fixtures;

	const files = await readdir('test/fixtures');
	const readmeFiles = files.filter(
		(f) => f.startsWith('readme.') && f.endsWith('.txt'),
	);

	for (const file of readmeFiles) {
		// Convert readme.user-switching.txt -> userSwitching
		const name = basename(file, '.txt')
			.replace('readme.', '')
			.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
		fixtures[name] = await readFile(`test/fixtures/${file}`, 'utf-8');
	}

	return fixtures;
}

describe('parseReadmeFile', () => {
	describe('all fixtures parse without errors', () => {
		it('parses all fixture files, extracts expected fields, and saves snapshots', async () => {
			const allFixtures = await loadFixtures();
			const fixtureNames = Object.keys(allFixtures);

			// Ensure we have fixtures loaded
			assert.ok(fixtureNames.length >= 17, 'Should have at least 17 fixtures');

			// Ensure results directory exists
			await mkdir(RESULTS_DIR, { recursive: true });

			// Get list of input files to derive output filenames
			const files = await readdir('test/fixtures');
			const readmeFiles = files.filter(
				(f) => f.startsWith('readme.') && f.endsWith('.txt'),
			);

			for (const file of readmeFiles) {
				// Convert readme.user-switching.txt -> userSwitching (for fixtures lookup)
				const name = basename(file, '.txt')
					.replace('readme.', '')
					.replace(/-([a-z])/g, (_, c) => c.toUpperCase());

				const content = allFixtures[name];
				const data = parseReadmeFile(content);

				// Save snapshot: readme.user-switching.txt -> readme.user-switching.json
				const outputFile = `${RESULTS_DIR}/${basename(file, '.txt')}.json`;
				await writeFile(outputFile, JSON.stringify(data, null, '\t') + '\n');

				// Every fixture should parse without throwing
				assert.ok(data, `${name}: should return data`);

				// Every fixture should have keywords array (even if empty)
				assert.ok(
					Array.isArray(data.keywords),
					`${name}: keywords should be array`,
				);

				// Every fixture should have sections object (even if empty)
				assert.ok(
					typeof data.sections === 'object',
					`${name}: sections should be object`,
				);

				// Most fixtures should have a name
				// (some edge cases might not, but real plugins should)
				if (data.name) {
					assert.ok(
						typeof data.name === 'string',
						`${name}: name should be string`,
					);
				}

				// If stableTag exists, it should be a string
				if (data.stableTag) {
					assert.ok(
						typeof data.stableTag === 'string',
						`${name}: stableTag should be string`,
					);
				}

				// If faq exists, it should be an array of objects with question/answer
				if (data.faq) {
					assert.ok(Array.isArray(data.faq), `${name}: faq should be array`);
					for (const item of data.faq) {
						assert.ok(
							typeof item.question === 'string',
							`${name}: faq question should be string`,
						);
						assert.ok(
							typeof item.answer === 'string',
							`${name}: faq answer should be string`,
						);
					}
				}

				// If screenshots exists, it should be an array of objects with description
				if (data.screenshots) {
					assert.ok(
						Array.isArray(data.screenshots),
						`${name}: screenshots should be array`,
					);
					for (const item of data.screenshots) {
						assert.ok(
							typeof item.description === 'string',
							`${name}: screenshot description should be string`,
						);
					}
				}
			}
		});
	});

	describe('edge cases', () => {
		it('returns empty keywords array when no tags', () => {
			const content = `=== Test Plugin ===
License: MIT

Short description here.
`;
			const data = parseReadmeFile(content);
			assert.deepStrictEqual(data.keywords, []);
		});

		it('returns undefined contributors when none present', () => {
			const content = `=== Test Plugin ===
License: MIT

Short description here.
`;
			const data = parseReadmeFile(content);
			assert.strictEqual(data.contributors, undefined);
		});

		it('returns empty sections when no section headers', () => {
			const content = `=== Test Plugin ===
License: MIT

Short description here.
`;
			const data = parseReadmeFile(content);
			assert.deepStrictEqual(data.sections, {});
		});

		it('handles content with no title', () => {
			const content = `License: MIT
Tags: test

Short description here.
`;
			const data = parseReadmeFile(content);
			assert.strictEqual(data.name, undefined);
			assert.strictEqual(data.license, 'MIT');
			assert.deepStrictEqual(data.keywords, ['test']);
		});

		it('trims whitespace from tags', () => {
			const content = `=== Test ===
Tags:   spaced ,  tags  ,  here

Description.
`;
			const data = parseReadmeFile(content);
			assert.deepStrictEqual(data.keywords, ['spaced', 'tags', 'here']);
		});

		it('trims whitespace from contributors', () => {
			const content = `=== Test ===
Contributors:   john ,  jane  ,  bob

Description.
`;
			const data = parseReadmeFile(content);
			assert.deepStrictEqual(data.contributors, ['john', 'jane', 'bob']);
		});

		it('stops short description at section heading', () => {
			const content = `=== Test Plugin ===
Tags: tag1

== Description ==

This should not be the short description.
`;
			const data = parseReadmeFile(content);
			assert.strictEqual(data.shortDescription, undefined);
		});

		it('handles mixed empty tags gracefully', () => {
			const content = `=== Test ===
Tags: valid, , , another

Description.
`;
			const data = parseReadmeFile(content);
			assert.deepStrictEqual(data.keywords, ['valid', 'another']);
		});
	});
});
