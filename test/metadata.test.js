import { describe, it } from 'node:test';
import assert from 'node:assert';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
	buildMetadataFromContent,
	createArtifact,
	createSignedArtifact,
	discoverAssets,
	matchAssetFiles,
	parseComposerJson,
	parsePackageJson,
	parsePluginHeaders,
} from '../src/metadata.js';
import { parseReadmeFile } from '../src/readme-parser.js';
import { generateVerificationKeyPair } from '../src/keys.js';

describe('buildMetadataFromContent', () => {
	it('throws if version is missing', async () => {
		const { keypair } = await generateVerificationKeyPair();

		await assert.rejects(
			buildMetadataFromContent({
				did: 'did:plc:test123',
				keypair,
				slug: 'test-plugin',
				filename: 'test-plugin/test-plugin.php',
				zipData: Buffer.from('fake zip'),
				downloadUrl: 'https://example.com/test.zip',
			}),
			{
				message: 'Plugin file is missing required "Version:" header',
			},
		);
	});

	it('succeeds with valid did and version', async () => {
		const { keypair } = await generateVerificationKeyPair();

		const { metadata } = await buildMetadataFromContent({
			did: 'did:plc:validtest123',
			keypair,
			slug: 'valid-plugin',
			filename: 'valid-plugin/valid-plugin.php',
			version: '2.0.0',
			name: 'Valid Test Plugin',
			description: 'A valid test plugin',
			author: { name: 'Test Author' },
			zipData: Buffer.from('fake zip'),
			downloadUrl: 'https://example.com/valid.zip',
		});

		assert.strictEqual(metadata.id, 'did:plc:validtest123');
		assert.strictEqual(metadata.name, 'Valid Test Plugin');
		assert.strictEqual(metadata.slug, 'valid-plugin');
		assert.strictEqual(metadata.filename, 'valid-plugin/valid-plugin.php');
		assert.strictEqual(metadata.releases[0].version, '2.0.0');
		assert.strictEqual(metadata.description, 'A valid test plugin');
		assert.strictEqual(metadata.authors[0].name, 'Test Author');
	});

	it('includes keywords from options', async () => {
		const { keypair } = await generateVerificationKeyPair();

		const { metadata } = await buildMetadataFromContent({
			did: 'did:plc:test123',
			keypair,
			slug: 'test-plugin',
			filename: 'test-plugin/test-plugin.php',
			version: '1.0.0',
			keywords: ['tag1', 'tag2', 'tag3'],
			description: 'This is the short description.',
			license: 'GPL-2.0-or-later',
			zipData: Buffer.from('fake zip'),
			downloadUrl: 'https://example.com/test.zip',
		});

		assert.deepStrictEqual(metadata.keywords, ['tag1', 'tag2', 'tag3']);
		assert.strictEqual(metadata.description, 'This is the short description.');
		assert.strictEqual(metadata.license, 'GPL-2.0-or-later');
	});

	it('uses provided license', async () => {
		const { keypair } = await generateVerificationKeyPair();

		const { metadata } = await buildMetadataFromContent({
			did: 'did:plc:test123',
			keypair,
			slug: 'test-plugin',
			filename: 'test-plugin/test-plugin.php',
			version: '1.0.0',
			license: 'MIT',
			zipData: Buffer.from('fake zip'),
			downloadUrl: 'https://example.com/test.zip',
		});

		assert.strictEqual(metadata.license, 'MIT');
	});

	it('includes requirements from options', async () => {
		const { keypair } = await generateVerificationKeyPair();

		const { metadata } = await buildMetadataFromContent({
			did: 'did:plc:test123',
			keypair,
			slug: 'test-plugin',
			filename: 'test-plugin/test-plugin.php',
			version: '1.0.0',
			requiresWp: '6.0',
			requiresPhp: '8.1',
			zipData: Buffer.from('fake zip'),
			downloadUrl: 'https://example.com/test.zip',
		});

		assert.deepStrictEqual(metadata.releases[0].requires, {
			'env:wp': '>=6.0',
			'env:php': '>=8.1',
		});
	});

	it('includes suggests with testedUpTo when provided', async () => {
		const { keypair } = await generateVerificationKeyPair();

		const { metadata } = await buildMetadataFromContent({
			did: 'did:plc:test123',
			keypair,
			slug: 'test-plugin',
			filename: 'test-plugin/test-plugin.php',
			version: '1.0.0',
			requiresWp: '6.0',
			testedUpTo: '6.4',
			zipData: Buffer.from('fake zip'),
			downloadUrl: 'https://example.com/test.zip',
		});

		assert.deepStrictEqual(metadata.releases[0].suggests, {
			'env:wp': '>=6.4',
		});
	});

	it('falls back to requiresWp for suggests when testedUpTo is not provided', async () => {
		const { keypair } = await generateVerificationKeyPair();

		const { metadata } = await buildMetadataFromContent({
			did: 'did:plc:test123',
			keypair,
			slug: 'test-plugin',
			filename: 'test-plugin/test-plugin.php',
			version: '1.0.0',
			requiresWp: '6.0',
			zipData: Buffer.from('fake zip'),
			downloadUrl: 'https://example.com/test.zip',
		});

		assert.deepStrictEqual(metadata.releases[0].suggests, {
			'env:wp': '>=6.0',
		});
	});

	it('sets suggests to empty object when neither testedUpTo nor requiresWp is provided', async () => {
		const { keypair } = await generateVerificationKeyPair();

		const { metadata } = await buildMetadataFromContent({
			did: 'did:plc:test123',
			keypair,
			slug: 'test-plugin',
			filename: 'test-plugin/test-plugin.php',
			version: '1.0.0',
			zipData: Buffer.from('fake zip'),
			downloadUrl: 'https://example.com/test.zip',
		});

		assert.deepStrictEqual(metadata.releases[0].suggests, {});
	});

	it('includes security contact from securityContact option', async () => {
		const { keypair } = await generateVerificationKeyPair();

		const { metadata } = await buildMetadataFromContent({
			did: 'did:plc:test123',
			keypair,
			slug: 'test-plugin',
			filename: 'test-plugin/test-plugin.php',
			version: '1.0.0',
			securityContact: 'https://example.com/security',
			zipData: Buffer.from('fake zip'),
			downloadUrl: 'https://example.com/test.zip',
		});

		assert.deepStrictEqual(metadata.security, [
			{ url: 'https://example.com/security' },
		]);
	});

	it('has empty security array when no securityContact provided', async () => {
		const { keypair } = await generateVerificationKeyPair();

		const { metadata } = await buildMetadataFromContent({
			did: 'did:plc:test123',
			keypair,
			slug: 'test-plugin',
			filename: 'test-plugin/test-plugin.php',
			version: '1.0.0',
			zipData: Buffer.from('fake zip'),
			downloadUrl: 'https://example.com/test.zip',
		});

		assert.deepStrictEqual(metadata.security, []);
	});

	it('formats email security contact correctly', async () => {
		const { keypair } = await generateVerificationKeyPair();

		const { metadata } = await buildMetadataFromContent({
			did: 'did:plc:test123',
			keypair,
			slug: 'test-plugin',
			filename: 'test-plugin/test-plugin.php',
			version: '1.0.0',
			securityContact: 'security@example.com',
			zipData: Buffer.from('fake zip'),
			downloadUrl: 'https://example.com/test.zip',
		});

		assert.deepStrictEqual(metadata.security, [
			{ email: 'security@example.com' },
		]);
	});

	it('formats URL security contact correctly', async () => {
		const { keypair } = await generateVerificationKeyPair();

		const { metadata } = await buildMetadataFromContent({
			did: 'did:plc:test123',
			keypair,
			slug: 'test-plugin',
			filename: 'test-plugin/test-plugin.php',
			version: '1.0.0',
			securityContact: 'https://example.com/security-policy',
			zipData: Buffer.from('fake zip'),
			downloadUrl: 'https://example.com/test.zip',
		});

		assert.deepStrictEqual(metadata.security, [
			{ url: 'https://example.com/security-policy' },
		]);
	});

	it('treats mailto: URLs as URLs not emails', async () => {
		const { keypair } = await generateVerificationKeyPair();

		const { metadata } = await buildMetadataFromContent({
			did: 'did:plc:test123',
			keypair,
			slug: 'test-plugin',
			filename: 'test-plugin/test-plugin.php',
			version: '1.0.0',
			securityContact: 'mailto:security@example.com',
			zipData: Buffer.from('fake zip'),
			downloadUrl: 'https://example.com/test.zip',
		});

		assert.deepStrictEqual(metadata.security, [
			{ url: 'mailto:security@example.com' },
		]);
	});

	it('includes sections from options', async () => {
		const { keypair } = await generateVerificationKeyPair();

		const { metadata } = await buildMetadataFromContent({
			did: 'did:plc:test123',
			keypair,
			slug: 'test-plugin',
			filename: 'test-plugin/test-plugin.php',
			version: '1.0.0',
			sections: {
				description: '<p>This is the description.</p>',
				installation: '<p>Upload the plugin.</p>',
				faq: '<h4>Question?</h4><p>Answer.</p>',
			},
			zipData: Buffer.from('fake zip'),
			downloadUrl: 'https://example.com/test.zip',
		});

		assert.deepStrictEqual(metadata.sections, {
			description: '<p>This is the description.</p>',
			installation: '<p>Upload the plugin.</p>',
			faq: '<h4>Question?</h4><p>Answer.</p>',
		});
	});

	it('defaults sections to empty object when not provided', async () => {
		const { keypair } = await generateVerificationKeyPair();

		const { metadata } = await buildMetadataFromContent({
			did: 'did:plc:test123',
			keypair,
			slug: 'test-plugin',
			filename: 'test-plugin/test-plugin.php',
			version: '1.0.0',
			zipData: Buffer.from('fake zip'),
			downloadUrl: 'https://example.com/test.zip',
		});

		assert.deepStrictEqual(metadata.sections, {});
	});

	it('returns overwrittenVersion as null when no matching version exists', async () => {
		const { keypair } = await generateVerificationKeyPair();

		const { metadata, overwrittenVersion } = await buildMetadataFromContent({
			did: 'did:plc:test123',
			keypair,
			slug: 'test-plugin',
			filename: 'test-plugin/test-plugin.php',
			version: '1.0.0',
			existingReleases: [{ version: '0.9.0' }],
			zipData: Buffer.from('fake zip'),
			downloadUrl: 'https://example.com/test.zip',
		});

		assert.strictEqual(overwrittenVersion, null);
		assert.strictEqual(metadata.releases.length, 2);
		assert.strictEqual(metadata.releases[0].version, '1.0.0');
		assert.strictEqual(metadata.releases[1].version, '0.9.0');
	});

	it('returns overwrittenVersion when matching version exists in existingReleases', async () => {
		const { keypair } = await generateVerificationKeyPair();

		const { metadata, overwrittenVersion } = await buildMetadataFromContent({
			did: 'did:plc:test123',
			keypair,
			slug: 'test-plugin',
			filename: 'test-plugin/test-plugin.php',
			version: '1.0.0',
			existingReleases: [
				{ version: '1.0.0', artifacts: { package: [{ url: 'old' }] } },
				{ version: '0.9.0' },
			],
			zipData: Buffer.from('fake zip'),
			downloadUrl: 'https://example.com/test.zip',
		});

		assert.strictEqual(overwrittenVersion, '1.0.0');
		assert.strictEqual(metadata.releases.length, 2);
		assert.strictEqual(metadata.releases[0].version, '1.0.0');
		assert.strictEqual(metadata.releases[1].version, '0.9.0');
		// Verify the new release replaced the old one (different URL)
		assert.strictEqual(
			metadata.releases[0].artifacts.package[0].url,
			'https://example.com/test.zip',
		);
	});

	it('preserves other releases when overwriting a version', async () => {
		const { keypair } = await generateVerificationKeyPair();

		const { metadata, overwrittenVersion } = await buildMetadataFromContent({
			did: 'did:plc:test123',
			keypair,
			slug: 'test-plugin',
			filename: 'test-plugin/test-plugin.php',
			version: '1.1.0',
			existingReleases: [
				{ version: '1.1.0' },
				{ version: '1.0.0' },
				{ version: '0.9.0' },
			],
			zipData: Buffer.from('fake zip'),
			downloadUrl: 'https://example.com/test.zip',
		});

		assert.strictEqual(overwrittenVersion, '1.1.0');
		assert.strictEqual(metadata.releases.length, 3);
		assert.strictEqual(metadata.releases[0].version, '1.1.0');
		assert.strictEqual(metadata.releases[1].version, '1.0.0');
		assert.strictEqual(metadata.releases[2].version, '0.9.0');
	});
});

describe('parseReadmeFile', () => {
	it('parses license from readme', () => {
		const content = `=== Test Plugin ===
License: GPL-2.0-or-later

Short description here.
`;
		const data = parseReadmeFile(content);
		assert.strictEqual(data.license, 'GPL-2.0-or-later');
	});

	it('parses tags into keywords array', () => {
		const content = `=== Test Plugin ===
Tags: seo, performance, cache

Short description here.
`;
		const data = parseReadmeFile(content);
		assert.deepStrictEqual(data.keywords, ['seo', 'performance', 'cache']);
	});

	it('returns empty keywords array when no tags', () => {
		const content = `=== Test Plugin ===
License: MIT

Short description here.
`;
		const data = parseReadmeFile(content);
		assert.deepStrictEqual(data.keywords, []);
	});

	it('extracts short description after header fields', () => {
		const content = `=== Test Plugin ===
Tags: tag1, tag2
License: GPL-2.0

This is the short description.

== Description ==

Long description here.
`;
		const data = parseReadmeFile(content);
		assert.strictEqual(data.shortDescription, 'This is the short description.');
	});

	it('stops at section heading', () => {
		const content = `=== Test Plugin ===
Tags: tag1

== Description ==

This should not be the short description.
`;
		const data = parseReadmeFile(content);
		assert.strictEqual(data.shortDescription, undefined);
	});

	it('trims whitespace from tags', () => {
		const content = `=== Test Plugin ===
Tags:   spaced ,  tags  ,  here

Description.
`;
		const data = parseReadmeFile(content);
		assert.deepStrictEqual(data.keywords, ['spaced', 'tags', 'here']);
	});
});

describe('parsePluginHeaders', () => {
	it('parses all standard headers', () => {
		const content = `<?php
/**
 * Plugin Name: My Plugin
 * Plugin URI: https://example.com/plugin
 * Plugin ID: did:plc:abc123
 * Description: A test plugin
 * Version: 1.2.3
 * Author: John Doe
 * Author URI: https://example.com
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: my-plugin
 * Domain Path: /languages
 * Requires at least: 6.0
 * Requires PHP: 8.1
 * Update URI: https://example.com/updates
 * Security: security@example.com
 */
`;
		const headers = parsePluginHeaders(content);
		assert.strictEqual(headers.name, 'My Plugin');
		assert.strictEqual(headers.pluginUri, 'https://example.com/plugin');
		assert.strictEqual(headers.pluginId, 'did:plc:abc123');
		assert.strictEqual(headers.description, 'A test plugin');
		assert.strictEqual(headers.version, '1.2.3');
		assert.strictEqual(headers.author, 'John Doe');
		assert.strictEqual(headers.authorUri, 'https://example.com');
		assert.strictEqual(headers.license, 'GPL-2.0-or-later');
		assert.strictEqual(
			headers.licenseUri,
			'https://www.gnu.org/licenses/gpl-2.0.html',
		);
		assert.strictEqual(headers.textDomain, 'my-plugin');
		assert.strictEqual(headers.domainPath, '/languages');
		assert.strictEqual(headers.requiresWp, '6.0');
		assert.strictEqual(headers.requiresPhp, '8.1');
		assert.strictEqual(headers.updateUri, 'https://example.com/updates');
		assert.strictEqual(headers.security, 'security@example.com');
	});

	it('parses Security header as email', () => {
		const content = `<?php
/**
 * Plugin Name: Test Plugin
 * Plugin ID: did:plc:test123
 * Version: 1.0.0
 * Security: security@example.com
 */
`;
		const headers = parsePluginHeaders(content);
		assert.strictEqual(headers.security, 'security@example.com');
	});

	it('parses Security header as URL', () => {
		const content = `<?php
/**
 * Plugin Name: Test Plugin
 * Plugin ID: did:plc:test123
 * Version: 1.0.0
 * Security: https://example.com/security
 */
`;
		const headers = parsePluginHeaders(content);
		assert.strictEqual(headers.security, 'https://example.com/security');
	});

	it('returns empty object for content without headers', () => {
		const content = `<?php
// No headers here
echo "Hello";
`;
		const headers = parsePluginHeaders(content);
		assert.deepStrictEqual(headers, {});
	});

	it('trims whitespace from aligned header values', () => {
		const content = `<?php
/**
 * Plugin Name:       My Plugin
 * Plugin URI:        https://example.com/plugin
 * Plugin ID:         did:plc:abc123
 * Description:       A test plugin
 * Version:           1.2.3
 * Author:            John Doe
 * Author URI:        https://example.com
 * License:           GPL-2.0-or-later
 * Requires at least: 6.0
 * Requires PHP:      8.1
 */
`;
		const headers = parsePluginHeaders(content);
		assert.strictEqual(headers.name, 'My Plugin');
		assert.strictEqual(headers.pluginUri, 'https://example.com/plugin');
		assert.strictEqual(headers.pluginId, 'did:plc:abc123');
		assert.strictEqual(headers.description, 'A test plugin');
		assert.strictEqual(headers.version, '1.2.3');
		assert.strictEqual(headers.author, 'John Doe');
		assert.strictEqual(headers.authorUri, 'https://example.com');
		assert.strictEqual(headers.license, 'GPL-2.0-or-later');
		assert.strictEqual(headers.requiresWp, '6.0');
		assert.strictEqual(headers.requiresPhp, '8.1');
	});
});

describe('parseComposerJson', () => {
	it('extracts license from composer.json', () => {
		const content = JSON.stringify({
			name: 'test/plugin',
			license: 'MIT',
		});

		const data = parseComposerJson(content);
		assert.strictEqual(data.license, 'MIT');
	});

	it('extracts security contact from composer.json support.security field', () => {
		const content = JSON.stringify({
			name: 'test/plugin',
			support: {
				security: 'https://example.com/security-policy',
			},
		});

		const data = parseComposerJson(content);
		assert.strictEqual(
			data.securityContact,
			'https://example.com/security-policy',
		);
	});

	it('extracts both license and security contact', () => {
		const content = JSON.stringify({
			name: 'test/plugin',
			license: 'GPL-2.0-or-later',
			support: {
				security: 'security@example.com',
			},
		});

		const data = parseComposerJson(content);
		assert.strictEqual(data.license, 'GPL-2.0-or-later');
		assert.strictEqual(data.securityContact, 'security@example.com');
	});

	it('returns empty object when fields not present', () => {
		const content = JSON.stringify({
			name: 'test/plugin',
			support: {
				email: 'support@example.com',
			},
		});

		const data = parseComposerJson(content);
		assert.strictEqual(data.license, undefined);
		assert.strictEqual(data.securityContact, undefined);
	});

	it('returns empty object for invalid JSON', () => {
		const content = 'not valid json {';

		const data = parseComposerJson(content);
		assert.deepStrictEqual(data, {});
	});
});

describe('parsePackageJson', () => {
	it('extracts license from package.json', () => {
		const content = JSON.stringify({
			name: 'test-plugin',
			license: 'MIT',
		});

		const data = parsePackageJson(content);
		assert.strictEqual(data.license, 'MIT');
	});

	it('returns empty object when license not present', () => {
		const content = JSON.stringify({
			name: 'test-plugin',
			version: '1.0.0',
		});

		const data = parsePackageJson(content);
		assert.strictEqual(data.license, undefined);
	});

	it('returns empty object for invalid JSON', () => {
		const content = 'not valid json {';

		const data = parsePackageJson(content);
		assert.deepStrictEqual(data, {});
	});
});

describe('createArtifact', () => {
	it('creates artifact with url and checksum', () => {
		const artifact = createArtifact({
			url: 'https://example.com/file.zip',
			checksum: 'sha256:abc123',
		});

		assert.deepStrictEqual(artifact, {
			url: 'https://example.com/file.zip',
			checksum: 'sha256:abc123',
		});
	});

	it('includes signature when provided', () => {
		const artifact = createArtifact({
			url: 'https://example.com/file.zip',
			checksum: 'sha256:abc123',
			signature: 'sig123',
		});

		assert.deepStrictEqual(artifact, {
			url: 'https://example.com/file.zip',
			checksum: 'sha256:abc123',
			signature: 'sig123',
		});
	});

	it('includes content-type when provided', () => {
		const artifact = createArtifact({
			url: 'https://example.com/file.zip',
			checksum: 'sha256:abc123',
			contentType: 'application/zip',
		});

		assert.deepStrictEqual(artifact, {
			url: 'https://example.com/file.zip',
			checksum: 'sha256:abc123',
			'content-type': 'application/zip',
		});
	});

	it('includes all optional fields when provided', () => {
		const artifact = createArtifact({
			url: 'https://example.com/file.zip',
			checksum: 'sha256:abc123',
			contentType: 'application/zip',
			signature: 'sig123',
		});

		assert.deepStrictEqual(artifact, {
			url: 'https://example.com/file.zip',
			checksum: 'sha256:abc123',
			'content-type': 'application/zip',
			signature: 'sig123',
		});
	});
});

describe('createSignedArtifact', () => {
	it('creates artifact with url, checksum, and signature', async () => {
		const { keypair } = await generateVerificationKeyPair();

		const artifact = await createSignedArtifact({
			url: 'https://example.com/file.zip',
			data: Buffer.from('test data'),
			keypair,
		});

		assert.deepStrictEqual(Object.keys(artifact).sort(), [
			'checksum',
			'signature',
			'url',
		]);
		assert.strictEqual(artifact.url, 'https://example.com/file.zip');
		assert.ok(artifact.checksum.startsWith('sha256:'));
		assert.ok(artifact.signature);
	});

	it('includes content-type when provided', async () => {
		const { keypair } = await generateVerificationKeyPair();

		const artifact = await createSignedArtifact({
			url: 'https://example.com/file.zip',
			data: Buffer.from('test data'),
			keypair,
			contentType: 'application/zip',
		});

		assert.deepStrictEqual(Object.keys(artifact).sort(), [
			'checksum',
			'content-type',
			'signature',
			'url',
		]);
		assert.strictEqual(artifact.url, 'https://example.com/file.zip');
		assert.ok(artifact.checksum.startsWith('sha256:'));
		assert.ok(artifact.signature);
		assert.strictEqual(artifact['content-type'], 'application/zip');
	});
});

describe('buildMetadataFromContent artifact content-type', () => {
	it('includes application/zip content-type in artifact', async () => {
		const { keypair } = await generateVerificationKeyPair();

		const { metadata } = await buildMetadataFromContent({
			did: 'did:plc:test123',
			keypair,
			slug: 'test-plugin',
			filename: 'test-plugin/test-plugin.php',
			version: '1.0.0',
			zipData: Buffer.from('fake zip'),
			downloadUrl: 'https://example.com/test.zip',
		});

		const artifact = metadata.releases[0].artifacts.package[0];
		assert.strictEqual(artifact['content-type'], 'application/zip');
	});
});

describe('discoverAssets', () => {
	it('throws when directory does not exist', async () => {
		await assert.rejects(
			discoverAssets({
				assetsDir: '/nonexistent/path',
				assetsUrl: 'https://example.com/assets/',
			}),
			{
				message: 'Assets directory not found: /nonexistent/path',
			},
		);
	});

	it('throws when no matching asset files found', async () => {
		const testDir = join(tmpdir(), `fair-test-${Date.now()}`);
		await mkdir(testDir);

		try {
			await writeFile(join(testDir, 'unrelated.txt'), 'not an asset');

			await assert.rejects(
				discoverAssets({
					assetsDir: testDir,
					assetsUrl: 'https://example.com/assets/',
				}),
				{
					message: `No asset files found in directory: ${testDir}`,
				},
			);
		} finally {
			await rm(testDir, { recursive: true });
		}
	});

	it('discovers banner files', async () => {
		const testDir = join(tmpdir(), `fair-test-${Date.now()}`);
		await mkdir(testDir);

		try {
			await writeFile(join(testDir, 'banner-772x250.png'), '');
			await writeFile(join(testDir, 'banner-1544x500.jpg'), '');

			const { banners, icons } = await discoverAssets({
				assetsDir: testDir,
				assetsUrl: 'https://example.com/assets/',
			});

			assert.strictEqual(banners.length, 2);
			assert.strictEqual(icons.length, 0);

			const banner772 = banners.find((b) => b.width === 772);
			assert.strictEqual(
				banner772.url,
				'https://example.com/assets/banner-772x250.png',
			);
			assert.strictEqual(banner772['content-type'], 'image/png');
			assert.strictEqual(banner772.height, 250);
			assert.strictEqual(banner772.width, 772);

			const banner1544 = banners.find((b) => b.width === 1544);
			assert.strictEqual(
				banner1544.url,
				'https://example.com/assets/banner-1544x500.jpg',
			);
			assert.strictEqual(banner1544['content-type'], 'image/jpeg');
			assert.strictEqual(banner1544.height, 500);
			assert.strictEqual(banner1544.width, 1544);
		} finally {
			await rm(testDir, { recursive: true });
		}
	});

	it('discovers icon files', async () => {
		const testDir = join(tmpdir(), `fair-test-${Date.now()}`);
		await mkdir(testDir);

		try {
			await writeFile(join(testDir, 'icon.svg'), '');
			await writeFile(join(testDir, 'icon-128x128.png'), '');
			await writeFile(join(testDir, 'icon-256x256.gif'), '');

			const { banners, icons } = await discoverAssets({
				assetsDir: testDir,
				assetsUrl: 'https://example.com/assets',
			});

			assert.strictEqual(banners.length, 0);
			assert.strictEqual(icons.length, 3);

			const svg = icons.find((i) => i.url.endsWith('.svg'));
			assert.strictEqual(svg.url, 'https://example.com/assets/icon.svg');
			assert.strictEqual(svg['content-type'], 'image/svg+xml');
			assert.strictEqual(svg.height, null);
			assert.strictEqual(svg.width, null);

			const icon128 = icons.find((i) => i.width === 128);
			assert.strictEqual(
				icon128.url,
				'https://example.com/assets/icon-128x128.png',
			);
			assert.strictEqual(icon128['content-type'], 'image/png');
			assert.strictEqual(icon128.height, 128);

			const icon256 = icons.find((i) => i.width === 256);
			assert.strictEqual(
				icon256.url,
				'https://example.com/assets/icon-256x256.gif',
			);
			assert.strictEqual(icon256['content-type'], 'image/gif');
		} finally {
			await rm(testDir, { recursive: true });
		}
	});

	it('adds trailing slash to assetsUrl if missing', async () => {
		const testDir = join(tmpdir(), `fair-test-${Date.now()}`);
		await mkdir(testDir);

		try {
			await writeFile(join(testDir, 'icon.svg'), '');

			const { icons } = await discoverAssets({
				assetsDir: testDir,
				assetsUrl: 'https://example.com/assets',
			});

			assert.strictEqual(icons[0].url, 'https://example.com/assets/icon.svg');
		} finally {
			await rm(testDir, { recursive: true });
		}
	});

	it('handles assetsUrl with trailing slash', async () => {
		const testDir = join(tmpdir(), `fair-test-${Date.now()}`);
		await mkdir(testDir);

		try {
			await writeFile(join(testDir, 'icon.svg'), '');

			const { icons } = await discoverAssets({
				assetsDir: testDir,
				assetsUrl: 'https://example.com/assets/',
			});

			assert.strictEqual(icons[0].url, 'https://example.com/assets/icon.svg');
		} finally {
			await rm(testDir, { recursive: true });
		}
	});

	it('ignores non-matching files', async () => {
		const testDir = join(tmpdir(), `fair-test-${Date.now()}`);
		await mkdir(testDir);

		try {
			await writeFile(join(testDir, 'icon.svg'), '');
			await writeFile(join(testDir, 'screenshot-1.png'), '');
			await writeFile(join(testDir, 'readme.txt'), '');

			const { banners, icons } = await discoverAssets({
				assetsDir: testDir,
				assetsUrl: 'https://example.com/assets/',
			});

			assert.strictEqual(banners.length, 0);
			assert.strictEqual(icons.length, 1);
		} finally {
			await rm(testDir, { recursive: true });
		}
	});
});

describe('matchAssetFiles', () => {
	it('returns empty arrays for no matching files', () => {
		const { banners, icons, screenshots } = matchAssetFiles(
			{ 'readme.txt': null, 'random.jpg': null },
			'https://example.com/assets/',
		);

		assert.deepStrictEqual(banners, []);
		assert.deepStrictEqual(icons, []);
		assert.deepStrictEqual(screenshots, []);
	});

	it('matches standard banner file', () => {
		const { banners } = matchAssetFiles(
			{ 'banner-772x250.png': null },
			'https://example.com/assets/',
		);

		assert.strictEqual(banners.length, 1);
		assert.deepStrictEqual(banners[0], {
			url: 'https://example.com/assets/banner-772x250.png',
			'content-type': 'image/png',
			height: 250,
			width: 772,
		});
	});

	it('matches retina banner file', () => {
		const { banners } = matchAssetFiles(
			{ 'banner-1544x500.jpg': null },
			'https://example.com/assets/',
		);

		assert.strictEqual(banners.length, 1);
		assert.deepStrictEqual(banners[0], {
			url: 'https://example.com/assets/banner-1544x500.jpg',
			'content-type': 'image/jpeg',
			height: 500,
			width: 1544,
		});
	});

	it('matches SVG icon file', () => {
		const { icons } = matchAssetFiles(
			{ 'icon.svg': null },
			'https://example.com/assets/',
		);

		assert.strictEqual(icons.length, 1);
		assert.deepStrictEqual(icons[0], {
			url: 'https://example.com/assets/icon.svg',
			'content-type': 'image/svg+xml',
			height: null,
			width: null,
		});
	});

	it('matches standard icon file', () => {
		const { icons } = matchAssetFiles(
			{ 'icon-128x128.png': null },
			'https://example.com/assets/',
		);

		assert.strictEqual(icons.length, 1);
		assert.deepStrictEqual(icons[0], {
			url: 'https://example.com/assets/icon-128x128.png',
			'content-type': 'image/png',
			height: 128,
			width: 128,
		});
	});

	it('matches retina icon file', () => {
		const { icons } = matchAssetFiles(
			{ 'icon-256x256.gif': null },
			'https://example.com/assets/',
		);

		assert.strictEqual(icons.length, 1);
		assert.deepStrictEqual(icons[0], {
			url: 'https://example.com/assets/icon-256x256.gif',
			'content-type': 'image/gif',
			height: 256,
			width: 256,
		});
	});

	it('matches multiple banner and icon files', () => {
		const { banners, icons } = matchAssetFiles(
			{
				'banner-772x250.png': null,
				'banner-1544x500.jpg': null,
				'icon.svg': null,
				'icon-128x128.png': null,
				'icon-256x256.png': null,
			},
			'https://example.com/assets/',
		);

		assert.strictEqual(banners.length, 2);
		assert.strictEqual(icons.length, 3);
	});

	it('handles jpeg extension', () => {
		const { banners } = matchAssetFiles(
			{ 'banner-772x250.jpeg': null },
			'https://example.com/assets/',
		);

		assert.strictEqual(banners.length, 1);
		assert.strictEqual(banners[0]['content-type'], 'image/jpeg');
	});

	it('ignores files that do not match patterns', () => {
		const { banners, icons, screenshots } = matchAssetFiles(
			{
				'icon.svg': null,
				'banner-wrong-size.png': null,
				'icon-64x64.png': null,
			},
			'https://example.com/assets/',
		);

		assert.strictEqual(banners.length, 0);
		assert.strictEqual(icons.length, 1);
		assert.strictEqual(screenshots.length, 0);
	});

	it('constructs URLs correctly with base URL', () => {
		const { icons } = matchAssetFiles(
			{ 'icon.svg': null },
			'https://ps.w.org/my-plugin/assets/',
		);

		assert.strictEqual(
			icons[0].url,
			'https://ps.w.org/my-plugin/assets/icon.svg',
		);
	});

	it('matches screenshot files', () => {
		const { screenshots } = matchAssetFiles(
			{ 'screenshot-1.png': null, 'screenshot-2.jpg': null },
			'https://example.com/assets/',
		);

		assert.strictEqual(screenshots.length, 2);
		assert.deepStrictEqual(screenshots[0], {
			url: 'https://example.com/assets/screenshot-1.png',
			'content-type': 'image/png',
			height: null,
			width: null,
		});
		assert.deepStrictEqual(screenshots[1], {
			url: 'https://example.com/assets/screenshot-2.jpg',
			'content-type': 'image/jpeg',
			height: null,
			width: null,
		});
	});

	it('sorts screenshots by number', () => {
		const { screenshots } = matchAssetFiles(
			{
				'screenshot-3.png': null,
				'screenshot-1.png': null,
				'screenshot-10.png': null,
				'screenshot-2.png': null,
			},
			'https://example.com/assets/',
		);

		assert.strictEqual(screenshots.length, 4);
		assert.ok(screenshots[0].url.includes('screenshot-1.png'));
		assert.ok(screenshots[1].url.includes('screenshot-2.png'));
		assert.ok(screenshots[2].url.includes('screenshot-3.png'));
		assert.ok(screenshots[3].url.includes('screenshot-10.png'));
	});

	it('matches jpeg extension for screenshots', () => {
		const { screenshots } = matchAssetFiles(
			{ 'screenshot-1.jpeg': null },
			'https://example.com/assets/',
		);

		assert.strictEqual(screenshots.length, 1);
		assert.strictEqual(screenshots[0]['content-type'], 'image/jpeg');
	});

	it('does not match gif screenshots', () => {
		const { screenshots } = matchAssetFiles(
			{ 'screenshot-1.gif': null },
			'https://example.com/assets/',
		);

		assert.strictEqual(screenshots.length, 0);
	});

	it('uses dimensions from files map', () => {
		const { screenshots } = matchAssetFiles(
			{
				'screenshot-1.png': { width: 1280, height: 720 },
				'screenshot-2.jpg': { width: 800, height: 600 },
			},
			'https://example.com/assets/',
		);

		assert.strictEqual(screenshots.length, 2);
		assert.strictEqual(screenshots[0].width, 1280);
		assert.strictEqual(screenshots[0].height, 720);
		assert.strictEqual(screenshots[1].width, 800);
		assert.strictEqual(screenshots[1].height, 600);
	});

	it('uses null for screenshots with null dimensions', () => {
		const { screenshots } = matchAssetFiles(
			{
				'screenshot-1.png': { width: 1280, height: 720 },
				'screenshot-2.jpg': null,
			},
			'https://example.com/assets/',
		);

		assert.strictEqual(screenshots.length, 2);
		assert.strictEqual(screenshots[0].width, 1280);
		assert.strictEqual(screenshots[0].height, 720);
		assert.strictEqual(screenshots[1].width, null);
		assert.strictEqual(screenshots[1].height, null);
	});
});

describe('buildMetadataFromContent with assets', () => {
	it('includes banners and icons in artifacts', async () => {
		const { keypair } = await generateVerificationKeyPair();

		const banners = [
			{
				url: 'https://example.com/assets/banner-772x250.png',
				'content-type': 'image/png',
				height: 250,
				width: 772,
			},
		];

		const icons = [
			{
				url: 'https://example.com/assets/icon.svg',
				'content-type': 'image/svg+xml',
				height: null,
				width: null,
			},
		];

		const { metadata } = await buildMetadataFromContent({
			did: 'did:plc:test123',
			keypair,
			slug: 'test-plugin',
			filename: 'test-plugin/test-plugin.php',
			version: '1.0.0',
			zipData: Buffer.from('fake zip'),
			downloadUrl: 'https://example.com/test.zip',
			banners,
			icons,
		});

		const artifacts = metadata.releases[0].artifacts;

		assert.strictEqual(artifacts.banner.length, 1);
		assert.strictEqual(artifacts.icon.length, 1);
		assert.strictEqual(artifacts.package.length, 1);

		assert.deepStrictEqual(artifacts.banner[0], banners[0]);
		assert.deepStrictEqual(artifacts.icon[0], icons[0]);
	});

	it('orders artifacts as banner, icon, package', async () => {
		const { keypair } = await generateVerificationKeyPair();

		const { metadata } = await buildMetadataFromContent({
			did: 'did:plc:test123',
			keypair,
			slug: 'test-plugin',
			filename: 'test-plugin/test-plugin.php',
			version: '1.0.0',
			zipData: Buffer.from('fake zip'),
			downloadUrl: 'https://example.com/test.zip',
			banners: [
				{
					url: 'https://example.com/banner.png',
					'content-type': 'image/png',
					height: 250,
					width: 772,
				},
			],
			icons: [
				{
					url: 'https://example.com/icon.svg',
					'content-type': 'image/svg+xml',
					height: null,
					width: null,
				},
			],
		});

		const artifactKeys = Object.keys(metadata.releases[0].artifacts);
		assert.deepStrictEqual(artifactKeys, ['banner', 'icon', 'package']);
	});

	it('omits banner key when no banners provided', async () => {
		const { keypair } = await generateVerificationKeyPair();

		const { metadata } = await buildMetadataFromContent({
			did: 'did:plc:test123',
			keypair,
			slug: 'test-plugin',
			filename: 'test-plugin/test-plugin.php',
			version: '1.0.0',
			zipData: Buffer.from('fake zip'),
			downloadUrl: 'https://example.com/test.zip',
			icons: [
				{
					url: 'https://example.com/icon.svg',
					'content-type': 'image/svg+xml',
					height: null,
					width: null,
				},
			],
		});

		const artifacts = metadata.releases[0].artifacts;
		assert.strictEqual('banner' in artifacts, false);
		assert.strictEqual('icon' in artifacts, true);
		assert.strictEqual('package' in artifacts, true);
	});

	it('omits icon key when no icons provided', async () => {
		const { keypair } = await generateVerificationKeyPair();

		const { metadata } = await buildMetadataFromContent({
			did: 'did:plc:test123',
			keypair,
			slug: 'test-plugin',
			filename: 'test-plugin/test-plugin.php',
			version: '1.0.0',
			zipData: Buffer.from('fake zip'),
			downloadUrl: 'https://example.com/test.zip',
			banners: [
				{
					url: 'https://example.com/banner.png',
					'content-type': 'image/png',
					height: 250,
					width: 772,
				},
			],
		});

		const artifacts = metadata.releases[0].artifacts;
		assert.strictEqual('banner' in artifacts, true);
		assert.strictEqual('icon' in artifacts, false);
		assert.strictEqual('package' in artifacts, true);
	});
});
