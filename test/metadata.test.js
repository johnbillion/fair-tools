import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
	buildMetadataFromContent,
	createArtifact,
	createSignedArtifact,
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
