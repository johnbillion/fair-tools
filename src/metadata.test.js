import { describe, it } from 'node:test';
import assert from 'node:assert';
import { buildMetadataFromContent } from './metadata.js';
import { generateVerificationKeyPair } from './keys.js';

describe('buildMetadataFromContent', () => {
	it('throws if Plugin ID header is missing', async () => {
		const { keypair } = await generateVerificationKeyPair();

		const pluginContent = `<?php
/**
 * Plugin Name: Test Plugin
 * Version: 1.0.0
 */
`;

		await assert.rejects(
			buildMetadataFromContent({
				did: 'did:plc:test123',
				keypair,
				slug: 'test-plugin',
				pluginContent,
				zipData: Buffer.from('fake zip'),
				downloadUrl: 'https://example.com/test.zip',
			}),
			{
				message: 'Plugin file is missing required "Plugin ID:" header',
			}
		);
	});

	it('throws if Plugin ID does not match provided DID', async () => {
		const { keypair } = await generateVerificationKeyPair();

		const pluginContent = `<?php
/**
 * Plugin Name: Test Plugin
 * Plugin ID: did:plc:different123
 * Version: 1.0.0
 */
`;

		await assert.rejects(
			buildMetadataFromContent({
				did: 'did:plc:test123',
				keypair,
				slug: 'test-plugin',
				pluginContent,
				zipData: Buffer.from('fake zip'),
				downloadUrl: 'https://example.com/test.zip',
			}),
			{
				message: 'Plugin ID mismatch: plugin file has "did:plc:different123" but DID "did:plc:test123" was provided',
			}
		);
	});

	it('throws if Version header is missing', async () => {
		const { keypair } = await generateVerificationKeyPair();

		const pluginContent = `<?php
/**
 * Plugin Name: Test Plugin
 * Plugin ID: did:plc:test123
 */
`;

		await assert.rejects(
			buildMetadataFromContent({
				did: 'did:plc:test123',
				keypair,
				slug: 'test-plugin',
				pluginContent,
				zipData: Buffer.from('fake zip'),
				downloadUrl: 'https://example.com/test.zip',
			}),
			{
				message: 'Plugin file is missing required "Version:" header',
			}
		);
	});

	it('succeeds with valid Plugin ID and Version headers', async () => {
		const { keypair } = await generateVerificationKeyPair();

		const pluginContent = `<?php
/**
 * Plugin Name: Valid Test Plugin
 * Plugin ID: did:plc:validtest123
 * Version: 2.0.0
 * Description: A valid test plugin
 * Author: Test Author
 */
`;

		const metadata = await buildMetadataFromContent({
			did: 'did:plc:validtest123',
			keypair,
			slug: 'valid-plugin',
			pluginContent,
			zipData: Buffer.from('fake zip'),
			downloadUrl: 'https://example.com/valid.zip',
		});

		assert.strictEqual(metadata.id, 'did:plc:validtest123');
		assert.strictEqual(metadata.name, 'Valid Test Plugin');
		assert.strictEqual(metadata.slug, 'valid-plugin');
		assert.strictEqual(metadata.releases[0].version, '2.0.0');
		assert.strictEqual(metadata.description, 'A valid test plugin');
		assert.strictEqual(metadata.authors[0].name, 'Test Author');
	});

	it('uses slug as name if Plugin Name header is missing', async () => {
		const { keypair } = await generateVerificationKeyPair();

		const pluginContent = `<?php
/**
 * Plugin ID: did:plc:test123
 * Version: 1.0.0
 */
`;

		const metadata = await buildMetadataFromContent({
			did: 'did:plc:test123',
			keypair,
			slug: 'my-plugin-slug',
			pluginContent,
			zipData: Buffer.from('fake zip'),
			downloadUrl: 'https://example.com/test.zip',
		});

		assert.strictEqual(metadata.name, 'my-plugin-slug');
	});

	it('parses readme content for keywords and description', async () => {
		const { keypair } = await generateVerificationKeyPair();

		const pluginContent = `<?php
/**
 * Plugin Name: Test Plugin
 * Plugin ID: did:plc:test123
 * Version: 1.0.0
 */
`;

		const readmeContent = `=== Test Plugin ===
Tags: tag1, tag2, tag3
License: GPL-2.0-or-later

This is the short description from readme.
`;

		const metadata = await buildMetadataFromContent({
			did: 'did:plc:test123',
			keypair,
			slug: 'test-plugin',
			pluginContent,
			readmeContent,
			zipData: Buffer.from('fake zip'),
			downloadUrl: 'https://example.com/test.zip',
		});

		assert.deepStrictEqual(metadata.keywords, ['tag1', 'tag2', 'tag3']);
		assert.strictEqual(metadata.description, 'This is the short description from readme.');
		assert.strictEqual(metadata.license, 'GPL-2.0-or-later');
	});

	it('prefers spdxLicense over header and readme licenses', async () => {
		const { keypair } = await generateVerificationKeyPair();

		const pluginContent = `<?php
/**
 * Plugin Name: Test Plugin
 * Plugin ID: did:plc:test123
 * Version: 1.0.0
 * License: GPLv2
 */
`;

		const readmeContent = `=== Test Plugin ===
License: GPL-2.0

Short description.
`;

		const metadata = await buildMetadataFromContent({
			did: 'did:plc:test123',
			keypair,
			slug: 'test-plugin',
			pluginContent,
			readmeContent,
			spdxLicense: 'MIT',
			zipData: Buffer.from('fake zip'),
			downloadUrl: 'https://example.com/test.zip',
		});

		assert.strictEqual(metadata.license, 'MIT');
	});

	it('includes requirements from headers', async () => {
		const { keypair } = await generateVerificationKeyPair();

		const pluginContent = `<?php
/**
 * Plugin Name: Test Plugin
 * Plugin ID: did:plc:test123
 * Version: 1.0.0
 * Requires at least: 6.0
 * Requires PHP: 8.1
 */
`;

		const metadata = await buildMetadataFromContent({
			did: 'did:plc:test123',
			keypair,
			slug: 'test-plugin',
			pluginContent,
			zipData: Buffer.from('fake zip'),
			downloadUrl: 'https://example.com/test.zip',
		});

		assert.deepStrictEqual(metadata.releases[0].requires, {
			'env:wp': '>=6.0',
			'env:php': '>=8.1',
		});
	});
});
