#!/usr/bin/env node

import { readFile, writeFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { importVerificationKeyPair } from '../keys.js';
import { buildMetadata } from '../metadata.js';

const { values } = parseArgs({
	options: {
		plugin: {
			type: 'string',
			short: 'p',
		},
		zip: {
			type: 'string',
			short: 'z',
		},
		url: {
			type: 'string',
			short: 'u',
		},
		did: {
			type: 'string',
			short: 'd',
		},
		key: {
			type: 'string',
			short: 'k',
		},
		releases: {
			type: 'string',
			short: 'r',
		},
		output: {
			type: 'string',
			short: 'o',
		},
		help: {
			type: 'boolean',
			short: 'h',
		},
	},
});

if (values.help) {
	console.log(`Usage: fair-build-metadata [options]

Build a FAIR metadata document for a WordPress plugin.

Required options:
  -p, --plugin <file>     Path to main plugin PHP file
  -z, --zip <file>        Path to plugin zip file
  -u, --url <url>         Public download URL for the zip
  -d, --did <did>         Package DID (did:plc:...)
  -k, --key <file>        Path to key file (JSON with privateKey)

Optional:
  -r, --releases <file>   Path to existing releases JSON array
  -o, --output <file>     Write metadata to file (default: stdout)
  -h, --help              Show this help message

The key file should be the JSON file created by fair-create-did,
containing the verificationKey.privateKey field.`);
	process.exit(0);
}

// Validate required options
const required = ['plugin', 'zip', 'url', 'did', 'key'];
const missing = required.filter((opt) => !values[opt]);
if (missing.length > 0) {
	console.error(`Error: Missing required options: ${missing.map((o) => `--${o}`).join(', ')}`);
	console.error('Run with --help for usage information.');
	process.exit(1);
}

// Load the key file
let keyData;
try {
	const keyContent = await readFile(values.key, 'utf-8');
	keyData = JSON.parse(keyContent);
} catch (err) {
	console.error(`Error reading key file: ${err.message}`);
	process.exit(1);
}

// Extract the verification private key
const privateKeyHex = keyData.verificationKey?.privateKey;
if (!privateKeyHex) {
	console.error('Error: Key file must contain verificationKey.privateKey');
	process.exit(1);
}

// Import the keypair
const { keypair } = await importVerificationKeyPair(privateKeyHex);

// Load existing releases if provided
let existingReleases = [];
if (values.releases) {
	try {
		const releasesContent = await readFile(values.releases, 'utf-8');
		existingReleases = JSON.parse(releasesContent);
		if (!Array.isArray(existingReleases)) {
			console.error('Error: Releases file must contain a JSON array');
			process.exit(1);
		}
	} catch (err) {
		console.error(`Error reading releases file: ${err.message}`);
		process.exit(1);
	}
}

// Build the metadata
const metadata = await buildMetadata({
	did: values.did,
	keypair,
	pluginFile: values.plugin,
	zipFile: values.zip,
	downloadUrl: values.url,
	existingReleases,
});

const output = JSON.stringify(metadata, null, 2);

if (values.output) {
	await writeFile(values.output, output + '\n');
	console.log(`Metadata written to ${values.output}`);
} else {
	console.log(output);
}
