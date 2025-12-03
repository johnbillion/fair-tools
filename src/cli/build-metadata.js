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
		'signing-file': {
			type: 'string',
			short: 'f',
		},
		'signing-key': {
			type: 'string',
			short: 'k',
		},
		metadata: {
			type: 'string',
			short: 'm',
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
  -p, --plugin <file>       Path to main plugin PHP file
  -z, --zip <file>          Path to plugin zip file
  -u, --url <url>           Public download URL for the zip
  -d, --did <did>           Package DID (did:plc:...)

Signing key:
  -f, --signing-file <file> Path to key file (JSON with verificationKeys)
  -k, --signing-key <key>   Which verification key to sign with (default: first)

  If --signing-file is not provided, uses FAIR_PRIVATE_KEY environment variable.

Optional:
  -m, --metadata <file>     Path to existing metadata.json to preserve previous releases
  -o, --output <file>       Write metadata to file (default: stdout)
  -h, --help                Show this help message

Examples:
  # Local usage with key file
  build-metadata --signing-file ./dids/did:plc:xxx.json --plugin ./plugin.php ...

  # Specify which verification key to use
  build-metadata --signing-file ./dids/did:plc:xxx.json --signing-key did:key:z6Mk... --plugin ./plugin.php ...

  # CI usage with environment variable (set FAIR_PRIVATE_KEY)
  build-metadata --plugin ./plugin.php ...`);
	process.exit(0);
}

// Validate required options
const required = ['plugin', 'zip', 'url', 'did'];
const missing = required.filter((opt) => !values[opt]);
if (missing.length > 0) {
	console.error(`Error: Missing required options: ${missing.map((o) => `--${o}`).join(', ')}`);
	console.error('Run with --help for usage information.');
	process.exit(1);
}

// Validate key options
if (values['signing-key'] && !values['signing-file']) {
	console.error('Error: --signing-key can only be used with --signing-file');
	process.exit(1);
}

// Get the private key
let privateKeyHex;

if (values['signing-file']) {
	// Load from key file
	let keyData;
	try {
		const keyContent = await readFile(values['signing-file'], 'utf-8');
		keyData = JSON.parse(keyContent);
	} catch (err) {
		console.error(`Error reading key file: ${err.message}`);
		process.exit(1);
	}

	const verificationKeys = keyData.verificationKeys || {};
	const publicKeys = Object.keys(verificationKeys);

	if (publicKeys.length === 0) {
		console.error('Error: Key file must contain at least one verification key');
		process.exit(1);
	}

	if (values['signing-key']) {
		privateKeyHex = verificationKeys[values['signing-key']];
		if (!privateKeyHex) {
			console.error(`Error: Verification key ${values['signing-key']} not found in key file`);
			console.error(`Available keys: ${publicKeys.join(', ')}`);
			process.exit(1);
		}
	} else {
		privateKeyHex = verificationKeys[publicKeys[0]];
	}
} else {
	// Use environment variable
	privateKeyHex = process.env.FAIR_PRIVATE_KEY;
	if (!privateKeyHex) {
		console.error('Error: Either --signing-file or FAIR_PRIVATE_KEY environment variable is required');
		console.error('Run with --help for usage information.');
		process.exit(1);
	}
}

// Import the keypair
const { keypair } = await importVerificationKeyPair(privateKeyHex);

// Load existing releases if provided
let existingReleases = [];
if (values.metadata) {
	try {
		const metadataContent = await readFile(values.metadata, 'utf-8');
		const existingMetadata = JSON.parse(metadataContent);
		existingReleases = existingMetadata.releases || [];
		if (!Array.isArray(existingReleases)) {
			console.error('Error: Metadata file releases property must be an array');
			process.exit(1);
		}
	} catch (err) {
		console.error(`Error reading metadata file: ${err.message}`);
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
