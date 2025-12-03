#!/usr/bin/env node

import { readFile, writeFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { importVerificationKeyPair } from '../keys.js';
import { buildMetadata } from '../metadata.js';
import { loadVerificationKey, SigningKeyError } from './signing.js';

const { values } = parseArgs({
	options: {
		'plugin-file': {
			type: 'string',
			short: 'p',
		},
		'zip-file': {
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
		'metadata-file': {
			type: 'string',
			short: 'm',
		},
		'output-file': {
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
  -p, --plugin-file <file>  Path to main plugin PHP file
  -z, --zip-file <file>     Path to plugin zip file
  -u, --url <url>           Public download URL for the zip
  -d, --did <did>           Package DID (did:plc:...)

Signing key:
  -f, --signing-file <file> Path to key file (JSON with verificationKeys)
  -k, --signing-key <key>   Which verification key to sign with (default: first)

  If --signing-file is not provided, uses FAIR_PRIVATE_KEY environment variable.

Optional:
  -m, --metadata-file <file>  Path to existing metadata.json to preserve previous releases
  -o, --output-file <file>    Write metadata to file (default: stdout)
  -h, --help                  Show this help message

Examples:
  # Local usage with key file
  build-metadata --signing-file ./dids/did:plc:xxx.json --plugin-file ./plugin.php ...

  # Specify which verification key to use
  build-metadata --signing-file ./dids/did:plc:xxx.json --signing-key did:key:z6Mk... --plugin-file ./plugin.php ...

  # CI usage with environment variable (set FAIR_PRIVATE_KEY)
  build-metadata --plugin-file ./plugin.php ...`);
	process.exit(0);
}

// Validate required options
const required = ['plugin-file', 'zip-file', 'url', 'did'];
const missing = required.filter((opt) => !values[opt]);
if (missing.length > 0) {
	console.error(`Error: Missing required options: ${missing.map((o) => `--${o}`).join(', ')}`);
	console.error('Run with --help for usage information.');
	process.exit(1);
}

// Load signing key
let privateKeyHex;
try {
	({ privateKeyHex } = await loadVerificationKey({
		signingFile: values['signing-file'],
		signingKey: values['signing-key'],
	}));
} catch (err) {
	if (err instanceof SigningKeyError) {
		console.error(`Error: ${err.message}`);
		process.exit(1);
	}
	throw err;
}
const { keypair } = await importVerificationKeyPair(privateKeyHex);

// Load existing releases if provided
let existingReleases = [];
if (values['metadata-file']) {
	try {
		const metadataContent = await readFile(values['metadata-file'], 'utf-8');
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
let metadata;
try {
	metadata = await buildMetadata({
		did: values.did,
		keypair,
		pluginFile: values['plugin-file'],
		zipFile: values['zip-file'],
		downloadUrl: values.url,
		existingReleases,
	});
} catch (err) {
	console.error(`Error building metadata: ${err.message}`);
	process.exit(1);
}

const output = JSON.stringify(metadata, null, 2);

if (values['output-file']) {
	try {
		await writeFile(values['output-file'], output + '\n');
	} catch (err) {
		console.error(`Error writing output file: ${err.message}`);
		process.exit(1);
	}
	console.log(`Metadata written to ${values['output-file']}`);
} else {
	console.log(output);
}
