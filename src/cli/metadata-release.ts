#!/usr/bin/env node

import { readFile, writeFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { importVerificationKeyPair } from '../keys.js';
import { buildMetadata } from '../metadata.js';
import { loadVerificationKey, SigningKeyError } from '../signing.js';
import { verificationKeyHelp } from './lib/help.js';
import { validatePlcDid, DidValidationError } from '../did-validation.js';

const { values } = parseArgs({
	options: {
		'plugin-file': {
			type: 'string',
		},
		'zip-file': {
			type: 'string',
		},
		url: {
			type: 'string',
		},
		did: {
			type: 'string',
		},
		'signing-file': {
			type: 'string',
		},
		'signing-key': {
			type: 'string',
		},
		'metadata-file': {
			type: 'string',
		},
		'output-file': {
			type: 'string',
		},
		'assets-dir': {
			type: 'string',
		},
		'assets-url': {
			type: 'string',
		},
		help: {
			type: 'boolean',
		},
	},
});

if (values.help) {
	console.log(`Usage: fair-tools metadata release [options]

Build a FAIR metadata document for a release of a plugin for WordPress.

Required options:
  --plugin-file <file>    Path to main plugin PHP file
  --zip-file <file>       Path to plugin zip file
  --url <url>             Public download URL for the zip
  --did <did>             Package DID (did:plc:...)

${verificationKeyHelp()}

Optional:
  --metadata-file <file>  Path to existing metadata.json to preserve previous releases
  --output-file <file>    Write metadata to file (default: stdout)
  --assets-dir <dir>      Local assets directory (e.g., .wordpress-org)
  --assets-url <url>      Base URL for assets (required with --assets-dir)
  --help                  Show this help message

Examples:
  # Local usage with key file
  fair-tools metadata release --signing-file ./dids/did:plc:xxx.json --plugin-file ./plugin.php ...

  # Specify which verification key to use
  fair-tools metadata release --signing-file ./dids/did:plc:xxx.json --signing-key did:key:z6Mk... --plugin-file ./plugin.php ...

  # CI usage with environment variable (set FAIR_VERIFICATION_KEY)
  fair-tools metadata release --plugin-file ./plugin.php ...`);
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

// Validate DID format
try {
	validatePlcDid(values.did);
} catch (err) {
	if (err instanceof DidValidationError) {
		console.error(`Error: ${err.message}`);
		process.exit(1);
	}
	throw err;
}

// Validate assets options (both must be provided together)
if (values['assets-dir'] && !values['assets-url']) {
	console.error('Error: --assets-url is required when using --assets-dir');
	process.exit(1);
}
if (values['assets-url'] && !values['assets-dir']) {
	console.error('Error: --assets-dir is required when using --assets-url');
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
let overwrittenVersion;
try {
	({ metadata, overwrittenVersion } = await buildMetadata({
		did: values.did,
		keypair,
		pluginFile: values['plugin-file'],
		zipFile: values['zip-file'],
		downloadUrl: values.url,
		existingReleases,
		assetsDir: values['assets-dir'],
		assetsUrl: values['assets-url'],
	}));
} catch (err) {
	console.error(`Error building metadata: ${err.message}`);
	process.exit(1);
}

if (overwrittenVersion) {
	console.warn(`Warning: Overwriting existing release version ${overwrittenVersion}`);
}

const output = JSON.stringify(metadata, null, '\t');

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
