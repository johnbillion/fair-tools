#!/usr/bin/env node

import { readFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { importRotationKeyPair } from '../keys.js';
import { updateDID } from '../did.js';

const { values } = parseArgs({
	options: {
		did: {
			type: 'string',
			short: 'd',
		},
		url: {
			type: 'string',
			short: 'u',
		},
		'signing-file': {
			type: 'string',
			short: 'f',
		},
		'signing-key': {
			type: 'string',
			short: 'k',
		},
		help: {
			type: 'boolean',
			short: 'h',
		},
	},
});

if (values.help) {
	console.log(`Usage: fair-update-did [options]

Update a FAIR DID with a service URL.

Required options:
  -d, --did <did>         The DID to update (did:plc:...)
  -u, --url <url>         The FAIR service URL

Signing key:
  -f, --signing-file <file>  Path to key file for signing (JSON with rotationKeys)
  -k, --signing-key <key>    Which rotation key to sign with (default: first)

  If --signing-file is not provided, uses FAIR_ROTATION_KEY environment variable.

Optional:
  -h, --help              Show this help message`);
	process.exit(0);
}

// Validate required options
const required = ['did', 'url'];
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

	const rotationKeys = keyData.rotationKeys || {};
	const publicKeys = Object.keys(rotationKeys);

	if (publicKeys.length === 0) {
		console.error('Error: Key file must contain at least one rotation key');
		process.exit(1);
	}

	if (values['signing-key']) {
		privateKeyHex = rotationKeys[values['signing-key']];
		if (!privateKeyHex) {
			console.error(`Error: Rotation key ${values['signing-key']} not found in key file`);
			console.error(`Available keys: ${publicKeys.join(', ')}`);
			process.exit(1);
		}
	} else {
		privateKeyHex = rotationKeys[publicKeys[0]];
	}
} else {
	// Use environment variable
	privateKeyHex = process.env.FAIR_ROTATION_KEY;
	if (!privateKeyHex) {
		console.error('Error: Either --signing-file or FAIR_ROTATION_KEY environment variable is required');
		console.error('Run with --help for usage information.');
		process.exit(1);
	}
}

// Import the keypair
const { keypair } = await importRotationKeyPair(privateKeyHex);

console.log(`Updating DID ${values.did}...`);

await updateDID({
	did: values.did,
	serviceUrl: values.url,
	signer: keypair,
});

console.log(`DID updated with service URL: ${values.url}`);
console.log(`View at: https://web.plc.directory/did/${values.did}`);
