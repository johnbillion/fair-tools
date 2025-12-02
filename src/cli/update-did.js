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
		key: {
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
  -k, --key <file>        Path to key file (JSON with rotationKey.privateKey)

Optional:
  -h, --help              Show this help message

The key file should be the JSON file created by fair-create-did.`);
	process.exit(0);
}

// Validate required options
const required = ['did', 'url', 'key'];
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

// Extract the rotation private key
const privateKeyHex = keyData.rotationKey?.privateKey;
if (!privateKeyHex) {
	console.error('Error: Key file must contain rotationKey.privateKey');
	process.exit(1);
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
