#!/usr/bin/env node

import { parseArgs } from 'node:util';
import { importRotationKeyPair } from '../keys.js';
import { updateDID } from '../did.js';
import { loadRotationKey, SigningKeyError } from './lib/signing.js';
import { logPlcError } from './lib/plc-error.js';

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
	console.log(`Usage: fair-tools update-did [options]

Update a FAIR DID with a service URL.

Required options:
  -d, --did <did>         The DID to update (did:plc:...)
  -u, --url <url>         The FAIR service URL

Signing key:
  -f, --signing-file <file>  Path to key file (JSON with rotationKeys, or multibase)
  -k, --signing-key <key>    Which rotation key to sign with (default: first, JSON only)

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

// Load signing key
let privateKeyHex;
try {
	({ privateKeyHex } = await loadRotationKey({
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
const { keypair, publicKey: signerPublicKey } = await importRotationKeyPair(privateKeyHex);

console.log(`Updating DID ${values.did}...`);

try {
	await updateDID({
		did: values.did,
		serviceUrl: values.url,
		signer: keypair,
	});
} catch (err) {
	logPlcError('Error updating DID', err, { signerPublicKey });
	process.exit(1);
}

console.log(`DID updated with service URL: ${values.url}`);
console.log(`View at: https://web.plc.directory/did/${values.did}`);
