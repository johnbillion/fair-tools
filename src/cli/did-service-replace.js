#!/usr/bin/env node

import { parseArgs } from 'node:util';
import { importRotationKeyPair } from '../keys.js';
import { replaceServiceUrl } from '../did.js';
import { loadRotationKey, SigningKeyError } from '../signing.js';
import { logPlcError } from './lib/plc-error.js';
import { rotationKeyHelp } from './lib/help.js';

const { values } = parseArgs({
	options: {
		did: {
			type: 'string',
			short: 'd',
		},
		'old-url': {
			type: 'string',
			short: 'o',
		},
		'new-url': {
			type: 'string',
			short: 'n',
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
	console.log(`Usage: fair-tools did service replace [options]

Replace the FAIR service URL for a DID.

Required options:
  -d, --did <did>         The DID to update (did:plc:...)
  -o, --old-url <url>     The current FAIR service URL
  -n, --new-url <url>     The new FAIR service URL

${rotationKeyHelp()}

Optional:
  -h, --help              Show this help message`);
	process.exit(0);
}

// Validate required options
const required = ['did', 'old-url', 'new-url'];
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
	await replaceServiceUrl({
		did: values.did,
		oldUrl: values['old-url'],
		newUrl: values['new-url'],
		signer: keypair,
	});
} catch (err) {
	logPlcError('Error updating DID', err, { signerPublicKey });
	process.exit(1);
}

console.log(`DID updated with service URL: ${values['new-url']}`);
console.log(`View at: https://web.plc.directory/did/${values.did}`);
