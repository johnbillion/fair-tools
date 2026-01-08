#!/usr/bin/env node

import { parseArgs } from 'node:util';
import { importRotationKeyPair } from '../keys.js';
import { replaceAlsoKnownAs } from '../did.js';
import { loadRotationKey, SigningKeyError } from '../signing.js';
import { logPlcError } from './lib/plc-error.js';
import { rotationKeyHelp } from './lib/help.js';
import { validatePlcDid, DidValidationError } from '../did-validation.js';

const { values } = parseArgs({
	options: {
		did: {
			type: 'string',
		},
		'old-url': {
			type: 'string',
		},
		'new-url': {
			type: 'string',
		},
		'signing-file': {
			type: 'string',
		},
		'signing-key': {
			type: 'string',
		},
		help: {
			type: 'boolean',
		},
	},
});

if (values.help) {
	console.log(`Usage: fair-tools did aka replace [options]

Replace a URL in the alsoKnownAs field of a DID.

Required options:
  --did <did>      The DID to update (did:plc:...)
  --old-url <url>  The current alsoKnownAs URL to replace
  --new-url <url>  The new URL

${rotationKeyHelp()}

Optional:
  --help           Show this help message`);
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
	await replaceAlsoKnownAs({
		did: values.did,
		oldUrl: values['old-url'],
		newUrl: values['new-url'],
		signer: keypair,
	});
} catch (err) {
	logPlcError('Error updating DID', err, { signerPublicKey });
	process.exit(1);
}

console.log(`Replaced alsoKnownAs URL: ${values['old-url']} -> ${values['new-url']}`);
console.log(`View at: https://web.plc.directory/did/${values.did}`);
