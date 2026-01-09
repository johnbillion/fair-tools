#!/usr/bin/env node

import { parseArgs } from 'node:util';
import { PlcClientError } from '@did-plc/lib';
import { importRotationKeyPair } from '../keys.js';
import { addAlsoKnownAs } from '../did.js';
import { loadRotationKey, SigningKeyError } from '../signing.js';
import { logPlcError } from './lib/plc-error.js';
import { rotationKeyHelp } from './lib/help.js';
import { validatePlcDid, DidValidationError } from '../did-validation.js';

const { values } = parseArgs({
	options: {
		did: {
			type: 'string',
		},
		url: {
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
	console.log(`Usage: fair-tools did aka add [options]

Add a URL to the alsoKnownAs field of a DID.

Required options:
  --did <did>  The DID to update (did:plc:...)
  --url <url>  The URL to add to alsoKnownAs

${rotationKeyHelp()}

Optional:
  --help       Show this help message`);
	process.exit(0);
}

// Validate required options
if (!values.did || !values.url) {
	const missing = [];
	if (!values.did) missing.push('--did');
	if (!values.url) missing.push('--url');
	console.error(`Error: Missing required options: ${missing.join(', ')}`);
	console.error('Run with --help for usage information.');
	process.exit(1);
}

const did = values.did;
const url = values.url;

// Validate DID format
try {
	validatePlcDid(did);
} catch (err) {
	if (err instanceof DidValidationError) {
		console.error(`Error: ${err.message}`);
		process.exit(1);
	}
	throw err;
}

// Load signing key
let privateKeyHex: string;
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

console.log(`Updating DID ${did}...`);

try {
	await addAlsoKnownAs({
		did,
		url,
		signer: keypair,
	});
} catch (err) {
	if (err instanceof PlcClientError) {
		logPlcError('Error updating DID', err, { signerPublicKey });
		process.exit(1);
	}
	throw err;
}

console.log(`Added to alsoKnownAs: ${url}`);
console.log(`View at: https://web.plc.directory/did/${did}`);
