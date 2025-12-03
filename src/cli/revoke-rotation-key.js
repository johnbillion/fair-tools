#!/usr/bin/env node

import { writeFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { importRotationKeyPair } from '../keys.js';
import { revokeRotationKey } from '../did.js';
import { loadRotationKeyForRevocation, SigningKeyError } from './signing.js';

const { values } = parseArgs({
	options: {
		did: {
			type: 'string',
			short: 'd',
		},
		revoke: {
			type: 'string',
			short: 'r',
		},
		'signing-file': {
			type: 'string',
			short: 'f',
		},
		'signing-key': {
			type: 'string',
			short: 'k',
		},
		cleanup: {
			type: 'boolean',
		},
		help: {
			type: 'boolean',
			short: 'h',
		},
	},
});

if (values.help) {
	console.log(`Usage: revoke-rotation-key [options]

Revoke a rotation key from an existing DID.

Required:
  -d, --did <did>           The DID to update (did:plc:...)
  -r, --revoke <key>        The rotation key to revoke (did:key:...)

Signing key:
  -f, --signing-file <file>  Path to key file for signing (JSON with rotationKeys)
  -k, --signing-key <key>    Which rotation key to sign with (default: first available)

  If --signing-file is not provided, uses FAIR_ROTATION_KEY environment variable.

Optional:
  --cleanup                 Remove revoked key from key file after success
  -h, --help                Show this help message

You cannot revoke the rotation key used to sign this operation.
At least one rotation key must remain.`);
	process.exit(0);
}

// Validate required options
if (!values.did) {
	console.error('Error: Missing required option: --did');
	console.error('Run with --help for usage information.');
	process.exit(1);
}

if (!values.revoke) {
	console.error('Error: Missing required option: --revoke');
	console.error('Run with --help for usage information.');
	process.exit(1);
}

if (values.cleanup && !values['signing-file']) {
	console.error('Error: --cleanup requires --signing-file');
	process.exit(1);
}

// Load signing key
let privateKeyHex, signerPublicKey, keyData;
try {
	({ privateKeyHex, signerPublicKey, keyData } = await loadRotationKeyForRevocation({
		signingFile: values['signing-file'],
		signingKey: values['signing-key'],
		revokeKey: values.revoke,
	}));
} catch (err) {
	if (err instanceof SigningKeyError) {
		console.error(`Error: ${err.message}`);
		process.exit(1);
	}
	throw err;
}

const { keypair: signer, publicKey: derivedPublicKey } = await importRotationKeyPair(privateKeyHex);
signerPublicKey = signerPublicKey || derivedPublicKey;

// Check if env var key is being revoked
if (signerPublicKey === values.revoke) {
	console.error('Error: Cannot use the key being revoked to sign the operation');
	process.exit(1);
}

console.log(`Revoking rotation key from DID ${values.did}...`);
console.log(`  Key to revoke: ${values.revoke}`);
console.log(`  Signing with:  ${signerPublicKey}`);

try {
	await revokeRotationKey({
		did: values.did,
		rotationKey: values.revoke,
		signer,
	});
} catch (err) {
	console.error(`Error revoking rotation key: ${err.message}`);
	process.exit(1);
}

console.log('Rotation key revoked successfully.');

// Remove the revoked key from the key file if requested
if (values.cleanup && keyData && keyData.rotationKeys[values.revoke]) {
	delete keyData.rotationKeys[values.revoke];
	try {
		await writeFile(values['signing-file'], JSON.stringify(keyData, null, 2) + '\n', { mode: 0o600 });
	} catch (err) {
		console.error(`Error writing key file: ${err.message}`);
		process.exit(1);
	}
	console.log(`Removed revoked key from ${values['signing-file']}`);
} else if (keyData && keyData.rotationKeys[values.revoke]) {
	console.log(`Note: The revoked key still exists in ${values['signing-file']}. Use --cleanup to delete it.`);
}

console.log(`View at: https://web.plc.directory/did/${values.did}`);
