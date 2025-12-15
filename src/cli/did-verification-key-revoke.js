#!/usr/bin/env node

import { writeFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { importRotationKeyPair } from '../keys.js';
import { revokeVerificationKey } from '../did.js';
import { loadRotationKey, SigningKeyError } from '../signing.js';
import { logPlcError } from './lib/plc-error.js';
import { rotationKeyHelp } from './lib/help.js';
import {
	validatePlcDid,
	DidValidationError,
	validateVerificationKey,
	PublicKeyValidationError,
} from '../did-validation.js';

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
	console.log(`Usage: fair-tools did verification-key revoke [options]

Revoke a verification key from an existing DID.

Required:
  -d, --did <did>           The DID to update (did:plc:...)
  -r, --revoke <key>        The verification key to revoke (did:key:z6Mk...)

${rotationKeyHelp()}

Optional:
  --cleanup                 Remove revoked key from key file after success
  -h, --help                Show this help message`);
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

// Validate verification key format
try {
	validateVerificationKey(values.revoke);
} catch (err) {
	if (err instanceof PublicKeyValidationError) {
		console.error(`Error: ${err.message}`);
		process.exit(1);
	}
	throw err;
}

// Load signing key
let privateKeyHex, keyData;
try {
	({ privateKeyHex, keyData } = await loadRotationKey({
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
const { keypair: signer, publicKey: signerPublicKey } =
	await importRotationKeyPair(privateKeyHex);

console.log(`Revoking verification key from DID ${values.did}...`);
console.log(`  Key to revoke: ${values.revoke}`);
console.log(`  Signing with:  ${signerPublicKey}`);

try {
	await revokeVerificationKey({
		did: values.did,
		publicKey: values.revoke,
		signer,
	});
} catch (err) {
	logPlcError('Error revoking verification key', err, { signerPublicKey });
	process.exit(1);
}

console.log('Verification key revoked successfully.');

// Remove the revoked key from the key file if requested
if (
	values.cleanup &&
	keyData &&
	keyData.verificationKeys &&
	keyData.verificationKeys[values.revoke]
) {
	delete keyData.verificationKeys[values.revoke];
	try {
		await writeFile(
			values['signing-file'],
			JSON.stringify(keyData, null, 2) + '\n',
			{ mode: 0o600 },
		);
	} catch (err) {
		console.error(`Error writing key file: ${err.message}`);
		process.exit(1);
	}
	console.log(`Removed revoked key from ${values['signing-file']}`);
} else if (
	keyData &&
	keyData.verificationKeys &&
	keyData.verificationKeys[values.revoke]
) {
	console.log(
		`Note: The revoked key still exists in ${values['signing-file']}. Use --cleanup to delete it.`,
	);
}

console.log(`View at: https://web.plc.directory/did/${values.did}`);
