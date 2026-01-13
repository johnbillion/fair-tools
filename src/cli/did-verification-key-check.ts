#!/usr/bin/env node

import { parseArgs } from 'node:util';
import { readFile } from 'node:fs/promises';
import { getVerificationPublicKeyMultibase, parsePublicKeyOnly, VerificationKeyInputError } from '../keys.js';
import { validatePlcDid, DidValidationError } from '../did-validation.js';
import { checkVerificationKey, MetadataFetchError } from '../verify.js';

const { values } = parseArgs({
	options: {
		did: {
			type: 'string',
		},
		key: {
			type: 'string',
		},
		'key-file': {
			type: 'string',
		},
		help: {
			type: 'boolean',
		},
	},
});

if (values.help) {
	console.log(`Usage: fair-tools did verification-key check [options]

Check if a verification key is valid for signing.

Valid verification keys are present in the verification methods property of the DID document.

Required:
  --did <did>          The DID to check (did:plc:...)

Key input (one required):
  --key <key>          Public key in did:key format (did:key:z6Mk...) or multibase format (z6Mk...).
  --key-file <file>    Read verification key from file. Accepts a public key or a private keypair.
                       Public key should be in did:key format (did:key:z6Mk...) or multibase format (z6Mk...).
                       Private key can be in PEM, multibase, or hex format.

Optional:
  --help               Show this help message

Exit codes:
  0  Key is valid (present in DID document)
  1  Key is not valid (not found or DID has no verification keys)
  2  Error occurred (invalid input, network error, etc.)`);
	process.exit(0);
}

// Validate required options
if (!values.did) {
	console.error('Error: Missing required option: --did');
	console.error('Run with --help for usage information.');
	process.exit(2);
}

if (!values.key && !values['key-file']) {
	console.error('Error: Must provide either --key or --key-file');
	console.error('Run with --help for usage information.');
	process.exit(2);
}

if (values.key && values['key-file']) {
	console.error('Error: Cannot specify both --key and --key-file');
	console.error('Run with --help for usage information.');
	process.exit(2);
}

const did = values.did;

// Validate DID format
try {
	validatePlcDid(did);
} catch (err) {
	if (err instanceof DidValidationError) {
		console.error(`Error: ${err.message}`);
		process.exit(2);
	}
	throw err;
}

// Extract the public key multibase
let publicKeyMultibase: string;
try {
	if (values['key-file']) {
		// --key-file accepts both public and private keys
		const keyInput = await readFile(values['key-file'], 'utf-8');
		publicKeyMultibase = await getVerificationPublicKeyMultibase(keyInput);
	} else {
		// --key only accepts public keys
		publicKeyMultibase = await parsePublicKeyOnly(values.key!);
	}
} catch (err) {
	if (err instanceof VerificationKeyInputError) {
		console.error(`Error: ${err.message}`);
		process.exit(2);
	}
	if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
		console.error(`Error reading key file: ${(err as Error).message}`);
		process.exit(2);
	}
	throw err;
}

// Check if the key is valid for the DID
console.log(`Checking verification key for ${did}...`);

let result;
try {
	result = await checkVerificationKey(did, publicKeyMultibase);
} catch (err) {
	if (err instanceof MetadataFetchError) {
		console.error(`Error: Failed to fetch DID document: ${err.message}`);
		process.exit(2);
	}
	throw err;
}

if (result.allKeys.length === 0) {
	console.log(`\n❌ No verification keys found in DID document`);
	console.log(`The DID ${did} has no verification keys.`);
	process.exit(1);
}

if (result.valid) {
	console.log(`\n✓ Verification key is valid`);
	console.log(`Key ID: ${result.matchingKeyId}`);
	console.log(`Public key: ${result.publicKeyMultibase}`);
	console.log(`This key can be used to sign releases for ${did}`);
	process.exit(0);
} else {
	console.log(`\n❌ Verification key is not valid`);
	console.log(`Public key: ${result.publicKeyMultibase}`);
	console.log(`This key is not present in the verification methods of ${did}`);
	console.log(`\nValid keys for this DID:`);
	for (const vk of result.allKeys) {
		console.log(`  ${vk.id}: ${vk.publicKeyMultibase}`);
	}
	process.exit(1);
}
