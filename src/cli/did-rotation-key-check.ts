#!/usr/bin/env node

import { parseArgs } from 'node:util';
import { readFile } from 'node:fs/promises';
import { getRotationPublicKeyMultibase, parseRotationPublicKeyOnly, RotationKeyInputError } from '../keys.js';
import { validatePlcDid, DidValidationError } from '../did-validation.js';
import { checkRotationKey, DidLogFetchError, DidLogValidationError } from '../verify.js';

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
	console.log(`Usage: fair-tools did rotation-key check [options]

Check if a rotation key is valid for signing PLC operations.

Valid rotation keys are present in the latest operation in the DID log, not in the DID document.

Required:
  --did <did>          The DID to check (did:plc:...)

Key input (one required):
  --key <key>          Public key in did:key format (did:key:zQ3sh...) or multibase format (zQ3sh...).
  --key-file <file>    Read rotation key from file. Accepts a public key or a private keypair.
                       Public key should be in did:key format (did:key:zQ3sh...) or multibase format (zQ3sh...).
                       Private key can be in PEM, multibase, or hex format.

Optional:
  --help               Show this help message

Exit codes:
  0  Key is valid (present in latest DID log operation)
  1  Key is not valid (not found or DID has no rotation keys)
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
		publicKeyMultibase = await getRotationPublicKeyMultibase(keyInput);
	} else {
		// --key only accepts public keys
		publicKeyMultibase = await parseRotationPublicKeyOnly(values.key!);
	}
} catch (err) {
	if (err instanceof RotationKeyInputError) {
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
console.log(`Checking rotation key for ${did}...`);

let result;
try {
	result = await checkRotationKey(did, publicKeyMultibase);
} catch (err) {
	if (err instanceof DidLogFetchError) {
		console.error(`Error: Failed to fetch DID log: ${err.message}`);
		process.exit(2);
	}
	if (err instanceof DidLogValidationError) {
		console.error(`Error: DID log validation failed: ${err.message}`);
		process.exit(2);
	}
	throw err;
}

if (result.allKeys.length === 0) {
	console.log(`\n❌ No rotation keys found in DID log`);
	console.log(`The DID ${did} has no rotation keys.`);
	process.exit(1);
}

if (result.valid) {
	console.log(`\n✓ Rotation key is valid`);
	console.log(`Public key: did:key:${result.publicKeyMultibase}`);
	console.log(`This key can be used to sign PLC operations for ${did}`);
	process.exit(0);
} else {
	console.log(`\n❌ Rotation key is not valid`);
	console.log(`Public key: did:key:${result.publicKeyMultibase}`);
	console.log(`This key is not present in the latest operation of the DID log for ${did}`);
	console.log(`\nValid rotation keys for this DID:`);
	for (const key of result.allKeys) {
		console.log(`  did:key:${key}`);
	}
	process.exit(1);
}
