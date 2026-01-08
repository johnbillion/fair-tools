#!/usr/bin/env node

import { parseArgs } from 'node:util';
import { validateDidLog, DidLogFetchError, DidLogValidationError } from '../plc-log.js';
import { validatePlcDid, DidValidationError } from '../did-validation.js';

const { values } = parseArgs({
	options: {
		did: {
			type: 'string',
		},
		help: {
			type: 'boolean',
		},
	},
});

if (values.help) {
	console.log(`Usage: fair-tools did log verify [options]

Validate a PLC DID's complete operation history from genesis to current state.

This validates:
  - Genesis operation structure and DID computation
  - Each operation's signature against the previous operation's rotation keys
  - CID chain integrity

Required options:
  --did <did>    The DID to validate (did:plc:...)

Optional:
  --help         Show this help message

Exit codes:
  0  Validation passed
  1  Validation failed (invalid signature, broken chain, etc.)
  2  Could not validate (network error, DID not found, etc.)`);
	process.exit(0);
}

// Validate required options
if (!values.did) {
	console.error('Error: Missing required option: --did');
	console.error('Run with --help for usage information.');
	process.exit(2);
}

// Validate DID format
try {
	validatePlcDid(values.did);
} catch (err) {
	if (err instanceof DidValidationError) {
		console.error(`Error: ${err.message}`);
		process.exit(2);
	}
	throw err;
}

console.log(`Validating DID log for ${values.did}...\n`);

try {
	const result = await validateDidLog(values.did);

	// Display each validated operation
	for (const op of result.operations) {
		const opNum = op.index + 1;
		console.log(`  ✓ Operation ${opNum}: ${op.type} (${op.cid})`);
		console.log(`    Signed by: ${op.signingKey}`);
	}

	console.log(`\n✓ DID log validated successfully (${result.operations.length} operations)`);
} catch (err) {
	if (err instanceof DidLogFetchError) {
		// Exit code 2: could not validate
		console.error(`\n✗ Could not fetch DID log: ${err.message}`);
		process.exit(2);
	}

	if (err instanceof DidLogValidationError) {
		// Exit code 1: validation failed
		console.error(`\n✗ DID log validation failed: ${err.message}`);
		process.exit(1);
	}

	throw err;
}
