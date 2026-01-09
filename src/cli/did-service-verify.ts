#!/usr/bin/env node

import { parseArgs } from 'node:util';
import { verifyServiceEndpoint, MetadataFetchError, MetadataVerificationError } from '../verify.js';
import { validatePlcDid, DidValidationError } from '../did-validation.js';
import { displayReleases } from './lib/display-releases.js';

const { values } = parseArgs({
	options: {
		did: {
			type: 'string',
		},
		url: {
			type: 'string',
		},
		'all-releases': {
			type: 'boolean',
		},
		help: {
			type: 'boolean',
		},
	},
});

if (values.help) {
	console.log(`Usage: fair-tools did service verify [options]

Verify a FAIR package management service endpoint URL.

This fetches metadata from the URL and verifies:
  - The URL is accessible (HTTPS required)
  - Response is valid FAIR metadata JSON
  - Metadata DID matches the expected DID
  - Release signatures are valid
  - Release checksums are valid (if present)

Required options:
  --did <did>       The DID to verify against (must match metadata.id)
  --url <url>       The service endpoint URL to verify (must be HTTPS)

Optional:
  --all-releases    Verify all releases, not just the latest
  --help            Show this help message

Exit codes:
  0  Verification passed
  1  Verification failed (invalid signature, checksum mismatch, etc.)
  2  Could not verify (network error, missing data, invalid input, etc.)`);
	process.exit(0);
}

// Validate required options
if (!values.did || !values.url) {
	const missing = [];
	if (!values.did) missing.push('--did');
	if (!values.url) missing.push('--url');
	console.error(`Error: Missing required options: ${missing.join(', ')}`);
	console.error('Run with --help for usage information.');
	process.exit(2);
}

const did = values.did;
const url = values.url;

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

console.log(`Verifying service endpoint for ${did}...`);
console.log(`URL: ${url}`);

try {
	const releases = await verifyServiceEndpoint(url, {
		did,
		allReleases: values['all-releases'],
	});

	console.log(`\n✓ Service endpoint verification passed`);
	displayReleases(releases);
} catch (err) {
	if (err instanceof MetadataFetchError) {
		console.error(`\n✗ ${err.message}`);
		process.exit(2);
	}

	if (err instanceof MetadataVerificationError) {
		console.error(`\n✗ ${err.message}`);
		if (err.result) {
			displayReleases(err.result, true);
		}
		process.exit(1);
	}

	throw err;
}
