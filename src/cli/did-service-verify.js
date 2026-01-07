#!/usr/bin/env node

import { parseArgs } from 'node:util';
import { verifyServiceEndpoint, MetadataFetchError, MetadataVerificationError } from '../verify.js';
import { validatePlcDid, DidValidationError } from '../did-validation.js';

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
const required = ['did', 'url'];
const missing = required.filter((opt) => !values[opt]);
if (missing.length > 0) {
	console.error(`Error: Missing required options: ${missing.map((o) => `--${o}`).join(', ')}`);
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

// Validate URL format
if (!values.url.startsWith('https://')) {
	console.error('Error: URL must use HTTPS');
	process.exit(2);
}

console.log(`Verifying service endpoint for ${values.did}...`);
console.log(`URL: ${values.url}`);

/**
 * Display release verification details.
 * @param {object[]} releases
 * @param {boolean} [failed=false] - Whether the releases are from a failed verification
 */
function displayReleases(releases, failed = false) {
	for (const release of releases) {
		const icon = failed ? '✗' : '✓';
		console.log(`\n${icon} Release v${release.version}`);

		for (const artifact of release.artifacts) {
			const sigStatus = artifact.signatureValid ? `Signature valid (${artifact.keyId})` : 'Signature FAILED';
			const checksumStatus = artifact.checksumValid ? 'checksum valid' : 'checksum FAILED';
			const artifactIcon = artifact.signatureValid && artifact.checksumValid ? '✓' : '✗';
			console.log(`  ${artifactIcon} ${artifact.url}: ${sigStatus}, ${checksumStatus}`);
		}
	}
}

try {
	const releases = await verifyServiceEndpoint(values.url, {
		did: values.did,
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
