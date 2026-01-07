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

try {
	const result = await verifyServiceEndpoint(values.url, {
		did: values.did,
		allReleases: values['all-releases'],
	});

	if (result.valid) {
		console.log(`\n✓ Service endpoint verification passed`);
	} else {
		console.log(`\n✗ Service endpoint verification failed`);
	}

	// Show release results
	for (const release of result.releases) {
		const icon = release.valid ? '✓' : '✗';
		console.log(`\n${icon} Release v${release.version}`);

		for (const artifact of release.artifacts) {
			const sigStatus = artifact.signatureValid ? `Signature valid (${artifact.keyId})` : 'Signature FAILED';
			let checksumStatus;
			if (artifact.checksumMissing) {
				checksumStatus = 'checksum missing';
			} else if (artifact.checksumValid) {
				checksumStatus = 'checksum valid';
			} else {
				checksumStatus = 'checksum FAILED';
			}
			const artifactIcon = artifact.signatureValid && (artifact.checksumMissing || artifact.checksumValid) ? '✓' : '✗';
			console.log(`  ${artifactIcon} ${artifact.url}: ${sigStatus}, ${checksumStatus}`);
		}
	}

	// Show warnings
	if (result.warnings.length > 0) {
		console.log('\nWarnings:');
		for (const warning of result.warnings) {
			console.log(`  ⚠ ${warning}`);
		}
	}

	// Show errors
	if (result.errors.length > 0) {
		console.log('\nErrors:');
		for (const error of result.errors) {
			console.log(`  ✗ ${error}`);
		}
	}

	// Exit code based on whether any errors caused failure
	if (!result.valid) {
		// Determine if it was a verification failure or couldn't verify
		const couldNotVerify = result.errors.some(
			(e) =>
				e.includes('Failed to fetch') ||
				e.includes('not found') ||
				e.includes('No verification keys') ||
				e.includes('DID mismatch'),
		);
		process.exit(couldNotVerify ? 2 : 1);
	}
} catch (err) {
	if (err instanceof MetadataFetchError) {
		console.error(`\n✗ ${err.message}`);
		process.exit(2);
	}

	if (err instanceof MetadataVerificationError) {
		console.error(`\n✗ ${err.message}`);
		process.exit(1);
	}

	throw err;
}
