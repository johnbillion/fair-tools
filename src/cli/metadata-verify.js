#!/usr/bin/env node

import { parseArgs } from 'node:util';
import { readFile } from 'node:fs/promises';
import { fetchFairMetadata, verifyMetadata, MetadataFetchError, MetadataVerificationError } from '../verify.js';
import { validatePlcDid, DidValidationError } from '../did-validation.js';

const { values } = parseArgs({
	options: {
		did: {
			type: 'string',
		},
		url: {
			type: 'string',
		},
		file: {
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
	console.log(`Usage: fair-tools metadata verify [options]

Verify a FAIR metadata document including signature and checksum validation.

Required options:
  --did <did>       The DID to verify against (must match metadata.id)
  --url <url>       URL to fetch metadata from (exactly one of --url or --file required)
  --file <path>     Local file path to metadata (exactly one of --url or --file required)

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
if (!values.did) {
	console.error('Error: Missing required option: --did');
	console.error('Run with --help for usage information.');
	process.exit(2);
}

if (!values.url && !values.file) {
	console.error('Error: Must provide either --url or --file');
	console.error('Run with --help for usage information.');
	process.exit(2);
}

if (values.url && values.file) {
	console.error('Error: Cannot provide both --url and --file');
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

const source = values.url || values.file;

console.log(`Verifying metadata for ${values.did}...`);
console.log(`Source: ${source}`);

try {
	// Load or fetch metadata
	let metadata;
	if (values.url) {
		try {
			metadata = await fetchFairMetadata(values.url);
		} catch (err) {
			if (err instanceof MetadataFetchError) {
				console.error(`\n✗ ${err.message}`);
				process.exit(2);
			}
			throw err;
		}
	} else {
		let content;
		try {
			content = await readFile(values.file, 'utf-8');
		} catch (err) {
			console.error(`\n✗ Failed to read file: ${err.message}`);
			process.exit(2);
		}
		try {
			metadata = JSON.parse(content);
		} catch (err) {
			console.error(`\n✗ Invalid JSON: ${err.message}`);
			process.exit(2);
		}
	}

	// Verify the metadata
	const releases = await verifyMetadata(metadata, {
		did: values.did,
		allReleases: values['all-releases'],
	});

	console.log(`\n✓ Metadata verification passed`);
	displayReleases(releases);
} catch (err) {
	if (err instanceof MetadataVerificationError) {
		console.error(`\n✗ ${err.message}`);
		if (err.result) {
			displayReleases(err.result, true);
		}
		process.exit(1);
	}
	throw err;
}

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
