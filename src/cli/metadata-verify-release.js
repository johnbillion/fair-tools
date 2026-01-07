#!/usr/bin/env node

import { parseArgs } from 'node:util';
import { readFile } from 'node:fs/promises';
import { fetchFairMetadata, verifyMetadataRelease, MetadataFetchError, MetadataVerificationError } from '../verify.js';
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
		version: {
			type: 'string',
		},
		help: {
			type: 'boolean',
		},
	},
});

if (values.help) {
	console.log(`Usage: fair-tools metadata verify-release [options]

Verify a specific release version from a FAIR metadata document.

Required options:
  --did <did>       The DID to verify against (must match metadata.id)
  --version <ver>   The release version to verify (e.g., "1.2.3")
  --url <url>       URL to fetch metadata from (exactly one of --url or --file required)
  --file <path>     Local file path to metadata (exactly one of --url or --file required)

Optional:
  --help            Show this help message

Exit codes:
  0  Verification passed
  1  Verification failed (invalid signature, checksum mismatch, etc.)
  2  Could not verify (network error, missing data, invalid input, etc.)`);
	process.exit(0);
}

// Validate required options
const required = ['did', 'version'];
const missing = required.filter((opt) => !values[opt]);
if (missing.length > 0) {
	console.error(`Error: Missing required options: ${missing.map((o) => `--${o}`).join(', ')}`);
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

// Validate URL format if provided
if (values.url && !values.url.startsWith('https://')) {
	console.error('Error: URL must use HTTPS');
	process.exit(2);
}

const source = values.url || values.file;

console.log(`Verifying release v${values.version} for ${values.did}...`);
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

	// Verify the specific release
	const result = await verifyMetadataRelease(metadata, values.version, {
		did: values.did,
		source,
	});

	if (result.valid) {
		console.log(`\n✓ Release v${values.version} verification passed`);
	} else {
		console.log(`\n✗ Release v${values.version} verification failed`);
	}

	// Show release results
	for (const release of result.releases) {
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

	process.exit(result.valid ? 0 : 1);
} catch (err) {
	if (err instanceof MetadataVerificationError) {
		console.error(`\n✗ ${err.message}`);
		process.exit(1);
	}
	throw err;
}
