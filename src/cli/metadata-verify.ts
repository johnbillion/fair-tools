#!/usr/bin/env node

import { parseArgs } from 'node:util';
import { readFile } from 'node:fs/promises';
import {
	fetchFairMetadata,
	verifyMetadata,
	MetadataFetchError,
	MetadataVerificationError,
	Metadata,
} from '../verify.js';
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

const source = values.url || values.file;

console.log(`Verifying metadata for ${did}...`);
console.log(`Source: ${source}`);

try {
	// Load or fetch metadata
	let metadata: Metadata;
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
		let content: string;
		try {
			content = await readFile(values.file!, 'utf-8');
		} catch (err) {
			console.error(`\n✗ Failed to read file: ${(err as Error).message}`);
			process.exit(2);
		}
		try {
			metadata = JSON.parse(content);
		} catch (err) {
			console.error(`\n✗ Invalid JSON: ${(err as Error).message}`);
			process.exit(2);
		}
	}

	// Verify the metadata
	const releases = await verifyMetadata(metadata, {
		did,
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
