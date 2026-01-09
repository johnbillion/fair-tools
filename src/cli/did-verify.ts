#!/usr/bin/env node

import { parseArgs } from 'node:util';
import { validatePlcDid, DidValidationError } from '../did-validation.js';
import { verifyDid } from '../verify.js';

const { values } = parseArgs({
	options: {
		did: {
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
	console.log(`Usage: fair-tools did verify [options]

Comprehensive verification of a DID, its document, and FAIR metadata.

This command performs:
  1. DID log validation - Verifies the complete operation history from genesis
  2. DID document validation - Ensures computed state matches current document
  3. Service endpoint verification - Validates FAIR metadata at each service URL
  4. Domain alias verification - Checks fair:// aliases resolve correctly

Required options:
  --did <did>       The DID to verify (did:plc:...)

Optional:
  --all-releases    Verify all releases, not just the latest
  --help            Show this help message

Exit codes:
  0  All verifications passed
  1  Verification failed (invalid signature, broken chain, etc.)
  2  Could not verify (network error, DID not found, etc.)`);
	process.exit(0);
}

// Validate required options
if (!values.did) {
	console.error('Error: Missing required option: --did');
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

console.log(`Verifying ${did}...\n`);

const result = await verifyDid({
	did,
	allReleases: values['all-releases'],
});

// DID Log
console.log('DID Log Validation:');
if (result.log.valid) {
	console.log(`  ✓ ${result.log.operationCount} operations validated`);
	console.log(`  ✓ Current state computed successfully`);
} else {
	console.log(`  ✗ ${result.log.error}`);
}

// Services
console.log('\nService Endpoints:');
if (result.services.length === 0) {
	console.log('  - No FairPackageManagementRepo services found');
} else {
	for (const service of result.services) {
		console.log(`\n  ${service.url}:`);

		if (service.valid) {
			console.log('    ✓ Metadata document valid');
			for (const release of service.releases || []) {
				console.log(`    ✓ Release v${release.version}`);
				for (const artifact of release.artifacts) {
					console.log(`      ✓ ${artifact.url}: Signature valid (${artifact.keyId}), checksum valid`);
				}
			}
		} else {
			console.log(`    ✗ ${service.error}`);
			// Show release results if available
			if (service.releases) {
				for (const release of service.releases) {
					console.log(`    ✗ Release v${release.version}`);
					for (const artifact of release.artifacts) {
						const sigStatus = artifact.signatureValid ? `Signature valid (${artifact.keyId})` : 'Signature FAILED';
						const checksumStatus = artifact.checksumValid ? 'checksum valid' : 'checksum FAILED';
						const icon = artifact.signatureValid && artifact.checksumValid ? '✓' : '✗';
						console.log(`      ${icon} ${artifact.url}: ${sigStatus}, ${checksumStatus}`);
					}
				}
			}
		}
	}
}

// Domain Aliases
console.log('\nDomain Aliases:');
if (result.alias) {
	if (result.alias.note) {
		console.log(`  - ${result.alias.note}`);
	} else if (result.alias.valid) {
		console.log(`  ✓ ${result.alias.url}`);
		console.log(`    DNS record _fairpm.${result.alias.domain} verified`);
	} else {
		console.log(`  ✗ ${result.alias.url}: ${result.alias.error}`);
	}
}

// Overall result
console.log('');
if (result.valid) {
	console.log('Overall: PASSED');
} else {
	console.log('Overall: FAILED');

	if (result.errors.length > 0) {
		console.log('\nErrors:');
		for (const error of result.errors) {
			console.log(`  ✗ ${error}`);
		}
	}
}

// Exit code
if (!result.valid) {
	process.exit(1);
}
