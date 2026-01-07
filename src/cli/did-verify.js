#!/usr/bin/env node

import { parseArgs } from 'node:util';
import { Client } from '@did-plc/lib';
import { validateDidLog, DidLogFetchError, DidLogValidationError } from '../plc-log.js';
import { verifyServiceEndpoint, MetadataFetchError, MetadataVerificationError } from '../verify.js';
import {
	getFairAlias,
	verifyDomainDid,
	NoAliasError,
	MultipleAliasesError,
	DnsRecordNotFoundError,
	DnsRecordInvalidError,
	DidMismatchError,
} from '../domain.js';
import { validatePlcDid, DidValidationError } from '../did-validation.js';
import { PLC_DIRECTORY_URL, FAIR_SERVICE_TYPE } from '../did.js';

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

/** @type {{valid: boolean, did: string, log: object, services: object[], alias: object|null, warnings: string[], errors: string[]}} */
const result = {
	valid: true,
	did: values.did,
	log: { valid: false },
	services: [],
	alias: null,
	warnings: [],
	errors: [],
};

console.log(`Verifying ${values.did}...\n`);

// 1. Validate DID log
console.log('DID Log Validation:');

try {
	const logResult = await validateDidLog(values.did);
	result.log = {
		valid: true,
		operationCount: logResult.operations.length,
	};

	console.log(`  ✓ ${logResult.operations.length} operations validated`);
	console.log(`  ✓ Current state computed successfully`);
} catch (err) {
	result.valid = false;
	if (err instanceof DidLogFetchError) {
		result.log = { valid: false, error: err.message };
		result.errors.push(`DID log: ${err.message}`);
		console.log(`  ✗ Could not fetch DID log: ${err.message}`);
	} else if (err instanceof DidLogValidationError) {
		result.log = { valid: false, error: err.message };
		result.errors.push(`DID log: ${err.message}`);
		console.log(`  ✗ ${err.message}`);
	} else {
		throw err;
	}
}

// 2. Fetch DID document and find FAIR services
let didDocument;
try {
	const client = new Client(PLC_DIRECTORY_URL);
	didDocument = await client.getDocument(values.did);
} catch (err) {
	result.valid = false;
	result.errors.push(`Could not fetch DID document: ${err.message}`);
	console.log(`\n✗ Could not fetch DID document: ${err.message}`);
	process.exit(2);
}

// Find FAIR service endpoints
const fairServices = (didDocument.service || []).filter((s) => s.type === FAIR_SERVICE_TYPE);

console.log('\nService Endpoints:');

if (fairServices.length === 0) {
	result.warnings.push('No FairPackageManagementRepo services found');
	console.log('  ⚠ No FairPackageManagementRepo services found');
} else {
	// 3. Verify each service endpoint
	for (const service of fairServices) {
		const serviceUrl = service.serviceEndpoint;

		console.log(`\n  ${serviceUrl}:`);

		try {
			const serviceResult = await verifyServiceEndpoint(serviceUrl, {
				did: values.did,
				allReleases: values['all-releases'],
			});

			result.services.push({
				url: serviceUrl,
				valid: serviceResult.valid,
				releases: serviceResult.releases,
				warnings: serviceResult.warnings,
				errors: serviceResult.errors,
			});

			if (!serviceResult.valid) {
				result.valid = false;
				result.errors.push(...serviceResult.errors.map((e) => `${serviceUrl}: ${e}`));
			}
			result.warnings.push(...serviceResult.warnings.map((w) => `${serviceUrl}: ${w}`));

			if (serviceResult.valid) {
				console.log('    ✓ Metadata document valid');
			} else {
				console.log('    ✗ Metadata verification failed');
			}

			// Show release results
			for (const release of serviceResult.releases) {
				const releaseIcon = release.valid ? '✓' : '✗';
				console.log(`    ${releaseIcon} Release v${release.version}`);

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
					const icon = artifact.signatureValid && (artifact.checksumMissing || artifact.checksumValid) ? '✓' : '✗';
					console.log(`      ${icon} ${artifact.url}: ${sigStatus}, ${checksumStatus}`);
				}
			}
		} catch (err) {
			result.valid = false;
			const errorMsg =
				err instanceof MetadataFetchError || err instanceof MetadataVerificationError
					? err.message
					: `Unexpected error: ${err.message}`;

			result.services.push({
				url: serviceUrl,
				valid: false,
				error: errorMsg,
			});
			result.errors.push(`${serviceUrl}: ${errorMsg}`);

			console.log(`    ✗ ${errorMsg}`);
		}
	}
}

// 4. Verify domain aliases
console.log('\nDomain Aliases:');

try {
	const alias = await getFairAlias(values.did);
	const domain = alias.replace(/^fair:\/\//, '').replace(/\/$/, '');

	try {
		await verifyDomainDid(domain, values.did);
		result.alias = {
			url: alias,
			domain,
			valid: true,
		};

		console.log(`  ✓ ${alias}`);
		console.log(`    DNS record _fairpm.${domain} verified`);
	} catch (err) {
		result.valid = false;
		const errorMsg =
			err instanceof DnsRecordNotFoundError || err instanceof DnsRecordInvalidError || err instanceof DidMismatchError
				? err.message
				: `DNS verification failed: ${err.message}`;

		result.alias = {
			url: alias,
			domain,
			valid: false,
			error: errorMsg,
		};
		result.errors.push(`Domain alias ${alias}: ${errorMsg}`);

		console.log(`  ✗ ${alias}: ${errorMsg}`);
	}
} catch (err) {
	if (err instanceof NoAliasError) {
		result.alias = { valid: true, note: 'No fair:// alias configured' };
		console.log('  - No fair:// alias configured');
	} else if (err instanceof MultipleAliasesError) {
		result.valid = false;
		result.alias = { valid: false, error: err.message };
		result.errors.push(`Domain alias: ${err.message}`);
		console.log(`  ✗ ${err.message}`);
	} else {
		throw err;
	}
}

// Output final result
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

if (result.warnings.length > 0) {
	console.log('\nWarnings:');
	for (const warning of result.warnings) {
		console.log(`  ⚠ ${warning}`);
	}
}

// Determine exit code
if (!result.valid) {
	// Check if it was a "could not verify" situation
	const couldNotVerify =
		result.errors.some(
			(e) =>
				e.includes('Could not fetch') ||
				e.includes('Failed to fetch') ||
				e.includes('not found') ||
				e.includes('No verification keys'),
		) ||
		(result.log && !result.log.valid && result.log.error?.includes('Failed to fetch'));

	process.exit(couldNotVerify ? 2 : 1);
}
