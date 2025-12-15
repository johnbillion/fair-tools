#!/usr/bin/env node

import { parseArgs } from 'node:util';
import {
	DnsRecordNotFoundError,
	DnsRecordInvalidError,
	verifyDomainDid,
} from '../domain.js';
import { validatePlcDid, DidValidationError } from '../did-validation.js';

const { values } = parseArgs({
	options: {
		domain: {
			type: 'string',
			short: 'd',
		},
		did: {
			type: 'string',
			short: 'i',
		},
		help: {
			type: 'boolean',
			short: 'h',
		},
	},
});

if (values.help) {
	console.log(`Usage: fair-tools did domain verify [options]

Verify the DID DNS record of a domain. Use this to check DNS propagation
before adding a domain alias to a DID's alsoKnownAs field.

Required options:
  -d, --domain <domain>   The domain to verify (e.g., example.com)
  -i, --did <did>         The DID that should own this domain (did:plc:...)

Optional:
  -h, --help              Show this help message

DNS Record Setup:
  To verify a domain, add a TXT record at _fairpm.<domain> with the value:
    did=<your-did>

  Example:
    Host: _fairpm.example.com
    Type: TXT
    Value: did=did:plc:abc123...`);
	process.exit(0);
}

// Validate required options
const required = ['domain', 'did'];
const missing = required.filter((opt) => !values[opt]);
if (missing.length > 0) {
	console.error(
		`Error: Missing required options: ${missing.map((o) => `--${o}`).join(', ')}`,
	);
	console.error('Run with --help for usage information.');
	process.exit(1);
}

// Validate DID format
try {
	validatePlcDid(values.did);
} catch (err) {
	if (err instanceof DidValidationError) {
		console.error(`Error: ${err.message}`);
		process.exit(1);
	}
	throw err;
}

console.log(`Verifying domain ${values.domain}...`);

try {
	await verifyDomainDid(values.domain, values.did);
	console.log(`\n✓ Domain verified: ${values.domain}`);
	console.log(`  DNS record: _fairpm.${values.domain}`);
	console.log(`  DID: ${values.did}`);
} catch (err) {
	console.error(`\n✗ ${err.message}`);
	if (
		err instanceof DnsRecordNotFoundError ||
		err instanceof DnsRecordInvalidError
	) {
		console.error(`\n  To verify this domain, add a TXT record:`);
		console.error(`    Host: _fairpm.${values.domain}`);
		console.error(`    Value: did=${values.did}`);
	}
	process.exit(1);
}
