#!/usr/bin/env node

import { parseArgs } from 'node:util';
import { DnsRecordNotFoundError, DnsRecordInvalidError, verifyDomainDid } from '../domain.js';
import { validatePlcDid, DidValidationError } from '../did-validation.js';

const { values } = parseArgs({
	options: {
		domain: {
			type: 'string',
		},
		did: {
			type: 'string',
		},
		help: {
			type: 'boolean',
		},
	},
});

if (values.help) {
	console.log(`Usage: fair-tools did domain verify [options]

Verify the DID DNS record of a domain. Use this to check DNS propagation
before adding a domain alias to a DID's alsoKnownAs field.

Required options:
  --domain <domain>  The domain to verify (e.g., example.com)
  --did <did>        The DID that should own this domain (did:plc:...)

Optional:
  --help             Show this help message

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
if (!values.domain || !values.did) {
	const missing = [];
	if (!values.domain) missing.push('--domain');
	if (!values.did) missing.push('--did');
	console.error(`Error: Missing required options: ${missing.join(', ')}`);
	console.error('Run with --help for usage information.');
	process.exit(1);
}

const domain = values.domain;
const did = values.did;

// Validate DID format
try {
	validatePlcDid(did);
} catch (err) {
	if (err instanceof DidValidationError) {
		console.error(`Error: ${err.message}`);
		process.exit(1);
	}
	throw err;
}

console.log(`Verifying domain ${domain}...`);

try {
	await verifyDomainDid(domain, did);
	console.log(`\n✓ Domain verified: ${domain}`);
	console.log(`  DNS record: _fairpm.${domain}`);
	console.log(`  DID: ${did}`);
} catch (err) {
	console.error(`\n✗ ${(err as Error).message}`);
	if (err instanceof DnsRecordNotFoundError || err instanceof DnsRecordInvalidError) {
		console.error(`\n  To verify this domain, add a TXT record:`);
		console.error(`    Host: _fairpm.${domain}`);
		console.error(`    Value: did=${did}`);
	}
	process.exit(1);
}
