#!/usr/bin/env node

import { parseArgs } from 'node:util';
import { DnsRecordNotFoundError, DnsRecordInvalidError, getFairAlias, verifyDomainDid } from '../domain.js';
import { validatePlcDid, DidValidationError } from '../did-validation.js';

const { values } = parseArgs({
	options: {
		did: {
			type: 'string',
		},
		help: {
			type: 'boolean',
		},
	},
});

if (values.help) {
	console.log(`Usage: fair-tools did domain verify-alias [options]

Verify the fair:// domain alias in a DID's alsoKnownAs field.

This command fetches the DID document, extracts the fair:// alias from
the alsoKnownAs field, and verifies it by checking the corresponding
DNS TXT record.

Required options:
  --did <did>  The DID to verify the alias for (did:plc:...)

Optional:
  --help       Show this help message

DNS Record Setup:
  The fair:// alias requires a TXT record at _fairpm.<domain> with the value:
    did=<your-did>

  Example:
    Host: _fairpm.example.com
    Type: TXT
    Value: did=did:plc:abc123...`);
	process.exit(0);
}

// Validate required options
if (!values.did) {
	console.error('Error: Missing required option: --did');
	console.error('Run with --help for usage information.');
	process.exit(1);
}

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

console.log(`Fetching DID document for ${did}...`);

let alias: string;
try {
	alias = await getFairAlias(did);
} catch (err) {
	console.error(`\n✗ ${(err as Error).message}`);
	process.exit(1);
}

const domain = alias.replace(/^fair:\/\//, '').replace(/\/$/, '');

console.log(`\nVerifying ${alias}...`);

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
