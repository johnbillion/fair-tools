import { resolveTxt } from 'node:dns/promises';
import { Client } from '@did-plc/lib';
import { PLC_DIRECTORY_URL } from './did.js';

const DOMAIN_REGEX = /^[a-z0-9][a-z0-9-]{0,62}(\.[a-z0-9][a-z0-9-]{0,62})+$/i;
const DID_RECORD_REGEX = /^did="?([^"]+)"?$/;

export class InvalidDomainError extends Error {}

export class DnsRecordNotFoundError extends Error {
	constructor(recordHost) {
		super(`No DNS TXT record found at ${recordHost}`);
	}
}

export class DnsRecordInvalidError extends Error {}

export class DidMismatchError extends Error {
	constructor(expectedDid, foundDid) {
		super(`DID mismatch: expected ${expectedDid}, found ${foundDid}`);
	}
}

export class NoAliasError extends Error {
	constructor() {
		super('No fair:// alias found in alsoKnownAs field');
	}
}

export class MultipleAliasesError extends Error {
	constructor(count) {
		super(`Found ${count} fair:// aliases, but only one is allowed`);
	}
}

/**
 * Validate domain format
 * @param {string} domain
 * @throws {InvalidDomainError} If domain is invalid
 */
export function validateDomain(domain) {
	if (!domain) {
		throw new InvalidDomainError('Domain is required');
	}

	if (domain.length > 255) {
		throw new InvalidDomainError('Domain must not exceed 255 characters');
	}

	if (!DOMAIN_REGEX.test(domain)) {
		throw new InvalidDomainError('Invalid domain format');
	}

	if (domain.toLowerCase().startsWith('www.')) {
		throw new InvalidDomainError('Use the bare domain without www prefix');
	}
}

/**
 * Look up DNS TXT record and verify DID
 * @param {string} domain
 * @param {string} expectedDid
 * @throws {InvalidDomainError} If domain format is invalid
 * @throws {DnsRecordNotFoundError} If no DNS TXT record exists
 * @throws {DnsRecordInvalidError} If the DNS record format is invalid
 * @throws {DidMismatchError} If the DID in the record doesn't match
 */
export async function verifyDomainDid(domain, expectedDid) {
	validateDomain(domain);
	const recordHost = `_fairpm.${domain}`;

	let records;
	try {
		records = await resolveTxt(recordHost);
	} catch (err) {
		if (err.code === 'ENODATA' || err.code === 'ENOTFOUND') {
			throw new DnsRecordNotFoundError(recordHost);
		}
		throw err;
	}

	// records is array of arrays: [['did=did:plc:...'], ['other']]
	// Flatten and find did= entries
	const flatRecords = records.flat();
	const didRecords = flatRecords.filter((r) => r.startsWith('did='));

	if (didRecords.length === 0) {
		throw new DnsRecordInvalidError(`No did= entry found in TXT record at ${recordHost}`);
	}

	// Parse the first did= record
	const match = didRecords[0].match(DID_RECORD_REGEX);
	if (!match) {
		throw new DnsRecordInvalidError(`Invalid did= format in TXT record: ${didRecords[0]}`);
	}

	const foundDid = match[1];
	if (foundDid !== expectedDid) {
		throw new DidMismatchError(expectedDid, foundDid);
	}
}

/**
 * Fetch DID document and extract the fair:// alias
 * @param {string} did
 * @param {string} [plcUrl] - The PLC directory URL (defaults to https://plc.directory)
 * @returns {Promise<string | null>} - The fair:// URL or null if none exists
 * @throws {MultipleAliasesError} If more than one fair:// alias exists
 */
export async function getFairAlias(did, plcUrl = PLC_DIRECTORY_URL) {
	const client = new Client(plcUrl);
	const doc = await client.getDocument(did);
	const aliases = (doc.alsoKnownAs || []).filter((url) => url.startsWith('fair://'));

	if (aliases.length === 0) {
		throw new NoAliasError();
	}

	if (aliases.length > 1) {
		throw new MultipleAliasesError(aliases.length);
	}

	return aliases[0];
}
