import { resolveTxt } from 'node:dns/promises';

/**
 * Maximum length of a domain name per DNS specification.
 */
const MAX_DOMAIN_LENGTH = 255;

const DOMAIN_REGEX = /^[a-z0-9][a-z0-9-]{0,62}(\.[a-z0-9][a-z0-9-]{0,62})+$/i;
const DID_RECORD_REGEX = /^did="?([^"]+)"?$/;

export class InvalidDomainError extends Error {}

export class DnsRecordNotFoundError extends Error {
	constructor(recordHost: string) {
		super(`No DNS TXT record found at ${recordHost}`);
	}
}

export class DnsRecordInvalidError extends Error {}

export class DidMismatchError extends Error {
	constructor(expectedDid: string, foundDid: string) {
		super(`DID mismatch: expected ${expectedDid}, found ${foundDid}`);
	}
}

/**
 * Validate domain format
 * @param {string} domain
 * @throws {InvalidDomainError} If domain is invalid
 */
export function validateDomain(domain: string): void {
	if (!domain) {
		throw new InvalidDomainError('Domain is required');
	}

	if (domain.length > MAX_DOMAIN_LENGTH) {
		throw new InvalidDomainError(`Domain must not exceed ${MAX_DOMAIN_LENGTH} characters`);
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
export async function verifyDomainDid(domain: string, expectedDid: string): Promise<void> {
	validateDomain(domain);
	const recordHost = `_fairpm.${domain}`;

	let records: string[][];
	try {
		records = await resolveTxt(recordHost);
	} catch (err) {
		const error = err as NodeJS.ErrnoException;
		if (error.code === 'ENODATA' || error.code === 'ENOTFOUND') {
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

// Re-export from plc.js for backward compatibility
export { getFairAlias, NoAliasError, MultipleAliasesError } from './plc.js';
