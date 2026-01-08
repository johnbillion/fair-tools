import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
	validateDomain,
	InvalidDomainError,
	DnsRecordNotFoundError,
	DnsRecordInvalidError,
	DidMismatchError,
	NoAliasError,
	MultipleAliasesError,
} from '../src/domain.js';

describe('validateDomain', () => {
	it('accepts valid domain', () => {
		assert.doesNotThrow(() => validateDomain('example.com'));
	});

	it('accepts subdomain', () => {
		assert.doesNotThrow(() => validateDomain('sub.example.com'));
	});

	it('accepts domain with hyphens', () => {
		assert.doesNotThrow(() => validateDomain('my-domain.example.com'));
	});

	it('throws InvalidDomainError for empty domain', () => {
		assert.throws(() => validateDomain(''), InvalidDomainError);
	});

	it('throws InvalidDomainError for null domain', () => {
		assert.throws(() => validateDomain(null), InvalidDomainError);
	});

	it('accepts uppercase domain', () => {
		assert.doesNotThrow(() => validateDomain('EXAMPLE.COM'));
	});

	it('throws InvalidDomainError for domain exceeding 255 characters', () => {
		// Create a valid-format domain that exceeds 255 chars
		// Each label max 63 chars, so use multiple labels
		const longDomain = 'a'.repeat(63) + '.' + 'b'.repeat(63) + '.' + 'c'.repeat(63) + '.' + 'd'.repeat(63) + '.com';
		assert.ok(longDomain.length > 255, `Domain should be > 255 chars, got ${longDomain.length}`);
		assert.throws(() => validateDomain(longDomain), {
			message: 'Domain must not exceed 255 characters',
		});
	});

	it('throws InvalidDomainError for single label domain', () => {
		assert.throws(() => validateDomain('localhost'), InvalidDomainError);
	});

	it('throws InvalidDomainError for domain starting with hyphen', () => {
		assert.throws(() => validateDomain('-example.com'), InvalidDomainError);
	});

	it('throws InvalidDomainError for domain with invalid characters', () => {
		assert.throws(() => validateDomain('example_.com'), InvalidDomainError);
	});

	it('throws InvalidDomainError for www prefix', () => {
		assert.throws(() => validateDomain('www.example.com'), {
			message: 'Use the bare domain without www prefix',
		});
	});
});

describe('Error classes', () => {
	describe('InvalidDomainError', () => {
		it('is instanceof Error', () => {
			const err = new InvalidDomainError('test message');
			assert.strictEqual(err.message, 'test message');
			assert.ok(err instanceof Error);
		});
	});

	describe('DnsRecordNotFoundError', () => {
		it('is instanceof Error', () => {
			const err = new DnsRecordNotFoundError('_fairpm.example.com');
			assert.strictEqual(err.message, 'No DNS TXT record found at _fairpm.example.com');
			assert.ok(err instanceof Error);
		});
	});

	describe('DnsRecordInvalidError', () => {
		it('is instanceof Error', () => {
			const err = new DnsRecordInvalidError('Invalid format');
			assert.strictEqual(err.message, 'Invalid format');
			assert.ok(err instanceof Error);
		});
	});

	describe('DidMismatchError', () => {
		it('is instanceof Error', () => {
			const err = new DidMismatchError('did:plc:expected', 'did:plc:found');
			assert.strictEqual(err.message, 'DID mismatch: expected did:plc:expected, found did:plc:found');
			assert.ok(err instanceof Error);
		});
	});

	describe('NoAliasError', () => {
		it('is instanceof Error', () => {
			const err = new NoAliasError();
			assert.strictEqual(err.message, 'No fair:// alias found in alsoKnownAs field');
			assert.ok(err instanceof Error);
		});
	});

	describe('MultipleAliasesError', () => {
		it('is instanceof Error', () => {
			const err = new MultipleAliasesError(2);
			assert.strictEqual(err.message, 'Found 2 fair:// aliases, but only one is allowed');
			assert.ok(err instanceof Error);
		});
	});
});
