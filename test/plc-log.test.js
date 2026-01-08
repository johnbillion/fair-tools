import { describe, it, mock } from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import { DidLogValidationError, DidLogFetchError, validateOperations, fetchDidLog } from '../src/plc-log.js';

// Load fixture once for all tests
const FIXTURE_DID = 'did:plc:q2afge25l63iz553aumeqi3w';
const validLog = JSON.parse(readFileSync(new URL('./fixtures/plc-log-q2afge25l63iz553aumeqi3w.json', import.meta.url)));

describe('fetchDidLog', () => {
	it('throws DidLogFetchError on network error', async () => {
		const originalFetch = globalThis.fetch;
		globalThis.fetch = mock.fn(() => Promise.reject(new Error('Network failed')));

		try {
			await assert.rejects(
				() => fetchDidLog('did:plc:test123'),
				(err) => {
					assert.ok(err instanceof DidLogFetchError);
					assert.ok(err.message.includes('Failed to fetch DID log'));
					return true;
				},
			);
		} finally {
			globalThis.fetch = originalFetch;
		}
	});

	it('throws DidLogFetchError when DID not found (404)', async () => {
		const originalFetch = globalThis.fetch;
		globalThis.fetch = mock.fn(() =>
			Promise.resolve({
				ok: false,
				status: 404,
			}),
		);

		try {
			await assert.rejects(
				() => fetchDidLog('did:plc:notfound'),
				(err) => {
					assert.ok(err instanceof DidLogFetchError);
					assert.ok(err.message.includes('HTTP 404'));
					return true;
				},
			);
		} finally {
			globalThis.fetch = originalFetch;
		}
	});

	it('throws DidLogFetchError on other HTTP errors', async () => {
		const originalFetch = globalThis.fetch;
		globalThis.fetch = mock.fn(() =>
			Promise.resolve({
				ok: false,
				status: 500,
			}),
		);

		try {
			await assert.rejects(
				() => fetchDidLog('did:plc:test123'),
				(err) => {
					assert.ok(err instanceof DidLogFetchError);
					assert.ok(err.message.includes('HTTP 500'));
					return true;
				},
			);
		} finally {
			globalThis.fetch = originalFetch;
		}
	});

	it('throws DidLogFetchError on invalid JSON response', async () => {
		const originalFetch = globalThis.fetch;
		globalThis.fetch = mock.fn(() =>
			Promise.resolve({
				ok: true,
				json: () => Promise.reject(new Error('Invalid JSON')),
			}),
		);

		try {
			await assert.rejects(
				() => fetchDidLog('did:plc:test123'),
				(err) => {
					assert.ok(err instanceof DidLogFetchError);
					assert.ok(err.message.includes('Failed to parse DID log response'));
					return true;
				},
			);
		} finally {
			globalThis.fetch = originalFetch;
		}
	});
});

describe('validateOperations', () => {
	it('throws DidLogValidationError for empty log', async () => {
		await assert.rejects(
			() => validateOperations('did:plc:test123', []),
			(err) => {
				assert.ok(err instanceof DidLogValidationError);
				assert.ok(err.message.includes('empty or invalid'));
				return true;
			},
		);
	});

	it('throws DidLogValidationError when genesis has non-null prev', async () => {
		const ops = [
			{
				prev: 'bafysomeothercid',
				rotationKeys: ['did:key:zQ3shtest'],
				verificationMethods: {},
				services: {},
				alsoKnownAs: [],
				sig: 'fakesig',
			},
		];

		await assert.rejects(
			() => validateOperations('did:plc:test123', ops),
			(err) => {
				assert.ok(err instanceof DidLogValidationError);
				assert.ok(err.message.includes('Genesis operation must have null prev'));
				return true;
			},
		);
	});

	it('throws DidLogValidationError when computed DID does not match', async () => {
		const ops = [
			{
				type: 'plc_operation',
				prev: null,
				rotationKeys: ['did:key:zQ3shZc2QzApp2oymGvQbzP8eKheVshBHbU4ZYjeXqwSKEn6N'],
				verificationMethods: {
					atproto: 'did:key:zQ3shZc2QzApp2oymGvQbzP8eKheVshBHbU4ZYjeXqwSKEn6N',
				},
				alsoKnownAs: [],
				services: {},
				sig: 'MEUCIQDLbsQO8kQl1x7zyXwASVpZUFI3PnJg9LlJmOmxNYxPgQIgGrHm7AYdYq7EgHiCIIIRQ3LB9Dn3LMdmPC1bPbfX2Xk',
			},
		];

		await assert.rejects(
			() => validateOperations('did:plc:wrongdid12345678901234', ops),
			(err) => {
				assert.ok(err instanceof DidLogValidationError);
				assert.ok(err.message.includes('DID mismatch'));
				return true;
			},
		);
	});

	it('throws DidLogValidationError on invalid genesis signature', async () => {
		const ops = [
			{
				type: 'plc_operation',
				prev: null,
				rotationKeys: ['did:key:zQ3shZc2QzApp2oymGvQbzP8eKheVshBHbU4ZYjeXqwSKEn6N'],
				verificationMethods: {},
				alsoKnownAs: [],
				services: {},
				sig: 'invalidsignature',
			},
		];

		await assert.rejects(
			() => validateOperations('did:plc:test123', ops),
			(err) => {
				assert.ok(err instanceof DidLogValidationError);
				return true;
			},
		);
	});

	it('throws DidLogValidationError when second operation has wrong prev CID', async () => {
		// Use valid first operation from fixture, tamper with second operation's prev
		const tamperedLog = [validLog[0], { ...validLog[1], prev: 'bafyreigtamperedcidvalue1234567890abcdefg' }];

		await assert.rejects(
			() => validateOperations(FIXTURE_DID, tamperedLog),
			(err) => {
				assert.ok(err instanceof DidLogValidationError);
				assert.ok(err.message.includes('prev mismatch'));
				return true;
			},
		);
	});

	it('throws DidLogValidationError when second operation has invalid signature', async () => {
		// Use valid first operation from fixture, tamper with second operation's signature
		const tamperedLog = [validLog[0], { ...validLog[1], sig: 'tamperedsignaturethatwontverify' }];

		await assert.rejects(
			() => validateOperations(FIXTURE_DID, tamperedLog),
			(err) => {
				assert.ok(err instanceof DidLogValidationError);
				return true;
			},
		);
	});

	it('validates a valid DID log successfully', async () => {
		const result = await validateOperations(FIXTURE_DID, validLog);

		assert.strictEqual(result.did, FIXTURE_DID);
		assert.strictEqual(result.operations.length, validLog.length);
	});

	it('throws DidLogValidationError when DID has been tombstoned', async () => {
		// Use valid first operation from fixture, add tombstone as second
		const tombstoneOps = [
			validLog[0],
			{
				type: 'plc_tombstone',
				prev: 'bafyreig4gzh5lnlskbqjveytxqn6k2yuqj5cixeqjxz3cjh6xmzqvqgque', // CID of first op
				sig: 'fakesig',
			},
		];

		await assert.rejects(
			() => validateOperations(FIXTURE_DID, tombstoneOps),
			(err) => {
				assert.ok(err instanceof DidLogValidationError);
				assert.ok(err.message.includes('tombstoned'));
				return true;
			},
		);
	});
});
