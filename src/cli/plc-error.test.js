import { describe, it, mock } from 'node:test';
import assert from 'node:assert';
import { formatPlcError, diagnosePlcError, logPlcError } from './plc-error.js';

describe('formatPlcError', () => {
	it('returns message for regular errors', () => {
		const err = new Error('Something went wrong');
		assert.strictEqual(formatPlcError(err), 'Something went wrong');
	});

	it('formats PlcClientError with string data', () => {
		const err = new Error('Request failed with status code 400');
		err.status = 400;
		err.data = 'Invalid signature on op';
		assert.strictEqual(
			formatPlcError(err),
			'Request failed with status code 400 (400): Invalid signature on op'
		);
	});

	it('formats PlcClientError with object data containing message', () => {
		const err = new Error('Request failed with status code 400');
		err.status = 400;
		err.data = { message: 'Key not found' };
		assert.strictEqual(
			formatPlcError(err),
			'Request failed with status code 400 (400): Key not found'
		);
	});

	it('formats PlcClientError with object data containing error', () => {
		const err = new Error('Request failed with status code 500');
		err.status = 500;
		err.data = { error: 'Internal server error' };
		assert.strictEqual(
			formatPlcError(err),
			'Request failed with status code 500 (500): Internal server error'
		);
	});

	it('JSON stringifies object data without message or error', () => {
		const err = new Error('Request failed with status code 400');
		err.status = 400;
		err.data = { code: 'INVALID_OP', details: 'bad' };
		assert.strictEqual(
			formatPlcError(err),
			'Request failed with status code 400 (400): {"code":"INVALID_OP","details":"bad"}'
		);
	});

	it('excludes data when includeData is false', () => {
		const err = new Error('Request failed with status code 400');
		err.status = 400;
		err.data = 'Some detailed error message';
		assert.strictEqual(
			formatPlcError(err, { includeData: false }),
			'Request failed with status code 400 (400)'
		);
	});

	it('returns status without data when error has status but no data', () => {
		const err = new Error('Request failed with status code 404');
		err.status = 404;
		assert.strictEqual(
			formatPlcError(err),
			'Request failed with status code 404 (404)'
		);
	});
});

describe('diagnosePlcError', () => {
	it('returns empty array for non-400 errors', () => {
		const err = new Error('Server error');
		err.status = 500;
		err.data = 'Internal error';
		assert.deepStrictEqual(diagnosePlcError(err), []);
	});

	it('returns empty array when data is not a string and has no message', () => {
		const err = new Error('Bad request');
		err.status = 400;
		err.data = { code: 'INVALID' };
		assert.deepStrictEqual(diagnosePlcError(err), []);
	});

	it('extracts hints from object data with message property', () => {
		const err = new Error('Bad request');
		err.status = 400;
		const op = {
			rotationKeys: ['did:key:zQ3shpnvgkfhKzXp7cokYi1y6QGnue371C4BFFwFJz6qj3RNH'],
		};
		err.data = { message: `Invalid signature on op: ${JSON.stringify(op)}` };
		const hints = diagnosePlcError(err, {
			signerPublicKey: 'did:key:zQ3shgzHYGG4X5pQHMiJKbjgnF7foYR3LeLbon7zeF32yDZPQ',
		});
		assert.ok(hints.some((h) => h.includes('is not in the DID\'s current rotation keys')));
	});

	it('returns empty array when no JSON can be extracted', () => {
		const err = new Error('Bad request');
		err.status = 400;
		err.data = 'Something unexpected happened';
		assert.deepStrictEqual(diagnosePlcError(err), []);
	});

	it('returns empty array for malformed JSON', () => {
		const err = new Error('Bad request');
		err.status = 400;
		err.data = 'Invalid signature on op: {not valid json}';
		const hints = diagnosePlcError(err, {
			signerPublicKey: 'did:key:zQ3shgzHYGG4X5pQHMiJKbjgnF7foYR3LeLbon7zeF32yDZPQ',
		});
		assert.deepStrictEqual(hints, []);
	});

	describe('signing key errors', () => {
		it('detects when signing key is not in rotation keys', () => {
			const err = new Error('Bad request');
			err.status = 400;
			const op = {
				rotationKeys: ['did:key:zQ3shpnvgkfhKzXp7cokYi1y6QGnue371C4BFFwFJz6qj3RNH'],
				verificationMethods: {},
			};
			err.data = `Invalid signature on op: ${JSON.stringify(op)}`;
			const hints = diagnosePlcError(err, {
				signerPublicKey: 'did:key:zQ3shgzHYGG4X5pQHMiJKbjgnF7foYR3LeLbon7zeF32yDZPQ',
			});
			assert.ok(hints.some((h) => h.includes('is not in the DID\'s current rotation keys')));
			assert.ok(hints.some((h) => h.includes('Use --signing-key')));
		});

		it('does not add signing key hint when signing key is valid', () => {
			const err = new Error('Bad request');
			err.status = 400;
			const op = {
				rotationKeys: ['did:key:zQ3shpnvgkfhKzXp7cokYi1y6QGnue371C4BFFwFJz6qj3RNH'],
			};
			err.data = `some error: ${JSON.stringify(op)}`;
			const hints = diagnosePlcError(err, {
				signerPublicKey: 'did:key:zQ3shpnvgkfhKzXp7cokYi1y6QGnue371C4BFFwFJz6qj3RNH',
			});
			assert.ok(!hints.some((h) => h.includes('is not in the DID\'s current rotation keys')));
		});
	});

});

describe('logPlcError', () => {
	it('includes data when no hints are available', () => {
		const err = new Error('Request failed with status code 400');
		err.status = 400;
		err.data = 'Some error without JSON';
		const logs = [];
		const originalError = console.error;
		console.error = (msg) => logs.push(msg);
		try {
			logPlcError('Error', err);
		} finally {
			console.error = originalError;
		}
		assert.strictEqual(logs.length, 1);
		assert.ok(logs[0].includes('Some error without JSON'));
	});

	it('excludes data when hints are available', () => {
		const err = new Error('Request failed with status code 400');
		err.status = 400;
		const op = {
			rotationKeys: ['did:key:zQ3shpnvgkfhKzXp7cokYi1y6QGnue371C4BFFwFJz6qj3RNH'],
		};
		err.data = `Invalid signature on op: ${JSON.stringify(op)}`;
		const logs = [];
		const originalError = console.error;
		console.error = (msg) => logs.push(msg);
		try {
			logPlcError('Error', err, {
				signerPublicKey: 'did:key:zQ3shgzHYGG4X5pQHMiJKbjgnF7foYR3LeLbon7zeF32yDZPQ',
			});
		} finally {
			console.error = originalError;
		}
		// The error message should not include the JSON blob
		assert.ok(!logs[0].includes('rotationKeys'));
		assert.ok(logs[0].includes('(400)'));
	});
});
