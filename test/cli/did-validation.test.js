import { describe, it } from 'node:test';
import assert from 'node:assert';
import { validatePlcDid, DidValidationError } from '../../src/did-validation.js';

describe('validatePlcDid', () => {
	it('accepts valid did:plc: DIDs with correct length', () => {
		// Valid DIDs are exactly 32 characters: did:plc: (8) + 24 char identifier
		assert.doesNotThrow(() => {
			validatePlcDid('did:plc:abcdefghijklmnopqrstuvwx');
		});
	});

	it('rejects DIDs without did:plc: prefix', () => {
		assert.throws(
			() => validatePlcDid('abcdefghijklmnopqrstuvwx'),
			DidValidationError
		);
		assert.throws(
			() => validatePlcDid('aaa:bbb:abcdefghijklmnopqrstuvwx'),
			DidValidationError
		);
	});

	it('rejects DIDs with incorrect length', () => {
		// Too short (only 9 chars after prefix)
		assert.throws(
			() => validatePlcDid('did:plc:abc123xyz'),
			DidValidationError
		);
		// Too long (25 chars after prefix)
		assert.throws(
			() => validatePlcDid('did:plc:abcdefghijklmnopqrstuvwxy'),
			DidValidationError
		);
		// Just the prefix
		assert.throws(
			() => validatePlcDid('did:plc:'),
			DidValidationError
		);
	});
});
