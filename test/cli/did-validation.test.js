import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
	validatePlcDid,
	DidValidationError,
	validateVerificationKey,
	validateRotationKey,
	PublicKeyValidationError,
} from '../../src/did-validation.js';

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
			DidValidationError,
		);
		assert.throws(
			() => validatePlcDid('aaa:bbb:abcdefghijklmnopqrstuvwx'),
			DidValidationError,
		);
	});

	it('rejects DIDs with incorrect length', () => {
		// Too short (only 9 chars after prefix)
		assert.throws(
			() => validatePlcDid('did:plc:abc123xyz'),
			DidValidationError,
		);
		// Too long (25 chars after prefix)
		assert.throws(
			() => validatePlcDid('did:plc:abcdefghijklmnopqrstuvwxy'),
			DidValidationError,
		);
		// Just the prefix
		assert.throws(() => validatePlcDid('did:plc:'), DidValidationError);
	});
});

describe('validateVerificationKey', () => {
	it('accepts valid did:key:z6Mk... keys with correct length', () => {
		// Valid Ed25519 verification key (56 characters)
		assert.doesNotThrow(() => {
			validateVerificationKey(
				'did:key:z6MkonuqnprS4byrHnywm4VhDAPQrrivf3k89yGM9arTv1dt',
			);
		});
	});

	it('rejects keys without did:key: prefix', () => {
		assert.throws(
			() =>
				validateVerificationKey(
					'z6MkonuqnprS4byrHnywm4VhDAPQrrivf3k89yGM9arTv1dt',
				),
			PublicKeyValidationError,
		);
	});

	it('rejects keys with wrong prefix (rotation key instead of verification)', () => {
		assert.throws(
			() =>
				validateVerificationKey(
					'did:key:zQ3shpSUddxatBNRu5sCJyStPAmVVSDqhWNbR6Dqb8U9JNJYA',
				),
			(err) => {
				assert.ok(err instanceof PublicKeyValidationError);
				assert.ok(
					err.message.includes('rotation key'),
					'Error should mention rotation key',
				);
				return true;
			},
		);
	});

	it('rejects keys with unknown prefix', () => {
		assert.throws(
			() =>
				validateVerificationKey(
					'did:key:z1234567890abcdefghijklmnopqrstuvwxyz12345678',
				),
			PublicKeyValidationError,
		);
	});

	it('rejects keys with incorrect length', () => {
		// Too short
		assert.throws(
			() => validateVerificationKey('did:key:z6MkShortKey'),
			PublicKeyValidationError,
		);
		// Too long
		assert.throws(
			() =>
				validateVerificationKey(
					'did:key:z6MkonuqnprS4byrHnywm4VhDAPQrrivf3k89yGM9arTv1dtXXX',
				),
			PublicKeyValidationError,
		);
	});
});

describe('validateRotationKey', () => {
	it('accepts valid did:key:zQ3sh... keys with correct length', () => {
		// Valid Secp256k1 rotation key (57 characters)
		assert.doesNotThrow(() => {
			validateRotationKey(
				'did:key:zQ3shpSUddxatBNRu5sCJyStPAmVVSDqhWNbR6Dqb8U9JNJYA',
			);
		});
	});

	it('rejects keys without did:key: prefix', () => {
		assert.throws(
			() =>
				validateRotationKey(
					'zQ3shpSUddxatBNRu5sCJyStPAmVVSDqhWNbR6Dqb8U9JNJYA',
				),
			PublicKeyValidationError,
		);
	});

	it('rejects keys with wrong prefix (verification key instead of rotation)', () => {
		assert.throws(
			() =>
				validateRotationKey(
					'did:key:z6MkonuqnprS4byrHnywm4VhDAPQrrivf3k89yGM9arTv1dt',
				),
			(err) => {
				assert.ok(err instanceof PublicKeyValidationError);
				assert.ok(
					err.message.includes('verification key'),
					'Error should mention verification key',
				);
				return true;
			},
		);
	});

	it('rejects keys with unknown prefix', () => {
		assert.throws(
			() =>
				validateRotationKey('did:key:z1234567890abcdefghijklmnopqrstuvwxyzAB'),
			PublicKeyValidationError,
		);
	});

	it('rejects keys with incorrect length', () => {
		// Too short
		assert.throws(
			() => validateRotationKey('did:key:zQ3shShortKey'),
			PublicKeyValidationError,
		);
		// Too long
		assert.throws(
			() =>
				validateRotationKey(
					'did:key:zQ3shpSUddxatBNRu5sCJyStPAmVVSDqhWNbR6Dqb8U9JNJYAXXX',
				),
			PublicKeyValidationError,
		);
	});
});
