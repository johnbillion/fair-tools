import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
	extractVerificationKeys,
	verifyArtifactChecksum,
	validateMetadataStructure,
	ChecksumVerificationError,
} from '../src/verify.js';
import { METADATA_CONTEXT } from '../src/metadata.js';

describe('extractVerificationKeys', () => {
	it('extracts keys with #fair fragment', () => {
		const didDocument = {
			verificationMethod: [
				{ id: 'did:plc:test#fair', publicKeyMultibase: 'z6MkTest1' },
				{ id: 'did:plc:test#fair2', publicKeyMultibase: 'z6MkTest2' },
				{ id: 'did:plc:test#atproto', publicKeyMultibase: 'z6MkOther' },
			],
		};

		const keys = extractVerificationKeys(didDocument);

		assert.strictEqual(keys.length, 2);
		assert.strictEqual(keys[0].id, 'did:plc:test#fair');
		assert.strictEqual(keys[1].id, 'did:plc:test#fair2');
	});

	it('returns empty array when no fair keys present', () => {
		const didDocument = {
			verificationMethod: [{ id: 'did:plc:test#atproto', publicKeyMultibase: 'z6MkOther' }],
		};

		const keys = extractVerificationKeys(didDocument);

		assert.strictEqual(keys.length, 0);
	});

	it('returns empty array when verificationMethod is missing', () => {
		const didDocument = {};

		const keys = extractVerificationKeys(didDocument);

		assert.strictEqual(keys.length, 0);
	});

	it('handles undefined verificationMethod', () => {
		const didDocument = { verificationMethod: undefined };

		const keys = extractVerificationKeys(didDocument);

		assert.strictEqual(keys.length, 0);
	});
});

describe('verifyArtifactChecksum', () => {
	it('verifies valid sha256 checksum', () => {
		const data = Buffer.from('test data');
		// SHA256 of 'test data'
		const checksum = 'sha256:916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9';

		assert.doesNotThrow(() => verifyArtifactChecksum(data, checksum));
	});

	it('throws ChecksumVerificationError for mismatched checksum', () => {
		const data = Buffer.from('test data');
		const checksum = 'sha256:0000000000000000000000000000000000000000000000000000000000000000';

		assert.throws(() => verifyArtifactChecksum(data, checksum), ChecksumVerificationError);
	});

	it('throws ChecksumVerificationError for unsupported algorithm', () => {
		const data = Buffer.from('test data');
		const checksum = 'md5:abc123';

		assert.throws(
			() => verifyArtifactChecksum(data, checksum),
			(err) => {
				assert.ok(err instanceof ChecksumVerificationError);
				assert.ok(err.message.includes('Unsupported checksum algorithm'));
				return true;
			},
		);
	});
});

describe('validateMetadataStructure', () => {
	it('validates correct metadata structure', () => {
		const metadata = {
			'@context': METADATA_CONTEXT,
			id: 'did:plc:test123456789012345678',
			releases: [],
		};

		const result = validateMetadataStructure(metadata, 'did:plc:test123456789012345678');

		assert.strictEqual(result.valid, true);
		assert.strictEqual(result.errors.length, 0);
	});

	it('fails for wrong @context', () => {
		const metadata = {
			'@context': 'https://wrong.context/v1',
			id: 'did:plc:test123456789012345678',
			releases: [],
		};

		const result = validateMetadataStructure(metadata, 'did:plc:test123456789012345678');

		assert.strictEqual(result.valid, false);
		assert.ok(result.errors.some((e) => e.includes('@context')));
	});

	it('fails for DID mismatch', () => {
		const metadata = {
			'@context': METADATA_CONTEXT,
			id: 'did:plc:wrong12345678901234567',
			releases: [],
		};

		const result = validateMetadataStructure(metadata, 'did:plc:test123456789012345678');

		assert.strictEqual(result.valid, false);
		assert.ok(result.errors.some((e) => e.includes('DID mismatch')));
	});

	it('fails for missing releases array', () => {
		const metadata = {
			'@context': METADATA_CONTEXT,
			id: 'did:plc:test123456789012345678',
		};

		const result = validateMetadataStructure(metadata, 'did:plc:test123456789012345678');

		assert.strictEqual(result.valid, false);
		assert.ok(result.errors.some((e) => e.includes('releases')));
	});

	it('fails for non-array releases', () => {
		const metadata = {
			'@context': METADATA_CONTEXT,
			id: 'did:plc:test123456789012345678',
			releases: 'not an array',
		};

		const result = validateMetadataStructure(metadata, 'did:plc:test123456789012345678');

		assert.strictEqual(result.valid, false);
		assert.ok(result.errors.some((e) => e.includes('releases')));
	});

	it('collects multiple errors', () => {
		const metadata = {
			'@context': 'wrong',
			id: 'wrong-did',
		};

		const result = validateMetadataStructure(metadata, 'did:plc:test123456789012345678');

		assert.strictEqual(result.valid, false);
		assert.ok(result.errors.length >= 2);
	});
});
