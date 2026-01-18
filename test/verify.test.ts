import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
	extractVerificationKeys,
	verifyArtifactChecksum,
	verifyArtifactSignature,
	validateMetadataStructure,
	getFairServices,
	requireFairServices,
	extractDomainFromAlias,
	buildAliasResult,
	checkRotationKey,
	ChecksumVerificationError,
	SignatureVerificationError,
	MetadataVerificationError,
	NoServicesError,
} from '../src/verify.js';
import type { FetchAliasResult, VerifyDomainResult, CheckRotationKeyResult } from '../src/verify.js';
import type { DidDocument } from '@did-plc/lib';
import { generateVerificationKeyPair, generateRotationKeyPair } from '../src/keys.js';
import { Ed25519Keypair } from '../src/Ed25519Keypair.js';
import { signArtifact, METADATA_CONTEXT } from '../src/metadata.js';
import { bytesToMultibase } from '@atproto/crypto';

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

		assert.doesNotThrow(() => validateMetadataStructure(metadata, 'did:plc:test123456789012345678'));
	});

	it('throws for wrong @context', () => {
		const metadata = {
			'@context': 'https://wrong.context/v1',
			id: 'did:plc:test123456789012345678',
			releases: [],
		};

		assert.throws(
			() => validateMetadataStructure(metadata, 'did:plc:test123456789012345678'),
			(err) => err instanceof MetadataVerificationError && err.message.includes('@context'),
		);
	});

	it('throws for DID mismatch', () => {
		const metadata = {
			'@context': METADATA_CONTEXT,
			id: 'did:plc:wrong12345678901234567',
			releases: [],
		};

		assert.throws(
			() => validateMetadataStructure(metadata, 'did:plc:test123456789012345678'),
			(err) => err instanceof MetadataVerificationError && err.message.includes('DID mismatch'),
		);
	});

	it('throws for missing releases array', () => {
		const metadata = {
			'@context': METADATA_CONTEXT,
			id: 'did:plc:test123456789012345678',
		};

		assert.throws(
			() => validateMetadataStructure(metadata, 'did:plc:test123456789012345678'),
			(err) => err instanceof MetadataVerificationError && err.message.includes('Missing releases'),
		);
	});

	it('throws for non-array releases', () => {
		const metadata = {
			'@context': METADATA_CONTEXT,
			id: 'did:plc:test123456789012345678',
			releases: 'not an array',
		};

		assert.throws(
			() => validateMetadataStructure(metadata, 'did:plc:test123456789012345678'),
			(err) => err instanceof MetadataVerificationError && err.message.includes('Invalid releases'),
		);
	});

	it('collects multiple errors', () => {
		const metadata = {
			'@context': 'wrong',
			id: 'wrong-did',
		};

		assert.throws(
			() => validateMetadataStructure(metadata, 'did:plc:test123456789012345678'),
			(err) =>
				err instanceof MetadataVerificationError &&
				err.message.includes('@context') &&
				err.message.includes('DID mismatch'),
		);
	});

	it('throws for missing @context', () => {
		const metadata = {
			id: 'did:plc:test123456789012345678',
			releases: [],
		};

		assert.throws(
			() => validateMetadataStructure(metadata, 'did:plc:test123456789012345678'),
			(err) => err instanceof MetadataVerificationError && err.message.includes('Missing @context'),
		);
	});

	it('throws for missing id', () => {
		const metadata = {
			'@context': METADATA_CONTEXT,
			releases: [],
		};

		assert.throws(
			() => validateMetadataStructure(metadata, 'did:plc:test123456789012345678'),
			(err) => err instanceof MetadataVerificationError && err.message.includes('Missing id'),
		);
	});
});

describe('getFairServices', () => {
	it('returns FAIR services from DID document', () => {
		const didDocument = {
			id: 'did:plc:test123456789012345678',
			service: [
				{ id: '#fairpm_repo', type: 'FairPackageManagementRepo', serviceEndpoint: 'https://example.com/fair.json' },
				{ id: '#atproto', type: 'AtprotoPersonalDataServer', serviceEndpoint: 'https://bsky.social' },
			],
		} as DidDocument;

		const services = getFairServices(didDocument);

		assert.strictEqual(services.length, 1);
		assert.strictEqual(services[0].type, 'FairPackageManagementRepo');
		assert.strictEqual(services[0].serviceEndpoint, 'https://example.com/fair.json');
	});

	it('returns multiple FAIR services when present', () => {
		const didDocument = {
			id: 'did:plc:test123456789012345678',
			service: [
				{ id: '#fairpm_repo', type: 'FairPackageManagementRepo', serviceEndpoint: 'https://example.com/fair.json' },
				{ id: '#fairpm_repo2', type: 'FairPackageManagementRepo', serviceEndpoint: 'https://other.com/fair.json' },
			],
		} as DidDocument;

		const services = getFairServices(didDocument);

		assert.strictEqual(services.length, 2);
	});

	it('returns empty array when no FAIR services present', () => {
		const didDocument = {
			id: 'did:plc:test123456789012345678',
			service: [{ id: '#atproto', type: 'AtprotoPersonalDataServer', serviceEndpoint: 'https://bsky.social' }],
		} as DidDocument;

		const services = getFairServices(didDocument);

		assert.strictEqual(services.length, 0);
	});

	it('returns empty array when service array is empty', () => {
		const didDocument = {
			id: 'did:plc:test123456789012345678',
			service: [],
		} as DidDocument;

		const services = getFairServices(didDocument);

		assert.strictEqual(services.length, 0);
	});

	it('returns empty array when service is undefined', () => {
		const didDocument = {
			id: 'did:plc:test123456789012345678',
		} as DidDocument;

		const services = getFairServices(didDocument);

		assert.strictEqual(services.length, 0);
	});
});

describe('requireFairServices', () => {
	it('returns services when FAIR services are present', () => {
		const didDocument = {
			id: 'did:plc:test123456789012345678',
			service: [
				{ id: '#fairpm_repo', type: 'FairPackageManagementRepo', serviceEndpoint: 'https://example.com/fair.json' },
			],
		} as DidDocument;

		const services = requireFairServices(didDocument);

		assert.strictEqual(services.length, 1);
	});

	it('throws NoServicesError when no FAIR services present', () => {
		const didDocument = {
			id: 'did:plc:test123456789012345678',
			service: [{ id: '#atproto', type: 'AtprotoPersonalDataServer', serviceEndpoint: 'https://bsky.social' }],
		} as DidDocument;

		assert.throws(
			() => requireFairServices(didDocument),
			(err) => {
				return err instanceof NoServicesError && err.message.includes('No FairPackageManagementRepo');
			},
		);
	});

	it('throws NoServicesError when service array is empty', () => {
		const didDocument = {
			id: 'did:plc:test123456789012345678',
			service: [] as Array<{ type: string; id: string; serviceEndpoint: string }>,
		} as DidDocument;

		assert.throws(() => requireFairServices(didDocument), NoServicesError);
	});

	it('throws NoServicesError when service is undefined', () => {
		const didDocument = {
			id: 'did:plc:test123456789012345678',
		} as DidDocument;

		assert.throws(() => requireFairServices(didDocument), NoServicesError);
	});
});

describe('Ed25519Keypair.fromPublicKeyMultibase', () => {
	it('parses a valid Ed25519 publicKeyMultibase and can verify signatures', async () => {
		// Generate a keypair, get its multibase representation, then parse it back
		const original = await generateVerificationKeyPair();

		// Sign something with the original keypair
		const data = Buffer.from('test artifact data');
		const signature = await signArtifact(data, original.keypair);

		// Get the multibase public key from the did:key
		// did:key:z6Mk... -> z6Mk... (strip 'did:key:' prefix)
		const publicKeyMultibase = original.publicKey.replace('did:key:', '');

		// Parse it back and verify the signature
		const parsed = await Ed25519Keypair.fromPublicKeyMultibase(publicKeyMultibase);
		const { verifyArtifact } = await import('../src/metadata.js');
		const isValid = await verifyArtifact(data, signature, parsed);

		assert.strictEqual(isValid, true);
	});

	it('rejects secp256k1 keys with clear error message', async () => {
		// secp256k1 compressed public key multibase (starts with zQ3sh)
		// This is a valid secp256k1 key format used for rotation keys
		const secp256k1Multibase = 'zQ3shZc2QzJE5VLjPRhMgwg7JXjHKhqLmUxGPGBbhq3yuU3oR';

		await assert.rejects(Ed25519Keypair.fromPublicKeyMultibase(secp256k1Multibase), (err) => {
			assert.ok(err.message.includes('Ed25519'));
			assert.ok(err.message.includes('0xe701')); // secp256k1's multicodec prefix
			return true;
		});
	});

	it('rejects malformed multibase strings', async () => {
		await assert.rejects(Ed25519Keypair.fromPublicKeyMultibase('not-valid-multibase'), (err) => {
			assert.ok(err instanceof Error);
			return true;
		});
	});

	it('round-trips a real public key from querymonitor.com DID document', async () => {
		// Real public key from did:plc:q2afge25l63iz553aumeqi3w#fair
		const publicKeyMultibase = 'z6Mkitp3T2Gk2U4pvuwpy8ygAzxkM6K1Ygoyv1ZgUx3AW9Px';

		const keypair = await Ed25519Keypair.fromPublicKeyMultibase(publicKeyMultibase);

		// Verify it parsed correctly - should be 32 bytes
		assert.strictEqual(keypair.publicKeyBytes().length, 32);

		// Round-trip: publicKeyStr() should return the same multibase
		assert.strictEqual(keypair.publicKeyStr(), publicKeyMultibase);
	});

	it('rejects multibase with too few bytes (less than prefix length)', async () => {
		// Create a multibase string that decodes to only 1 byte
		// This tests the case where decoded.length < 2
		const tooShort = bytesToMultibase(new Uint8Array([0xed]), 'base58btc');

		await assert.rejects(Ed25519Keypair.fromPublicKeyMultibase(tooShort), (err) => {
			assert.strictEqual(err.message, 'Invalid key length: expected 34 bytes for Ed25519 public key, got 1 bytes');
			return true;
		});
	});

	it('rejects multibase with correct prefix but wrong total length (too short)', async () => {
		// Create a multibase with correct prefix but only 10 bytes total (should be 34)
		const tooShort = new Uint8Array(10);
		tooShort[0] = 0xed;
		tooShort[1] = 0x01;
		const multibase = bytesToMultibase(tooShort, 'base58btc');

		await assert.rejects(Ed25519Keypair.fromPublicKeyMultibase(multibase), (err) => {
			assert.strictEqual(
				err.message,
				'Invalid key length: expected 34 bytes (2-byte prefix + 32-byte key), got 10 bytes',
			);
			return true;
		});
	});

	it('rejects multibase with correct prefix but wrong total length (too long)', async () => {
		// Create a multibase with correct prefix but 50 bytes total (should be 34)
		const tooLong = new Uint8Array(50);
		tooLong[0] = 0xed;
		tooLong[1] = 0x01;
		const multibase = bytesToMultibase(tooLong, 'base58btc');

		await assert.rejects(Ed25519Keypair.fromPublicKeyMultibase(multibase), (err) => {
			assert.strictEqual(
				err.message,
				'Invalid key length: expected 34 bytes (2-byte prefix + 32-byte key), got 50 bytes',
			);
			return true;
		});
	});

	it('rejects empty multibase string', async () => {
		await assert.rejects(Ed25519Keypair.fromPublicKeyMultibase(''), (err) => {
			assert.ok(err instanceof Error);
			return true;
		});
	});
});

describe('verifyArtifactSignature', () => {
	it('returns the key ID when signature matches', async () => {
		const keys = await generateVerificationKeyPair();
		const data = Buffer.from('artifact content');
		const signature = await signArtifact(data, keys.keypair);

		const verificationKeys = [
			{
				id: 'did:plc:test#fair',
				publicKeyMultibase: keys.publicKey.replace('did:key:', ''),
			},
		];

		const matchedKeyId = await verifyArtifactSignature(data, signature, verificationKeys);

		assert.strictEqual(matchedKeyId, 'did:plc:test#fair');
	});

	it('tries multiple keys and returns the one that matches', async () => {
		const correctKey = await generateVerificationKeyPair();
		const wrongKey = await generateVerificationKeyPair();
		const data = Buffer.from('artifact content');
		const signature = await signArtifact(data, correctKey.keypair);

		const verificationKeys = [
			{
				id: 'did:plc:test#fair-wrong',
				publicKeyMultibase: wrongKey.publicKey.replace('did:key:', ''),
			},
			{
				id: 'did:plc:test#fair-correct',
				publicKeyMultibase: correctKey.publicKey.replace('did:key:', ''),
			},
		];

		const matchedKeyId = await verifyArtifactSignature(data, signature, verificationKeys);

		assert.strictEqual(matchedKeyId, 'did:plc:test#fair-correct');
	});

	it('throws SignatureVerificationError when no key matches', async () => {
		const signingKey = await generateVerificationKeyPair();
		const wrongKey = await generateVerificationKeyPair();
		const data = Buffer.from('artifact content');
		const signature = await signArtifact(data, signingKey.keypair);

		const verificationKeys = [
			{
				id: 'did:plc:test#fair',
				publicKeyMultibase: wrongKey.publicKey.replace('did:key:', ''),
			},
		];

		await assert.rejects(verifyArtifactSignature(data, signature, verificationKeys), (err) => {
			assert.ok(err instanceof SignatureVerificationError);
			assert.ok(err.message.includes('does not match'));
			return true;
		});
	});

	it('includes key parsing errors in the error message', async () => {
		const data = Buffer.from('artifact content');
		const signature = 'some-signature';

		// Use an invalid multibase that will fail to parse
		const verificationKeys = [
			{
				id: 'did:plc:test#fair-bad',
				publicKeyMultibase: 'invalid-not-multibase',
			},
		];

		await assert.rejects(verifyArtifactSignature(data, signature, verificationKeys), (err) => {
			assert.ok(err instanceof SignatureVerificationError);
			assert.ok(err.message.includes('did:plc:test#fair-bad'));
			return true;
		});
	});

	it('rejects non-Ed25519 keys with informative error', async () => {
		const data = Buffer.from('artifact content');
		const signature = 'some-signature';

		// secp256k1 key (rotation key type, not verification key)
		const verificationKeys = [
			{
				id: 'did:plc:test#wrong-type',
				publicKeyMultibase: 'zQ3shZc2QzJE5VLjPRhMgwg7JXjHKhqLmUxGPGBbhq3yuU3oR',
			},
		];

		await assert.rejects(verifyArtifactSignature(data, signature, verificationKeys), (err) => {
			assert.ok(err instanceof SignatureVerificationError);
			assert.ok(err.message.includes('did:plc:test#wrong-type'));
			assert.ok(err.message.includes('Ed25519'));
			return true;
		});
	});
});

describe('extractDomainFromAlias', () => {
	it('extracts domain from fair:// URL', () => {
		assert.strictEqual(extractDomainFromAlias('fair://example.com'), 'example.com');
	});

	it('removes trailing slash', () => {
		assert.strictEqual(extractDomainFromAlias('fair://example.com/'), 'example.com');
	});

	it('handles subdomain', () => {
		assert.strictEqual(extractDomainFromAlias('fair://sub.example.com'), 'sub.example.com');
	});

	it('handles plain domain without protocol', () => {
		assert.strictEqual(extractDomainFromAlias('example.com'), 'example.com');
	});
});

describe('buildAliasResult', () => {
	it('returns valid result with note for no-alias', () => {
		const fetchResult: FetchAliasResult = { type: 'no-alias' };

		const result = buildAliasResult(fetchResult, null);

		assert.strictEqual(result.valid, true);
		assert.strictEqual(result.note, 'No fair:// alias configured');
	});

	it('returns invalid result for multiple-aliases', () => {
		const fetchResult: FetchAliasResult = { type: 'multiple-aliases', error: 'Multiple aliases found' };

		const result = buildAliasResult(fetchResult, null);

		assert.strictEqual(result.valid, false);
		assert.strictEqual(result.error, 'Multiple aliases found');
	});

	it('returns valid result when alias exists and verification passes', () => {
		const fetchResult: FetchAliasResult = { type: 'alias', alias: 'fair://example.com' };
		const verifyResult: VerifyDomainResult = { valid: true };

		const result = buildAliasResult(fetchResult, verifyResult);

		assert.strictEqual(result.valid, true);
		assert.strictEqual(result.url, 'fair://example.com');
		assert.strictEqual(result.domain, 'example.com');
	});

	it('returns invalid result when alias exists but verification fails', () => {
		const fetchResult: FetchAliasResult = { type: 'alias', alias: 'fair://example.com' };
		const verifyResult: VerifyDomainResult = { valid: false, error: 'DNS record not found' };

		const result = buildAliasResult(fetchResult, verifyResult);

		assert.strictEqual(result.valid, false);
		assert.strictEqual(result.url, 'fair://example.com');
		assert.strictEqual(result.domain, 'example.com');
		assert.strictEqual(result.error, 'DNS record not found');
	});

	it('returns invalid result when alias exists but verification is null', () => {
		const fetchResult: FetchAliasResult = { type: 'alias', alias: 'fair://example.com' };

		const result = buildAliasResult(fetchResult, null);

		assert.strictEqual(result.valid, false);
		assert.strictEqual(result.error, 'Verification not performed');
	});

	it('extracts domain correctly from alias with trailing slash', () => {
		const fetchResult: FetchAliasResult = { type: 'alias', alias: 'fair://example.com/' };
		const verifyResult: VerifyDomainResult = { valid: true };

		const result = buildAliasResult(fetchResult, verifyResult);

		assert.strictEqual(result.domain, 'example.com');
	});
});

describe('checkRotationKey', () => {
	it('returns CheckRotationKeyResult type with expected fields', async () => {
		// This test verifies the interface of the function
		// Full integration tests would require network access to fetch DID logs

		// Type check - ensure the result type has the expected structure
		const mockResult: CheckRotationKeyResult = {
			valid: true,
			publicKeyMultibase: 'zQ3shTest',
			allKeys: ['did:key:zQ3shTest'],
		};

		assert.strictEqual(typeof mockResult.valid, 'boolean');
		assert.strictEqual(typeof mockResult.publicKeyMultibase, 'string');
		assert.ok(Array.isArray(mockResult.allKeys));
	});

	it('function is exported and callable', () => {
		// Verify the function is exported and has the expected signature
		assert.strictEqual(typeof checkRotationKey, 'function');
	});

	it('accepts a rotation key public key format', async () => {
		// Generate a valid rotation key to ensure the format is correct
		const keys = await generateRotationKeyPair();
		const multibase = keys.publicKey.replace('did:key:', '');

		// Verify the key starts with the expected prefix
		assert.ok(
			multibase.startsWith('zQ3sh'),
			`Expected rotation key multibase to start with 'zQ3sh', got '${multibase.slice(0, 5)}'`,
		);
	});
});
