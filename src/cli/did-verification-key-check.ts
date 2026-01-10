#!/usr/bin/env node

import { parseArgs } from 'node:util';
import { readFile } from 'node:fs/promises';
import crypto from 'node:crypto';
import { importVerificationKeyPair } from '../keys.js';
import { SigningKeyError, isMultibaseVerificationKey, isPKCS8PrivateKeyPEM, isHexPrivateKey } from '../signing.js';
import { validatePlcDid, DidValidationError } from '../did-validation.js';
import { extractVerificationKeys } from '../verify.js';
import { PLC_DIRECTORY_URL, createPlcClient } from '../plc.js';
import { Ed25519Keypair } from '../Ed25519Keypair.js';

const { values } = parseArgs({
	options: {
		did: {
			type: 'string',
		},
		key: {
			type: 'string',
		},
		'key-file': {
			type: 'string',
		},
		help: {
			type: 'boolean',
		},
	},
});

if (values.help) {
	console.log(`Usage: fair-tools did verification-key check [options]

Check if a verification key is valid for signing.

Valid verification keys are present in the verification methods property of the DID document.

Required:
  --did <did>          The DID to check (did:plc:...)

Key input (one required):
  --key <key>          Verification key (public: did:key:z6Mk... or z6Mk..., or private: PEM/multibase/hex)
  --key-file <file>    Read verification key from file

Optional:
  --help               Show this help message

Exit codes:
  0  Key is valid (present in DID document)
  1  Key is not valid (not found or DID has no verification keys)
  2  Error occurred (invalid input, network error, etc.)`);
	process.exit(0);
}

// Validate required options
if (!values.did) {
	console.error('Error: Missing required option: --did');
	console.error('Run with --help for usage information.');
	process.exit(2);
}

if (!values.key && !values['key-file']) {
	console.error('Error: Must provide either --key or --key-file');
	console.error('Run with --help for usage information.');
	process.exit(2);
}

if (values.key && values['key-file']) {
	console.error('Error: Cannot specify both --key and --key-file');
	console.error('Run with --help for usage information.');
	process.exit(2);
}

const did = values.did;

// Validate DID format
try {
	validatePlcDid(did);
} catch (err) {
	if (err instanceof DidValidationError) {
		console.error(`Error: ${err.message}`);
		process.exit(2);
	}
	throw err;
}

// Load the key
let keyInput: string;
try {
	if (values['key-file']) {
		keyInput = (await readFile(values['key-file'], 'utf-8')).trim();
	} else {
		keyInput = values.key!.trim();
	}
} catch (err) {
	console.error(`Error reading key file: ${(err as Error).message}`);
	process.exit(2);
}

// Determine if the key is a public key or private key and extract the public key multibase
let publicKeyMultibase: string;

try {
	// Check if it's a did:key format (public key)
	if (keyInput.startsWith('did:key:')) {
		const multibase = keyInput.slice('did:key:'.length);
		// Validate it by creating a keypair
		await Ed25519Keypair.fromPublicKeyMultibase(multibase);
		publicKeyMultibase = multibase;
	}
	// Check if it's a raw multibase public key (starts with z6Mk for Ed25519)
	else if (keyInput.startsWith('z6Mk')) {
		// Validate it by creating a keypair
		await Ed25519Keypair.fromPublicKeyMultibase(keyInput);
		publicKeyMultibase = keyInput;
	}
	// Check if it's a private key format
	else if (isPKCS8PrivateKeyPEM(keyInput) || isMultibaseVerificationKey(keyInput) || isHexPrivateKey(keyInput)) {
		// Import the private key and derive the public key
		const { privateKeyHex } = await loadVerificationKeyFromString(keyInput);
		const { keypair } = await importVerificationKeyPair(privateKeyHex);
		publicKeyMultibase = keypair.publicKeyStr();
	} else {
		throw new SigningKeyError(
			'Unrecognized key format. Expected a public key (did:key:z6Mk... or z6Mk...) or private key (PEM, multibase, or hex)',
		);
	}
} catch (err) {
	if (err instanceof SigningKeyError) {
		console.error(`Error: ${err.message}`);
		process.exit(2);
	} else if (err instanceof Error) {
		// Handle generic errors from key parsing (e.g., Ed25519Keypair.fromPublicKeyMultibase)
		console.error(`Error: ${err.message}`);
		process.exit(2);
	}
	throw err;
}

// Fetch the DID document
console.log(`Fetching DID document for ${did}...`);
const client = createPlcClient(PLC_DIRECTORY_URL);
let didDocument;
try {
	didDocument = await client.getDocument(did);
} catch (err) {
	console.error(`Error: Failed to fetch DID document: ${(err as Error).message}`);
	process.exit(2);
}

// Extract verification keys from the DID document
const verificationKeys = extractVerificationKeys(didDocument);

if (verificationKeys.length === 0) {
	console.log(`\n❌ No verification keys found in DID document`);
	console.log(`The DID ${did} has no verification keys.`);
	process.exit(1);
}

// Check if the public key multibase is in the verification methods
const matchingKey = verificationKeys.find((vk) => vk.publicKeyMultibase === publicKeyMultibase);

if (matchingKey) {
	console.log(`\n✓ Verification key is valid`);
	console.log(`Key ID: ${matchingKey.id}`);
	console.log(`Public key: ${publicKeyMultibase}`);
	console.log(`This key can be used to sign releases for ${did}`);
	process.exit(0);
} else {
	console.log(`\n❌ Verification key is not valid`);
	console.log(`Public key: ${publicKeyMultibase}`);
	console.log(`This key is not present in the verification methods of ${did}`);
	console.log(`\nValid keys for this DID:`);
	for (const vk of verificationKeys) {
		console.log(`  ${vk.id}: ${vk.publicKeyMultibase}`);
	}
	process.exit(1);
}

/**
 * Load a verification key from a string (PEM, multibase, or hex).
 */
async function loadVerificationKeyFromString(key: string): Promise<{ privateKeyHex: string }> {
	const trimmed = key.trim();

	if (isPKCS8PrivateKeyPEM(trimmed)) {
		let keyObject: crypto.KeyObject;
		try {
			keyObject = crypto.createPrivateKey({
				key: trimmed,
				format: 'pem',
			});
		} catch {
			throw new SigningKeyError('Invalid verification key. The PEM file could not be parsed.');
		}

		// Export as JWK to get the raw 'd' parameter (private key)
		const jwk = keyObject.export({
			format: 'jwk',
		});
		if (!jwk.d) {
			throw new SigningKeyError('Invalid verification key. The PEM file is missing private key data.');
		}

		// JWK 'd' is base64url-encoded
		const rawKey = Buffer.from(jwk.d, 'base64url');
		if (rawKey.length !== 32) {
			throw new SigningKeyError('Invalid verification key. The key has the wrong length.');
		}

		return { privateKeyHex: rawKey.toString('hex') };
	}

	if (isMultibaseVerificationKey(trimmed)) {
		// Decode multibase verification key
		const { base58btc } = await import('multiformats/bases/base58');
		const { ED25519_PRIV_PREFIX } = await import('../signing.js');

		let decoded: Uint8Array;
		try {
			decoded = base58btc.decode(trimmed);
		} catch {
			throw new SigningKeyError('Invalid key format. The key could not be decoded.');
		}

		if (decoded.length < 2) {
			throw new SigningKeyError('Invalid key format. The key is too short.');
		}

		const prefixHex = Buffer.from(decoded.slice(0, 2)).toString('hex');
		const ED25519_PRIV_PREFIX_HEX = Buffer.from(ED25519_PRIV_PREFIX).toString('hex');

		if (prefixHex !== ED25519_PRIV_PREFIX_HEX) {
			throw new SigningKeyError(`Unrecognized key type (prefix: ${prefixHex}). Expected a verification key.`);
		}

		const rawKey = decoded.slice(2);

		// Sodium format: 64 bytes (32-byte seed + 32-byte public key)
		if (rawKey.length === 64) {
			return { privateKeyHex: Buffer.from(rawKey.slice(0, 32)).toString('hex') };
		}

		throw new SigningKeyError('Invalid key format. Expected a 64-byte Sodium-format Ed25519 key.');
	}

	if (isHexPrivateKey(trimmed)) {
		return { privateKeyHex: trimmed.toLowerCase() };
	}

	throw new SigningKeyError('Unrecognized key format. Expected a PEM, multibase, or hex encoded verification key.');
}
