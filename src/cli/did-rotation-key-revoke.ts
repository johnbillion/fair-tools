#!/usr/bin/env node

import { writeFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { PlcClientError } from '@did-plc/lib';
import { importRotationKeyPair } from '../keys.js';
import { revokeRotationKey } from '../did.js';
import { loadRotationKeyForRevocation, SigningKeyError, KeyData } from '../signing.js';
import { logPlcError } from './lib/plc-error.js';
import { rotationKeyHelp } from './lib/help.js';
import {
	validatePlcDid,
	DidValidationError,
	validateRotationKey,
	PublicKeyValidationError,
} from '../did-validation.js';

const { values } = parseArgs({
	options: {
		did: {
			type: 'string',
		},
		revoke: {
			type: 'string',
		},
		'signing-file': {
			type: 'string',
		},
		'signing-key': {
			type: 'string',
		},
		cleanup: {
			type: 'boolean',
		},
		help: {
			type: 'boolean',
		},
	},
});

if (values.help) {
	console.log(`Usage: fair-tools did rotation-key revoke [options]

Revoke a rotation key from an existing DID.

Required:
  --did <did>      The DID to update (did:plc:...)
  --revoke <key>   The rotation key to revoke (did:key:...)

${rotationKeyHelp({ signingKeyDefault: 'first available' })}

Optional:
  --cleanup        Remove revoked key from key file after success
  --help           Show this help message

You cannot revoke the rotation key used to sign this operation.
At least one rotation key must remain.`);
	process.exit(0);
}

// Validate required options
if (!values.did) {
	console.error('Error: Missing required option: --did');
	console.error('Run with --help for usage information.');
	process.exit(1);
}

if (!values.revoke) {
	console.error('Error: Missing required option: --revoke');
	console.error('Run with --help for usage information.');
	process.exit(1);
}

if (values.cleanup && !values['signing-file']) {
	console.error('Error: --cleanup requires --signing-file');
	process.exit(1);
}

const did = values.did;
const revokeKey = values.revoke;

// Validate DID format
try {
	validatePlcDid(did);
} catch (err) {
	if (err instanceof DidValidationError) {
		console.error(`Error: ${err.message}`);
		process.exit(1);
	}
	throw err;
}

// Validate the rotation key that is to be revoked
try {
	validateRotationKey(revokeKey);
} catch (err) {
	if (err instanceof PublicKeyValidationError) {
		console.error(`Error: ${err.message}`);
		process.exit(1);
	}
	throw err;
}

// Load signing key
let privateKeyHex: string;
let keyData: KeyData | null;
try {
	({ privateKeyHex, keyData } = await loadRotationKeyForRevocation({
		signingFile: values['signing-file'],
		signingKey: values['signing-key'],
		revokeKey,
	}));
} catch (err) {
	if (err instanceof SigningKeyError) {
		console.error(`Error: ${err.message}`);
		process.exit(1);
	}
	throw err;
}

const { keypair: signer, publicKey: signerPublicKey } = await importRotationKeyPair(privateKeyHex);

// Check if env var key is being revoked
if (signerPublicKey === revokeKey) {
	console.error('Error: Cannot use the key being revoked to sign the operation');
	process.exit(1);
}

console.log(`Revoking rotation key from DID ${did}...`);
console.log(`  Key to revoke: ${revokeKey}`);
console.log(`  Signing with:  ${signerPublicKey}`);

try {
	await revokeRotationKey({
		did,
		rotationKey: revokeKey,
		signer,
	});
} catch (err) {
	if (err instanceof PlcClientError) {
		logPlcError('Error revoking rotation key', err, { signerPublicKey });
		process.exit(1);
	}
	throw err;
}

console.log('Rotation key revoked successfully.');

// Remove the revoked key from the key file if requested
if (values.cleanup && keyData?.rotationKeys?.[revokeKey]) {
	delete keyData.rotationKeys[revokeKey];
	try {
		await writeFile(values['signing-file']!, JSON.stringify(keyData, null, '\t') + '\n', { mode: 0o600 });
	} catch (err) {
		console.error(`Error writing key file: ${(err as Error).message}`);
		process.exit(1);
	}
	console.log(`Removed revoked key from ${values['signing-file']}`);
} else if (keyData?.rotationKeys?.[revokeKey]) {
	console.log(`Note: The revoked key still exists in ${values['signing-file']}. Use --cleanup to delete it.`);
}

console.log(`View at: https://web.plc.directory/did/${did}`);
