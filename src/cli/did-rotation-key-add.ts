#!/usr/bin/env node

import { parseArgs } from 'node:util';
import { PlcClientError } from '@did-plc/lib';
import { importRotationKeyPair, generateRotationKeyPair } from '../keys.js';
import { addRotationKey } from '../plc.js';
import { loadRotationKey, SigningKeyError, KeyData } from '../signing.js';
import { saveRotationKeyToFile, SaveKeyError } from '../keyfile.js';
import { logPlcError } from './lib/plc-error.js';
import { rotationKeyHelp } from './lib/help.js';
import { validatePlcDid, DidValidationError } from '../did-validation.js';

const { values } = parseArgs({
	options: {
		did: {
			type: 'string',
		},
		'signing-file': {
			type: 'string',
		},
		'signing-key': {
			type: 'string',
		},
		'output-file': {
			type: 'string',
		},
		help: {
			type: 'boolean',
		},
	},
});

if (values.help) {
	console.log(`Usage: fair-tools did rotation-key add [options]

Generate a new rotation key and add it to an existing DID.

Required:
  --did <did>          The DID to update (did:plc:...)

${rotationKeyHelp()}

Optional:
  --output-file <file> Write new key to this file instead of --signing-file
                       If file exists, appends to rotationKeys. Otherwise writes PEM.
  --help               Show this help message

The new rotation key will be appended to --signing-file unless --output-file is specified.`);
	process.exit(0);
}

// Validate required options
if (!values.did) {
	console.error('Error: Missing required option: --did');
	console.error('Run with --help for usage information.');
	process.exit(1);
}

const did = values.did;

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

// Load signing key
let privateKeyHex: string;
let keyData: KeyData | null;
try {
	({ privateKeyHex, keyData } = await loadRotationKey({
		signingFile: values['signing-file'],
		signingKey: values['signing-key'],
	}));
} catch (err) {
	if (err instanceof SigningKeyError) {
		console.error(`Error: ${err.message}`);
		process.exit(1);
	}
	throw err;
}
const { keypair: signer, publicKey: signerPublicKey } = await importRotationKeyPair(privateKeyHex);

// Validate that we have somewhere to save the new key
if (!values['output-file'] && !keyData) {
	console.error('Error: No output file specified. Use --signing-file or --output-file to save the key.');
	process.exit(1);
}

// Generate a new rotation key
console.log('Generating new rotation key...');
const newRotationKey = await generateRotationKeyPair();

console.log(`Adding rotation key to DID ${did}...`);

try {
	await addRotationKey({
		did,
		rotationKey: newRotationKey.publicKey,
		signer,
	});
} catch (err) {
	if (err instanceof PlcClientError) {
		logPlcError('Error adding rotation key', err, { signerPublicKey });
		process.exit(1);
	}
	throw err;
}

// Save the new key
const outputFile = values['output-file'] || values['signing-file']!;
try {
	const { appended } = await saveRotationKeyToFile({
		outputFile,
		key: newRotationKey,
	});
	if (appended) {
		console.log(`Key appended to: ${outputFile}`);
	} else {
		console.log(`Key written to: ${outputFile}`);
	}
} catch (err) {
	if (err instanceof SaveKeyError) {
		console.error(`Error saving key: ${err.message}`);
		console.error('');
		console.error('\x1b[33m\x1b[1mWARNING: The key was added to the DID but could not be saved locally.\x1b[0m');
		console.error(`\x1b[33mPublic key: ${newRotationKey.publicKey}\x1b[0m`);
		console.error('\x1b[33mYou may need to revoke this key if you cannot recover it.\x1b[0m');
		process.exit(1);
	}
	throw err;
}

console.log('Rotation key added successfully.');
console.log(`Public key: ${newRotationKey.publicKey}`);
console.log(`View at: https://web.plc.directory/did/${did}`);
