#!/usr/bin/env node

import { stat, mkdir } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { generateRotationKeyPair, generateVerificationKeyPair } from '../keys.js';
import { createDID } from '../did.js';
import {
	KEY_DIR_MODE,
	getKeyFilePath,
	formatKeyFileContent,
	writeKeyFile,
} from '../keyfile.js';
import { logPlcError } from './plc-error.js';

const { values } = parseArgs({
	options: {
		directory: {
			type: 'string',
			short: 'd',
		},
		help: {
			type: 'boolean',
			short: 'h',
		},
	},
});

if (values.help) {
	console.log(`Usage: fair-create-did -d <directory>

Create a new FAIR DID and publish it to plc.directory.

Options:
  -d, --directory <dir>     Write keys to <dir>/<did>.json
  -h, --help                Show this help message

The output file will contain a JSON object with the rotation and verification
keys needed to manage this DID. Files are saved with 0600 permissions.`);
	process.exit(0);
}

if (!values.directory) {
	console.error('Error: -d <directory> is required');
	process.exit(1);
}

// Ensure directory exists
try {
	const dirStat = await stat(values.directory);
	if (!dirStat.isDirectory()) {
		console.error(`Error: ${values.directory} is not a directory`);
		process.exit(1);
	}
} catch (err) {
	if (err.code === 'ENOENT') {
		await mkdir(values.directory, { recursive: true, mode: KEY_DIR_MODE });
	} else {
		throw err;
	}
}

console.log('Generating rotation key...');
const rotationKey = await generateRotationKeyPair();

console.log('Generating verification key...');
const verificationKey = await generateVerificationKeyPair();

console.log('Creating DID and publishing to plc.directory...');
let did;
try {
	did = await createDID({
		verificationKey: verificationKey.publicKey,
		rotationKey: rotationKey.publicKey,
		keypair: rotationKey.keypair,
	});
} catch (err) {
	logPlcError('Error creating DID', err);
	process.exit(1);
}

// Determine output path
const outputPath = getKeyFilePath(values.directory, did);

// Check that the file doesn't already exist
try {
	await stat(outputPath);
	console.error(`Error: Output file already exists: ${outputPath}`);
	process.exit(1);
} catch (err) {
	if (err.code !== 'ENOENT') {
		throw err;
	}
}

const output = formatKeyFileContent({ did, rotationKey, verificationKey });
try {
	await writeKeyFile(outputPath, output);
} catch (err) {
	console.error(`Error writing key file: ${err.message}`);
	process.exit(1);
}

console.log(`DID created: ${did}`);
console.log(`View at: https://web.plc.directory/did/${did}`);
console.log(`Keys written to ${outputPath}`);
console.log('');
console.log('\x1b[33m\x1b[1mWARNING: Back up this file immediately!\x1b[0m');
console.log('\x1b[33mThis file contains the private keys needed to manage your DID.');
console.log('If you lose this file, you will lose control of your DID permanently.\x1b[0m');
