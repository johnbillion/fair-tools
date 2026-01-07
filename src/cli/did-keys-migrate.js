#!/usr/bin/env node

import { parseArgs } from 'node:util';
import { migrateKeysToPEM, MigrateKeysError } from '../keyfile.js';

const { values } = parseArgs({
	options: {
		'signing-file': {
			type: 'string',
		},
		help: {
			type: 'boolean',
		},
	},
});

if (values.help) {
	console.log(`Usage: fair-tools did keys migrate [options]

Migrate keys from hex or multibase format to PEM format.

This command converts private keys encoded as hex or multibase to
PEM format. A backup of the original file is created with a .bak extension
before any changes are made.

Required:
  --signing-file <file>  Path to the JSON key file to migrate

Optional:
  --help                 Show this help message

Examples:
  fair-tools did keys migrate --signing-file ./dids/did:plc:abc123.json`);
	process.exit(0);
}

// Validate required options
if (!values['signing-file']) {
	console.error('Error: Missing required option: --signing-file');
	console.error('Run with --help for usage information.');
	process.exit(1);
}

// Run migration
try {
	const result = await migrateKeysToPEM({
		keyFile: values['signing-file'],
	});

	const totalMigrated = result.rotationKeysMigrated + result.verificationKeysMigrated;
	const totalAlreadyPEM = result.rotationKeysAlreadyPEM + result.verificationKeysAlreadyPEM;

	if (totalMigrated === 0 && totalAlreadyPEM === 0) {
		console.log('No keys found in the file.');
		process.exit(0);
	}

	if (totalMigrated === 0) {
		console.log('All keys are already in PEM format. No migration needed.');
		process.exit(0);
	}

	console.log('Migration summary:');
	console.log(`  Rotation keys migrated: ${result.rotationKeysMigrated}`);
	console.log(`  Verification keys migrated: ${result.verificationKeysMigrated}`);
	console.log(`  Rotation keys already PEM: ${result.rotationKeysAlreadyPEM}`);
	console.log(`  Verification keys already PEM: ${result.verificationKeysAlreadyPEM}`);

	if (result.backupPath) {
		console.log(`Backup saved to: ${result.backupPath}`);
		console.log('Migration complete.');
	}
} catch (err) {
	if (err instanceof MigrateKeysError) {
		console.error(`Error: ${err.message}`);
		process.exit(1);
	}
	throw err;
}
