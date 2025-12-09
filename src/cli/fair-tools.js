#!/usr/bin/env node

const commands = {
	'add-aka': { description: 'Add a URL to the alsoKnownAs field', load: () => import('./add-aka.js') },
	'add-rotation-key': { description: 'Add a rotation key to a DID', load: () => import('./add-rotation-key.js') },
	'add-verification-key': { description: 'Add a verification key to a DID', load: () => import('./add-verification-key.js') },
	'build-metadata': { description: 'Build a FAIR metadata document', load: () => import('./build-metadata.js') },
	'create-did': { description: 'Create a new FAIR DID', load: () => import('./create-did.js') },
	'revoke-rotation-key': { description: 'Revoke a rotation key from a DID', load: () => import('./revoke-rotation-key.js') },
	'revoke-verification-key': { description: 'Revoke a verification key from a DID', load: () => import('./revoke-verification-key.js') },
	'update-did': { description: 'Update a DID with a service URL', load: () => import('./update-did.js') },
};

function showHelp() {
	const maxLen = Math.max(...Object.keys(commands).map((name) => name.length));

	const commandList = Object.entries(commands)
		.sort(([a], [b]) => a.localeCompare(b))
		.map(([name, { description }]) => `  ${name.padEnd(maxLen)}  ${description}`)
		.join('\n');

	console.log(`Usage: fair-tools <command> [options]

Commands:
${commandList}

Run 'fair-tools <command> --help' for more information on a command.`);
}

const command = process.argv[2];

if (!command || command === '--help' || command === '-h') {
	showHelp();
	process.exit(0);
}

if (!commands[command]) {
	console.error(`Unknown command: ${command}`);
	console.error('');
	showHelp();
	process.exit(1);
}

// Remove the command from argv so the subcommand sees the right args
process.argv.splice(2, 1);

await commands[command].load();
