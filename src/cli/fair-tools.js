#!/usr/bin/env node

const commands = {
	did: {
		create: { description: 'Create a new FAIR DID', load: () => import('./did-create.js') },
		service: {
			add: { description: 'Add a service URL to a DID', load: () => import('./did-service-add.js') },
			replace: { description: 'Replace a service URL in a DID', load: () => import('./did-service-replace.js') },
		},
		'verification-key': {
			add: { description: 'Add a verification key', load: () => import('./did-verification-key-add.js') },
			revoke: { description: 'Revoke a verification key', load: () => import('./did-verification-key-revoke.js') },
		},
		'rotation-key': {
			add: { description: 'Add a rotation key', load: () => import('./did-rotation-key-add.js') },
			revoke: { description: 'Revoke a rotation key', load: () => import('./did-rotation-key-revoke.js') },
		},
		aka: {
			add: { description: 'Add a URL to the alsoKnownAs field', load: () => import('./did-aka-add.js') },
			replace: { description: 'Replace a URL in the alsoKnownAs field', load: () => import('./did-aka-replace.js') },
		},
	},
	metadata: {
		build: { description: 'Build a FAIR metadata document', load: () => import('./metadata-build.js') },
	},
};

function isCommand(obj) {
	return obj && typeof obj.load === 'function';
}

function collectCommands(obj, prefix = []) {
	const results = [];
	for (const [key, value] of Object.entries(obj)) {
		const path = [...prefix, key];
		if (isCommand(value)) {
			results.push({ path, ...value });
		} else {
			results.push(...collectCommands(value, path));
		}
	}
	return results;
}

function showHelp() {
	const allCommands = collectCommands(commands);
	const maxLen = Math.max(...allCommands.map((c) => c.path.join(' ').length));

	const lines = allCommands.map((c) => `  ${c.path.join(' ').padEnd(maxLen + 2)}${c.description}`);

	console.log(`Usage: fair-tools <command> [options]

Commands:
${lines.join('\n')}

Run 'fair-tools <command> --help' for more information on a command.`);
}

function showSubHelp(obj, path) {
	const subCommands = collectCommands(obj, []);
	const maxLen = Math.max(...subCommands.map((c) => c.path.join(' ').length));

	const lines = subCommands.map((c) => `  ${c.path.join(' ').padEnd(maxLen + 2)}${c.description}`);

	console.log(`Usage: fair-tools ${path.join(' ')} <command> [options]

Commands:
${lines.join('\n')}

Run 'fair-tools ${path.join(' ')} <command> --help' for more information.`);
}

const args = process.argv.slice(2);

if (args.length === 0 || args[0] === '--help' || args[0] === '-h') {
	showHelp();
	process.exit(0);
}

// Walk the command tree
let current = commands;
let depth = 0;

while (depth < args.length) {
	const arg = args[depth];

	if (arg === '--help' || arg === '-h') {
		showSubHelp(current, args.slice(0, depth));
		process.exit(0);
	}

	if (!current[arg]) {
		console.error(`Unknown command: ${args.slice(0, depth + 1).join(' ')}`);
		console.error('');
		if (depth === 0) {
			showHelp();
		} else {
			showSubHelp(current, args.slice(0, depth));
		}
		process.exit(1);
	}

	current = current[arg];
	depth++;

	if (isCommand(current)) {
		break;
	}
}

if (!isCommand(current)) {
	showSubHelp(current, args.slice(0, depth));
	process.exit(0);
}

// Remove the command path from argv so the subcommand sees the right args
process.argv.splice(2, depth);

await current.load();
