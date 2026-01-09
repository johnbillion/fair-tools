#!/usr/bin/env node

type Command = {
	description: string;
	load: () => Promise<unknown>;
};

type CommandTree = Command | { [key: string]: CommandTree };

const commands: { [key: string]: CommandTree } = {
	did: {
		create: {
			description: 'Create a new DID',
			load: () => import('./did-create.js'),
		},
		verify: {
			description: 'Fully verify a DID, its document, and FAIR metadata',
			load: () => import('./did-verify.js'),
		},
		service: {
			add: {
				description: 'Add a service URL to a DID',
				load: () => import('./did-service-add.js'),
			},
			replace: {
				description: 'Replace a service URL in a DID',
				load: () => import('./did-service-replace.js'),
			},
			remove: {
				description: 'Remove a service URL from a DID',
				load: () => import('./did-service-remove.js'),
			},
			verify: {
				description: 'Verify a FAIR service endpoint URL',
				load: () => import('./did-service-verify.js'),
			},
		},
		'verification-key': {
			add: {
				description: 'Add a verification key',
				load: () => import('./did-verification-key-add.js'),
			},
			revoke: {
				description: 'Revoke a verification key',
				load: () => import('./did-verification-key-revoke.js'),
			},
		},
		'rotation-key': {
			add: {
				description: 'Add a rotation key',
				load: () => import('./did-rotation-key-add.js'),
			},
			revoke: {
				description: 'Revoke a rotation key',
				load: () => import('./did-rotation-key-revoke.js'),
			},
		},
		keys: {
			migrate: {
				description: 'Migrate keys from hex/multibase to PEM format',
				load: () => import('./did-keys-migrate.js'),
			},
		},
		log: {
			verify: {
				description: 'Validate a DID operation log from genesis',
				load: () => import('./did-log-verify.js'),
			},
		},
		aka: {
			add: {
				description: 'Add a URL to the alsoKnownAs field',
				load: () => import('./did-aka-add.js'),
			},
			replace: {
				description: 'Replace a URL in the alsoKnownAs field',
				load: () => import('./did-aka-replace.js'),
			},
			remove: {
				description: 'Remove a URL from the alsoKnownAs field',
				load: () => import('./did-aka-remove.js'),
			},
		},
		domain: {
			verify: {
				description: "Verify a domain's DNS record for a DID",
				load: () => import('./did-domain-verify.js'),
			},
			'verify-alias': {
				description: 'Verify alsoKnownAs domain aliases for a DID',
				load: () => import('./did-domain-verify-alias.js'),
			},
		},
	},
	metadata: {
		release: {
			description: 'Build a FAIR metadata document containing a new release',
			load: () => import('./metadata-release.js'),
		},
		verify: {
			description: 'Verify a FAIR metadata document',
			load: () => import('./metadata-verify.js'),
		},
		'verify-release': {
			description: 'Verify a specific release from a metadata document',
			load: () => import('./metadata-verify-release.js'),
		},
	},
};

/**
 * Checks if an object is a command definition.
 */
function isCommand(obj: CommandTree): obj is Command {
	return obj && typeof obj.load === 'function';
}

type CollectedCommand = Command & { path: string[] };

/**
 * Recursively collects all commands from a command tree.
 */
function collectCommands(obj: { [key: string]: CommandTree }, prefix: string[] = []): CollectedCommand[] {
	const results: CollectedCommand[] = [];
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

/**
 * Displays the main help message with all available commands.
 */
function showHelp(): void {
	const allCommands = collectCommands(commands);
	const maxLen = Math.max(...allCommands.map((c) => c.path.join(' ').length));

	const lines = allCommands.map((c) => `  ${c.path.join(' ').padEnd(maxLen + 2)}${c.description}`);

	console.log(`Usage: fair-tools <command> [options]

Commands:
${lines.join('\n')}

Run 'fair-tools <command> --help' for more information on a command.`);
}

/**
 * Displays help for a subcommand group.
 */
function showSubHelp(obj: { [key: string]: CommandTree }, path: string[]): void {
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
let current: { [key: string]: CommandTree } | CommandTree = commands;
let depth = 0;

while (depth < args.length && !isCommand(current)) {
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
}

if (!isCommand(current)) {
	showSubHelp(current, args.slice(0, depth));
	process.exit(0);
}

// Remove the command path from argv so the subcommand sees the right args
process.argv.splice(2, depth);

await current.load();
