import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const packageJson = JSON.parse(readFileSync(join(__dirname, '../../package.json'), 'utf-8'));

export const version: string = packageJson.version;

/**
 * Shared fetch options for all HTTP requests.
 */
export const fetchOptions: RequestInit = {
	headers: {
		'User-Agent': `fair-tools/${version}`,
	},
	signal: AbortSignal.timeout(30000),
};
