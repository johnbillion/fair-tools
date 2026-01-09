import packageJson from '../package.json' with { type: 'json' };

export const version: string = packageJson.version;

export const userAgent = `fair-tools/${version}`;
export const timeout = 30000;

/**
 * Shared fetch options for all HTTP requests.
 */
export const fetchOptions: RequestInit = {
	headers: {
		'User-Agent': userAgent,
	},
	signal: AbortSignal.timeout(timeout),
};
