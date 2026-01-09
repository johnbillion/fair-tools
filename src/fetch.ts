/**
 * Shared fetch options for all HTTP requests.
 */
export const fetchOptions: RequestInit = {
	signal: AbortSignal.timeout(30000),
};
