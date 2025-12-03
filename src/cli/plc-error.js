/**
 * Formats a PLC client error for display to the user.
 *
 * The @did-plc/lib library throws PlcClientError which has:
 * - status: HTTP status code
 * - data: Response body from PLC server (often contains error details)
 * - message: Generic axios error message
 *
 * @param {Error} err - The error to format
 * @returns {string} A formatted error message
 */
export function formatPlcError(err) {
	// Check if this is a PlcClientError with additional data
	if (err.status && err.data) {
		const details = typeof err.data === 'string'
			? err.data
			: err.data.message || err.data.error || JSON.stringify(err.data);
		return `${err.message} (${err.status}): ${details}`;
	}
	return err.message;
}
