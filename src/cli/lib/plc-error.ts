interface PlcClientError {
	message: string;
	status?: number;
	data?:
		| string
		| {
				message?: string;
				error?: string;
		  };
}

/**
 * Formats a PLC client error for display to the user.
 *
 * The @did-plc/lib library throws PlcClientError which has:
 * - status: HTTP status code
 * - data: Response body from PLC server (often contains error details)
 * - message: Generic axios error message
 *
 * @param {PlcClientError} err - The error to format
 * @param {{
 *   includeData?: boolean
 * }} [options] - Options
 * @returns {string} A formatted error message
 */
export function formatPlcError(err, { includeData = true } = {}) {
	// Check if this is a PlcClientError with additional data
	if (err.status && err.data && includeData) {
		const details =
			typeof err.data === 'string' ? err.data : err.data.message || err.data.error || JSON.stringify(err.data);
		return `${err.message} (${err.status}): ${details}`;
	}
	if (err.status) {
		return `${err.message} (${err.status})`;
	}
	return err.message;
}

/**
 * Logs a PLC error with diagnostic hints to stderr.
 *
 * @param {string} prefix - The error prefix (e.g., "Error adding rotation key")
 * @param {PlcClientError} err - The error to log
 * @param {{
 *   signerPublicKey?: string
 * }} [context] - Context for diagnosis
 */
export function logPlcError(prefix, err, context = {}) {
	const hints = diagnosePlcError(err, context);
	console.error(`\x1b[31m${prefix}: ${formatPlcError(err, { includeData: hints.length === 0 })}\x1b[0m`);
	for (const hint of hints) {
		console.error(`\x1b[33m  - ${hint}\x1b[0m`);
	}
}

/**
 * Extracts the operation JSON from a PLC error message.
 *
 * @param {string} data - The error data string
 * @returns {object|null} The parsed operation or null if not found/invalid
 */
function extractOperationFromError(data) {
	const jsonMatch = data.match(/: ({.+})$/);
	if (!jsonMatch) {
		return null;
	}
	try {
		return JSON.parse(jsonMatch[1]);
	} catch {
		return null;
	}
}

/**
 * Diagnoses a PLC error and returns actionable hints.
 *
 * Analyzes the error response to identify common issues and provide
 * helpful suggestions to the user.
 *
 * @param {PlcClientError} err - The error to diagnose
 * @param {{
 *   signerPublicKey?: string
 * }} [context] - Additional context for diagnosis
 * @returns {string[]} Array of diagnostic hints (may be empty)
 */
export function diagnosePlcError(err: PlcClientError, context: { signerPublicKey?: string } = {}): string[] {
	const hints: string[] = [];

	if (err.status !== 400) {
		return hints;
	}

	// err.data can be a string or an object with a message property
	const dataString = typeof err.data === 'string' ? err.data : err.data?.message;

	if (typeof dataString !== 'string') {
		return hints;
	}

	const op = extractOperationFromError(dataString);

	if (!op) {
		return hints;
	}

	// Check if the signing key is valid
	if (context.signerPublicKey && Array.isArray(op.rotationKeys)) {
		if (!op.rotationKeys.includes(context.signerPublicKey)) {
			hints.push(`The signing key ${context.signerPublicKey} is not in the DID's current rotation keys.`);
			hints.push('This can happen if the key was revoked or was never added to the DID.');
			hints.push('Use --signing-key to specify a different rotation key, or check your key file.');
		}
	}

	return hints;
}
