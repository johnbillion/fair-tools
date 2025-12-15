/**
 * Error thrown when a DID validation fails.
 */
export class DidValidationError extends Error {}

/**
 * Expected length of a valid did:plc: identifier.
 * Format: did:plc: (8 chars) + 24 character base32 hash = 32 characters total.
 */
const DID_PLC_LENGTH = 32;

/**
 * Validates that a DID has the required did:plc: prefix and correct length.
 *
 * @param {string} did - The DID to validate
 * @throws {DidValidationError} If the DID doesn't start with 'did:plc:' or has incorrect length
 */
export function validatePlcDid(did) {
	if (!did.startsWith('did:plc:')) {
		throw new DidValidationError(
			`Invalid DID format. DID must start with 'did:plc:' prefix.`,
		);
	}
	if (did.length !== DID_PLC_LENGTH) {
		throw new DidValidationError(
			`Invalid DID format. DID must be ${DID_PLC_LENGTH} characters in length.`,
		);
	}
}
