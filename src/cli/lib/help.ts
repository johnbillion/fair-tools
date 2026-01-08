/**
 * Help text utilities for CLI commands.
 */

/**
 * Generate signing key help text for rotation key operations.
 *
 * @param {{ signingKeyDefault?: string }} opts
 * @returns {string}
 */
export function rotationKeyHelp({ signingKeyDefault = 'first' } = {}) {
	return `Signing key:
  --signing-file <file>  Path to key file (JSON with rotationKeys, or PEM)
  --signing-key <key>    Which rotation key to sign with (default: ${signingKeyDefault}, JSON only)

  If --signing-file is not provided, uses FAIR_ROTATION_KEY environment variable.`;
}

/**
 * Generate signing key help text for verification key operations.
 *
 * @returns {string}
 */
export function verificationKeyHelp() {
	return `Signing key:
  --signing-file <file>  Path to key file (JSON with verificationKeys, or PEM)
  --signing-key <key>    Which verification key to sign with (default: first, JSON only)

  If --signing-file is not provided, uses FAIR_VERIFICATION_KEY environment variable.`;
}
