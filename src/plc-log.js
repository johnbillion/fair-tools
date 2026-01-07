import { assureValidSig, didForCreateOp, getLastOpWithCid } from '@did-plc/lib';
import { PLC_DIRECTORY_URL } from './did.js';

/**
 * Error thrown when DID log validation fails.
 */
export class DidLogValidationError extends Error {}

/**
 * Error thrown when the DID log cannot be fetched.
 */
export class DidLogFetchError extends Error {}

/**
 * Fetches the full operation log for a DID from the PLC directory.
 *
 * @param {string} did - The DID to fetch the log for (did:plc:...)
 * @param {string} [plcUrl] - The PLC directory URL (defaults to https://plc.directory)
 * @returns {Promise<object[]>} The array of operations
 * @throws {DidLogFetchError} If the log cannot be fetched
 */
export async function fetchDidLog(did, plcUrl = PLC_DIRECTORY_URL) {
	const url = `${plcUrl}/${did}/log`;

	let response;
	try {
		response = await fetch(url);
	} catch (err) {
		throw new DidLogFetchError(`Failed to fetch DID log: ${err.message}`);
	}

	if (response.status === 404) {
		throw new DidLogFetchError(`DID not found: ${did}`);
	}

	if (!response.ok) {
		throw new DidLogFetchError(`Failed to fetch DID log: HTTP ${response.status}`);
	}

	try {
		return await response.json();
	} catch (err) {
		throw new DidLogFetchError(`Failed to parse DID log response: ${err.message}`);
	}
}

/**
 * Validates an operation log for a DID.
 *
 * Validates:
 * - Genesis operation structure and DID computation
 * - All signatures (secp256k1 rotation keys)
 * - CID chain (prev field matches previous operation CID)
 * - Key rotation validity
 *
 * Note: Custom validation is implemented instead of using validateOperationLog
 * from @did-plc/lib because that function incorrectly validates verification
 * method keys (which are just data) as if they were rotation keys. FAIR uses
 * Ed25519 for verification keys, which the library doesn't support.
 *
 * See:
 *
 * - https://github.com/did-method-plc/did-method-plc/pull/47
 * - https://github.com/did-method-plc/did-method-plc/issues/139
 *
 * @param {string} did - The DID to validate (did:plc:...)
 * @param {object[]} ops - The operation log array
 * @returns {Promise<{did: string, operations: {index: number, cid: string, type: string, signingKey: string}[]}>}
 * @throws {DidLogValidationError} If validation fails
 */
export async function validateOperations(did, ops) {
	if (!Array.isArray(ops) || ops.length === 0) {
		throw new DidLogValidationError('DID log is empty or invalid');
	}

	const validatedOps = [];

	try {
		// Validate genesis operation
		const genesisOp = ops[0];

		if (genesisOp.prev !== null) {
			throw new DidLogValidationError('Genesis operation must have null prev');
		}

		// Verify the DID is correctly derived from the genesis operation
		const computedDid = await didForCreateOp(genesisOp);
		if (computedDid !== did) {
			throw new DidLogValidationError(`DID mismatch: expected ${did}, computed ${computedDid}`);
		}

		// Verify genesis signature against its own rotation keys and get the signing key
		const genesisSigningKey = await assureValidSig(genesisOp.rotationKeys, genesisOp);

		// Get CID of genesis operation
		const genesisWithCid = await getLastOpWithCid(ops.slice(0, 1));
		let prevCid = genesisWithCid.cid;

		validatedOps.push({
			index: 0,
			cid: prevCid.toString(),
			type: genesisOp.type,
			signingKey: genesisSigningKey,
		});

		// Track current valid rotation keys
		let currentRotationKeys = genesisOp.rotationKeys;

		// Validate each subsequent operation
		for (let i = 1; i < ops.length; i++) {
			const op = ops[i];

			// Check for tombstone
			if (op.type === 'plc_tombstone') {
				throw new DidLogValidationError('DID has been tombstoned');
			}

			// Verify prev field matches the CID of the previous operation
			if (op.prev !== prevCid.toString()) {
				throw new DidLogValidationError(
					`Operation ${i}: prev mismatch, expected ${prevCid.toString()}, got ${op.prev}`,
				);
			}

			// Verify signature against current rotation keys (from previous state) and get signing key
			const signingKey = await assureValidSig(currentRotationKeys, op);

			// Update rotation keys for next iteration
			currentRotationKeys = op.rotationKeys;

			// Get CID of this operation for next iteration
			const opWithCid = await getLastOpWithCid(ops.slice(0, i + 1));
			prevCid = opWithCid.cid;

			validatedOps.push({
				index: i,
				cid: prevCid.toString(),
				type: op.type,
				signingKey,
			});
		}

		return {
			did,
			operations: validatedOps,
		};
	} catch (err) {
		if (err instanceof DidLogValidationError) {
			throw err;
		}
		throw new DidLogValidationError(`DID log validation failed: ${err.message}`);
	}
}

/**
 * Fetches and validates a DID's full operation log.
 *
 * @param {string} did - The DID to validate (did:plc:...)
 * @param {string} [plcUrl] - The PLC directory URL (defaults to https://plc.directory)
 * @returns {Promise<{did: string, operations: {index: number, cid: string, type: string, signingKey: string}[]}>}
 * @throws {DidLogFetchError} If the log cannot be fetched
 * @throws {DidLogValidationError} If validation fails
 */
export async function validateDidLog(did, plcUrl = PLC_DIRECTORY_URL) {
	const ops = await fetchDidLog(did, plcUrl);
	return validateOperations(did, ops);
}
