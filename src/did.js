import { addSignature, Client, didForCreateOp } from '@did-plc/lib';

/**
 * @typedef {import('@atproto/crypto').Secp256k1Keypair} Secp256k1Keypair
 */

/**
 * Default PLC directory URL.
 *
 * @type {string}
 */
export const PLC_DIRECTORY_URL = 'https://plc.directory';

/**
 * FAIR package management repo service type.
 *
 * @type {string}
 */
export const FAIR_SERVICE_TYPE = 'FairPackageManagementRepo';

/**
 * FAIR service ID used in DID documents.
 *
 * Must not include the leading '#' character.
 *
 * @type {string}
 */
export const FAIR_SERVICE_ID = 'fairpm_repo';


/**
 * Creates an unsigned FAIR genesis operation.
 *
 * This creates the initial operation for a new FAIR package DID.
 * The operation does NOT include the FAIR service - this should be
 * added in a subsequent update operation after the DID is created.
 *
 * @param {object} opts - Options for the operation
 * @param {string} opts.verificationKey - The verification key (did:key format)
 * @param {string[]} opts.rotationKeys - Array of rotation keys (did:key format)
 * @returns {object} The unsigned genesis operation
 */
function createGenesisOperation({ verificationKey, rotationKeys }) {
	return {
		type: 'plc_operation',
		verificationMethods: {
			fair: verificationKey,
		},
		rotationKeys,
		alsoKnownAs: [],
		services: {},
		prev: null,
	};
}

/**
 * Creates a signed FAIR genesis operation.
 *
 * This creates the initial operation for a new FAIR package DID.
 * The operation does NOT include the FAIR service - this should be
 * added in a subsequent updateDID() operation after the DID is created.
 *
 * @param {object} opts - Options for the operation
 * @param {string} opts.verificationKey - The verification public key
 * @param {string} opts.rotationKey - The rotation public key
 * @param {Secp256k1Keypair} opts.keypair - The rotation keypair to sign with
 * @returns {Promise<{ op: object, did: string }>} The signed operation and the generated DID
 */
export async function generateDID({ verificationKey, rotationKey, keypair }) {
	const unsigned = createGenesisOperation({ verificationKey, rotationKeys: [rotationKey] });
	const op = await addSignature(unsigned, keypair);
	const did = await didForCreateOp(op);
	return { op, did };
}

/**
 * Creates a PLC directory client.
 *
 * @param {string} [url] - The PLC directory URL (defaults to https://plc.directory)
 * @returns {Client} The PLC client
 */
function createPlcClient(url = PLC_DIRECTORY_URL) {
	return new Client(url);
}

/**
 * Submits a genesis operation to the PLC directory.
 *
 * @param {object} opts - Options
 * @param {object} opts.op - The signed genesis operation
 * @param {string} opts.did - The DID for this operation
 * @param {string} [opts.plcUrl] - The PLC directory URL (defaults to https://plc.directory)
 * @returns {Promise<void>}
 */
async function submitDID({ op, did, plcUrl = PLC_DIRECTORY_URL }) {
	const client = createPlcClient(plcUrl);
	await client.sendOperation(did, op);
}

/**
 * Creates a new FAIR package DID and submits it to the PLC directory.
 *
 * This creates the DID without a FAIR service initially. Use updateDID()
 * to add the service URL after the DID is created.
 *
 * @param {object} opts - Options
 * @param {string} opts.verificationKey - The verification public key (did:key format)
 * @param {string} opts.rotationKey - The rotation public key (did:key format)
 * @param {Secp256k1Keypair} opts.keypair - The rotation keypair to sign with
 * @param {string} [opts.plcUrl] - The PLC directory URL (defaults to https://plc.directory)
 * @returns {Promise<string>} The created DID
 */
export async function createDID({ verificationKey, rotationKey, keypair, plcUrl = PLC_DIRECTORY_URL }) {
	const { op, did } = await generateDID({
		verificationKey,
		rotationKey,
		keypair,
	});
	await submitDID({ op, did, plcUrl });
	return did;
}

/**
 * Updates the FAIR service URL for an existing DID.
 *
 * This adds or updates the FAIR package management service endpoint
 * in the DID document.
 *
 * @param {object} opts - Options
 * @param {string} opts.did - The DID to update
 * @param {string} opts.serviceUrl - The FAIR service endpoint URL
 * @param {Secp256k1Keypair} opts.signer - The keypair to sign with (must be a rotation key)
 * @param {string} [opts.plcUrl] - The PLC directory URL (defaults to https://plc.directory)
 * @returns {Promise<void>}
 */
export async function updateDID({ did, serviceUrl, signer, plcUrl = PLC_DIRECTORY_URL }) {
	const client = createPlcClient(plcUrl);
	await client.updateData(did, signer, (lastOp) => ({
		...lastOp,
		services: {
			...lastOp.services,
			[FAIR_SERVICE_ID]: {
				type: FAIR_SERVICE_TYPE,
				endpoint: serviceUrl,
			},
		},
	}));
}
