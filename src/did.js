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
 * Creates an updated operation with the FAIR service URL set.
 *
 * @param {object} lastOp - The previous operation
 * @param {string} serviceUrl - The FAIR service endpoint URL
 * @returns {object} The updated operation
 */
export function updateServiceUrlInOp(lastOp, serviceUrl) {
	return {
		...lastOp,
		services: {
			...lastOp.services,
			[FAIR_SERVICE_ID]: {
				type: FAIR_SERVICE_TYPE,
				endpoint: serviceUrl,
			},
		},
	};
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
	await client.updateData(did, signer, (lastOp) => updateServiceUrlInOp(lastOp, serviceUrl));
}

/**
 * Generates a unique key ID for a verification method.
 *
 * @param {object} verificationMethods - Existing verification methods
 * @returns {string} A unique key ID
 */
export function generateVerificationKeyId(verificationMethods) {
	if (!verificationMethods.fair) {
		return 'fair';
	}
	let i = 2;
	while (verificationMethods[`fair${i}`]) {
		i++;
	}
	return `fair${i}`;
}

/**
 * Creates an updated operation with a new verification key added.
 *
 * @param {object} lastOp - The previous operation
 * @param {string} verificationKey - The new verification key (did:key format)
 * @returns {object} The updated operation
 */
export function addVerificationKeyToOp(lastOp, verificationKey) {
	const keyId = generateVerificationKeyId(lastOp.verificationMethods);
	return {
		...lastOp,
		verificationMethods: {
			...lastOp.verificationMethods,
			[keyId]: verificationKey,
		},
	};
}

/**
 * Adds a new verification key to an existing DID.
 *
 * The new key is added with a unique ID (fair, fair2, fair3, etc.).
 *
 * @param {object} opts - Options
 * @param {string} opts.did - The DID to update
 * @param {string} opts.verificationKey - The new verification key (did:key format)
 * @param {Secp256k1Keypair} opts.signer - The keypair to sign with (must be a rotation key)
 * @param {string} [opts.plcUrl] - The PLC directory URL (defaults to https://plc.directory)
 * @returns {Promise<void>}
 */
export async function addVerificationKey({ did, verificationKey, signer, plcUrl = PLC_DIRECTORY_URL }) {
	const client = createPlcClient(plcUrl);
	await client.updateData(did, signer, (lastOp) => addVerificationKeyToOp(lastOp, verificationKey));
}

/**
 * Creates an updated operation with a new rotation key added.
 *
 * @param {object} lastOp - The previous operation
 * @param {string} rotationKey - The new rotation key (did:key format)
 * @returns {object} The updated operation
 * @throws {Error} If the rotation key already exists
 */
export function addRotationKeyToOp(lastOp, rotationKey) {
	if (lastOp.rotationKeys.includes(rotationKey)) {
		throw new Error(`Rotation key already exists: ${rotationKey}`);
	}
	return {
		...lastOp,
		rotationKeys: [...lastOp.rotationKeys, rotationKey],
	};
}

/**
 * Adds a new rotation key to an existing DID.
 *
 * The new key is appended to the existing rotation keys.
 *
 * @param {object} opts - Options
 * @param {string} opts.did - The DID to update
 * @param {string} opts.rotationKey - The new rotation key (did:key format)
 * @param {Secp256k1Keypair} opts.signer - The keypair to sign with (must be an existing rotation key)
 * @param {string} [opts.plcUrl] - The PLC directory URL (defaults to https://plc.directory)
 * @returns {Promise<void>}
 */
export async function addRotationKey({ did, rotationKey, signer, plcUrl = PLC_DIRECTORY_URL }) {
	const client = createPlcClient(plcUrl);
	await client.updateData(did, signer, (lastOp) => addRotationKeyToOp(lastOp, rotationKey));
}

/**
 * Creates an updated operation with a verification key removed.
 *
 * @param {object} lastOp - The previous operation
 * @param {string} publicKey - The verification key to revoke (did:key format)
 * @returns {object} The updated operation
 * @throws {Error} If the verification key is not found
 */
export function revokeVerificationKeyFromOp(lastOp, publicKey) {
	const keyId = Object.entries(lastOp.verificationMethods)
		.find(([, value]) => value === publicKey)?.[0];
	if (!keyId) {
		throw new Error(`Verification key ${publicKey} not found in DID`);
	}
	const { [keyId]: _, ...remainingMethods } = lastOp.verificationMethods;
	return {
		...lastOp,
		verificationMethods: remainingMethods,
	};
}

/**
 * Revokes a verification key from an existing DID.
 *
 * Removes the specified verification method from the DID document.
 *
 * @param {object} opts - Options
 * @param {string} opts.did - The DID to update
 * @param {string} opts.publicKey - The verification key to revoke (did:key format)
 * @param {Secp256k1Keypair} opts.signer - The keypair to sign with (must be a rotation key)
 * @param {string} [opts.plcUrl] - The PLC directory URL (defaults to https://plc.directory)
 * @returns {Promise<void>}
 */
export async function revokeVerificationKey({ did, publicKey, signer, plcUrl = PLC_DIRECTORY_URL }) {
	const client = createPlcClient(plcUrl);
	await client.updateData(did, signer, (lastOp) => revokeVerificationKeyFromOp(lastOp, publicKey));
}

/**
 * Creates an updated operation with a rotation key removed.
 *
 * @param {object} lastOp - The previous operation
 * @param {string} rotationKey - The rotation key to revoke (did:key format)
 * @returns {object} The updated operation
 * @throws {Error} If the rotation key is not found or is the last one
 */
export function revokeRotationKeyFromOp(lastOp, rotationKey) {
	if (!lastOp.rotationKeys.includes(rotationKey)) {
		throw new Error(`Rotation key ${rotationKey} not found in DID`);
	}
	const remaining = lastOp.rotationKeys.filter((k) => k !== rotationKey);
	if (remaining.length === 0) {
		throw new Error('Cannot revoke the last rotation key');
	}
	return {
		...lastOp,
		rotationKeys: remaining,
	};
}

/**
 * Revokes a rotation key from an existing DID.
 *
 * Removes the specified rotation key from the DID document.
 * Cannot remove the last rotation key - at least one must remain.
 *
 * @param {object} opts - Options
 * @param {string} opts.did - The DID to update
 * @param {string} opts.rotationKey - The rotation key to revoke (did:key format)
 * @param {Secp256k1Keypair} opts.signer - The keypair to sign with (must be an existing rotation key)
 * @param {string} [opts.plcUrl] - The PLC directory URL (defaults to https://plc.directory)
 * @returns {Promise<void>}
 */
export async function revokeRotationKey({ did, rotationKey, signer, plcUrl = PLC_DIRECTORY_URL }) {
	const signerPublicKey = signer.did();
	if (rotationKey === signerPublicKey) {
		throw new Error('Cannot revoke the rotation key used to sign this operation');
	}
	const client = createPlcClient(plcUrl);
	await client.updateData(did, signer, (lastOp) => revokeRotationKeyFromOp(lastOp, rotationKey));
}

/**
 * Creates an updated operation with a new alsoKnownAs URL added.
 *
 * @param {object} lastOp - The previous operation
 * @param {string} url - The URL to add to alsoKnownAs
 * @returns {object} The updated operation
 * @throws {Error} If the URL already exists in alsoKnownAs
 */
export function addAlsoKnownAsToOp(lastOp, url) {
	const existing = lastOp.alsoKnownAs || [];
	if (existing.includes(url)) {
		throw new Error(`URL already exists in alsoKnownAs: ${url}`);
	}
	return {
		...lastOp,
		alsoKnownAs: [...existing, url],
	};
}

/**
 * Adds a new URL to the alsoKnownAs field of an existing DID.
 *
 * The URL is appended to the existing alsoKnownAs array.
 *
 * @param {object} opts - Options
 * @param {string} opts.did - The DID to update
 * @param {string} opts.url - The URL to add to alsoKnownAs
 * @param {Secp256k1Keypair} opts.signer - The keypair to sign with (must be a rotation key)
 * @param {string} [opts.plcUrl] - The PLC directory URL (defaults to https://plc.directory)
 * @returns {Promise<void>}
 */
export async function addAlsoKnownAs({ did, url, signer, plcUrl = PLC_DIRECTORY_URL }) {
	const client = createPlcClient(plcUrl);
	await client.updateData(did, signer, (lastOp) => addAlsoKnownAsToOp(lastOp, url));
}
