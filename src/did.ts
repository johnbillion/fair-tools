import { addSignature, Client, didForCreateOp } from '@did-plc/lib';

/**
 * @typedef {import('@atproto/crypto').Secp256k1Keypair} Secp256k1Keypair
 * @typedef {import('@did-plc/lib').UnsignedOperation} UnsignedOperation
 * @typedef {import('@did-plc/lib').Operation} Operation
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
 * Creates an unsigned PLC DID genesis operation.
 *
 * This creates the initial operation for a new PLC DID for a FAIR package.
 * The operation does NOT include the FAIR service - this should be
 * added in a subsequent update operation after the DID is created.
 *
 * @param {{
 *   verificationKey: string, // did:key:z6Mk...
 *   rotationKeys: string[] // did:key:zQ3sh...
 * }} opts
 * @returns {UnsignedOperation} The unsigned genesis operation
 */
function createGenesisOperation({
	verificationKey,
	rotationKeys,
}: {
	verificationKey: string;
	rotationKeys: string[];
}) {
	return {
		type: 'plc_operation' as const,
		verificationMethods: {
			fair: verificationKey,
		},
		rotationKeys,
		alsoKnownAs: [] as string[],
		services: {} as Record<string, { type: string; endpoint: string }>,
		prev: null,
	};
}

/**
 * Creates a signed PLC DID genesis operation.
 *
 * This creates the initial operation for a new PLC DID for a FAIR package.
 * The operation does NOT include the FAIR service - this should be
 * added in a subsequent updateDID() operation after the DID is created.
 *
 * @param {{
 *   verificationKey: string, // did:key:z6Mk...
 *   rotationKey: string, // did:key:zQ3sh...
 *   keypair: Secp256k1Keypair
 * }} opts
 * @returns {Promise<{
 *   op: Operation,
 *   did: string
 * }>}
 */
export async function generateDID({ verificationKey, rotationKey, keypair }) {
	const unsigned = createGenesisOperation({
		verificationKey,
		rotationKeys: [rotationKey],
	});
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
 * @param {{
 *   op: Operation,
 *   did: string, // did:plc:...
 *   plcUrl?: string // defaults to https://plc.directory
 * }} opts
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
 * @param {{
 *   verificationKey: string, // did:key:z6Mk...
 *   rotationKey: string, // did:key:zQ3sh...
 *   keypair: Secp256k1Keypair,
 *   plcUrl?: string // defaults to https://plc.directory
 * }} opts
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
 * @param {UnsignedOperation} lastOp - The previous operation
 * @param {string} serviceUrl - The FAIR service endpoint URL
 * @returns {UnsignedOperation} The updated operation
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
 * @param {{
 *   did: string, // did:plc:...
 *   serviceUrl: string,
 *   signer: Secp256k1Keypair, // must be a rotation key
 *   plcUrl?: string // defaults to https://plc.directory
 * }} opts
 * @returns {Promise<void>}
 */
export async function updateDID({ did, serviceUrl, signer, plcUrl = PLC_DIRECTORY_URL }) {
	const client = createPlcClient(plcUrl);
	await client.updateData(did, signer, (lastOp) => updateServiceUrlInOp(lastOp, serviceUrl));
}

/**
 * Generates a unique key ID for a verification method.
 *
 * @param {Record<string, string>} verificationMethods - Existing verification methods
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
 * @param {UnsignedOperation} lastOp - The previous operation
 * @param {string} verificationKey - The new verification key (did:key format)
 * @returns {UnsignedOperation} The updated operation
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
 * @param {{
 *   did: string, // did:plc:...
 *   verificationKey: string, // did:key:z6Mk...
 *   signer: Secp256k1Keypair, // must be a rotation key
 *   plcUrl?: string // defaults to https://plc.directory
 * }} opts
 * @returns {Promise<void>}
 */
export async function addVerificationKey({ did, verificationKey, signer, plcUrl = PLC_DIRECTORY_URL }) {
	const client = createPlcClient(plcUrl);
	await client.updateData(did, signer, (lastOp) => addVerificationKeyToOp(lastOp, verificationKey));
}

/**
 * Creates an updated operation with a new rotation key added.
 *
 * @param {UnsignedOperation} lastOp - The previous operation
 * @param {string} rotationKey - The new rotation key (did:key format)
 * @returns {UnsignedOperation} The updated operation
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
 * @param {{
 *   did: string, // did:plc:...
 *   rotationKey: string, // did:key:zQ3sh...
 *   signer: Secp256k1Keypair, // must be an existing rotation key
 *   plcUrl?: string // defaults to https://plc.directory
 * }} opts
 * @returns {Promise<void>}
 */
export async function addRotationKey({ did, rotationKey, signer, plcUrl = PLC_DIRECTORY_URL }) {
	const client = createPlcClient(plcUrl);
	await client.updateData(did, signer, (lastOp) => addRotationKeyToOp(lastOp, rotationKey));
}

/**
 * Creates an updated operation with a verification key removed.
 *
 * @param {UnsignedOperation} lastOp - The previous operation
 * @param {string} publicKey - The verification key to revoke (did:key format)
 * @returns {UnsignedOperation} The updated operation
 * @throws {Error} If the verification key is not found
 */
export function revokeVerificationKeyFromOp(lastOp, publicKey) {
	const keyId = Object.entries(lastOp.verificationMethods).find(([, value]) => value === publicKey)?.[0];
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
 * @param {{
 *   did: string, // did:plc:...
 *   publicKey: string, // did:key:z6Mk... to revoke
 *   signer: Secp256k1Keypair, // must be a rotation key
 *   plcUrl?: string // defaults to https://plc.directory
 * }} opts
 * @returns {Promise<void>}
 */
export async function revokeVerificationKey({ did, publicKey, signer, plcUrl = PLC_DIRECTORY_URL }) {
	const client = createPlcClient(plcUrl);
	await client.updateData(did, signer, (lastOp) => revokeVerificationKeyFromOp(lastOp, publicKey));
}

/**
 * Creates an updated operation with a rotation key removed.
 *
 * @param {UnsignedOperation} lastOp - The previous operation
 * @param {string} rotationKey - The rotation key to revoke (did:key format)
 * @returns {UnsignedOperation} The updated operation
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
 * @param {{
 *   did: string, // did:plc:...
 *   rotationKey: string, // did:key:zQ3sh... to revoke
 *   signer: Secp256k1Keypair, // must be an existing rotation key
 *   plcUrl?: string // defaults to https://plc.directory
 * }} opts
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
 * @param {UnsignedOperation} lastOp - The previous operation
 * @param {string} url - The URL to add to alsoKnownAs
 * @returns {UnsignedOperation} The updated operation
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
 * @param {{
 *   did: string, // did:plc:...
 *   url: string,
 *   signer: Secp256k1Keypair, // must be a rotation key
 *   plcUrl?: string // defaults to https://plc.directory
 * }} opts
 * @returns {Promise<void>}
 */
export async function addAlsoKnownAs({ did, url, signer, plcUrl = PLC_DIRECTORY_URL }) {
	const client = createPlcClient(plcUrl);
	await client.updateData(did, signer, (lastOp) => addAlsoKnownAsToOp(lastOp, url));
}

/**
 * Creates an updated operation with an alsoKnownAs URL replaced.
 *
 * This specifically verifies the old URL exists before updating,
 * to prevent accidental overwrites.
 *
 * @param {UnsignedOperation} lastOp - The previous operation
 * @param {string} oldUrl - The current alsoKnownAs URL to replace
 * @param {string} newUrl - The new URL
 * @returns {UnsignedOperation} The updated operation
 * @throws {Error} If the old URL doesn't exist or new URL already exists
 */
export function replaceAlsoKnownAsInOp(lastOp, oldUrl, newUrl) {
	const existing = lastOp.alsoKnownAs || [];
	const index = existing.indexOf(oldUrl);
	if (index === -1) {
		throw new Error(`URL not found in alsoKnownAs: ${oldUrl}`);
	}
	if (existing.includes(newUrl)) {
		throw new Error(`URL already exists in alsoKnownAs: ${newUrl}`);
	}
	const updated = [...existing];
	updated[index] = newUrl;
	return {
		...lastOp,
		alsoKnownAs: updated,
	};
}

/**
 * Replaces a URL in the alsoKnownAs field of an existing DID.
 *
 * This verifies the old URL exists before updating, to prevent
 * accidental overwrites.
 *
 * @param {{
 *   did: string, // did:plc:...
 *   oldUrl: string,
 *   newUrl: string,
 *   signer: Secp256k1Keypair, // must be a rotation key
 *   plcUrl?: string // defaults to https://plc.directory
 * }} opts
 * @returns {Promise<void>}
 */
export async function replaceAlsoKnownAs({ did, oldUrl, newUrl, signer, plcUrl = PLC_DIRECTORY_URL }) {
	const client = createPlcClient(plcUrl);
	await client.updateData(did, signer, (lastOp) => replaceAlsoKnownAsInOp(lastOp, oldUrl, newUrl));
}

/**
 * Creates an updated operation with the FAIR service URL replaced.
 *
 * This specifically verifies the old URL matches before updating,
 * to prevent accidental overwrites.
 *
 * @param {UnsignedOperation} lastOp - The previous operation
 * @param {string} oldUrl - The current service endpoint URL to replace
 * @param {string} newUrl - The new service endpoint URL
 * @returns {UnsignedOperation} The updated operation
 * @throws {Error} If the FAIR service doesn't exist or oldUrl doesn't match
 */
export function replaceServiceUrlInOp(lastOp, oldUrl, newUrl) {
	const existingService = lastOp.services?.[FAIR_SERVICE_ID];
	if (!existingService) {
		throw new Error(`FAIR service not found in DID`);
	}
	if (existingService.endpoint !== oldUrl) {
		throw new Error(`Current service URL does not match: expected "${oldUrl}", found "${existingService.endpoint}"`);
	}
	return {
		...lastOp,
		services: {
			...lastOp.services,
			[FAIR_SERVICE_ID]: {
				type: FAIR_SERVICE_TYPE,
				endpoint: newUrl,
			},
		},
	};
}

/**
 * Replaces the FAIR service URL for an existing DID.
 *
 * This verifies the old URL matches before updating, to prevent
 * accidental overwrites. Use updateDID() if you want to set the
 * URL without verifying the current value.
 *
 * @param {{
 *   did: string, // did:plc:...
 *   oldUrl: string,
 *   newUrl: string,
 *   signer: Secp256k1Keypair, // must be a rotation key
 *   plcUrl?: string // defaults to https://plc.directory
 * }} opts
 * @returns {Promise<void>}
 */
export async function replaceServiceUrl({ did, oldUrl, newUrl, signer, plcUrl = PLC_DIRECTORY_URL }) {
	const client = createPlcClient(plcUrl);
	await client.updateData(did, signer, (lastOp) => replaceServiceUrlInOp(lastOp, oldUrl, newUrl));
}

/**
 * Creates an updated operation with the FAIR service removed.
 *
 * This specifically verifies the URL matches before removing,
 * to prevent accidental removals.
 *
 * @param {UnsignedOperation} lastOp - The previous operation
 * @param {string} url - The service endpoint URL to verify before removal
 * @returns {UnsignedOperation} The updated operation
 * @throws {Error} If the FAIR service doesn't exist or URL doesn't match
 */
export function removeServiceUrlFromOp(lastOp, url) {
	const existingService = lastOp.services?.[FAIR_SERVICE_ID];
	if (!existingService) {
		throw new Error(`FAIR service not found in DID`);
	}
	if (existingService.endpoint !== url) {
		throw new Error(`Service URL does not match: expected "${url}", found "${existingService.endpoint}"`);
	}
	const { [FAIR_SERVICE_ID]: _, ...remainingServices } = lastOp.services;
	return {
		...lastOp,
		services: remainingServices,
	};
}

/**
 * Removes the FAIR service from an existing DID.
 *
 * This verifies the URL matches before removing, to prevent
 * accidental removals.
 *
 * @param {{
 *   did: string, // did:plc:...
 *   url: string, // service endpoint URL to verify before removal
 *   signer: Secp256k1Keypair, // must be a rotation key
 *   plcUrl?: string // defaults to https://plc.directory
 * }} opts
 * @returns {Promise<void>}
 */
export async function removeServiceUrl({ did, url, signer, plcUrl = PLC_DIRECTORY_URL }) {
	const client = createPlcClient(plcUrl);
	await client.updateData(did, signer, (lastOp) => removeServiceUrlFromOp(lastOp, url));
}

/**
 * Creates an updated operation with an alsoKnownAs URL removed.
 *
 * This specifically verifies the URL exists before removing,
 * to prevent errors.
 *
 * @param {UnsignedOperation} lastOp - The previous operation
 * @param {string} url - The URL to remove from alsoKnownAs
 * @returns {UnsignedOperation} The updated operation
 * @throws {Error} If the URL doesn't exist in alsoKnownAs
 */
export function removeAlsoKnownAsFromOp(lastOp, url) {
	const existing = lastOp.alsoKnownAs || [];
	if (!existing.includes(url)) {
		throw new Error(`URL not found in alsoKnownAs: ${url}`);
	}
	return {
		...lastOp,
		alsoKnownAs: existing.filter((u) => u !== url),
	};
}

/**
 * Removes a URL from the alsoKnownAs field of an existing DID.
 *
 * This verifies the URL exists before removing, to prevent errors.
 *
 * @param {{
 *   did: string, // did:plc:...
 *   url: string,
 *   signer: Secp256k1Keypair, // must be a rotation key
 *   plcUrl?: string // defaults to https://plc.directory
 * }} opts
 * @returns {Promise<void>}
 */
export async function removeAlsoKnownAs({ did, url, signer, plcUrl = PLC_DIRECTORY_URL }) {
	const client = createPlcClient(plcUrl);
	await client.updateData(did, signer, (lastOp) => removeAlsoKnownAsFromOp(lastOp, url));
}
