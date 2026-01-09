import { addSignature, Client, didForCreateOp, UnsignedOperation, Operation } from '@did-plc/lib';
import { Secp256k1Keypair } from '@atproto/crypto';

/**
 * Default PLC directory URL.
 */
export const PLC_DIRECTORY_URL = 'https://plc.directory';

/**
 * FAIR package management repo service type.
 */
export const FAIR_SERVICE_TYPE = 'FairPackageManagementRepo';

/**
 * FAIR service ID used in DID documents.
 *
 * Must not include the leading '#' character.
 */
export const FAIR_SERVICE_ID = 'fairpm_repo';

interface GenesisOperationOptions {
	verificationKey: string;
	rotationKeys: string[];
}

/**
 * Creates an unsigned PLC DID genesis operation.
 *
 * This creates the initial operation for a new PLC DID for a FAIR package.
 * The operation does NOT include the FAIR service - this should be
 * added in a subsequent update operation after the DID is created.
 */
function createGenesisOperation({ verificationKey, rotationKeys }: GenesisOperationOptions): UnsignedOperation {
	return {
		type: 'plc_operation' as const,
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
 * Creates a signed PLC DID genesis operation.
 *
 * This creates the initial operation for a new PLC DID for a FAIR package.
 * The operation does NOT include the FAIR service - this should be
 * added in a subsequent updateDID() operation after the DID is created.
 */
interface GenerateDIDOptions {
	verificationKey: string;
	rotationKey: string;
	keypair: Secp256k1Keypair;
}

export async function generateDID({
	verificationKey,
	rotationKey,
	keypair,
}: GenerateDIDOptions): Promise<{ op: Operation; did: string }> {
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
 */
function createPlcClient(url = PLC_DIRECTORY_URL): Client {
	return new Client(url);
}

interface SubmitDIDOptions {
	/** The genesis operation */
	op: Operation;
	/** The DID identifier (did:plc:...) */
	did: string;
	plcUrl?: string;
}

interface CreateDIDOptions {
	/** The verification key (did:key:z6Mk...) */
	verificationKey: string;
	/** The rotation key (did:key:zQ3sh...) */
	rotationKey: string;
	keypair: Secp256k1Keypair;
	plcUrl?: string;
}

interface DidUpdateOptions {
	/** The DID identifier (did:plc:...) */
	did: string;
	/** Must be a rotation key */
	signer: Secp256k1Keypair;
	plcUrl?: string;
}

interface UpdateDIDOptions extends DidUpdateOptions {
	serviceUrl: string;
}

interface AddVerificationKeyOptions extends DidUpdateOptions {
	/** The verification key (did:key:z6Mk...) */
	verificationKey: string;
}

interface AddRotationKeyOptions extends DidUpdateOptions {
	/** The rotation key (did:key:zQ3sh...) */
	rotationKey: string;
}

interface RevokeVerificationKeyOptions extends DidUpdateOptions {
	publicKey: string;
}

interface RevokeRotationKeyOptions extends DidUpdateOptions {
	/** The rotation key (did:key:zQ3sh...) */
	rotationKey: string;
}

interface AddAlsoKnownAsOptions extends DidUpdateOptions {
	url: string;
}

interface ReplaceAlsoKnownAsOptions extends DidUpdateOptions {
	oldUrl: string;
	newUrl: string;
}

interface ReplaceServiceUrlOptions extends DidUpdateOptions {
	oldUrl: string;
	newUrl: string;
}

interface RemoveServiceUrlOptions extends DidUpdateOptions {
	url: string;
}

interface RemoveAlsoKnownAsOptions extends DidUpdateOptions {
	url: string;
}

/**
 * Submits a genesis operation to the PLC directory.
 */
async function submitDID({ op, did, plcUrl = PLC_DIRECTORY_URL }: SubmitDIDOptions): Promise<void> {
	const client = createPlcClient(plcUrl);
	await client.sendOperation(did, op);
}

/**
 * Creates a new FAIR package DID and submits it to the PLC directory.
 *
 * This creates the DID without a FAIR service initially. Use updateDID()
 * to add the service URL after the DID is created.
 */
export async function createDID({
	verificationKey,
	rotationKey,
	keypair,
	plcUrl = PLC_DIRECTORY_URL,
}: CreateDIDOptions): Promise<string> {
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
 */
export function updateServiceUrlInOp(lastOp: UnsignedOperation, serviceUrl: string): UnsignedOperation {
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
 */
export async function updateDID({
	did,
	serviceUrl,
	signer,
	plcUrl = PLC_DIRECTORY_URL,
}: UpdateDIDOptions): Promise<void> {
	const client = createPlcClient(plcUrl);
	await client.updateData(did, signer, (lastOp) => updateServiceUrlInOp(lastOp, serviceUrl));
}

/**
 * Generates a unique key ID for a verification method.
 * @returns {string} A unique key ID
 */
export function generateVerificationKeyId(verificationMethods: Record<string, string>): string {
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
export function addVerificationKeyToOp(lastOp: UnsignedOperation, verificationKey: string): UnsignedOperation {
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
 */
export async function addVerificationKey({
	did,
	verificationKey,
	signer,
	plcUrl = PLC_DIRECTORY_URL,
}: AddVerificationKeyOptions): Promise<void> {
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
export function addRotationKeyToOp(lastOp: UnsignedOperation, rotationKey: string): UnsignedOperation {
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
export async function addRotationKey({
	did,
	rotationKey,
	signer,
	plcUrl = PLC_DIRECTORY_URL,
}: AddRotationKeyOptions): Promise<void> {
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
export function revokeVerificationKeyFromOp(lastOp: UnsignedOperation, publicKey: string): UnsignedOperation {
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
 */
export async function revokeVerificationKey({
	did,
	publicKey,
	signer,
	plcUrl = PLC_DIRECTORY_URL,
}: RevokeVerificationKeyOptions): Promise<void> {
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
export function revokeRotationKeyFromOp(lastOp: UnsignedOperation, rotationKey: string): UnsignedOperation {
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
export async function revokeRotationKey({
	did,
	rotationKey,
	signer,
	plcUrl = PLC_DIRECTORY_URL,
}: RevokeRotationKeyOptions): Promise<void> {
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
export function addAlsoKnownAsToOp(lastOp: UnsignedOperation, url: string): UnsignedOperation {
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
 */
export async function addAlsoKnownAs({
	did,
	url,
	signer,
	plcUrl = PLC_DIRECTORY_URL,
}: AddAlsoKnownAsOptions): Promise<void> {
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
export function replaceAlsoKnownAsInOp(lastOp: UnsignedOperation, oldUrl: string, newUrl: string): UnsignedOperation {
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
 */
export async function replaceAlsoKnownAs({
	did,
	oldUrl,
	newUrl,
	signer,
	plcUrl = PLC_DIRECTORY_URL,
}: ReplaceAlsoKnownAsOptions): Promise<void> {
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
export function replaceServiceUrlInOp(lastOp: UnsignedOperation, oldUrl: string, newUrl: string): UnsignedOperation {
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
 */
export async function replaceServiceUrl({
	did,
	oldUrl,
	newUrl,
	signer,
	plcUrl = PLC_DIRECTORY_URL,
}: ReplaceServiceUrlOptions): Promise<void> {
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
export function removeServiceUrlFromOp(lastOp: UnsignedOperation, url: string): UnsignedOperation {
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
 */
export async function removeServiceUrl({
	did,
	url,
	signer,
	plcUrl = PLC_DIRECTORY_URL,
}: RemoveServiceUrlOptions): Promise<void> {
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
export function removeAlsoKnownAsFromOp(lastOp: UnsignedOperation, url: string): UnsignedOperation {
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
 */
export async function removeAlsoKnownAs({
	did,
	url,
	signer,
	plcUrl = PLC_DIRECTORY_URL,
}: RemoveAlsoKnownAsOptions): Promise<void> {
	const client = createPlcClient(plcUrl);
	await client.updateData(did, signer, (lastOp) => removeAlsoKnownAsFromOp(lastOp, url));
}
