/**
 * PLC Directory client functions.
 *
 * Functions for interacting with the PLC directory to submit and update DIDs.
 */

import { Client, UnsignedOperation, Operation } from '@did-plc/lib';
import { Secp256k1Keypair } from '@atproto/crypto';
import {
	updateServiceUrlInOp,
	addVerificationKeyToOp,
	addRotationKeyToOp,
	revokeVerificationKeyFromOp,
	revokeRotationKeyFromOp,
	addAlsoKnownAsToOp,
	replaceAlsoKnownAsInOp,
	replaceServiceUrlInOp,
	removeServiceUrlFromOp,
	removeAlsoKnownAsFromOp,
} from './did.js';

/**
 * Default PLC directory URL.
 */
export const PLC_DIRECTORY_URL = 'https://plc.directory';

/**
 * Creates a PLC directory client.
 */
export function createPlcClient(url = PLC_DIRECTORY_URL): Client {
	return new Client(url);
}

interface SubmitDIDOptions {
	/** The genesis operation */
	op: Operation;
	/** The DID identifier (did:plc:...) */
	did: string;
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
export async function submitDID({ op, did, plcUrl = PLC_DIRECTORY_URL }: SubmitDIDOptions): Promise<void> {
	const client = createPlcClient(plcUrl);
	await client.sendOperation(did, op);
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
	await client.updateData(did, signer, (lastOp: UnsignedOperation) => updateServiceUrlInOp(lastOp, serviceUrl));
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
	await client.updateData(did, signer, (lastOp: UnsignedOperation) => addVerificationKeyToOp(lastOp, verificationKey));
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
	await client.updateData(did, signer, (lastOp: UnsignedOperation) => addRotationKeyToOp(lastOp, rotationKey));
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
	await client.updateData(did, signer, (lastOp: UnsignedOperation) => revokeVerificationKeyFromOp(lastOp, publicKey));
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
	await client.updateData(did, signer, (lastOp: UnsignedOperation) => revokeRotationKeyFromOp(lastOp, rotationKey));
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
	await client.updateData(did, signer, (lastOp: UnsignedOperation) => addAlsoKnownAsToOp(lastOp, url));
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
	await client.updateData(did, signer, (lastOp: UnsignedOperation) => replaceAlsoKnownAsInOp(lastOp, oldUrl, newUrl));
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
	await client.updateData(did, signer, (lastOp: UnsignedOperation) => replaceServiceUrlInOp(lastOp, oldUrl, newUrl));
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
	await client.updateData(did, signer, (lastOp: UnsignedOperation) => removeServiceUrlFromOp(lastOp, url));
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
	await client.updateData(did, signer, (lastOp: UnsignedOperation) => removeAlsoKnownAsFromOp(lastOp, url));
}

export class NoAliasError extends Error {
	constructor() {
		super('No fair:// alias found in alsoKnownAs field');
	}
}

export class MultipleAliasesError extends Error {
	constructor(count: number) {
		super(`Found ${count} fair:// aliases, but only one is allowed`);
	}
}

/**
 * Fetch DID document and extract the fair:// alias
 * @param {string} did
 * @param {string} [plcUrl] - The PLC directory URL (defaults to https://plc.directory)
 * @returns {Promise<string>} - The fair:// URL
 * @throws {NoAliasError} If no fair:// alias exists
 * @throws {MultipleAliasesError} If more than one fair:// alias exists
 */
export async function getFairAlias(did: string, plcUrl = PLC_DIRECTORY_URL): Promise<string> {
	const client = createPlcClient(plcUrl);
	const doc = await client.getDocument(did);
	const aliases = (doc.alsoKnownAs || []).filter((url: string) => url.startsWith('fair://'));

	if (aliases.length === 0) {
		throw new NoAliasError();
	}

	if (aliases.length > 1) {
		throw new MultipleAliasesError(aliases.length);
	}

	return aliases[0];
}
