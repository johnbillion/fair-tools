import { addSignature, didForCreateOp, UnsignedOperation, Operation } from '@did-plc/lib';
import { Secp256k1Keypair } from '@atproto/crypto';
import { PLC_DIRECTORY_URL, submitDID as plcSubmitDID } from './plc.js';

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

interface CreateDIDOptions {
	/** The verification key (did:key:z6Mk...) */
	verificationKey: string;
	/** The rotation key (did:key:zQ3sh...) */
	rotationKey: string;
	keypair: Secp256k1Keypair;
	plcUrl?: string;
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
	await plcSubmitDID({ op, did, plcUrl });
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

// Re-export PLC directory functions and constants for backward compatibility
export { PLC_DIRECTORY_URL, createPlcClient } from './plc.js';
export { updateDID } from './plc.js';
export { addVerificationKey } from './plc.js';
export { addRotationKey } from './plc.js';
export { revokeVerificationKey } from './plc.js';
export { revokeRotationKey } from './plc.js';
export { addAlsoKnownAs } from './plc.js';
export { replaceAlsoKnownAs } from './plc.js';
export { replaceServiceUrl } from './plc.js';
export { removeServiceUrl } from './plc.js';
export { removeAlsoKnownAs } from './plc.js';
