import { addSignature, didForCreateOp, Operation, UnsignedOperation } from '@did-plc/lib';
import { Secp256k1Keypair } from '@atproto/crypto';
import { PLC_DIRECTORY_URL, submitDID as plcSubmitDID } from './plc.js';

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
 * added in a subsequent setFairServiceUrl() operation after the DID is created.
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
 * This creates the DID without a FAIR service initially. Use setFairServiceUrl()
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
