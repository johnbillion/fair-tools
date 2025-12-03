/**
 * FAIR Tools - Tools for the FAIR protocol.
 *
 * @package fair-tools
 */

// Key management utilities
export * from './src/keys.js';

// DID management utilities
export {
	PLC_DIRECTORY_URL,
	FAIR_SERVICE_TYPE,
	FAIR_SERVICE_ID,
	createDID,
	updateDID,
	addVerificationKey,
	addRotationKey,
	revokeRotationKey,
} from './src/did.js';

// Metadata utilities
export {
	METADATA_CONTEXT,
	RELEASE_CONTEXT,
	calculateChecksum,
	signArtifact,
	verifyArtifact,
	parsePluginHeaders,
	parseReadmeFile,
	createMetadataDocument,
	createReleaseDocument,
	createArtifact,
	createSignedArtifact,
	buildMetadata,
} from './src/metadata.js';
