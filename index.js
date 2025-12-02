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
} from './src/did.js';

