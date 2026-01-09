/**
 * Ambient module declarations for packages that don't expose types
 * compatible with our TypeScript configuration.
 *
 * We use uint8arrays v3.x and multiformats v9.x to deduplicate with
 * @atproto/crypto, @did-plc/lib, and their transitive dependencies
 * (@atproto/common, @ipld/dag-cbor).
 *
 * - uint8arrays v3.x ships types but doesn't include a "types" condition
 *   in its package.json "exports" field, so TypeScript can't resolve them
 *   with moduleResolution: "NodeNext". Fixed in v5+.
 *
 * - multiformats v9.x ships types for the main entry point but not for
 *   subpath exports like "./bases/base58". Fixed in v10+.
 *
 * Upgrading would cause duplicate copies of these packages.
 */

declare module 'uint8arrays' {
	export function toString(data: Uint8Array, encoding: string): string;
	export function fromString(data: string, encoding: string): Uint8Array;
}

declare module 'multiformats/bases/base58' {
	export const base58btc: {
		decode(input: string): Uint8Array;
		encode(input: Uint8Array): string;
	};
}
