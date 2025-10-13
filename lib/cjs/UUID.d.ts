/// <reference types="node" />
type OutputFormat = 'hex' | 'array' | 'buffer';
/**
 * Generates a UUID as Uint8Array, Buffer or Hex string (default).
 *
 * @param {number} version - UUID version 1-5 (default 4)
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer (default hex)
 * @param {Uint8Array|Buffer} seed - Seed value (random by default)
 * @param {Uint8Array|Buffer} mac - static mac value
 * @returns `string|Buffer|Uint8Array`
 */
export declare function UUID(version?: number, format?: OutputFormat, seed?: Uint8Array | Buffer, mac?: Uint8Array | Buffer): string | Buffer | Uint8Array;
export {};
//# sourceMappingURL=UUID.d.ts.map