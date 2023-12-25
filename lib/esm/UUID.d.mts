/// <reference types="node" resolution-mode="require"/>
interface Options {
    seed?: Uint8Array | Buffer;
    mac?: Uint8Array | Buffer;
    asBuffer?: boolean;
    asArray?: boolean;
    asHex?: boolean;
}
/**
 * Generates a UUID as Uint8Array, Buffer or Hex string (default).
 *
 * @param {number} version - UUID version 1-5 (default 4)
 * @param {Options} options - Object with asBuffer, asArray or asHex as true (default is number). If seeding is needed, use ``{seed: seed}``.If a mac ID is needed., use ``{mac: mac}``. Must be UInt8Array or Buffer of 16 bytes.
 * @returns string
 */
export declare function UUID(version?: number, options?: Options): string | Buffer | Uint8Array;
export {};
//# sourceMappingURL=UUID.d.ts.map