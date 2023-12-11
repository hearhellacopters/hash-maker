/// <reference types="node" resolution-mode="require"/>
interface Options {
    seed?: Uint8Array | Buffer;
    mac?: Uint8Array | Buffer;
    asBuffer?: boolean;
    asArray?: boolean;
}
/**
 * Generates a UUID as Uint8Array, Buffer or Hex string (default).
 *
 * @param {number} version - UUID version 1-5 (default 4)
 * @param {Uint8Array|Buffer} options.seed - If seeding is needed. Must be UInt8Array or Buffer of 16 bytes.
 * @param {Uint8Array|Buffer} options.mac - If a mac ID is needed. Must be UInt8Array or Buffer of 6 bytes. Else one is generated when needed.
 * @returns string
 */
export declare function UUID(version?: number, options?: Options): string | Buffer | Uint8Array;
export {};
//# sourceMappingURL=UUID.d.ts.map