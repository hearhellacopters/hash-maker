/// <reference types="node" resolution-mode="require"/>
interface Options32 {
    asJAMCRC?: boolean;
    asBuffer?: boolean;
    asArray?: boolean;
    asHex?: boolean;
    asNumber?: boolean;
}
/**
 * Cyclic Redundancy Check 32. Can also return as JAM with options.
 *
 * @param {string|Uint8Array|Buffer} message - Message as string, Uint8Array or Buffer
 * @param {Options32} options - Object with asJAMCRC, asBuffer, asArray, asHex or asNumber as true (default is number)
 * @returns ``string|Uint8Array|Buffer|number``
 */
export declare function CRC32(message: string | Uint8Array | Buffer, options?: Options32): number | string | Uint8Array | Buffer;
interface Options {
    asBuffer?: boolean;
    asArray?: boolean;
    asHex?: boolean;
    asNumber?: boolean;
}
/**
 * Cyclic Redundancy Check 3
 *
 * @param {string|Uint8Array|Buffer} message - Message as string, Uint8Array or Buffer
 * @param {Options} options - Object with asBuffer, asArray, asHex or asNumber as true (default is number)
 * @returns ``string|Uint8Array|Buffer``
 */
export declare function CRC3(message: string | Uint8Array | Buffer, options?: Options): number | string | Uint8Array | Buffer;
/**
 * Cyclic Redundancy Check 16
 *
 * @param {string|Uint8Array|Buffer} message - Message as string, Uint8Array or Buffer
 * @param {Options} options - Object with asBuffer, asArray, asHex or asNumber as true (default is number)
 * @returns ``string|Uint8Array|Buffer``
 */
export declare function CRC16(message: string | Uint8Array | Buffer, options?: Options): number | string | Uint8Array | Buffer;
export {};
//# sourceMappingURL=CRC32.d.ts.map