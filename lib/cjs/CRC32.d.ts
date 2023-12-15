/// <reference types="node" />
interface Options32 {
    asJAMCRC?: boolean;
    asBuffer?: boolean;
    asArray?: boolean;
    asHex?: boolean;
    asNumber?: boolean;
}
/**
 * Cyclic Redundancy Check 32. Can return as JAM as well in options.
 *
 * @param {string|Uint8Array|Buffer} message - Message as string, Uint8Array or Buffer
 * @param {Options32} options - Object with asString, asBuffer, asArray or asHex as true (default as hex string)
 * @returns ``string|Uint8Array|Buffer``
 */
export declare function CRC32(message: string | Uint8Array | Buffer, options?: Options32): number | string | Uint8Array | Buffer;
interface Options {
    asJAMCRC?: boolean;
    asBuffer?: boolean;
    asArray?: boolean;
    asHex?: boolean;
    asNumber?: boolean;
}
/**
 * Cyclic Redundancy Check 3
 *
 * @param {string|Uint8Array|Buffer} message - Message as string, Uint8Array or Buffer
 * @param {Options32} options - Object with asString, asBuffer, asArray or asHex as true (default as hex string)
 * @returns ``string|Uint8Array|Buffer``
 */
export declare function CRC3(message: string | Uint8Array | Buffer, options?: Options): number | string | Uint8Array | Buffer;
/**
 * Cyclic Redundancy Check 16
 *
 * @param {string|Uint8Array|Buffer} message - Message as string, Uint8Array or Buffer
 * @param {Options32} options - Object with asString, asBuffer, asArray or asHex as true (default as hex string)
 * @returns ``string|Uint8Array|Buffer``
 */
export declare function CRC16(message: string | Uint8Array | Buffer, options?: Options): number | string | Uint8Array | Buffer;
export {};
//# sourceMappingURL=CRC32.d.ts.map