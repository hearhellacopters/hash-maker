/// <reference types="node" />
interface Options {
    asBuffer?: boolean;
    asArray?: boolean;
    asHex?: boolean;
    asNumber?: boolean;
}
/**
 * Cyclic Redundancy Check 32
 * @param {string|Uint8Array|Buffer} message - Message as string, Uint8Array or Buffer
 * @returns number
 */
export declare function CRC32(message: string | Uint8Array | Buffer, options?: Options): number | string | Uint8Array | Buffer;
/**
 * Cyclic Redundancy Check 3
 * @param {string|Uint8Array|Buffer} message - Message as string, Uint8Array or Buffer
 * @returns number
 */
export declare function CRC3(message: string | Uint8Array | Buffer, options?: Options): number | string | Uint8Array | Buffer;
/**
 * Cyclic Redundancy Check 16
 * @param {string|Uint8Array|Buffer} message - Message as string, Uint8Array or Buffer
 * @returns number
 */
export declare function CRC16(message: string | Uint8Array | Buffer, options?: Options): number | string | Uint8Array | Buffer;
export {};
//# sourceMappingURL=CRC32.d.ts.map