/// <reference types="node" />
/**
 * Calculates Tiger 128, 160, 192 hash
 */
export declare class Tiger {
    _digestBitLen: number;
    _extraPasses: number;
    _bigEndian: boolean;
    _tiger2: boolean;
    _a: {
        value: bigint;
    };
    _b: {
        value: bigint;
    };
    _c: {
        value: bigint;
    };
    _aa: bigint;
    _bb: bigint;
    _cc: bigint;
    static L128: number;
    static L160: number;
    static L192: number;
    _x0: bigint;
    _x1: bigint;
    _x2: bigint;
    _x3: bigint;
    _x4: bigint;
    _x5: bigint;
    _x6: bigint;
    _x7: bigint;
    /**
     * Calculates Tiger 128, 160, 192 hash
     *
     * @param {128|160|192} digestBitLen - Return bit length
     * @param {number} extraPasses - For additional passes after the first 3.  For 'Tiger,4' we'd pass 1 here
     * @param {boolean} bigEndian - PHP originally had the final byte-order of the digest inverted.  If this old behavior is desired, set this to true.
     * @param {boolean} tiger2 - for Tiger2 hash instead
     */
    constructor(digestBitLen?: number, // 128, 160, 192
    extraPasses?: number, bigEndian?: boolean, tiger2?: boolean);
    _keySchedule(): void;
    _save(): void;
    _feedforward(): void;
    _compress(): void;
    _round(a: {
        value: bigint;
    }, b: {
        value: bigint;
    }, c: {
        value: bigint;
    }, x: bigint, mul: bigint): void;
    _pass(a: {
        value: bigint;
    }, b: {
        value: bigint;
    }, c: {
        value: bigint;
    }, mul: bigint): void;
    _split(message: bigint[], block: number): void;
    hash(input: Buffer | Uint8Array): Uint8Array;
}
type InputData = string | Uint8Array | Buffer;
type OutputFormat = 'hex' | 'array' | 'buffer';
/**
 * Creates a vary byte TIGER hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @param {128 | 160 | 192} bitLen - length of the returned hash (default 192)
 * @param {number} extraPasses - Extra cycles on the hash
 * @param {boolean} bigEndian - Is the bit order should to written in big endian (default false)
 * @returns `string | Uint8Array | Buffer`
 */
export declare function _TIGER(message: InputData, format?: OutputFormat, bitLen?: 128 | 160 | 192, extraPasses?: number, bigEndian?: boolean): string | Uint8Array | Buffer;
/**
 * Creates a vary byte TIGER hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @param {128 | 160 | 192} bitLen - length of the returned hash (default 192)
 * @param {number} extraPasses - Extra cycles on the hash
 * @param {boolean} bigEndian - Is the bit order should to written in big endian (default false)
 * @returns `string | Uint8Array | Buffer`
 */
export declare function TIGER_HMAC(message: InputData, key: InputData, format?: OutputFormat, bitLen?: 128 | 160 | 192, extraPasses?: number, bigEndian?: boolean): string | Uint8Array | Buffer;
/**
 * Creates a 16 byte TIGER128 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Uint8Array | Buffer`
 */
export declare function TIGER128(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 16 byte keyed TIGER128 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Uint8Array | Buffer`
 */
export declare function TIGER128_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 20 byte TIGER160 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Uint8Array | Buffer`
 */
export declare function TIGER160(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 20 byte keyed TIGER160 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Uint8Array | Buffer`
 */
export declare function TIGER160_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 24 byte TIGER192 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Uint8Array | Buffer`
 */
export declare function TIGER192(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 24 byte keyed TIGER192 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Uint8Array | Buffer`
 */
export declare function TIGER192_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a vary byte TIGER2 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @param {128 | 160 | 192} bitLen - length of the returned hash (default 192)
 * @param {number} extraPasses - Extra cycles on the hash
 * @param {boolean} bigEndian - Is the bit order should to written in big endian (default false)
 * @returns `string | Uint8Array | Buffer`
 */
export declare function TIGER2(message: InputData, format?: OutputFormat, bitLen?: 128 | 160 | 192, extraPasses?: number, bigEndian?: boolean): string | Uint8Array | Buffer;
/**
 * Creates a vary byte keyed TIGER2 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @param {128 | 160 | 192} bitLen - length of the returned hash (default 192)
 * @param {number} extraPasses - Extra cycles on the hash
 * @param {boolean} bigEndian - Is the bit order should to written in big endian (default false)
 * @returns `string | Uint8Array | Buffer`
 */
export declare function TIGER2_HMAC(message: InputData, key: InputData, format?: OutputFormat, bitLen?: 128 | 160 | 192, extraPasses?: number, bigEndian?: boolean): string | Uint8Array | Buffer;
/**
 * Creates a 16 byte TIGER2-128 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Uint8Array | Buffer`
 */
export declare function TIGER2_128(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 16 byte keyed TIGER2-128 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Uint8Array | Buffer`
 */
export declare function TIGER2_128_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 20 byte TIGER2-160 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Uint8Array | Buffer`
 */
export declare function TIGER2_160(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 20 byte keyed TIGER2-160 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Uint8Array | Buffer`
 */
export declare function TIGER2_160_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 24 byte TIGER2-192 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Uint8Array | Buffer`
 */
export declare function TIGER2_192(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 24 byte keyed TIGER2-192 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Uint8Array | Buffer`
 */
export declare function TIGER2_192_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Static class of all TIGER functions and classes
 */
export declare class TIGER {
    static Tiger: typeof Tiger;
    static TIGER: typeof _TIGER;
    static TIGER128: typeof TIGER128;
    static TIGER128_HMAC: typeof TIGER128_HMAC;
    static TIGER160: typeof TIGER160;
    static TIGER160_HMAC: typeof TIGER160_HMAC;
    static TIGER192: typeof TIGER192;
    static TIGER192_HMAC: typeof TIGER192_HMAC;
    static TIGER_HMAC: typeof TIGER_HMAC;
    static TIGER2: typeof TIGER2;
    static TIGER2_128: typeof TIGER2_128;
    static TIGER2_128_HMAC: typeof TIGER2_128_HMAC;
    static TIGER2_160: typeof TIGER2_160;
    static TIGER2_160_HMAC: typeof TIGER2_160_HMAC;
    static TIGER2_192: typeof TIGER2_192;
    static TIGER2_192_HMAC: typeof TIGER2_192_HMAC;
    static TIGER2_HMAC: typeof TIGER2_HMAC;
    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST(): string[];
}
export {};
//# sourceMappingURL=TIGER.d.ts.map