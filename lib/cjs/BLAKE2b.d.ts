/// <reference types="node" />
type InputData = string | Uint8Array | Buffer;
type OutputFormat = 'hex' | 'array' | 'buffer';
/**
 * Static class of all Blake2b functions
 */
export declare class Blake2b {
    b: Uint8Array;
    h: Uint32Array;
    t: number;
    c: number;
    outlen: number;
    constructor(outlen: number, key?: InputData, salt?: InputData, personal?: InputData);
    blake2bUpdate(input: Uint8Array | Buffer): void;
    blake2bCompress(last: boolean): void;
    blake2bFinal(): Uint8Array;
}
/**
 * Creates a vary length BLAKE2b of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {InputData?} key - key for hash
 * @param {number?} bitLen - length of hash (default 512 bits or 64 bytes)
 * @param {InputData?} salt - optional salt
 * @param {InputData?} personal - optional personal
 * @returns `string|Uint8Array|Buffer`
 */
export declare function BLAKE2b(message: InputData, format?: OutputFormat, key?: InputData, bitLen?: 128 | 224 | 256 | 384 | 512, salt?: InputData, personal?: InputData): string | Uint8Array | Buffer;
/**
 * Creates a 64 byte BLAKE2b of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {InputData?} key - key for hash
 * @param {InputData?} salt - optional salt
 * @param {InputData?} personal - optional personal
 * @returns `string|Uint8Array|Buffer`
 */
export declare function BLAKE2b512(message: InputData, format?: OutputFormat, key?: InputData, salt?: InputData, personal?: InputData): string | Uint8Array | Buffer;
/**
 * Creates a 64 byte keyed BLAKE2b of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData?} key - key for hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {InputData?} salt - optional salt
 * @param {InputData?} personal - optional personal
 * @returns `string|Uint8Array|Buffer`
 */
export declare function BLAKE2b512_HMAC(message: InputData, key?: InputData, format?: OutputFormat, salt?: InputData, personal?: InputData): string | Uint8Array | Buffer;
/**
 * Creates a 48 byte BLAKE2b of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {InputData?} key - key for hash
 * @param {InputData?} salt - optional salt
 * @param {InputData?} personal - optional personal
 * @returns `string|Uint8Array|Buffer`
 */
export declare function BLAKE2b384(message: InputData, format?: OutputFormat, key?: InputData, salt?: InputData, personal?: InputData): string | Uint8Array | Buffer;
/**
 * Creates a 48 byte keyed BLAKE2b of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData?} key - key for hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {InputData?} salt - optional salt
 * @param {InputData?} personal - optional personal
 * @returns `string|Uint8Array|Buffer`
 */
export declare function BLAKE2b384_HMAC(message: InputData, key?: InputData, format?: OutputFormat, salt?: InputData, personal?: InputData): string | Uint8Array | Buffer;
/**
 * Creates a 32 byte BLAKE2b of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {InputData?} key - key for hash
 * @param {InputData?} salt - optional salt
 * @param {InputData?} personal - optional personal
 * @returns `string|Uint8Array|Buffer`
 */
export declare function BLAKE2b256(message: InputData, format?: OutputFormat, key?: InputData, salt?: InputData, personal?: InputData): string | Uint8Array | Buffer;
/**
 * Creates a 32 byte keyed BLAKE2b of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData?} key - key for hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {InputData?} salt - optional salt
 * @param {InputData?} personal - optional personal
 * @returns `string|Uint8Array|Buffer`
 */
export declare function BLAKE2b256_HMAC(message: InputData, key?: InputData, format?: OutputFormat, salt?: InputData, personal?: InputData): string | Uint8Array | Buffer;
/**
 * Creates a 28 byte BLAKE2b of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {InputData?} key - key for hash
 * @param {InputData?} salt - optional salt
 * @param {InputData?} personal - optional personal
 * @returns `string|Uint8Array|Buffer`
 */
export declare function BLAKE2b224(message: InputData, format?: OutputFormat, key?: InputData, salt?: InputData, personal?: InputData): string | Uint8Array | Buffer;
/**
 * Creates a 28 byte keyed BLAKE2b of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData?} key - key for hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {InputData?} salt - optional salt
 * @param {InputData?} personal - optional personal
 * @returns `string|Uint8Array|Buffer`
 */
export declare function BLAKE2b224_HMAC(message: InputData, key?: InputData, format?: OutputFormat, salt?: InputData, personal?: InputData): string | Uint8Array | Buffer;
/**
 * Creates a vary length keyed BLAKE2b of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData?} key - key for hash
 * @param {number?} bitLen - length of hash (default 512 bit or 64 bytes)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {InputData?} salt - optional salt
 * @param {InputData?} personal - optional personal
 * @returns `string|Uint8Array|Buffer`
 */
export declare function BLAKE2b_HMAC(message: InputData, key?: InputData, bitLen?: 128 | 224 | 256 | 384 | 512, format?: OutputFormat, salt?: InputData, personal?: InputData): string | Uint8Array | Buffer;
export {};
//# sourceMappingURL=BLAKE2b.d.ts.map