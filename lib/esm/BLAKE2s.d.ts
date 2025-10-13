/// <reference types="node" />
type InputData = string | Uint8Array | Buffer;
type OutputFormat = 'hex' | 'array' | 'buffer';
/**
 * Static class of all Blake2s functions
 */
export declare class Blake2s {
    h: Uint32Array;
    b: Uint8Array;
    c: number;
    t: number;
    outlen: number;
    constructor(outlen: number, key?: InputData);
    blake2sUpdate(input: Uint8Array | Buffer): void;
    blake2sCompress(last: boolean): void;
    blake2sFinal(): Uint8Array;
}
/**
 * Creates a vary length BLAKE2s of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {InputData?} key - key for hash
 * @param {number?} bitLen - length of hash (default 32 bytes)
 * @returns `string|Uint8Array|Buffer`
 */
export declare function BLAKE2s(message: InputData, format?: OutputFormat, key?: InputData, bitLen?: 256 | 224): string | Uint8Array | Buffer;
/**
 * Creates a 32 byte BLAKE2s of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {InputData?} key - key for hash
 * @returns `string|Uint8Array|Buffer`
 */
export declare function BLAKE2s256(message: InputData, format?: OutputFormat, key?: InputData): string | Uint8Array | Buffer;
/**
 * Creates a 32 byte keyed BLAKE2s of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - key for hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function BLAKE2s256_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 28 byte BLAKE2s of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {InputData?} key - key for hash
 * @returns `string|Uint8Array|Buffer`
 */
export declare function BLAKE2s224(message: InputData, format?: OutputFormat, key?: InputData): string | Uint8Array | Buffer;
/**
 * Creates a 28 byte keyed BLAKE2s of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - key for hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function BLAKE2s224_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a very length keyed BLAKE2s of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - key for hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {number?} bitLen - length of hash (default 256 bits or 32 bytes)
 * @returns `string|Uint8Array|Buffer`
 */
export declare function BLAKE2s_HMAC(message: InputData, key?: InputData, format?: OutputFormat, bitLen?: 224 | 256): string | Uint8Array | Buffer;
export {};
//# sourceMappingURL=BLAKE2s.d.ts.map