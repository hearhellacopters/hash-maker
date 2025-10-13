/// <reference types="node" />
type InputData = string | Uint8Array | Buffer;
type OutputFormat = 'hex' | 'array' | 'buffer';
/**
 * Creates a 64 byte SHA512 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @param {number} outputBits - size of output in bits (default 512 or 64 bytes)
 * @returns `string|Uint8Array|Buffer`
 */
export declare function SHA512(message: InputData, format?: OutputFormat, outputBits?: number): string | Buffer | Uint8Array;
/**
 * Creates a 64 byte SHA512 HMAC hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - key for hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @param {number} outputBits - size of output in bits (default 512 or 64 bytes)
 * @returns `string|Uint8Array|Buffer`
 */
export declare function SHA512_HMAC(message: InputData, key: InputData, format?: OutputFormat, outputBits?: number): string | Buffer | Uint8Array;
/**
 * Creates a 48 byte SHA384 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @param {number} outputBits - size of output in bits (default 384 or 48 bytes)
 * @returns `string|Uint8Array|Buffer`
 */
export declare function SHA384(message: InputData, format?: OutputFormat, outputBits?: number): string | Buffer | Uint8Array;
/**
 * Creates a 48 byte SHA384 HMAC hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - key for hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @param {number} outputBits - size of output in bits (default 384 or 48 bytes)
 * @returns `string|Uint8Array|Buffer`
 */
export declare function SHA384_HMAC(message: InputData, key: InputData, format?: OutputFormat, outputBits?: number): string | Buffer | Uint8Array;
/**
 * Creates a 28 byte SHA512/224 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function SHA512_224(message: InputData, format?: OutputFormat): string | Buffer | Uint8Array;
/**
 * Creates a 32 byte SHA512/256 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function SHA512_256(message: InputData, format?: OutputFormat): string | Buffer | Uint8Array;
/**
 * Creates a 32 byte SHA512/256 HMAC hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - key for hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function SHA512_256_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Buffer | Uint8Array;
/**
 * Creates a 28 byte SHA512/224 HMAC hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - key for hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function SHA512_224_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Buffer | Uint8Array;
export {};
//# sourceMappingURL=SHA512.d.ts.map