/// <reference types="node" />
type InputData = string | Uint8Array | Buffer;
type OutputFormat = 'hex' | 'array' | 'buffer';
/**
 * Creates a 32 byte SHA256 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function SHA256(message: InputData, format?: OutputFormat): string | number[] | Buffer;
/**
 * Creates a 32 byte keyed SHA256 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function SHA256_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 32 byte SHA256 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function SHA256_DOUBLE(message: InputData, format?: OutputFormat): string | number[] | Buffer;
/**
 * Creates a 28 byte SHA224 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function SHA224(message: InputData, format?: OutputFormat): string | number[] | Buffer;
/**
 * Creates a 28 byte SHA224 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function SHA224_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
export {};
//# sourceMappingURL=SHA256.d.ts.map