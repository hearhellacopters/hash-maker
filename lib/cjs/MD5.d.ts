/// <reference types="node" />
type InputData = string | Uint8Array | Buffer;
type OutputFormat = 'hex' | 'array' | 'buffer';
/**
 * Creates a 16 byte MD5 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function MD5(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 16 byte keyed MD5 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function MD5_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
export {};
//# sourceMappingURL=MD5.d.ts.map