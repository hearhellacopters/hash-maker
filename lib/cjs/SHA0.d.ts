/// <reference types="node" />
type InputData = string | Uint8Array | Buffer;
type OutputFormat = 'hex' | 'array' | 'buffer';
/**
 * Creates a 20 byte SHA0 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function SHA0(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 20 byte keyed SHA0 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function SHA0_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
export {};
//# sourceMappingURL=SHA0.d.ts.map