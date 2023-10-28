/// <reference types="node" />
interface Options {
    asString: boolean;
    asBuffer: boolean;
    asArray: boolean;
    asHex: boolean;
}
/**
 * Creates a 64 byte SHA512 hash of the message as either a string, hex, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {string|Uint8Array|Buffer} message - Message to hash
 * @param {Options} options - Object with asString, asBuffer, asArray or asHex as true (default as hex string)
 * @returns ```string|Uint8Array|Buffer```
 */
export declare function SHA512(message: string | Uint8Array | Buffer, options?: Options): string | Uint8Array | Buffer;
/**
 * Creates a 48 byte SHA384 hash of the message as either a string, hex, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {string|Uint8Array|Buffer} message - Message to hash
 * @param {Options} options - Object with asString, asBuffer, asArray or asHex as true (default as hex string)
 * @returns ```string|Uint8Array|Buffer```
 */
export declare function SHA384(message: string | Uint8Array | Buffer, options?: Options): string | Uint8Array | Buffer;
export {};
//# sourceMappingURL=SHA512.d.ts.map