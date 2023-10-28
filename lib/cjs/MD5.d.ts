/// <reference types="node" />
interface Options {
    asString: boolean;
    asBuffer: boolean;
    asArray: boolean;
    asHex: boolean;
}
/**
 * Creates a 16 byte MD5 hash of the message as either a string, hex, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {string|Uint8Array|Buffer} message - Message to hash
 * @param {Options} options - Object with asString, asBuffer, asArray or asHex as true (default as hex string)
 * @returns ```string|Uint8Array|Buffer```
 */
export declare function MD5(message: string | Uint8Array | Buffer, options?: Options): string | Uint8Array | Buffer;
export {};
//# sourceMappingURL=MD5.d.ts.map