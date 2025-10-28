/// <reference types="node" />
type InputData = string | Uint8Array | Buffer;
type OutputFormat = 'encoded' | 'hex' | 'array' | 'buffer';
/**
 * Creates a vary byte Argon2 of the password as either an encoded string, hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} password - Password to hash
 * @param {InputData} salt Salt for password
 * @param {OutputFormat?} format - Return format as an encoded string, hex string, Uint8Array, Buffer
 * @param {number?} time - computing time of the hash (default `1`)
 * @param {number?} memory - amount of memory to use in KiB (default `1024`)
 * @param {number?} hashLen - output hash length in bytes (default `32`)
 * @param {number?} parallelism - parallelism in the computing of the hash (default `1`)
 * @param {number} type - from {@link ArgonType} (default `Argon2d`)
 * @returns `string|Uint8Array|Buffer`
 */
export declare function _ARGON2(password: InputData, salt: InputData, format?: OutputFormat, time?: number, memory?: number, hashLen?: number, parallelism?: number, type?: number): string | Uint8Array | Buffer;
/**
 * Creates a vary byte Argon2d of the password as either an encoded string, hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} password - Password to hash
 * @param {InputData} salt Salt for password
 * @param {OutputFormat?} format - Return format as an encoded string, hex string, Uint8Array, Buffer
 * @param {number?} time - computing time of the hash (default `1`)
 * @param {number?} memory - amount of memory to use in KiB (default `1024`)
 * @param {number?} hashLen - output hash length in bytes (default `32`)
 * @param {number?} parallelism - parallelism in the computing of the hash (default `1`)
 * @returns `string|Uint8Array|Buffer`
 */
export declare function ARGON2D(password: InputData, salt: InputData, format?: OutputFormat, time?: number, memory?: number, hashLen?: number, parallelism?: number): string | Uint8Array | Buffer;
/**
 * Creates a vary byte Argon2i of the password as either an encoded string, hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} password - Password to hash
 * @param {InputData} salt Salt for password
 * @param {OutputFormat?} format - Return format as an encoded string, hex string, Uint8Array, Buffer
 * @param {number?} time - computing time of the hash (default `1`)
 * @param {number?} memory - amount of memory to use in KiB (default `1024`)
 * @param {number?} hashLen - output hash length in bytes (default `32`)
 * @param {number?} parallelism - parallelism in the computing of the hash (default `1`)
 * @returns `string|Uint8Array|Buffer`
 */
export declare function ARGON2I(password: InputData, salt: InputData, format?: OutputFormat, time?: number, memory?: number, hashLen?: number, parallelism?: number): string | Uint8Array | Buffer;
/**
 * Creates a vary byte Argon2id of the password as either an encoded string, hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} password - Password to hash
 * @param {InputData} salt Salt for password
 * @param {OutputFormat?} format - Return format as an encoded string, hex string, Uint8Array, Buffer
 * @param {number?} time - computing time of the hash (default `1`)
 * @param {number?} memory - amount of memory to use in KiB (default `1024`)
 * @param {number?} hashLen - output hash length in bytes (default `32`)
 * @param {number?} parallelism - parallelism in the computing of the hash (default `1`)
 * @returns `string|Uint8Array|Buffer`
 */
export declare function ARGON2ID(password: InputData, salt: InputData, format?: OutputFormat, time?: number, memory?: number, hashLen?: number, parallelism?: number): string | Uint8Array | Buffer;
/**
 * Creates a vary byte Argon2u of the password as either an encoded string, hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} password - Password to hash
 * @param {InputData} salt Salt for password
 * @param {OutputFormat?} format - Return format as an encoded string, hex string, Uint8Array, Buffer
 * @param {number?} time - computing time of the hash (default `1`)
 * @param {number?} memory - amount of memory to use in KiB (default `1024`)
 * @param {number?} hashLen - output hash length in bytes (default `32`)
 * @param {number?} parallelism - parallelism in the computing of the hash (default `1`)
 * @returns `string|Uint8Array|Buffer`
 */
export declare function ARGON2U(password: InputData, salt: InputData, format?: OutputFormat, time?: number, memory?: number, hashLen?: number, parallelism?: number): string | Uint8Array | Buffer;
/**
 * Static class of all Argon2 functions and classes
 */
export declare class ARGON2 {
    static ARGON2: typeof _ARGON2;
    static ARGON2D: typeof ARGON2D;
    static ARGON2I: typeof ARGON2I;
    static ARGON2ID: typeof ARGON2ID;
    static ARGON2U: typeof ARGON2U;
    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST(): string[];
}
export {};
//# sourceMappingURL=ARGON2.d.ts.map