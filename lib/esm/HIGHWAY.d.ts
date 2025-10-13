/// <reference types="node" />
type InputData = string | Uint8Array | Buffer;
type OutputFormat = 'hex' | 'array' | 'buffer';
/**
 * HighwayHash algorithm. See <a href="https://github.com/google/highwayhash">
 * HighwayHash on GitHub</a>
 */
export declare class HighwayHash {
    private v0;
    private v1;
    private mul0;
    private mul1;
    private done;
    /**
     *
     * @param {InputData} key 32 byte key
     */
    constructor(key?: InputData);
    /**
     * Updates the hash with 32 bytes of data. If you can read 4 long values
     * from your data efficiently, prefer using update() instead for more speed.
     * @param packet data array which has a length of at least pos + 32
     * @param pos position in the array to read the first of 32 bytes from
     */
    updatePacket(packet: Uint8Array, pos: number): void;
    /**
     * Updates the hash with 32 bytes of data given as 4 longs. This function is
     * more efficient than updatePacket when you can use it.
     * @param a0 first 8 bytes in little endian 64-bit long
     * @param a1 next 8 bytes in little endian 64-bit long
     * @param a2 next 8 bytes in little endian 64-bit long
     * @param a3 last 8 bytes in little endian 64-bit long
     */
    update(a0: bigint, a1: bigint, a2: bigint, a3: bigint): void;
    /**
     * Updates the hash with the last 1 to 31 bytes of the data. You must use
     * updatePacket first per 32 bytes of the data, if and only if 1 to 31 bytes
     * of the data are not processed after that, updateRemainder must be used for
     * those final bytes.
     * @param bytes data array which has a length of at least pos + size_mod32
     * @param pos position in the array to start reading size_mod32 bytes from
     * @param size_mod32 the amount of bytes to read
     */
    updateRemainder(bytes: Uint8Array, pos: number, size_mod32: number): void;
    /**
     * Computes the hash value after all bytes were processed. Invalidates the
     * state.
     *
     * NOTE: The 64-bit HighwayHash algorithm is declared stable and no longer subject to change.
     *
     * @return 64-bit hash
     */
    finalize64(): Uint8Array;
    /**
     * Computes the hash value after all bytes were processed. Invalidates the state.
     *
     * @return array of size 2 containing 128-bit hash
     */
    finalize128(): Uint8Array;
    /**
     * Computes the hash value after all bytes were processed. Invalidates the state.
     *
     * @return array of size 4 containing 256-bit hash
     */
    finalize256(): Uint8Array;
    private reset;
    private zipperMerge0;
    private zipperMerge1;
    private read64;
    private write64;
    private rotate32By;
    private permuteAndUpdate;
    private modularReduction;
    /**
     * NOTE: The 64-bit HighwayHash algorithm is declared stable and no longer subject to change.
     *
     * @param data array with data bytes
     * @param offset position of first byte of data to read from
     * @param length number of bytes from data to read
     * @param key array of size 4 with the key to initialize the hash with
     * @return 64-bit hash for the given data
     */
    static hash64(data: Uint8Array, offset: number | undefined, length: number | undefined, key: Uint8Array): Uint8Array;
    /**
     * @param data array with data bytes
     * @param offset position of first byte of data to read from
     * @param length number of bytes from data to read
     * @param key array of size 4 with the key to initialize the hash with
     * @return array of size 2 containing 128-bit hash for the given data
     */
    static hash128(data: Uint8Array, offset: number | undefined, length: number | undefined, key: Uint8Array): Uint8Array;
    /**
     * @param data array with data bytes
     * @param offset position of first byte of data to read from
     * @param length number of bytes from data to read
     * @param key array of size 4 with the key to initialize the hash with
     * @return array of size 4 containing 256-bit hash for the given data
     */
    static hash256(data: Uint8Array, offset: number | undefined, length: number | undefined, key: Uint8Array): Uint8Array;
    processAll(data: Uint8Array, offset?: number, length?: number): void;
}
/**
 * Creates a vary byte length keyed Highway Hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {64 | 128 | 256 } bitLen - length of hash (default 128 bits AKA 16 bytes)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function _HIGHWAY(message: InputData, key?: InputData, bitLen?: 64 | 128 | 256, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 8 byte length keyed Highway Hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HIGHWAY64(message: InputData, key?: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 16 byte length keyed Highway Hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HIGHWAY128(message: InputData, key?: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 32 byte length keyed Highway Hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HIGHWAY256(message: InputData, key?: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Static class of all Highway Hash functions and classes
 */
export declare class HIGHWAY {
    static Highway: typeof HighwayHash;
    static HIGHWAY: typeof _HIGHWAY;
    static HIGHWAY64: typeof HIGHWAY64;
    static HIGHWAY128: typeof HIGHWAY128;
    static HIGHWAY256: typeof HIGHWAY256;
    /**
       * List of all hashes in class
       */
    static get FUNCTION_LIST(): string[];
}
export {};
//# sourceMappingURL=HIGHWAY.d.ts.map