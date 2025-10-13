/// <reference types="node" />
type InputData = string | Uint8Array | Buffer;
type OutputFormat = 'hex' | 'array' | 'buffer';
interface Options {
    length?: number;
    rounds?: number;
}
interface state {
    message: Uint8Array;
    length: number;
    hash: number[];
}
/**
 * Base hasher class
 * @interface
 */
declare class Hasher {
    unitSize: number;
    unitOrder: number;
    blockSize: number;
    blockSizeInBytes: number;
    options: Options;
    state: state;
    /**
     * @param {Object} options
     * @constructor
     */
    constructor(options?: Options);
    /**
     * Reset hasher to initial state
     */
    reset(): void;
    /**
     * Return current state
     *
     * @returns {Object}
     */
    getState(): object;
    /**
     * Set current state
     *
     * @param {Object} state
     */
    setState(state: state): void;
    /**
     * Update message from binary data
     *
     * @param {InputData} message
     */
    update(message: InputData): void;
    /**
     * Convert various input types to Uint8Array
     *
     * @private
     * @param {InputData?} data
     * @returns {Uint8Array}
     */
    static convertToUint8Array(data?: InputData): Uint8Array;
    /**
     * Process ready blocks
     *
     * @protected
     */
    process(): void;
    /**
     * Finalize hash and return result
     *
     * @returns {Uint8Array}
     */
    finalize(): Uint8Array;
    /**
     * Get hash from state
     *
     * @protected
     * @param {number} [size=this.state.hash.length] - Limit hash size (in chunks)
     * @returns {Uint8Array}
     */
    getStateHash(size?: number): Uint8Array;
    /**
     * Add PKCS7 padding to message
     * Pad with bytes all of the same value as the number of padding bytes
     *
     * @protected
     * @param {number} length
     */
    addPaddingPKCS7(length: number): void;
    /**
     * Add ISO7816-4 padding to message
     * Pad with 0x80 followed by zero bytes
     *
     * @protected
     * @param {number} length
     */
    addPaddingISO7816(length: number): void;
    /**
     * Add zero padding to message
     * Pad with 0x00 characters
     *
     * @protected
     * @param {number} length
     */
    addPaddingZero(length: number): void;
    /**
     * Concatenate two Uint8Arrays
     *
     * @private
     * @param {Uint8Array} a
     * @param {Uint8Array} b
     * @returns {Uint8Array}
     */
    concatUint8Arrays(a: Uint8Array, b: Uint8Array): Uint8Array;
}
/**
 * Hasher for 32 bit big endian blocks
 * @interface
 */
declare class Hasher32be extends Hasher {
    blockUnits: number[];
    /**
     * @param {Object} [options]
     */
    constructor(options?: Options);
    /**
     * Process ready blocks
     *
     * @protected
     */
    process(): void;
    /**
     * Process ready blocks
     *
     * @protected
     * @param {number[]} M
     */
    processBlock(M: number[]): void;
    /**
     * Get hash from state
     *
     * @protected
     * @param {number} [size=this.state.hash.length] - Limit hash size (in chunks)
     * @returns {Uint8Array}
     */
    getStateHash(size: number): Uint8Array;
    /**
     * Add to message cumulative size of message in bits
     *
     * @protected
     */
    addLengthBits(): void;
}
/**
 * Calculates [SM3](https://tools.ietf.org/id/draft-oscca-cfrg-sm3-02.html) hash
 */
export declare class Sm3 extends Hasher32be {
    W: number[];
    options: {
        length: number;
        rounds: number;
    };
    /**
     * @param {Object} [options]
     * @param {number} [options.rounds=64] - Number of rounds (Must be greater than 16)
     * @param {number} [options.length=256] - Length of hash result
     */
    constructor(options?: Options);
    /**
     * Reset hasher to initial state
     */
    reset(): void;
    /**
     * @protected
     * @ignore
     * @param {number} x
     * @returns {number}
     */
    static p0(x: number): number;
    /**
     * @protected
     * @ignore
     * @param {number} x
     * @returns {number}
     */
    static p1(x: number): number;
    /**
     * @protected
     * @ignore
     * @param {number} i
     * @returns {number}
     */
    static tj(i: number): number;
    /**
     * @protected
     * @ignore
     * @param {number} i
     * @param {number} a
     * @param {number} b
     * @param {number} c
     * @returns {number}
     */
    static ffj(i: number, a: number, b: number, c: number): number;
    /**
     * @protected
     * @ignore
     * @param {number} i
     * @param {number} e
     * @param {number} f
     * @param {number} g
     * @returns {number}
     */
    static ggj(i: number, e: number, f: number, g: number): number;
    /**
     * Process ready blocks
     *
     * @protected
     * @ignore
     * @param {number[]} block - Block
     */
    processBlock(block: number[]): void;
    /**
     * Finalize hash and return result
     *
     * @returns {Uint8Array}
     */
    finalize(): Uint8Array;
}
/**
 * Creates a 32 byte SM3 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @param {number?} rounds - cycles (default 64)
 * @returns `string|Uint8Array|Buffer`
 */
export declare function _SM3(message: InputData, format?: OutputFormat, rounds?: number): string | Uint8Array | Buffer;
/**
 * Creates a 32 byte keyed SM3 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @param {number?} rounds - cycles (default 64)
 * @returns `string|Uint8Array|Buffer`
 */
export declare function SM3_HMAC(message: InputData, key: InputData, format?: OutputFormat, rounds?: number): string | Uint8Array | Buffer;
/**
 * Static class of all SM3 functions and classes
 */
export declare class SM3 {
    static Sm3: typeof Sm3;
    static SM3: typeof _SM3;
    static SM3_HMAC: typeof SM3_HMAC;
    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST(): string[];
}
export {};
//# sourceMappingURL=SM3.d.ts.map