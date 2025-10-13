/// <reference types="node" />
type InputData = string | Uint8Array | Buffer;
type OutputFormat = 'hex' | 'array' | 'buffer';
interface Options {
    length: number;
    rounds: number;
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
    convertToUint8Array(data?: InputData): Uint8Array;
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
    getStateHash(size?: number): Uint8Array;
    /**
     * Add to message cumulative size of message in bits
     *
     * @protected
     */
    addLengthBits(): void;
}
/**
 * Calculates Snefru v2.0 (2 rounds 128, 4 rounds 256), Snefru v2.5 (8 rounds) hash
 */
export declare class Snefru extends Hasher32be {
    W: number[];
    /**
     * @param {Object} [options]
  
     * | Hash type   | Length | Rounds |
     * |-------------|--------|--------|
     * | snefru128/2 | 128    | 2      |
     * | snefru256/4 | 256    | 4      |
     * | snefru128/8 | 128    | 8      |
     * | snefru256/8 | 256    | 8      |
     *
     * @param {number} [options.rounds=8] - Number of rounds (Can be from 2 to 8)
     * @param {number} [options.length=128] - Length of hash result (Can be from 32 to 480 with step 32).
     * Be careful, increasing of length will cause a reduction of the block size
     */
    constructor(options?: Options);
    /**
     * Reset hasher to initial state
     */
    reset(): void;
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
 * Creates a 32 byte SNEFRU/256/4 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function _SNEFRU(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 16 byte SNEFRU/128/2 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function SNEFRU128_2(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 32 byte SNEFRU/256/4 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function SNEFRU256_4(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 16 byte SNEFRU/128/8 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function SNEFRU128_8(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 32 byte SNEFRU/256/4 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function SNEFRU256_8(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Static class of all SNEFRU functions and classes
 */
export declare class SNEFRU {
    static Snefru: typeof Snefru;
    static SNEFRU: typeof _SNEFRU;
    static SNEFRU128_2: typeof SNEFRU128_2;
    static SNEFRU128_8: typeof SNEFRU128_8;
    static SNEFRU256_4: typeof SNEFRU256_4;
    static SNEFRU256_8: typeof SNEFRU256_8;
    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST(): string[];
}
export {};
//# sourceMappingURL=SNEFRU.d.ts.map