/// <reference types="node" />
type InputData = string | Uint8Array | Buffer;
type OutputFormat = 'hex' | 'array' | 'buffer';
interface Options {
    type: string;
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
    getStateHash(size?: number): Uint8Array;
    /**
     * Add to message cumulative size of message in bits
     *
     * @protected
     */
    addLengthBits(): void;
}
/**
 * Calculates [WHIRLPOOL (WHIRLPOOL-0, WHIRLPOOL-T)](http://www.larc.usp.br/~pbarreto/WhirlpoolPage.html) hash
 */
export declare class Whirlpool extends Hasher32be {
    C: number[];
    RC: number[];
    /**
     * @param {Object} [options]
     * @param {number} [options.rounds=10] - Number of rounds (Can be from 1 to 10)
     * @param {string} [options.type] - Algorithm type
     *
     * | Hash type   | Type      |
     * |-------------|-----------|
     * | whirlpool-0 | '0'       |
     * | whirlpool-t | 't'       |
     * | whirlpool   | undefined |
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
 * Creates a 64 byte WHIRLPOOL hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function _WHIRLPOOL(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 64 byte keyed WHIRLPOOL hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function WHIRLPOOL_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 64 byte WHIRLPOOL0 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function WHIRLPOOL0(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 64 byte keyed WHIRLPOOL0 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function WHIRLPOOL0_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 64 byte WHIRLPOOLT hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function WHIRLPOOLT(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 64 byte keyed WHIRLPOOLT hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function WHIRLPOOLT_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Static class of all WHIRLPOOL functions and classes
 */
export declare class WHIRLPOOL {
    static Whirlpool: typeof Whirlpool;
    static WHIRLPOOL: typeof _WHIRLPOOL;
    static WHIRLPOOL_HMAC: typeof WHIRLPOOL_HMAC;
    static WHIRLPOOL0: typeof WHIRLPOOL0;
    static WHIRLPOOL0_HMAC: typeof WHIRLPOOL0_HMAC;
    static WHIRLPOOLT: typeof WHIRLPOOLT;
    static WHIRLPOOLT_HMAC: typeof WHIRLPOOLT_HMAC;
    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST(): string[];
}
export {};
//# sourceMappingURL=WHIRLPOOL.d.ts.map