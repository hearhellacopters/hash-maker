/// <reference types="node" />
type InputData = string | Uint8Array | Buffer;
type OutputFormat = 'hex' | 'array' | 'buffer';
interface Options {
    length?: number;
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
 * Hasher for 32 bit little endian blocks
 * @interface
 */
declare class Hasher32le extends Hasher {
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
 * Calculates [RIPEMD-160 (RIPEMD-128, RIPEMD-256, RIPEMD-320)](http://homes.esat.kuleuven.be/~bosselae/ripemd160.html) hash
 */
export declare class Ripemd extends Hasher32le {
    /**
     * @param {Object} [options]
     * @param {number} [options.length=160] - Length of hash result
     *
     * | Hash type | Length |
     * |-----------|--------|
     * | ripemd128 | 128    |
     * | ripemd160 | 160    |
     * | ripemd256 | 256    |
     * | ripemd320 | 320    |
     */
    constructor(options?: Options);
    /**
     * Reset hasher to initial state
     */
    reset(): void;
    /**
     * @private
     * @ignore
     * @param {number} x
     * @param {number} y
     * @param {number} z
     * @returns {number}
     */
    static F(x: number, y: number, z: number): number;
    /**
     * @private
     * @ignore
     * @param {number} x
     * @param {number} y
     * @param {number} z
     * @returns {number}
     */
    static G(x: number, y: number, z: number): number;
    /**
     * @private
     * @ignore
     * @param {number} x
     * @param {number} y
     * @param {number} z
     * @returns {number}
     */
    static H(x: number, y: number, z: number): number;
    /**
     * @private
     * @ignore
     * @param {number} x
     * @param {number} y
     * @param {number} z
     * @returns {number}
     */
    static I(x: number, y: number, z: number): number;
    /**
     * @private
     * @ignore
     * @param {number} x
     * @param {number} y
     * @param {number} z
     * @returns {number}
     */
    static J(x: number, y: number, z: number): number;
    /**
     * @private
     * @ignore
     * @param {number} i
     * @param {number} bl
     * @param {number} cl
     * @param {number} dl
     * @returns {number}
     */
    static T(i: number, bl: number, cl: number, dl: number): number;
    /**
     * @private
     * @ignore
     * @param {number} i
     * @param {number} br
     * @param {number} cr
     * @param {number} dr
     * @returns {number}
     */
    static T64(i: number, br: number, cr: number, dr: number): number;
    /**
     * @private
     * @ignore
     * @param {number} i
     * @param {number} br
     * @param {number} cr
     * @param {number} dr
     * @returns {number}
     */
    static T80(i: number, br: number, cr: number, dr: number): number;
    /**
     * Process ready blocks
     *
     * @protected
     * @ignore
     * @param {number[]} block - Block
     */
    processBlock128(block: number[]): void;
    /**
     * Process ready blocks
     *
     * @protected
     * @ignore
     * @param {number[]} block - Block
     */
    processBlock160(block: number[]): void;
    /**
     * Process ready blocks
     *
     * @protected
     * @ignore
     * @param {number[]} block - Block
     */
    processBlock256(block: number[]): void;
    /**
     * Process ready blocks
     *
     * @protected
     * @ignore
     * @param {number[]} block - Block
     */
    processBlock320(block: number[]): void;
    /**
     * Finalize hash and return result
     *
     * @returns {Uint8Array}
     */
    finalize(): Uint8Array;
}
/**
 * Creates a 16 byte RIPEMD128 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function RIPEMD128(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 16 byte keyed RIPEMD128 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function RIPEMD128_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 20 byte RIPEMD160 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function RIPEMD160(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 20 byte keyed RIPEMD160 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function RIPEMD160_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 32 byte RIPEMD256 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function RIPEMD256(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 32 byte keyed RIPEMD256 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function RIPEMD256_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 40 byte RIPEMD256 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function RIPEMD320(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 40 byte keyed RIPEMD256 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function RIPEMD320_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a vary bit length RIPEMD hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @param {number} bits = bit length of hash
 * @returns `string|Uint8Array|Buffer`
 */
export declare function _RIPEMD(message: InputData, bits?: number, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a vary bit length keyed RIPEMD hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @param {number} bits = bit length of hash
 * @returns `string|Uint8Array|Buffer`
 */
export declare function RIPEMD_HMAC(message: InputData, key: InputData, bits?: number, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Static class of all RIPEMD functions
 */
export declare class RIPEMD {
    static Ripemd: typeof Ripemd;
    static RIPEMD: typeof _RIPEMD;
    static RIPEMD128: typeof RIPEMD128;
    static RIPEMD128_HMAC: typeof RIPEMD128_HMAC;
    static RIPEMD160: typeof RIPEMD160;
    static RIPEMD160_HMAC: typeof RIPEMD160_HMAC;
    static RIPEMD256: typeof RIPEMD256;
    static RIPEMD256_HMAC: typeof RIPEMD256_HMAC;
    static RIPEMD320: typeof RIPEMD320;
    static RIPEMD320_HMAC: typeof RIPEMD320_HMAC;
    static RIPEMD_HMAC: typeof RIPEMD_HMAC;
    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST(): string[];
}
export {};
//# sourceMappingURL=RIPEMD.d.ts.map