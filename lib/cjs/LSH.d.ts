/// <reference types="node" />
type LSHAlgorithm = "LSH256_224" | "LSH256_256" | "LSH512_224" | "LSH512_256" | "LSH512_384" | "LSH512_512";
type InputData = string | Uint8Array | Buffer;
type OutputFormat = 'hex' | 'array' | 'buffer';
declare abstract class Hash {
    /**
     * Creates and returns an object with the same output length.
     *
     * @return LSHDigest object
     */
    abstract newInstance(): Hash;
    /**
     * Returns the message block bit length used for internal calculations.
     *
     * @return Message block bit length
     */
    abstract getBlockSize(): number;
    /**
     * Returns the length of the hash output.
     *
     * @return Hash output length (in bits)
     */
    abstract getOutlenbits(): number;
    /**
     * Initializes internal state to prepare for computing a new message digest.
     */
    abstract reset(): void;
    /**
     * mProcesses data to compute message digest.
     *
     * @param data
     *            Data to calculate message digest
     */
    update(data?: Uint8Array, offset?: number, lenbits?: number): void;
    /**
     * Add data to calculate the final message digest.
     *
     * @param data
     *            Data to calculate message digest
     * @param offset
     *            Start offset of data array
     * @param lenbits
     *            Length of data (in bits)
     */
    doFinal(data?: Uint8Array, offset?: number, lenbits?: number): Uint8Array;
    /**
     * Returns a hash function object corresponding to the algorithm
     *
     * @param algorithm
     *            Algorithm
     * @return Hash function object
     */
    static getInstance(algorithm: LSHAlgorithm): Hash;
    /**
     * Calculate hash using algorithm
     */
    static digest(arg1: LSHAlgorithm | number, arg2?: Uint8Array | number, arg3?: Uint8Array | number, arg4?: number, arg5?: number): any;
}
/**
 * LSH256 algorithm implementation
 *
 * Word length: 32-bit (4-byte) Chain variable length: 512-bit (64-byte) Message block length: 1024-bit
 * (128-byte)
 */
export declare class Lsh256 extends Hash {
    private BLOCKSIZE;
    private NUMSTEP;
    private static IV224;
    private static IV256;
    private static STEP;
    private ALPHA_EVEN;
    private ALPHA_ODD;
    private BETA_EVEN;
    private BETA_ODD;
    private static GAMMA;
    private cv;
    private tcv;
    private msg;
    private block;
    private boff;
    private outlenbits;
    /**
     * LSH256 constructor
     *
     * Default constructor, 256-bit output setting
     *
     * @param outlenbits
     *            Output length, in bits
     */
    constructor(outlenbits?: number);
    /**
     * Creates and returns an object with the same output length.
     *
     * @return LSH256 object
     */
    newInstance(): Hash;
    private init;
    /**
     * Returns the internal block size.
     *
     * @return Internal block size
     */
    getBlockSize(): number;
    /**
     * Returns the output length.
     *
     * @return Output length, in bits
     */
    getOutlenbits(): number;
    /**
     * Initialize state variables
     */
    reset(): void;
    /**
     * Message handling functions for online operations
     *
     * @param data
     *            data
     * @param offset
     *            Data start offset
     * @param lenbits
     *            Data length (bits)
     */
    update(data: Uint8Array, offset?: number, lenbits?: number): void;
    /**
     * Update the final internal state and return the hash value.
     *
     * @return Hash value
     */
    doFinal(data?: Uint8Array, offset?: number, lenbits?: number): Uint8Array;
    /**
     * IV generation
     */
    private generateIV;
    /**
     * Compression operation of the LSH algorithm
     *
     * @param data
     *            data
     * @param offset
     *            Data start offset
     */
    private compress;
    /**
     * Message expansion operation used in the Compress function, processing BLOCKSIZE units at a time
     *
     * @param in
     *            data
     * @param offset
     *            Data start offset (bytes)
     */
    private msgExpansion;
    /**
     * Message add & mix operations used in the Compress function
     *
     * @param stepidx
     *            Step Index
     * @param alpha
     *            Left rotation value to apply to the upper 8 words
     * @param beta
     *            Left rotation value to apply to the lower 8 words
     */
    private step;
    /**
     * LSH's word permutation operation
     */
    private wordPermutation;
    /**
     * 332-bit left rotation operation
     *
     * @param value
     *            operand
     * @param rot
     *            Rotation value
     * @return The value rotated left by rot
     */
    private rol32;
}
/**
 * LSH512 algorithm implementation
 *
 * Word length: 64-bit (8-byte) Chain variable length: 1024-bit (128-byte) Message block length: 2048-bit
 * (256-byte)
 */
export declare class Lsh512 extends Hash {
    private BLOCKSIZE;
    private NUMSTEP;
    private static IV224;
    private static IV256;
    private static IV384;
    private static IV512;
    private static STEP;
    private ALPHA_EVEN;
    private ALPHA_ODD;
    private BETA_EVEN;
    private BETA_ODD;
    private static GAMMA;
    private cv;
    private tcv;
    private msg;
    private block;
    private boff;
    private outlenbits;
    /**
     * LSH512 constructor
     *
     * @param outlenbits
     *            Output length, in bits
     */
    constructor(outlenbits?: number);
    /**
     * Creates and returns an object with the same output length.
     *
     * @return LSH512 object
     */
    newInstance(): Hash;
    private init;
    /**
     * Return internal block size
     *
     * @return Internal block size
     */
    getBlockSize(): number;
    /**
     * Returns the output length.
     *
     * @return Output length, in bits
     */
    getOutlenbits(): number;
    /**
     * Initialize state variables
     */
    reset(): void;
    /**
     * Message handling functions for online operations
     *
     * @param data
     *            data
     * @param offset
     *            Data start offset
     * @param lenbits
     *            Data length (bits)
     */
    update(data?: Uint8Array, offset?: number, lenbits?: number): void;
    /**
     * Update the final internal state and return the hash value.
     *
     * @return Hash value
     */
    doFinal(data?: Uint8Array, offset?: number, lenbits?: number): Uint8Array;
    /**
     * IV generation
     */
    private generateIV;
    /**
     * Compression operation of the LSH algorithm
     *
     * @param data
     *            data
     * @param offset
     *            Data start offset
     */
    private compress;
    /**
     * Message expansion operation used in the Compress function, processing BLOCKSIZE units at a time
     *
     * @param in
     *            data
     * @param offset
     *            Data start offset (bytes)
     */
    private msgExpansion;
    /**
     * Message add & mix operations used in the Compress function
     *
     * @param stepidx
     *            Step Index
     * @param alpha
     *            Left rotation value to apply to the upper 8 words
     * @param beta
     *            Left rotation value to apply to the lower 8 words
     */
    private step;
    /**
     * LSH's word permutation operation
     */
    private wordPermutation;
    /**
     * 64-bit unit left rotation operation
     *
     * @param value
     *            operand
     * @param shift
     *            Rotation value
     * @return The value rotated left by rot
     */
    private rol64;
}
/**
 * Interface for MAC implementation
 */
declare abstract class Mac {
    /**
     * Initialization function
     *
     * @param key
     *            secret key
     */
    abstract init(key: Uint8Array): void;
    /**
     * Initialize an object for MAC calculation for new messages.
     */
    abstract reset(): void;
    /**
     * Add message
     *
     * @param msg
     *            Message to add
     */
    abstract update(msg?: Uint8Array): void;
    /**
     * MAC calculation including the last message
     *
     * @param msg
     *            Last message
     * @return MAC value
     */
    doFinal(msg?: Uint8Array): Uint8Array;
    /**
     * Creating an object for MAC calculation
     *
     * @param algorithm
     *            MessageDigest algorithm
     * @return Mac object
     */
    static getInstance(algorithm: LSHAlgorithm): Mac;
}
/**
 * HMAC implementation
 */
export declare class HMac extends Mac {
    private IPAD;
    private OPAD;
    private blocksize;
    private _digest;
    private i_key_pad;
    private o_key_pad;
    /**
     * Constructor
     *
     * @param md
     *            MessageDigest object
     */
    constructor(md: Hash);
    /**
     * Initialize internal state
     *
     * @param key
     *            secret key
     */
    init(key: Uint8Array): void;
    /**
     * Initialize the hash function and put i_key_pad into the hash function.
     */
    reset(): void;
    /**
     * Put the message for which you want to calculate the MAC into a hash function
     */
    update(msg: Uint8Array): void;
    /**
     * Compute H(i_key_pad || msg) and compute H(o_key_pad || H(i_key_pad || msg)).
     */
    doFinal(msg?: Uint8Array): Uint8Array;
    static digest(algorithm: LSHAlgorithm, key: Uint8Array, msg: Uint8Array): Uint8Array;
}
/**
 * Creates a vary byte length LSH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {256 | 512} bitLen - hash function to use
 * @param {224 | 256 | 384 | 512} hashLen - return hash length in bits (default 256, can't be greater than bitLen)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function _LSH(message: InputData, bitLen?: 256 | 512, hashLen?: 224 | 256 | 384 | 512, format?: OutputFormat): any;
/**
 * Creates a vary byte length keyed LSH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {256 | 512} bitLen - hash function to use
 * @param {224 | 256 | 384 | 512} hashLen - return hash length in bits (default 256, can't be greater than bitLen)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function LSH_HMAC(message: InputData, key: InputData, bitLen?: 256 | 512, hashLen?: 224 | 256 | 384 | 512, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates up to 32 bytes LSH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {224 | 256} hashLen - return hash length in bits (default 256, can't be greater than bitLen)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function LSH256(message: InputData, hashLen?: 224 | 256, format?: OutputFormat): any;
/**
 * Creates up to 32 bytes keyed LSH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {224 | 256} hashLen - return hash length in bits (default 256, can't be greater than bitLen)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function LSH256_HMAC(message: InputData, key: InputData, hashLen?: 224 | 256, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 28 byte LSH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function LSH256_224(message: InputData, format?: OutputFormat): any;
/**
 * Creates a 28 byte keyed LSH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function LSH256_224_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 32 byte LSH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function LSH256_256(message: InputData, format?: OutputFormat): any;
/**
 * Creates a 32 byte keyed LSH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function LSH256_256_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates up to 64 bytes LSH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {224 | 256 | 384 | 512} hashLen - return hash length in bits (default 256, can't be greater than 512)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function LSH512(message: InputData, hashLen?: 224 | 256 | 384 | 512, format?: OutputFormat): any;
/**
 * Creates up to 64 bytes keyed LSH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {224 | 256 | 384 | 512} hashLen - return hash length in bits (default 256, can't be greater than 512)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function LSH512_HMAC(message: InputData, key: InputData, hashLen?: 224 | 256 | 384 | 512, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 28 byte LSH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function LSH512_224(message: InputData, format?: OutputFormat): any;
/**
 * Creates a 28 byte keyed LSH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function LSH512_224_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 32 byte LSH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function LSH512_256(message: InputData, format?: OutputFormat): any;
/**
 * Creates a 32 byte keyed LSH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function LSH512_256_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 48 byte LSH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function LSH512_384(message: InputData, format?: OutputFormat): any;
/**
 * Creates a 48 byte keyed LSH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function LSH512_384_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 64 byte LSH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function LSH512_512(message: InputData, format?: OutputFormat): any;
/**
 * Creates a 64 byte keyed LSH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function LSH512_512_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Static class of all Locality-Sensitive Hashing (LSH) functions and classes
 */
export declare class LSH {
    static Lsh256: typeof Lsh256;
    static LSH: typeof _LSH;
    static LSH256: typeof LSH256;
    static LSH256_HMAC: typeof LSH256_HMAC;
    static LSH256_224: typeof LSH256_224;
    static LSH256_224_HMAC: typeof LSH256_224_HMAC;
    static LSH256_256: typeof LSH256_256;
    static LSH256_256_HMAC: typeof LSH256_256_HMAC;
    static Lsh512: typeof Lsh512;
    static LSH512: typeof LSH512;
    static LSH512_HMAC: typeof LSH512_HMAC;
    static LSH512_224: typeof LSH512_224;
    static LSH512_224_HMAC: typeof LSH512_224_HMAC;
    static LSH512_256: typeof LSH512_256;
    static LSH512_256_HMAC: typeof LSH512_256_HMAC;
    static LSH512_384: typeof LSH512_384;
    static LSH512_384_HMAC: typeof LSH512_384_HMAC;
    static LSH512_512: typeof LSH512_512;
    static LSH512_512_HMAC: typeof LSH512_512_HMAC;
    static LSH_HMAC: typeof LSH_HMAC;
    /**
     * List of all hashes in class
     */
    static get FUNCTION_LIST(): string[];
}
export {};
//# sourceMappingURL=LSH.d.ts.map