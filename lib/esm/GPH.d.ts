/// <reference types="node" />
type InputData = string | Uint8Array | Buffer;
/**
 * Robert Sedgwicks hash as a 32 bit number.
 *
 * @param {InputData} message - Message to hash
 * @param {number?} seed - starting value
 * @returns `number`
 */
export declare function RSHash(message: InputData, seed?: number): number;
/**
 * Justin Sobel hash as a 32bit number. (can't be seeded)
 *
 * @param {InputData} message - Message to hash
 * @returns `number`
 */
export declare function JSHash(message: InputData): number;
/**
 * Peter J. Weinberger hash as a 32 bit number.
 *
 * @param {InputData} message - Message to hash
 * @param {number?} seed - starting value
 * @returns `number`
 */
export declare function PJWHash(message: InputData, seed?: number): number;
/**
 * Executable and Linkable Format (ELF file format) hash as a 32 bit number. (PJW based, widley used on UNIX systems)
 *
 * @param {InputData} message - Message to hash
 * @param {number?} seed - starting value
 * @returns `number`
 */
export declare function ELFHash(message: InputData, seed?: number): number;
/**
 * Brian Kernighan and Dennis Ritchie hash as a 32 bit number.
 *
 * @param {InputData} message - Message to hash
 * @param {number?} seed - starting value
 * @returns `number`
 */
export declare function BKDRHash(message: InputData, seed?: number): number;
/**
 * Simple Database Management hash as a 32 bit number (a public-domain reimplementation of ndbm)
 *
 * @param {InputData} message - Message to hash
 * @param {number?} seed - starting value
 * @returns `number`
 */
export declare function SDBMHash(message: InputData, seed?: number): number;
/**
 * Daniel J. Bernstein hash as a 32 bit number. (can't be seeded)
 *
 * @param {InputData} message - Message to hash
 * @returns `number`
 */
export declare function DJBHash(message: InputData): number;
/**
 * Donald E. Knuth Hash as a 32 bit number. (can't be seeded)
 *
 * @param {InputData} message - Message to hash
 * @returns `number`
 */
export declare function DEKHash(message: InputData): number;
/**
 * Benjamin Pritchard Hash as a 32 bit number.
 *
 * @param {InputData} message - Message to hash
 * @param {number?} seed - starting value
 * @returns `number`
 */
export declare function BPHash(message: InputData, seed?: number): number;
/**
 * Anchor-based Probability Hash as a 32 bit number.
 *
 * @param {InputData} message - Message to hash
 * @param {number?} seed - starting value
 * @returns `number`
 */
export declare function APHash(message: InputData, seed?: number): number;
/**
 * Daniel J. Bernstein 2 hash as a 32 bit number. (can't be seeded)
 *
 * @param {InputData} message - Message to hash
 * @returns `number`
 */
export declare function DJB2Hash(message: InputData): number;
/**
 * Fowler/Noll/Vo Hash as a 32 bit number.
 *
 * @param {InputData} message - Message to hash
 * @param {number?} seed - starting value
 * @returns `number`
 */
export declare function FNVHash(message: InputData, seed?: number): number;
/**
 * Zilong Tan Fast Hash as a 32 bit number.
 *
 * @param {InputData} message - Message to hash
 * @param {number|bigint} seed - starting value
 * @returns `number`
 */
export declare function Fast32Hash(message: InputData, seed?: number | bigint): number;
/**
 * Zilong Tan Fast Hash as a 64 bit bigint.
 *
 * @param {InputData} message - Message to hash
 * @param {number|bigint} seed - starting value
 * @returns `bigint`
 */
export declare function Fast64Hash(message: InputData, seed?: number): bigint;
/**
 * Static class of all General Purpose Hash functions
 */
export declare class GPH {
    static RSHash: typeof RSHash;
    static JSHash: typeof JSHash;
    static PJWHash: typeof PJWHash;
    static ELFHash: typeof ELFHash;
    static BKDRHash: typeof BKDRHash;
    static SDBMHash: typeof SDBMHash;
    static DJBHash: typeof DJBHash;
    static DEKHash: typeof DEKHash;
    static BPHash: typeof BPHash;
    static APHash: typeof APHash;
    static DJB2Hash: typeof DJB2Hash;
    static FNVHash: typeof FNVHash;
    static Fast32Hash: typeof Fast32Hash;
    static Fast64Hash: typeof Fast64Hash;
    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST(): string[];
}
export {};
//# sourceMappingURL=GPH.d.ts.map