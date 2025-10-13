/// <reference types="node" />
import { MURMUR3_X64_128, MURMUR3_X86_32, MURMUR3_X86_128 } from './MURMUR3';
type InputData = string | Uint8Array | Buffer;
/**
 * MurMur1 hash as 32 bit number
 *
 * @param {InputData} message - Message to hash
 * @param {number?} seed - starting value
 * @returns
 */
export declare function MURMUR1(message: InputData, seed?: number): number;
/**
 * MurMur2 hash as a 32 bit number.
 *
 * @param {InputData} message - Message to hash
 * @param {number?} seed - starting value
 * @returns `number`
 */
export declare function MURMUR2_32(message: InputData, seed?: number): number;
/**
 * MurMur2A hash as a 32 bit number.
 *
 * @param {InputData} message - Message to hash
 * @param {number?} seed - starting value
 * @returns `number`
 */
export declare function MURMUR2A_32(message: InputData, seed?: number): number;
/**
 * Murmur2A hash as a 64 bit bigint.
 *
 * @param {InputData} message - Message to hash
 * @param {bigint?} seed - starting value
 * @returns `bigint`
 */
export declare function MURMUR2A_64(message: InputData, seed?: bigint): bigint;
/**
 * Murmur2B hash as a 64 bit bigint.
 *
 * @param {InputData} message - Message to hash
 * @param {bigint?} seed - starting value
 * @returns `bigint`
 */
export declare function MURMUR2B_64(message: InputData, seed?: bigint): bigint;
/**
 * Static class of all MurMur functions and classes
 */
export declare class MURMUR {
    static MURMUR1: typeof MURMUR1;
    static MURMUR2_32: typeof MURMUR2_32;
    static MURMUR2A_32: typeof MURMUR2A_32;
    static MURMUR2A_64: typeof MURMUR2A_64;
    static MURMUR2B_64: typeof MURMUR2B_64;
    static MURMUR3_X86_32: typeof MURMUR3_X86_32;
    static MURMUR3_X86_128: typeof MURMUR3_X86_128;
    static MURMUR3_X64_128: typeof MURMUR3_X64_128;
    /**
     * List of all hashes in class
     */
    static get FUNCTION_LIST(): string[];
}
export {};
//# sourceMappingURL=MURMUR.d.ts.map