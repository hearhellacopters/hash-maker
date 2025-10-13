/*!
 * +----------------------------------------------------------------------------------+
 * | murmurHash3.js v3.0.0 (http://github.com/karanlyons/murmurHash3.js)              |
 * | A TypeScript/JavaScript implementation of MurmurHash3's hashing algorithms.      |
 * |----------------------------------------------------------------------------------|
 * | Copyright (c) 2012-2020 Karan Lyons. Freely distributable under the MIT license. |
 * +----------------------------------------------------------------------------------+
 */
/// <reference types="node" />
type Brand<Name, Type> = Type & {
    _type?: Name;
};
type u32 = Brand<'u32', number>;
type u64 = Brand<'u64', [u32, u32]>;
type InputData = string | Uint8Array | Buffer;
type OutputFormat = 'hex' | 'array' | 'buffer';
export type x86hash32State = {
    h1: u32;
    len: number;
    rem: Uint8Array;
};
export type x86hash128State = {
    h1: u32;
    h2: u32;
    h3: u32;
    h4: u32;
    len: number;
    rem: Uint8Array;
};
export type x64hash128State = {
    h1: u64;
    h2: u64;
    len: number;
    rem: Uint8Array;
};
/**
 * Murmur3 x64 128 bit message hash.
 *
 * @param {InputData} message - Message to hash
 * @param {number?} seed - starting value
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function MURMUR3_X64_128(message: InputData, seed?: number, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Murmur3 x64 32 bit message hash as a int32 number.
 *
 * @param {InputData} message - Message to hash
 * @param {number?} seed - starting value
 * @returns `number`
 */
export declare function MURMUR3_X86_32(message: InputData, seed?: number): u32 | x86hash32State;
/**
 * Murmur3 x86 128 bit message hash.
 *
 * @param {InputData} message - Message to hash
 * @param {number?} seed - starting value
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function MURMUR3_X86_128(message: InputData, seed?: number, format?: OutputFormat): string | Uint8Array | Buffer;
export {};
//# sourceMappingURL=MURMUR3.d.ts.map