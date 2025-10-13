/// <reference types="node" />
type InputData = string | Uint8Array | Buffer;
type OutputFormat = 'hex' | 'array' | 'buffer';
/**
 * This interface documents the API for a hash function. This
 * interface somewhat mimics the standard java.security.MessageDigest class. We do not extend that class in order to provide compatibility with reduced Java implementations such as J2ME. Implementing a java.security.Provider compatible with Sun's JCA ought to be easy.
 *
 * A Digest object maintains a running state for a hash function computation. Data is inserted with update() calls; the result is obtained from a digest() method (where some final data can be inserted as well). When a digest output has been produced, the object is automatically reset, and can be used immediately for another digest operation. The state of a computation can be cloned with the copy() method; this can be used to get a partial hash result without interrupting the complete computation.
 *
 * Digest objects are stateful and hence not thread-safe; however, distinct Digest objects can be accessed concurrently without any problem.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @version $Revision: 232 $
 * @author Thomas Pornin <thomas.pornin@cryptolog.com>
 */
interface Digest {
    /**
     * Insert one more input data byte.
     *
     * @param input the input byte (0-255)
     */
    update(input: number): void;
    /**
     * Insert some more bytes.
     *
     * @param input the data bytes
     */
    update(input: Uint8Array): void;
    /**
     * Insert some more bytes.
     *
     * @param input the data buffer
     * @param off the data offset in input
     * @param len the data length (in bytes)
     */
    update(input: Uint8Array, off: number, len: number): void;
    /**
     * Finalize the current hash computation and return the hash value
     * in a newly-allocated Uint8Array. The object is reset.
     *
     * @return the hash output
     */
    digest(): Uint8Array;
    /**
     * Input some bytes, then finalize the current hash computation
     * and return the hash value in a newly-allocated Uint8Array. The object
     * is reset.
     *
     * @param inbuf the input data
     * @return the hash output
     */
    digest(inbuf: Uint8Array): Uint8Array;
    /**
     * Finalize the current hash computation and store the hash value
     * in the provided output buffer. The len parameter
     * contains the maximum number of bytes that should be written;
     * no more bytes than the natural hash function output length will
     * be produced. If len is smaller than the natural
     * hash output length, the hash output is truncated to its first
     * len bytes. The object is reset.
     *
     * @param outbuf the output buffer
     * @param off the output offset within outbuf
     * @param len the requested hash output length (in bytes)
     * @return the number of bytes actually written in outbuf
     */
    digest(outbuf: Uint8Array, off: number, len: number): number;
    /**
     * Get the natural hash function output length (in bytes).
     *
     * @return the digest output length (in bytes)
     */
    getDigestLength(): number;
    /**
     * Reset the object: this makes it suitable for a new hash computation.
     * The current computation, if any, is discarded.
     */
    reset(): void;
    /**
     * Clone the current state. The returned object evolves independently
     * of this object.
     *
     * @return the clone
     */
    copy(): Digest;
    /**
     * Get the "block length", which is the hash function internal block
     * length, in bytes. The block length is used by some protocols, such as HMAC.
     *
     * @return the internal block length (in bytes), or 0 if it is not defined by the algorithm
     */
    getBlockLength(): number;
    /**
     * Return a string description of this object.
     *
     * @return the string description
     */
    toString(): string;
}
/**
 * This class is a template which can be used to implement hash
 * functions. It takes care of some of the API, and also provides an
 * internal data buffer whose length is equal to the hash function
 * internal block length.
 *
 * Classes which use this template MUST provide a working getBlockLength
 * method even before initialization (alternatively, they may define a custom
 * getInternalBlockLength which does not call getBlockLength. The getDigestLength should
 * also be operational from the beginning, but it is acceptable that it
 * returns 0 while the doInit method has not been called yet.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @version   $Revision: 229 $
 * @author    Thomas Pornin <thomas.pornin@cryptolog.com>
 */
declare abstract class DigestEngine implements Digest {
    protected abstract engineReset(): void;
    protected abstract processBlock(data: Uint8Array): void;
    protected abstract doPadding(buf: Uint8Array, off: number): void;
    protected abstract doInit(): void;
    digestLen: number;
    blockLen: number;
    inputLen: number;
    inputBuf: Uint8Array;
    outputBuf: Uint8Array;
    blockCount: bigint;
    constructor();
    private adjustDigestLen;
    digest(): Uint8Array;
    digest(input: Uint8Array): Uint8Array;
    digest(input: Uint8Array, offset: number, len: number): number;
    reset(): void;
    update(input: number): void;
    update(input: Uint8Array): void;
    update(input: Uint8Array, offset: number, len: number): void;
    protected getInternalBlockLength(): number;
    protected flush(): number;
    getBlockBuffer(): Uint8Array;
    getBlockCount(): bigint;
    protected copyState<T>(dest: DigestEngine): T;
    getDigestLength(): number;
    copy(): Digest;
    getBlockLength(): number;
    toString(): string;
}
/**
 * Implementation of Jenkins' Lookup2 hash function ("My Hash"), converted from the C code.
 * This is a non-cryptographic 32-bit hash for variable-length data.
 *
 * Removed streaming: Assume full data in updates; concatenate all input and compute in doPadding.
 * No getByte; use array indexing on concatenated data.
 * Output big-endian 4 bytes.
 * Block length arbitrary (64 bytes) for HMAC.
 */
export declare class Lookup2 extends DigestEngine {
    private fullData;
    private initval;
    state: number;
    setSeed(seed: number): void;
    protected doInit(): void;
    protected engineReset(): void;
    protected processBlock(data: Uint8Array): void;
    update(input: number): void;
    update(input: Uint8Array): void;
    update(input: Uint8Array, off: number, len: number): void;
    protected doPadding(buf: Uint8Array, off: number): void;
    getDigestLength(): number;
    getBlockLength(): number;
    protected getInternalBlockLength(): number;
    protected dup(): Lookup2;
    getAlgorithmName(): string;
}
/**
 * Implementation of Jenkins' Lookup3 hash function, converted from the C code.
 * This is a non-cryptographic 32-bit hash for variable-length data, improvement on Lookup2.
 * Uses hashlittle() for little-endian, as most modern systems are.
 *
 * Removed streaming: Assume full data in updates; concatenate all input and compute in doPadding.
 * No getByte; use array indexing on concatenated data.
 * Initial value is 0.
 * Output is big-endian 4 bytes.
 * Block length arbitrary (64 bytes) for HMAC.
 */
declare class Lookup3 {
    private pc;
    private pb;
    private bitLen;
    /**
     *
     * @param {number} pc primary initval
     * @param {number} pb secondary initval
     */
    constructor(bitLen?: number, pc?: number, pb?: number);
    update(message: InputData): number | bigint;
    digest(): number | bigint;
    private load32;
    private rot;
    private mix;
    private final;
    private hashlittle2;
}
declare class SpookyHash {
    sc_numVars: number;
    sc_blockSize: number;
    sc_bufSize: number;
    sc_const: bigint;
    hash1: bigint;
    hash2: bigint;
    constructor(seed1?: bigint, seed2?: bigint);
    update(message: InputData): void;
    private short_mix;
    private mix;
    private short_end;
    private short;
    private end_partial;
    private end;
    private hash128;
    private encodeBELong;
    digest(format: OutputFormat): InputData;
}
/**
 * Creates a One At A Time 32 bit number from message.
 *
 * @param {Uint8Array} key - Message to hash
 * @param {number} [startingValue=0] - For updating / seeding
 * @returns `number`
 */
export declare function JENKINS_OAAT(key: Uint8Array, startingValue?: number): number;
/**
 * Creates a Jenkin's Lookup2 (MyHash) 32 bit number from message.
 *
 * @param {InputData} message - Message to hash
 * @param {number?} startingValue - For updating / seeding
 * @returns `number`
 */
export declare function JENKINS_LOOKUP2(message: InputData, startingValue?: number): number;
/**
 * Creates a Jenkin's Lookup3 (MyHash) hash from message.
 *
 * @param {InputData} message - Message to hash
 * @param {number?} [outLen=32] - output bit length, 64 will return a bigint (default 32 bit number)
 * @param {number} primaryInitval - primary seed value
 * @param {number} secondaryInitval - secondary seed value (only used on 64 bit)
 * @returns `number|bigint`
 */
declare function JENKINS_LOOKUP3(message: InputData, outLen?: number, primaryInitval?: number, secondaryInitval?: number): number | bigint;
/**
 * Creates a Jenkin's Lookup3 (MyHash) 32 bit number from message.
 *
 * @param {InputData} message - Message to hash
 * @param {number} primaryInitval - primary seed value
 * @returns `number`
 */
declare function JENKINS_LOOKUP3_32(message: InputData, primaryInitval?: number): number;
/**
 * Creates a Jenkin's Lookup3 (MyHash) 64 bit bigint from message.
 *
 * @param {InputData} message - Message to hash
 * @param {number} primaryInitval - primary seed value
 * @param {number} secondaryInitval - secondary seed value
 * @returns `bigint`
 */
declare function JENKINS_LOOKUP3_64(message: InputData, primaryInitval?: number, secondaryInitval?: number): bigint;
/**
 * Creates a Jenkin's Spooky up to 16 byte hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {32|64|128} bitLength - return hash bitlength (default 128 or 16 bytes)
 * @param {bigint} seed1 - First seed value
 * @param {bigint} seed1 - Second seed value
 * @returns `string|Uint8Array|Buffer`
 */
export declare function JENKINS_SPOOKY(message: InputData, format?: OutputFormat, bitLength?: 32 | 64 | 128, seed1?: bigint, seed2?: bigint): string | Uint8Array | Buffer;
/**
 * Creates a Jenkin's Spooky 16 byte hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {bigint} seed1 - First seed value
 * @param {bigint} seed1 - Second seed value
 * @returns `string|Uint8Array|Buffer`
 */
export declare function JENKINS_SPOOKY_128(message: InputData, format?: OutputFormat, seed1?: bigint, seed2?: bigint): string | Uint8Array | Buffer;
/**
 * Creates a Jenkin's Spooky 8 byte hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {bigint} seed1 - First seed value
 * @param {bigint} seed1 - Second seed value
 * @returns `string|Uint8Array|Buffer`
 */
export declare function JENKINS_SPOOKY_64(message: InputData, format?: OutputFormat, seed1?: bigint, seed2?: bigint): string | Uint8Array | Buffer;
/**
 * Creates a Jenkin's Spooky 4 byte hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {bigint} seed1 - First seed value
 * @param {bigint} seed1 - Second seed value
 * @returns `string|Uint8Array|Buffer`
 */
export declare function JENKINS_SPOOKY_32(message: InputData, format: OutputFormat | undefined, bitLength: 32 | 64 | 28, seed1?: bigint, seed2?: bigint): string | Uint8Array | Buffer;
/**
 * Creates a Jenkin's One At A Time 32 bit number from message.
 *
 * @param {InputData} message - Message to hash
 * @returns `number`
 */
declare function JENKINS_ONEATATIME(message: InputData): number;
/**
 * Static class of all Jenkins functions
 */
export declare class JENKINS {
    static ONEATATIME: typeof JENKINS_ONEATATIME;
    static Lookup2: typeof Lookup2;
    static LOOKUP2: typeof JENKINS_LOOKUP2;
    static Lookup3: typeof Lookup3;
    static LOOKUP3: typeof JENKINS_LOOKUP3;
    static LOOKUP3_32: typeof JENKINS_LOOKUP3_32;
    static LOOKUP3_64: typeof JENKINS_LOOKUP3_64;
    static Spooky: typeof SpookyHash;
    static SPOOKY: typeof JENKINS_SPOOKY;
    static SPOOKY_32: typeof JENKINS_SPOOKY_32;
    static SPOOKY_64: typeof JENKINS_SPOOKY_64;
    static SPOOKY_128: typeof JENKINS_SPOOKY_128;
    /**
     * List of all hashes in class
     */
    static get FUNCTION_LIST(): string[];
}
export {};
//# sourceMappingURL=JENKINS.d.ts.map