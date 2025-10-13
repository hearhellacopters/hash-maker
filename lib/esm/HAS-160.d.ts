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
 * Implementation of the HAS-160 hash function, converted from the C code in https://github.com/rhash/RHash/blob/master/librhash/has160.c.
 * HAS-160 is a 160-bit cryptographic hash function derived from SHA-1 with modifications for improved security, used in Korean standards like KCDSA.
 *
 * This conversion uses unsigned 32-bit operations with >>> 0 for safety. The compression function follows the pseudocode description from https://www.randombit.net/has160.html,
 * which matches the structure in the C code. The output is big-endian bytes, as standard for hashes.
 *
 * Regarding initialization: All state setup is in engineReset(), called from the constructor via super(). Constants are fixed and don't depend on uninitialized state.
 */
export declare class Has160 extends DigestEngine {
    private h;
    protected doInit(): void;
    protected engineReset(): void;
    protected processBlock(data: Uint8Array): void;
    private ROTL32;
    protected doPadding(buf: Uint8Array, off: number): void;
    getDigestLength(): number;
    getBlockLength(): number;
    protected getInternalBlockLength(): number;
    protected dup(): DigestEngine;
    getAlgorithmName(): string;
}
/**
 * Creates a 20 byte HAS160 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function _HAS160(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 20 byte keyed HAS160 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - Hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAS160_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Static class of all HAS-160 functions and classes
 */
export declare class HAS160 {
    static Has160: typeof Has160;
    static HAS160: typeof _HAS160;
    static HAS160_HMAC: typeof HAS160_HMAC;
    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST(): string[];
}
export {};
//# sourceMappingURL=HAS-160.d.ts.map