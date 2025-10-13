/// <reference types="node" />
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
type InputData = string | Uint8Array | Buffer;
type OutputFormat = 'hex' | 'array' | 'buffer';
/**
 * Implementation of the 32-bit FNV-0 hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 * FNV-0 is historic and deprecated, equivalent to FNV-1 with initial hash = 0.
 *
 * The repository provides utilities and library for FNV hashes, but the core algorithm is standard and implemented here faithfully.
 *
 * For HMAC compatibility, block length is set to 64 bytes (as per FNV standard recommendation).
 */
export declare class Fnv0_32 extends DigestEngine {
    private static readonly PRIME;
    private static readonly INIT;
    private static readonly MASK;
    private hash;
    protected doInit(): void;
    protected engineReset(): void;
    protected processBlock(data: Uint8Array): void;
    protected doPadding(buf: Uint8Array, off: number): void;
    getDigestLength(): number;
    getBlockLength(): number;
    protected getInternalBlockLength(): number;
    protected dup(): DigestEngine;
    getAlgorithmName(): string;
}
/**
 * Implementation of the 64-bit FNV-0 hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 * FNV-0 is historic and deprecated, equivalent to FNV-1 with initial hash = 0.
 *
 * The repository provides utilities and library for FNV hashes, but the core algorithm is standard and implemented here faithfully.
 * For HMAC compatibility, block length is set to 128 bytes (as per FNV standard recommendation).
 */
export declare class Fnv0_64 extends DigestEngine {
    private static readonly PRIME;
    private static readonly INIT;
    private static readonly MASK;
    private hash;
    protected doInit(): void;
    protected engineReset(): void;
    protected processBlock(data: Uint8Array): void;
    protected doPadding(buf: Uint8Array, off: number): void;
    getDigestLength(): number;
    getBlockLength(): number;
    protected getInternalBlockLength(): number;
    protected dup(): DigestEngine;
    getAlgorithmName(): string;
}
/**
 * Implementation of the 128-bit FNV-0 hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 * FNV-0 is historic and deprecated, equivalent to FNV-1 with initial hash = 0.
 *
 * Parameters from http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
 *
 * For HMAC compatibility, block length is set to 256 bytes (scaled from smaller variants).
 */
export declare class Fnv0_128 extends DigestEngine {
    private static readonly PRIME;
    private static readonly INIT;
    private static readonly MASK;
    private hash;
    protected doInit(): void;
    protected engineReset(): void;
    protected processBlock(data: Uint8Array): void;
    protected doPadding(buf: Uint8Array, off: number): void;
    getDigestLength(): number;
    getBlockLength(): number;
    protected getInternalBlockLength(): number;
    protected dup(): DigestEngine;
    getAlgorithmName(): string;
}
/**
 * Implementation of the 256-bit FNV-0 hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 * FNV-0 is historic and deprecated, equivalent to FNV-1 with initial hash = 0.
 *
 * Parameters from http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
 *
 * For HMAC compatibility, block length is set to 512 bytes (scaled from smaller variants).
 */
export declare class Fnv0_256 extends DigestEngine {
    private static readonly PRIME;
    private static readonly INIT;
    private static readonly MASK;
    private hash;
    protected doInit(): void;
    protected engineReset(): void;
    protected processBlock(data: Uint8Array): void;
    protected doPadding(buf: Uint8Array, off: number): void;
    getDigestLength(): number;
    getBlockLength(): number;
    protected getInternalBlockLength(): number;
    protected dup(): DigestEngine;
    getAlgorithmName(): string;
}
/**
 * Implementation of the 512-bit FNV-0 hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 * FNV-0 is historic and deprecated, equivalent to FNV-1 with initial hash = 0.
 *
 * Parameters from http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
 *
 * For HMAC compatibility, block length is set to 1024 bytes (scaled from smaller variants).
 */
export declare class Fnv0_512 extends DigestEngine {
    private static readonly PRIME;
    private static readonly INIT;
    private static readonly MASK;
    private hash;
    protected doInit(): void;
    protected engineReset(): void;
    protected processBlock(data: Uint8Array): void;
    protected doPadding(buf: Uint8Array, off: number): void;
    getDigestLength(): number;
    getBlockLength(): number;
    protected getInternalBlockLength(): number;
    protected dup(): DigestEngine;
    getAlgorithmName(): string;
}
/**
 * Implementation of the 1024-bit FNV-0 hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 * FNV-0 is historic and deprecated, equivalent to FNV-1 with initial hash = 0.
 *
 * Parameters from http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
 *
 * For HMAC compatibility, block length is set to 2048 bytes (scaled from smaller variants).
 */
export declare class Fnv0_1024 extends DigestEngine {
    private static readonly PRIME;
    private static readonly INIT;
    private static readonly MASK;
    private hash;
    protected doInit(): void;
    protected engineReset(): void;
    protected processBlock(data: Uint8Array): void;
    protected doPadding(buf: Uint8Array, off: number): void;
    getDigestLength(): number;
    getBlockLength(): number;
    protected getInternalBlockLength(): number;
    protected dup(): DigestEngine;
    getAlgorithmName(): string;
}
/**
 * Implementation of the 32-bit FNV-1 hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 *
 * The repository provides utilities and library for FNV hashes, but the core algorithm is standard and implemented here faithfully.
 * For HMAC compatibility, block length is set to 64 bytes.
 */
export declare class Fnv1_32 extends DigestEngine {
    private static readonly PRIME;
    private static readonly INIT;
    private static readonly MASK;
    private hash;
    protected doInit(): void;
    protected engineReset(): void;
    protected processBlock(data: Uint8Array): void;
    protected doPadding(buf: Uint8Array, off: number): void;
    getDigestLength(): number;
    getBlockLength(): number;
    protected getInternalBlockLength(): number;
    protected dup(): DigestEngine;
    getAlgorithmName(): string;
}
/**
 * Implementation of the 64-bit FNV-1 hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 *
 * The repository provides utilities and library for FNV hashes, but the core algorithm is standard and implemented here faithfully.
 * For HMAC compatibility, block length is set to 128 bytes.
 */
export declare class Fnv1_64 extends DigestEngine {
    private static readonly PRIME;
    private static readonly INIT;
    private static readonly MASK;
    private hash;
    protected doInit(): void;
    protected engineReset(): void;
    protected processBlock(data: Uint8Array): void;
    protected doPadding(buf: Uint8Array, off: number): void;
    getDigestLength(): number;
    getBlockLength(): number;
    protected getInternalBlockLength(): number;
    protected dup(): DigestEngine;
    getAlgorithmName(): string;
}
/**
 * Implementation of the 128-bit FNV-1 hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 *
 * Parameters from http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
 *
 * For HMAC compatibility, block length is set to 256 bytes (scaled from smaller variants).
 */
export declare class Fnv1_128 extends DigestEngine {
    private static readonly PRIME;
    private static readonly INIT;
    private static readonly MASK;
    private hash;
    protected doInit(): void;
    protected engineReset(): void;
    protected processBlock(data: Uint8Array): void;
    protected doPadding(buf: Uint8Array, off: number): void;
    getDigestLength(): number;
    getBlockLength(): number;
    protected getInternalBlockLength(): number;
    protected dup(): DigestEngine;
    getAlgorithmName(): string;
}
/**
 * Implementation of the 256-bit FNV-1 hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 *
 * Parameters from http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
 *
 * For HMAC compatibility, block length is set to 512 bytes (scaled from smaller variants).
 */
export declare class Fnv1_256 extends DigestEngine {
    private static readonly PRIME;
    private static readonly INIT;
    private static readonly MASK;
    private hash;
    protected doInit(): void;
    protected engineReset(): void;
    protected processBlock(data: Uint8Array): void;
    protected doPadding(buf: Uint8Array, off: number): void;
    getDigestLength(): number;
    getBlockLength(): number;
    protected getInternalBlockLength(): number;
    protected dup(): DigestEngine;
    getAlgorithmName(): string;
}
/**
 * Implementation of the 512-bit FNV-1 hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 *
 * Parameters from http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
 *
 * For HMAC compatibility, block length is set to 1024 bytes (scaled from smaller variants).
 */
export declare class Fnv1_512 extends DigestEngine {
    private static readonly PRIME;
    private static readonly INIT;
    private static readonly MASK;
    private hash;
    protected doInit(): void;
    protected engineReset(): void;
    protected processBlock(data: Uint8Array): void;
    protected doPadding(buf: Uint8Array, off: number): void;
    getDigestLength(): number;
    getBlockLength(): number;
    protected getInternalBlockLength(): number;
    protected dup(): DigestEngine;
    getAlgorithmName(): string;
}
/**
 * Implementation of the 1024-bit FNV-1 hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 *
 * Parameters from http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
 *
 * For HMAC compatibility, block length is set to 2048 bytes (scaled from smaller variants).
 */
export declare class Fnv1_1024 extends DigestEngine {
    private static readonly PRIME;
    private static readonly INIT;
    private static readonly MASK;
    private hash;
    protected doInit(): void;
    protected engineReset(): void;
    protected processBlock(data: Uint8Array): void;
    protected doPadding(buf: Uint8Array, off: number): void;
    getDigestLength(): number;
    getBlockLength(): number;
    protected getInternalBlockLength(): number;
    protected dup(): DigestEngine;
    getAlgorithmName(): string;
}
/**
 * Implementation of the 32-bit FNV-1a hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 * FNV-1a is the recommended variant for better hash distribution.
 *
 * The repository provides utilities and library for FNV hashes, but the core algorithm is standard and implemented here faithfully.
 * For HMAC compatibility, block length is set to 64 bytes.
 */
export declare class Fnv1a_32 extends DigestEngine {
    private static readonly PRIME;
    private static readonly INIT;
    private static readonly MASK;
    private hash;
    protected doInit(): void;
    protected engineReset(): void;
    protected processBlock(data: Uint8Array): void;
    protected doPadding(buf: Uint8Array, off: number): void;
    getDigestLength(): number;
    getBlockLength(): number;
    protected getInternalBlockLength(): number;
    protected dup(): DigestEngine;
    getAlgorithmName(): string;
}
/**
 * Implementation of the 64-bit FNV-1a hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 * FNV-1a is the recommended variant for better hash distribution.
 *
 * The repository provides utilities and library for FNV hashes, but the core algorithm is standard and implemented here faithfully.
 * For HMAC compatibility, block length is set to 128 bytes.
 */
export declare class Fnv1a_64 extends DigestEngine {
    private static readonly PRIME;
    private static readonly INIT;
    private static readonly MASK;
    private hash;
    protected doInit(): void;
    protected engineReset(): void;
    protected processBlock(data: Uint8Array): void;
    protected doPadding(buf: Uint8Array, off: number): void;
    getDigestLength(): number;
    getBlockLength(): number;
    protected getInternalBlockLength(): number;
    protected dup(): DigestEngine;
    getAlgorithmName(): string;
}
/**
 * Implementation of the 128-bit FNV-1a hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 * FNV-1a is the recommended variant for better hash distribution.
 *
 * Parameters from http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
 *
 * For HMAC compatibility, block length is set to 256 bytes (scaled from smaller variants).
 */
export declare class Fnv1a_128 extends DigestEngine {
    private static readonly PRIME;
    private static readonly INIT;
    private static readonly MASK;
    private hash;
    protected doInit(): void;
    protected engineReset(): void;
    protected processBlock(data: Uint8Array): void;
    protected doPadding(buf: Uint8Array, off: number): void;
    getDigestLength(): number;
    getBlockLength(): number;
    protected getInternalBlockLength(): number;
    protected dup(): DigestEngine;
    getAlgorithmName(): string;
}
/**
 * Implementation of the 256-bit FNV-1a hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 * FNV-1a is the recommended variant for better hash distribution.
 *
 * Parameters from http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
 *
 * For HMAC compatibility, block length is set to 512 bytes (scaled from smaller variants).
 */
export declare class Fnv1a_256 extends DigestEngine {
    private static readonly PRIME;
    private static readonly INIT;
    private static readonly MASK;
    private hash;
    protected doInit(): void;
    protected engineReset(): void;
    protected processBlock(data: Uint8Array): void;
    protected doPadding(buf: Uint8Array, off: number): void;
    getDigestLength(): number;
    getBlockLength(): number;
    protected getInternalBlockLength(): number;
    protected dup(): DigestEngine;
    getAlgorithmName(): string;
}
/**
 * Implementation of the 512-bit FNV-1a hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 * FNV-1a is the recommended variant for better hash distribution.
 *
 * Parameters from http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
 *
 * For HMAC compatibility, block length is set to 1024 bytes (scaled from smaller variants).
 */
export declare class Fnv1a_512 extends DigestEngine {
    private static readonly PRIME;
    private static readonly INIT;
    private static readonly MASK;
    private hash;
    protected doInit(): void;
    protected engineReset(): void;
    protected processBlock(data: Uint8Array): void;
    protected doPadding(buf: Uint8Array, off: number): void;
    getDigestLength(): number;
    getBlockLength(): number;
    protected getInternalBlockLength(): number;
    protected dup(): DigestEngine;
    getAlgorithmName(): string;
}
/**
 * Implementation of the 1024-bit FNV-1a hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 * FNV-1a is the recommended variant for better hash distribution.
 *
 * Parameters from http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
 *
 * For HMAC compatibility, block length is set to 2048 bytes (scaled from smaller variants).
 */
export declare class Fnv1a_1024 extends DigestEngine {
    private static readonly PRIME;
    private static readonly INIT;
    private static readonly MASK;
    private hash;
    protected doInit(): void;
    protected engineReset(): void;
    protected processBlock(data: Uint8Array): void;
    protected doPadding(buf: Uint8Array, off: number): void;
    getDigestLength(): number;
    getBlockLength(): number;
    protected getInternalBlockLength(): number;
    protected dup(): DigestEngine;
    getAlgorithmName(): string;
}
declare class Fnv {
    class: Fnv0_32 | Fnv0_64 | Fnv0_128 | Fnv0_256 | Fnv0_512 | Fnv0_1024 | Fnv1_32 | Fnv1_64 | Fnv1_128 | Fnv1_256 | Fnv1_512 | Fnv1_1024 | Fnv1a_32 | Fnv1a_64 | Fnv1a_128 | Fnv1a_256 | Fnv1a_512 | Fnv1a_1024;
    constructor(type?: "FNV0_32" | "FNV0_64" | "FNV0_128" | "FNV0_256" | "FNV0_512" | "FNV0_1024" | "FNV1_32" | "FNV1_64" | "FNV1_128" | "FNV1_256" | "FNV1_512" | "FNV1_1024" | "FNV1A_32" | "FNV1A_64" | "FNV1A_128" | "FNV1A_256" | "FNV1A_512" | "FNV1A_1024");
    update(message: InputData): void;
    digest(format: OutputFormat): string | Uint8Array | Buffer;
}
/**
 * Creates a FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param message - Message to hash
 * @param {32|64|128|256|512|1024} bitLen - Hash length (default 64 or 8 bytes)
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV0(message: InputData, bitLen?: 32 | 64 | 128 | 256 | 512 | 1024, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a keyed FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {32|64|128|256|512|1024} bitLen - Hash length (default 64 or 8 bytes)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV0_HMAC(message: InputData, key?: InputData, bitLen?: 32 | 64 | 128 | 256 | 512 | 1024, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 4 byte FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV0_32(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 4 byte keyed FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV0_32_HMAC(message: InputData, key?: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 8 byte FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV0_64(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 8 byte keyed FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV0_64_HMAC(message: InputData, key?: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 16 byte FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV0_128(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 16 byte keyed FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV0_128_HMAC(message: InputData, key?: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 32 byte FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV0_256(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 32 byte keyed FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV0_256_HMAC(message: InputData, key?: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 64 byte FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV0_512(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 64 byte keyed FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV0_512_HMAC(message: InputData, key?: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 128 byte FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV0_1024(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 128 byte keyed FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV0_1024_HMAC(message: InputData, key?: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param message - Message to hash
 * @param {32|64|128|256|512|1024} bitLen - Hash length (default 64 or 8 bytes)
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV1(message: InputData, bitLen?: 32 | 64 | 128 | 256 | 512 | 1024, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a keyed FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {32|64|128|256|512|1024} bitLen - Hash length (default 64 or 8 bytes)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV1_HMAC(message: InputData, key?: InputData, bitLen?: 32 | 64 | 128 | 256 | 512 | 1024, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 4 byte FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV1_32(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 4 byte keyed FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV1_32_HMAC(message: InputData, key?: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 8 byte FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV1_64(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 8 byte keyed FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV1_64_HMAC(message: InputData, key?: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 16 byte FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV1_128(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 16 byte keyed FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV1_128_HMAC(message: InputData, key?: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 32 byte FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV1_256(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 32 byte keyed FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV1_256_HMAC(message: InputData, key?: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 64 byte FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV1_512(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 64 byte keyed FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV1_512_HMAC(message: InputData, key?: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 128 byte FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV1_1024(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 128 byte keyed FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV1_1024_HMAC(message: InputData, key?: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a FNV1A of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param message - Message to hash
 * @param {32|64|128|256|512|1024} bitLen - Hash length (default 64 or 8 bytes)
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV1A(message: InputData, bitLen?: 32 | 64 | 128 | 256 | 512 | 1024, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a keyed FNV1A of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {32|64|128|256|512|1024} bitLen - Hash length (default 64 or 8 bytes)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV1A_HMAC(message: InputData, key?: InputData, bitLen?: 32 | 64 | 128 | 256 | 512 | 1024, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 4 byte FNV1a of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV1A_32(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 4 byte keyed FNV1a of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV1A_32_HMAC(message: InputData, key?: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 8 byte FNV1a of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV1A_64(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 8 byte keyed FNV1a of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV1A_64_HMAC(message: InputData, key?: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 16 byte FNV1a of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV1A_128(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 16 byte keyed FNV1a of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV1A_128_HMAC(message: InputData, key?: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 32 byte FNV1a of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV1A_256(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 32 byte keyed FNV1a of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV1A_256_HMAC(message: InputData, key?: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 64 byte FNV1a of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV1A_512(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 64 byte keyed FNV1a of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV1A_512_HMAC(message: InputData, key?: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 128 byte FNV1a of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV1A_1024(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 128 byte keyed FNV1a of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV1A_1024_HMAC(message: InputData, key?: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a FNV hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {0 | "0" | 1 | "1" | "1A"} type - FNV type (default 1A)
 * @param {32|64|128|256|512|1024} bitLen - Hash length (default 64 or 8 bytes)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function _FNV(message: InputData, type?: 0 | "0" | 1 | "1" | "1A", bitLen?: 32 | 64 | 128 | 256 | 512 | 1024, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a keyed FNV hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {0 | "0" | 1 | "1" | "1A"} type - FNV type (default 1A)
 * @param {32|64|128|256|512|1024} bitLen - Hash length (default 64 or 8 bytes)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function FNV_HMAC(message: InputData, key?: InputData, type?: 0 | "0" | 1 | "1" | "1A", bitLen?: 32 | 64 | 128 | 256 | 512 | 1024, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Static class of all Fowler/Noll/Vo FNV functions and classes
 */
export declare class FNV {
    static Fnv: typeof Fnv;
    static FNV: typeof _FNV;
    static FNV0: typeof FNV0;
    static FNV0_HMAC: typeof FNV0_HMAC;
    static FNV0_32_HMAC: typeof FNV0_32_HMAC;
    static FNV0_32: typeof FNV0_32;
    static FNV0_64_HMAC: typeof FNV0_64_HMAC;
    static FNV0_64: typeof FNV0_64;
    static FNV0_128_HMAC: typeof FNV0_128_HMAC;
    static FNV0_128: typeof FNV0_128;
    static FNV0_256_HMAC: typeof FNV0_256_HMAC;
    static FNV0_256: typeof FNV0_256;
    static FNV0_512_HMAC: typeof FNV0_512_HMAC;
    static FNV0_512: typeof FNV0_512;
    static FNV0_1024_HMAC: typeof FNV0_1024_HMAC;
    static FNV0_1024: typeof FNV0_1024;
    static FNV1: typeof FNV1;
    static FNV1_HMAC: typeof FNV1_HMAC;
    static FNV1_32_HMAC: typeof FNV1_32_HMAC;
    static FNV1_32: typeof FNV1_32;
    static FNV1_64_HMAC: typeof FNV1_64_HMAC;
    static FNV1_64: typeof FNV1_64;
    static FNV1_128_HMAC: typeof FNV1_128_HMAC;
    static FNV1_128: typeof FNV1_128;
    static FNV1_256_HMAC: typeof FNV1_256_HMAC;
    static FNV1_256: typeof FNV1_256;
    static FNV1_512_HMAC: typeof FNV1_512_HMAC;
    static FNV1_512: typeof FNV1_512;
    static FNV1_1024_HMAC: typeof FNV1_1024_HMAC;
    static FNV1_1024: typeof FNV1_1024;
    static FNV1A: typeof FNV1A;
    static FNV1A_HMAC: typeof FNV1A_HMAC;
    static FNV1A_32_HMAC: typeof FNV1A_32_HMAC;
    static FNV1A_32: typeof FNV1A_32;
    static FNV1A_64_HMAC: typeof FNV1A_64_HMAC;
    static FNV1A_64: typeof FNV1A_64;
    static FNV1A_128_HMAC: typeof FNV1A_128_HMAC;
    static FNV1A_128: typeof FNV1A_128;
    static FNV1A_256_HMAC: typeof FNV1A_256_HMAC;
    static FNV1A_256: typeof FNV1A_256;
    static FNV1A_512_HMAC: typeof FNV1A_512_HMAC;
    static FNV1A_512: typeof FNV1A_512;
    static FNV1A_1024_HMAC: typeof FNV1A_1024_HMAC;
    static FNV1A_1024: typeof FNV1A_1024;
    static FNV_HMAC: typeof FNV_HMAC;
    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST(): string[];
}
export {};
//# sourceMappingURL=FNV.d.ts.map