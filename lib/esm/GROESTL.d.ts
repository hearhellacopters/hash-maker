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
/**
 * This class implements Groestl-224 and Groestl-256.
 *
 * <pre>
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
 * </pre>
 *
 * @version   $Revision: 256 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
declare abstract class GroestlSmallCore extends DigestEngine {
    private H;
    private G;
    private M;
    constructor();
    private static T0;
    private T1;
    private T2;
    private T3;
    private T4;
    private T5;
    private T6;
    private T7;
    getBlockLength(): number;
    protected copyState<T>(dst: GroestlSmallCore): T;
    protected engineReset(): void;
    protected doPadding(output: Uint8Array, outputOffset: number): void;
    protected doInit(): void;
    private encodeBELong;
    private decodeBELong;
    private static circularLeft;
    private doPermP;
    private doPermQ;
    /** @see DigestEngine */
    protected processBlock(data: Uint8Array): void;
    toString(): string;
}
/**
 * This class implements Groestl-384 and Groestl-512.
 *
 * <pre>
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
 * </pre>
 *
 * @version   $Revision: 256 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
declare abstract class GroestlBigCore extends DigestEngine {
    private H;
    private G;
    private M;
    /**
     * Create the object.
     */
    constructor();
    private static T0;
    private T1;
    private T2;
    private T3;
    private T4;
    private T5;
    private T6;
    private T7;
    /** @see Digest */
    getBlockLength(): number;
    /** @see DigestEngine */
    protected copyState<T>(dst: GroestlBigCore): T;
    /** @see DigestEngine */
    protected engineReset(): void;
    /** @see DigestEngine */
    protected doPadding(output: Uint8Array, outputOffset: number): void;
    /** @see DigestEngine */
    protected doInit(): void;
    /**
     * Encode the 64-bit word {@code val} into the array
     * {@code buf} at offset {@code off}, in big-endian
     * convention (most significant byte first).
     *
     * @param val   the value to encode
     * @param buf   the destination buffer
     * @param off   the destination offset
     */
    private encodeBELong;
    /**
     * Decode a 64-bit big-endian word from the array {@code buf}
     * at offset {@code off}.
     *
     * @param buf   the source buffer
     * @param off   the source offset
     * @return  the decoded value
     */
    private decodeBELong;
    /**
     * Perform a circular rotation by {@code n} to the left
     * of the 64-bit word {@code x}. The {@code n} parameter
     * must lie between 1 and 63 (inclusive).
     *
     * @param x   the value to rotate
     * @param n   the rotation count (between 1 and 63)
     * @return  the rotated value
    */
    private static circularLeft;
    private doPermP;
    private doPermQ;
    /** @see DigestEngine */
    protected processBlock(data: Uint8Array): void;
    /** @see Digest */
    toString(): string;
}
/**
 * <p>This class implements the Groestl-224 digest algorithm under the
 * {@link Digest} API.</p>
 *
 * <pre>
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
 * </pre>
 *
 * @version   $Revision: 198 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
export declare class Groestl224 extends GroestlSmallCore {
    /**
     * Create the engine.
     */
    constructor();
    /** @see Digest */
    getDigestLength(): number;
    /** @see Digest */
    copy(): Digest;
}
/**
 * <p>This class implements the Groestl-256 digest algorithm under the
 * {@link Digest} API.</p>
 *
 * <pre>
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
 * </pre>
 *
 * @version   $Revision: 198 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
export declare class Groestl256 extends GroestlSmallCore {
    /**
     * Create the engine.
     */
    constructor();
    /** @see Digest */
    getDigestLength(): number;
    /** @see Digest */
    copy(): Digest;
}
/**
 * <p>This class implements the Groestl-384 digest algorithm under the
 * {@link Digest} API.</p>
 *
 * <pre>
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
 * </pre>
 *
 * @version   $Revision: 198 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
export declare class Groestl384 extends GroestlBigCore {
    /**
     * Create the engine.
     */
    constructor();
    /** @see Digest */
    getDigestLength(): number;
    /** @see Digest */
    copy(): Digest;
}
/**
 * <p>This class implements the Groestl-512 digest algorithm under the
 * {@link Digest} API.</p>
 *
 * <pre>
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
 * </pre>
 *
 * @version   $Revision: 198 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
export declare class Groestl512 extends GroestlBigCore {
    /**
     * Create the engine.
     */
    constructor();
    /** @see Digest */
    getDigestLength(): number;
    /** @see Digest */
    copy(): Digest;
}
type InputData = string | Uint8Array | Buffer;
type OutputFormat = 'hex' | 'array' | 'buffer';
/**
 * Creates a vary byte length Grøstl of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {224 | 256 | 384 | 512} bitLen - length of hash (default 512 bits AKA 64 bytes)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function _GROESTL(message: InputData, bitLen?: 224 | 256 | 384 | 512, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a vary byte length keyed Grøstl of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {224 | 256 | 384 | 512} bitLen - length of hash (default 512 bits AKA 64 bytes)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function GROESTL_HMAC(message: InputData, key: InputData, bitLen?: 224 | 256 | 384 | 512, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 28 byte Grøstl of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function GROESTL224(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 28 byte keyed Grøstl of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function GROESTL224_HMAC(message: InputData, key?: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 32 byte Grøstl of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function GROESTL256(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 32 byte keyed Grøstl of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function GROESTL256_HMAC(message: InputData, key?: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 48 byte Grøstl of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function GROESTL384(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 48 byte keyed Grøstl of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function GROESTL384_HMAC(message: InputData, key?: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 64 byte Grøstl of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function GROESTL512(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 64 byte keyed Grøstl of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function GROESTL512_HMAC(message: InputData, key?: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Static class of all Grøstl functions and classes
 */
export declare class GROESTL {
    static GROESTL: typeof _GROESTL;
    static Groestl224: typeof Groestl224;
    static GROESTL224: typeof GROESTL224;
    static GROESTL224_HMAC: typeof GROESTL224_HMAC;
    static Groestl256: typeof Groestl256;
    static GROESTL256: typeof GROESTL256;
    static GROESTL256_HMAC: typeof GROESTL256_HMAC;
    static Groestl384: typeof Groestl384;
    static GROESTL384: typeof GROESTL384;
    static GROESTL384_HMAC: typeof GROESTL384_HMAC;
    static Groestl512: typeof Groestl512;
    static GROESTL512: typeof GROESTL512;
    static GROESTL512_HMAC: typeof GROESTL512_HMAC;
    static GROESTL_HMAC: typeof GROESTL_HMAC;
    /**
     * List of all hashes in class
     */
    static get FUNCTION_LIST(): string[];
}
export {};
//# sourceMappingURL=GROESTL.d.ts.map