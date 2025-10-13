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
 * This class implements Luffa-224 and Luffa-256.
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
 * @version   $Revision: 240 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
declare abstract class LuffaSmallCore extends DigestEngine {
    private static IV;
    private static RC00;
    private static RC04;
    private static RC10;
    private static RC14;
    private static RC20;
    private static RC24;
    private V;
    private tmpBuf;
    constructor();
    /** @see DigestEngine */
    getInternalBlockLength(): number;
    /** @see Digest */
    getBlockLength(): number;
    /** @see DigestEngine */
    protected copyState<T>(dst: LuffaSmallCore): T;
    /** @see DigestEngine */
    protected engineReset(): void;
    /** @see DigestEngine */
    protected doPadding(output: Uint8Array, outputOffset: number): void;
    /** @see DigestEngine */
    protected doInit(): void;
    /**
     * Encode the 32-bit word {@code val} into the array
     * {@code buf} at offset {@code off}, in big-endian
     * convention (most significant byte first).
     *
     * @param val   the value to encode
     * @param buf   the destination buffer
     * @param off   the destination offset
     */
    private encodeBEInt;
    /**
     * Decode a 32-bit big-endian word from the array {@code buf}
     * at offset {@code off}.
     *
     * @param buf   the source buffer
     * @param off   the source offset
     * @return  the decoded value
     */
    private decodeBEInt;
    /** @see DigestEngine */
    protected processBlock(data: Uint8Array): void;
    /** @see Digest */
    toString(): string;
}
/**
 * <p>This class implements Luffa-384 digest algorithm under the
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
 * @version   $Revision: 235 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
export declare class Luffa384 extends DigestEngine {
    private static IV;
    private static RC00;
    private static RC04;
    private static RC10;
    private static RC14;
    private static RC20;
    private static RC24;
    private static RC30;
    private static RC34;
    private V;
    private tmpBuf;
    /**
     * Create the engine.
     */
    constructor();
    /** @see DigestEngine */
    getInternalBlockLength(): number;
    /** @see Digest */
    getBlockLength(): number;
    /** @see Digest */
    getDigestLength(): number;
    /** @see Digest */
    copy(): Digest;
    /** @see DigestEngine */
    protected copyState<T>(dst: Luffa384): T;
    /** @see DigestEngine */
    protected engineReset(): void;
    /** @see DigestEngine */
    protected doPadding(output: Uint8Array, outputOffset: number): void;
    /** @see DigestEngine */
    protected doInit(): void;
    /**
     * Encode the 32-bit word {@code val} into the array
     * {@code buf} at offset {@code off}, in big-endian
     * convention (most significant byte first).
     *
     * @param val   the value to encode
     * @param buf   the destination buffer
     * @param off   the destination offset
     */
    private encodeBEInt;
    /**
     * Decode a 32-bit big-endian word from the array {@code buf}
     * at offset {@code off}.
     *
     * @param buf   the source buffer
     * @param off   the source offset
     * @return  the decoded value
     */
    private decodeBEInt;
    /** @see DigestEngine */
    protected processBlock(data: Uint8Array): void;
    /** @see Digest */
    toString(): string;
}
/**
 * <p>This class implements Luffa-512 digest algorithm under the
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
 * @version   $Revision: 235 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
export declare class Luffa512 extends DigestEngine {
    private static IV;
    private static RC00;
    private static RC04;
    private static RC10;
    private static RC14;
    private static RC20;
    private static RC24;
    private static RC30;
    private static RC34;
    private static RC40;
    private static RC44;
    private V;
    private tmpBuf;
    /**
     * Create the engine.
     */
    constructor();
    /** @see DigestEngine */
    getInternalBlockLength(): number;
    /** @see Digest */
    getBlockLength(): number;
    /** @see Digest */
    getDigestLength(): number;
    /** @see Digest */
    copy(): Digest;
    /** @see DigestEngine */
    protected copyState<T>(dst: Luffa512): T;
    /** @see DigestEngine */
    protected engineReset(): void;
    /** @see DigestEngine */
    protected doPadding(out: Uint8Array, off: number): void;
    /** @see DigestEngine */
    protected doInit(): void;
    /**
     * Encode the 32-bit word {@code val} into the array
     * {@code buf} at offset {@code off}, in big-endian
     * convention (most significant byte first).
     *
     * @param val   the value to encode
     * @param buf   the destination buffer
     * @param off   the destination offset
     */
    private encodeBEInt;
    /**
     * Decode a 32-bit big-endian word from the array {@code buf}
     * at offset {@code off}.
     *
     * @param buf   the source buffer
     * @param off   the source offset
     * @return  the decoded value
     */
    private decodeBEInt;
    /** @see DigestEngine */
    protected processBlock(data: Uint8Array): void;
    /** @see Digest */
    toString(): string;
}
/**
 * <p>This class implements the Luffa-224 digest algorithm under the
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
 * @version   $Revision: 156 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
export declare class Luffa224 extends LuffaSmallCore {
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
 * <p>This class implements the Luffa-256 digest algorithm under the
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
 * @version   $Revision: 156 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
export declare class Luffa256 extends LuffaSmallCore {
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
 * Creates a vary byte length LUFFA of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {224 | 256 | 384 | 512} bitLen - length of hash (default 512 bits AKA 64 bytes)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function _LUFFA(message: InputData, bitLen?: 224 | 256 | 384 | 512, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a vary byte length keyed LUFFA of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {224 | 256 | 384 | 512} bitLen - length of hash (default 512 bits AKA 64 bytes)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function LUFFA_HMAC(message: InputData, key: InputData, bitLen?: 224 | 256 | 384 | 512, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 28 byte LUFFA of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function LUFFA224(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 28 byte keyed LUFFA of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function LUFFA224_HMAC(message: InputData, key?: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 32 byte LUFFA of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function LUFFA256(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 32 byte keyed LUFFA of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function LUFFA256_HMAC(message: InputData, key?: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 48 byte LUFFA of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function LUFFA384(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 48 byte keyed LUFFA of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function LUFFA384_HMAC(message: InputData, key?: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 64 byte LUFFA of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function LUFFA512(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 64 byte keyed LUFFA of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function LUFFA512_HMAC(message: InputData, key?: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Static class of all LUFFA functions and classes
 */
export declare class LUFFA {
    static LUFFA: typeof _LUFFA;
    static Luffa256: typeof Luffa256;
    static LUFFA256: typeof LUFFA256;
    static LUFFA256_HMAC: typeof LUFFA256_HMAC;
    static Luffa224: typeof Luffa224;
    static LUFFA224: typeof LUFFA224;
    static LUFFA224_HMAC: typeof LUFFA224_HMAC;
    static Luffa384: typeof Luffa384;
    static LUFFA384: typeof LUFFA384;
    static LUFFA384_HMAC: typeof LUFFA384_HMAC;
    static Luffa512: typeof Luffa512;
    static LUFFA512: typeof LUFFA512;
    static LUFFA512_HMAC: typeof LUFFA512_HMAC;
    static LUFFA_HMAC: typeof LUFFA_HMAC;
    /**
     * List of all hashes in class
     */
    static get FUNCTION_LIST(): string[];
}
export {};
//# sourceMappingURL=LUFFA.d.ts.map