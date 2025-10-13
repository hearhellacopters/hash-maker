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
 * This class implements the HAVAL digest algorithm, which accepts 15
 * variants based on the number of passes and digest output.
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
 * @version   $Revision: 214 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
declare abstract class HAVALCore extends DigestEngine {
    /**
     * Create the object.
     *
     * @param outputLength   output length (in bits)
     * @param passes         number of passes (3, 4 or 5)
     */
    constructor(outputLength: number, passes: number);
    /**
     * Output length, in 32-bit words (4, 5, 6, 7, or 8).
     */
    private olen;
    /**
     * Number of passes (3, 4 or 5).
     */
    private passes;
    /**
     * Padding buffer.
     */
    private padBuf;
    /**
     * State variables.
     */
    private s;
    /**
     * Pre-allocated array for input words.
     */
    private inw;
    /** @see DigestEngine */
    protected copyState<T>(dst: HAVALCore): T;
    /** @see Digest */
    getBlockLength(): number;
    /** @see DigestEngine */
    protected engineReset(): void;
    /** @see DigestEngine */
    protected doPadding(output: Uint8Array, outputOffset: number): void;
    /** @see DigestEngine */
    protected doInit(): void;
    private static K2;
    private static K3;
    private static K4;
    private static K5;
    private static wp2;
    private static wp3;
    private static wp4;
    private static wp5;
    /**
     * Encode the 32-bit word {@code val} into the array
     * {@code buf} at offset {@code buf}, in little-endian
     * convention (least significant byte first).
     *
     * @param val   the value to encode
     * @param buf   the destination buffer
     * @param off   the destination offset
     */
    private encodeLEInt;
    /**
     * Decode a 32-bit little-endian word from the array {@code buf}
     * at offset {@code off}.
     *
     * @param buf   the source buffer
     * @param off   the source offset
     * @return  the decoded value
     */
    private decodeLEInt;
    /**
     * Circular rotation of a 32-bit word to the left. The rotation
     * count must lie between 1 and 31 (inclusive).
     *
     * @param x   the value to rotate
     * @param n   the rotation count
     * @return  the rotated value
     */
    private circularLeft;
    /** @see DigestEngine */
    protected processBlock(data: Uint8Array): void;
    private F1;
    private F2;
    private F3;
    private F4;
    private F5;
    private pass31;
    private pass32;
    private pass33;
    private pass41;
    private pass42;
    private pass43;
    private pass44;
    private pass51;
    private pass52;
    private pass53;
    private pass54;
    private pass55;
    private mix128;
    private mix160_0;
    private mix160_1;
    private mix160_2;
    private mix160_3;
    private mix160_4;
    private mix192_0;
    private mix192_1;
    private mix192_2;
    private mix192_3;
    private mix192_4;
    private mix192_5;
    private write128;
    private write160;
    private write192;
    private write224;
    private write256;
    private writeOutput;
    /** @see Digest */
    toString(): string;
}
/**
 * This class implements HAVAL with 128-bit output and 3 passes.
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
export declare class Haval128_3 extends HAVALCore {
    /**
     * Create the object.
     */
    constructor();
    /** @see Digest */
    getDigestLength(): number;
    /** @see Digest */
    copy(): Digest;
}
/**
 * This class implements HAVAL with 128-bit output and 4 passes.
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
export declare class Haval128_4 extends HAVALCore {
    /**
     * Create the object.
     */
    constructor();
    /** @see Digest */
    getDigestLength(): number;
    /** @see Digest */
    copy(): Digest;
}
/**
 * This class implements HAVAL with 128-bit output and 5 passes.
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
export declare class Haval128_5 extends HAVALCore {
    /**
     * Create the object.
     */
    constructor();
    /** @see Digest */
    getDigestLength(): number;
    /** @see Digest */
    copy(): Digest;
}
/**
 * This class implements HAVAL with 160-bit output and 3 passes.
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
export declare class Haval160_3 extends HAVALCore {
    /**
     * Create the object.
     */
    constructor();
    /** @see Digest */
    getDigestLength(): number;
    /** @see Digest */
    copy(): Digest;
}
/**
 * This class implements HAVAL with 160-bit output and 4 passes.
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
export declare class Haval160_4 extends HAVALCore {
    /**
     * Create the object.
     */
    constructor();
    /** @see Digest */
    getDigestLength(): number;
    /** @see Digest */
    copy(): Digest;
}
/**
 * This class implements HAVAL with 160-bit output and 5 passes.
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
export declare class Haval160_5 extends HAVALCore {
    /**
     * Create the object.
     */
    constructor();
    /** @see Digest */
    getDigestLength(): number;
    /** @see Digest */
    copy(): Digest;
}
/**
 * This class implements HAVAL with 192-bit output and 3 passes.
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
export declare class Haval192_3 extends HAVALCore {
    /**
     * Create the object.
     */
    constructor();
    /** @see Digest */
    getDigestLength(): number;
    /** @see Digest */
    copy(): Digest;
}
/**
 * This class implements HAVAL with 192-bit output and 4 passes.
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
export declare class Haval192_4 extends HAVALCore {
    /**
     * Create the object.
     */
    constructor();
    /** @see Digest */
    getDigestLength(): number;
    /** @see Digest */
    copy(): Digest;
}
/**
 * This class implements HAVAL with 192-bit output and 5 passes.
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
export declare class Haval192_5 extends HAVALCore {
    /**
     * Create the object.
     */
    constructor();
    /** @see Digest */
    getDigestLength(): number;
    /** @see Digest */
    copy(): Digest;
}
/**
 * This class implements HAVAL with 224-bit output and 3 passes.
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
export declare class Haval224_3 extends HAVALCore {
    /**
     * Create the object.
     */
    constructor();
    /** @see Digest */
    getDigestLength(): number;
    /** @see Digest */
    copy(): Digest;
}
/**
 * This class implements HAVAL with 224-bit output and 4 passes.
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
export declare class Haval224_4 extends HAVALCore {
    /**
     * Create the object.
     */
    constructor();
    /** @see Digest */
    getDigestLength(): number;
    /** @see Digest */
    copy(): Digest;
}
/**
 * This class implements HAVAL with 224-bit output and 5 passes.
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
export declare class Haval224_5 extends HAVALCore {
    /**
     * Create the object.
     */
    constructor();
    /** @see Digest */
    getDigestLength(): number;
    /** @see Digest */
    copy(): Digest;
}
/**
 * This class implements HAVAL with 256-bit output and 3 passes.
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
export declare class Haval256_3 extends HAVALCore {
    /**
     * Create the object.
     */
    constructor();
    /** @see Digest */
    getDigestLength(): number;
    /** @see Digest */
    copy(): Digest;
}
/**
 * This class implements HAVAL with 256-bit output and 4 passes.
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
export declare class Haval256_4 extends HAVALCore {
    /**
     * Create the object.
     */
    constructor();
    /** @see Digest */
    getDigestLength(): number;
    /** @see Digest */
    copy(): Digest;
}
/**
 * This class implements HAVAL with 256-bit output and 5 passes.
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
export declare class Haval256_5 extends HAVALCore {
    /**
     * Create the object.
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
 * Creates a 16 byte vary rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {3|4|5} rounds - hash rounds
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL128(message: InputData, rounds?: 3 | 4 | 5, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 16 byte vary rounds keyed Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {3|4|5} rounds - hash rounds
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL128_HMAC(message: InputData, key: InputData, rounds?: 3 | 4 | 5, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 16 byte 3 rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL128_3(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 16 byte 3 rounds keyed Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL128_3_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 16 byte 4 rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL128_4(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 16 byte 4 rounds keyed Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL128_4_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 16 byte 5 rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL128_5(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 16 byte 5 rounds keyed Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL128_5_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 20 byte vary rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {3|4|5} rounds - hash rounds
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL160(message: InputData, rounds?: 3 | 4 | 5, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 20 byte vary rounds keyed Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {3|4|5} rounds - hash rounds
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL160_HMAC(message: InputData, key: InputData, rounds?: 3 | 4 | 5, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 20 byte 3 rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL160_3(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 20 byte 3 rounds keyed Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL160_3_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 20 byte 4 rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL160_4(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 20 byte 4 rounds keyed Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL160_4_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 20 byte 5 rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL160_5(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 20 byte 5 rounds keyed Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL160_5_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 24 byte vary rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {3|4|5} rounds - hash rounds
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL192(message: InputData, rounds?: 3 | 4 | 5, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 24 byte vary rounds keyed Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {3|4|5} rounds - hash rounds
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL192_HMAC(message: InputData, key: InputData, rounds?: 3 | 4 | 5, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 24 byte 3 rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL192_3(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 24 byte 3 rounds keyed Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL192_3_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 24 byte 4 rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL192_4(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 24 byte 4 rounds keyed Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL192_4_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 24 byte 5 rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL192_5(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 24 byte 5 rounds keyed Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL192_5_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 28 byte vary rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {3|4|5} rounds - hash rounds
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL224(message: InputData, rounds?: 3 | 4 | 5, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 28 byte vary rounds keyed Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {3|4|5} rounds - hash rounds
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL224_HMAC(message: InputData, key: InputData, rounds?: 3 | 4 | 5, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 28 byte 3 rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL224_3(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 28 byte 3 rounds keyed Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL224_3_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 28 byte 4 rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL224_4(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 28 byte 4 rounds keyed Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL224_4_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 28 byte 5 rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL224_5(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 28 byte 5 rounds keyed Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL224_5_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 32 byte vary rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {3|4|5} rounds - hash rounds
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL256(message: InputData, rounds?: 3 | 4 | 5, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 32 byte vary rounds keyed Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {3|4|5} rounds - hash rounds
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL256_HMAC(message: InputData, key: InputData, rounds?: 3 | 4 | 5, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 32 byte 3 rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL256_3(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 32 byte 3 rounds keyed Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL256_3_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 32 byte 4 rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL256_4(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 32 byte 4 rounds keyed Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL256_4_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 32 byte 5 rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL256_5(message: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a 32 byte 5 rounds keyed Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL256_5_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a vary byte vary rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {128|160|192|224|256} bitLen - hash length in bits (default 256 AKA 32 bytes)
 * @param {3|4|5} rounds - rounds to hash (default 3)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function _HAVAL(message: InputData, bitLen?: 128 | 160 | 192 | 224 | 256, rounds?: 3 | 4 | 5, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Creates a vary byte vary rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key = hash key
 * @param {128|160|192|224|256} bitLen - hash length in bits (default 256 AKA 32 bytes)
 * @param {3|4|5} rounds - rounds to hash (default 3)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function HAVAL_HMAC(message: InputData, key: InputData, bitLen?: 128 | 160 | 192 | 224 | 256, rounds?: 3 | 4 | 5, format?: OutputFormat): string | Uint8Array | Buffer;
/**
 * Static class of all HAVAL functions and classes
 */
export declare class HAVAL {
    static HAVAL: typeof _HAVAL;
    static Haval128_3: typeof Haval128_3;
    static Haval128_4: typeof Haval128_4;
    static Haval128_5: typeof Haval128_5;
    static Haval160_3: typeof Haval160_3;
    static Haval160_4: typeof Haval160_4;
    static Haval160_5: typeof Haval160_5;
    static Haval192_3: typeof Haval192_3;
    static Haval192_4: typeof Haval192_4;
    static Haval192_5: typeof Haval192_5;
    static Haval224_3: typeof Haval224_3;
    static Haval224_4: typeof Haval224_4;
    static Haval224_5: typeof Haval224_5;
    static Haval256_3: typeof Haval256_3;
    static Haval256_4: typeof Haval256_4;
    static Haval256_5: typeof Haval256_5;
    static HAVAL128: typeof HAVAL128;
    static HAVAL128_HMAC: typeof HAVAL128_HMAC;
    static HAVAL128_3: typeof HAVAL128_3;
    static HAVAL128_3_HMAC: typeof HAVAL128_3_HMAC;
    static HAVAL128_4: typeof HAVAL128_4;
    static HAVAL128_4_HMAC: typeof HAVAL128_4_HMAC;
    static HAVAL128_5: typeof HAVAL128_5;
    static HAVAL128_5_HMAC: typeof HAVAL128_5_HMAC;
    static HAVAL160: typeof HAVAL160;
    static HAVAL160_3: typeof HAVAL160_3;
    static HAVAL160_3_HMAC: typeof HAVAL160_3_HMAC;
    static HAVAL160_4: typeof HAVAL160_4;
    static HAVAL160_4_HMAC: typeof HAVAL160_4_HMAC;
    static HAVAL160_5: typeof HAVAL160_5;
    static HAVAL160_5_HMAC: typeof HAVAL160_5_HMAC;
    static HAVAL160_HMAC: typeof HAVAL160_HMAC;
    static HAVAL192: typeof HAVAL192;
    static HAVAL192_3: typeof HAVAL192_3;
    static HAVAL192_3_HMAC: typeof HAVAL192_3_HMAC;
    static HAVAL192_4: typeof HAVAL192_4;
    static HAVAL192_4_HMAC: typeof HAVAL192_4_HMAC;
    static HAVAL192_5: typeof HAVAL192_5;
    static HAVAL192_5_HMAC: typeof HAVAL192_5_HMAC;
    static HAVAL192_HMAC: typeof HAVAL192_HMAC;
    static HAVAL224: typeof HAVAL224;
    static HAVAL224_3: typeof HAVAL224_3;
    static HAVAL224_3_HMAC: typeof HAVAL224_3_HMAC;
    static HAVAL224_4: typeof HAVAL224_4;
    static HAVAL224_4_HMAC: typeof HAVAL224_4_HMAC;
    static HAVAL224_5: typeof HAVAL224_5;
    static HAVAL224_5_HMAC: typeof HAVAL224_5_HMAC;
    static HAVAL224_HMAC: typeof HAVAL224_HMAC;
    static HAVAL256: typeof HAVAL256;
    static HAVAL256_3: typeof HAVAL256_3;
    static HAVAL256_3_HMAC: typeof HAVAL256_3_HMAC;
    static HAVAL256_4: typeof HAVAL256_4;
    static HAVAL256_4_HMAC: typeof HAVAL256_4_HMAC;
    static HAVAL256_5: typeof HAVAL256_5;
    static HAVAL256_5_HMAC: typeof HAVAL256_5_HMAC;
    static HAVAL256_HMAC: typeof HAVAL256_HMAC;
    static HAVAL_HMAC: typeof HAVAL_HMAC;
    /**
     * List of all hashes in class
     */
    static get FUNCTION_LIST(): string[];
}
export {};
//# sourceMappingURL=HAVAL.d.ts.map