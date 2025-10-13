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
abstract class DigestEngine implements Digest {

    protected abstract engineReset(): void;

    protected abstract processBlock(data: Uint8Array): void;

    protected abstract doPadding(buf: Uint8Array, off: number): void;

    protected abstract doInit(): void;

    digestLen: number; blockLen: number; inputLen: number;

    inputBuf: Uint8Array; outputBuf: Uint8Array;

    blockCount: bigint;  // Using BigInt as per ES6 requirements for large integer values

    constructor() {
        this.doInit();
        this.digestLen = this.getDigestLength();
        this.blockLen = this.getInternalBlockLength();
        this.inputBuf = new Uint8Array(this.blockLen);
        this.outputBuf = new Uint8Array(this.digestLen);
        this.inputLen = 0;
        this.blockCount = BigInt(0);
    }

    private adjustDigestLen(): void {
        if (this.digestLen == undefined || this.digestLen === 0) {
            this.digestLen = this.getDigestLength();
            this.outputBuf = new Uint8Array(this.digestLen);
        }
    }

    digest(): Uint8Array;
    digest(input: Uint8Array): Uint8Array;
    digest(input: Uint8Array, offset: number, len: number): number;
    digest(input?: Uint8Array, offset?: number, len?: number): Uint8Array | number {
        if (input === undefined) {
            this.adjustDigestLen();
            const result = new Uint8Array(this.digestLen);
            this.digest(result, 0, this.digestLen);
            return result;
        } else if (offset === undefined || len === undefined) {
            this.update(input, 0, input.length);
            return this.digest();
        } else {
            this.adjustDigestLen();
            if (len >= this.digestLen) {
                this.doPadding(input, offset);
                this.reset();
                return this.digestLen;
            } else {
                this.doPadding(this.outputBuf, 0);
                arraycopy(this.outputBuf, 0, input, offset, len);
                this.reset();
                return len;
            }
        }
    }

    reset(): void {
        this.engineReset();
        this.inputLen = 0;
        this.blockCount = BigInt(0);
    }

    update(input: number): void;
    update(input: Uint8Array): void;
    update(input: Uint8Array, offset: number, len: number): void;
    update(input: number | Uint8Array, offset?: number, len?: number): void {
        if (typeof input === 'number') {
            this.inputBuf[this.inputLen++] = input;
            if (this.inputLen === this.blockLen) {
                this.processBlock(this.inputBuf);
                this.blockCount++;
                this.inputLen = 0;
            }
        } else if (offset === undefined || len === undefined) {
            this.update(input, 0, input.length);
        } else {
            while (len > 0) {
                var copyLen = this.blockLen - this.inputLen;
                if (copyLen > len) {
                    copyLen = len;
                }
                arraycopy(input, offset, this.inputBuf, this.inputLen, copyLen);
                offset += copyLen;
                this.inputLen += copyLen;
                len -= copyLen;
                if (this.inputLen == this.blockLen) {
                    this.processBlock(this.inputBuf);
                    this.blockCount++;
                    this.inputLen = 0;
                }
            }
        }
    }

    protected getInternalBlockLength(): number {
        return this.getBlockLength();
    }

    protected flush(): number {
        return this.inputLen;
    }

    getBlockBuffer() {
        return this.inputBuf;
    }

    getBlockCount() {
        return this.blockCount;
    }

    protected copyState<T>(dest: DigestEngine): T {
        dest.inputLen = this.inputLen;
        dest.blockCount = this.blockCount;
        arraycopy(this.inputBuf, 0, dest.inputBuf, 0, this.inputBuf.length);
        this.adjustDigestLen();
        dest.adjustDigestLen();
        arraycopy(this.outputBuf, 0, dest.outputBuf, 0, this.outputBuf.length);
        return dest as T;
    }

    getDigestLength(): number {
        throw new Error('Method not implemented.');
    }
    copy(): Digest {
        throw new Error('Method not implemented.');
    }
    getBlockLength(): number {
        throw new Error('Method not implemented.');
    }
    toString(): string {
        throw new Error('Method not implemented.');
    }
}

function arraycopy(
    src: BigInt64Array | Uint8Array | Uint16Array | Int32Array | Uint32Array | Float32Array | Uint8ClampedArray,
    srcPos: number = 0,
    dst: BigInt64Array | Uint8Array | Uint16Array | Int32Array | Uint32Array | Float32Array | Uint8ClampedArray,
    destPos: number = 0,
    length: number) {
    // Validate inputs
    const srcbyteLength = src.byteLength;
    if (srcPos + length > src.byteLength) {
        throw new Error(`memcpy${length}: Source buffer too small, ${srcbyteLength} of ${srcPos + length}`);
    }
    const dstbyteLength = dst.byteLength;
    if (destPos + length > dstbyteLength) {
        throw new Error(`memcpy${length}: Destination buffer too small, ${dstbyteLength} of ${destPos + length}`);
    }

    const dstView = new Uint8Array(dst.buffer, dst.byteOffset + destPos, length);
    const srcView = new Uint8Array(src.buffer, src.byteOffset + srcPos, length);

    dstView.set(srcView);
};

function urs64(x: bigint, n: number): bigint {
  const ux = BigInt.asUintN(64, x); // treat as unsigned 64-bit
  return BigInt.asUintN(64, ux >> BigInt(n));
}

/**
 * This class implements BMW-384 and BMW-512.
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

abstract class BMWBigCore extends DigestEngine {

    private M!: BigInt64Array;
    private H!: BigInt64Array;
    private H2!: BigInt64Array;
    private Q!: BigInt64Array;
    private W!: BigInt64Array;

    /**
     * Create the object.
     */
    constructor() {
        super();
    }

    /** @see Digest */
    public getBlockLength() {
        return 128;
    }

    /** @see DigestEngine */
    protected copyState<T>(dst: BMWBigCore): T {
        arraycopy(this.H, 0, dst.H, 0, this.H.byteLength);
        return super.copyState(dst) as T;
    }

    /** @see DigestEngine */
    protected engineReset() {
        const iv = this.getInitVal();
        arraycopy(iv, 0, this.H, 0, iv.byteLength);
    }

    abstract getInitVal(): BigInt64Array;

    static FINAL = new BigInt64Array([
        BigInt("0xaaaaaaaaaaaaaaa0"), BigInt("0xaaaaaaaaaaaaaaa1"),
        BigInt("0xaaaaaaaaaaaaaaa2"), BigInt("0xaaaaaaaaaaaaaaa3"),
        BigInt("0xaaaaaaaaaaaaaaa4"), BigInt("0xaaaaaaaaaaaaaaa5"),
        BigInt("0xaaaaaaaaaaaaaaa6"), BigInt("0xaaaaaaaaaaaaaaa7"),
        BigInt("0xaaaaaaaaaaaaaaa8"), BigInt("0xaaaaaaaaaaaaaaa9"),
        BigInt("0xaaaaaaaaaaaaaaaa"), BigInt("0xaaaaaaaaaaaaaaab"),
        BigInt("0xaaaaaaaaaaaaaaac"), BigInt("0xaaaaaaaaaaaaaaad"),
        BigInt("0xaaaaaaaaaaaaaaae"), BigInt("0xaaaaaaaaaaaaaaaf")
    ]);

    static K = new BigInt64Array([
        BigInt(BigInt(16) * BigInt("0x0555555555555555")), BigInt(BigInt(17) * BigInt("0x0555555555555555")),
        BigInt(BigInt(18) * BigInt("0x0555555555555555")), BigInt(BigInt(19) * BigInt("0x0555555555555555")),
        BigInt(BigInt(20) * BigInt("0x0555555555555555")), BigInt(BigInt(21) * BigInt("0x0555555555555555")),
        BigInt(BigInt(22) * BigInt("0x0555555555555555")), BigInt(BigInt(23) * BigInt("0x0555555555555555")),
        BigInt(BigInt(24) * BigInt("0x0555555555555555")), BigInt(BigInt(25) * BigInt("0x0555555555555555")),
        BigInt(BigInt(26) * BigInt("0x0555555555555555")), BigInt(BigInt(27) * BigInt("0x0555555555555555")),
        BigInt(BigInt(28) * BigInt("0x0555555555555555")), BigInt(BigInt(29) * BigInt("0x0555555555555555")),
        BigInt(BigInt(30) * BigInt("0x0555555555555555")), BigInt(BigInt(31) * BigInt("0x0555555555555555"))
    ]);

    private compress(m: BigInt64Array) {
        const h = this.H;
        const q = this.Q;
        const w = this.W;
        w[0] = (m[5] ^ h[5]) - (m[7] ^ h[7]) + (m[10] ^ h[10])
            + (m[13] ^ h[13]) + (m[14] ^ h[14]);
        w[1] = (m[6] ^ h[6]) - (m[8] ^ h[8]) + (m[11] ^ h[11])
            + (m[14] ^ h[14]) - (m[15] ^ h[15]);
        w[2] = (m[0] ^ h[0]) + (m[7] ^ h[7]) + (m[9] ^ h[9])
            - (m[12] ^ h[12]) + (m[15] ^ h[15]);
        w[3] = (m[0] ^ h[0]) - (m[1] ^ h[1]) + (m[8] ^ h[8])
            - (m[10] ^ h[10]) + (m[13] ^ h[13]);
        w[4] = (m[1] ^ h[1]) + (m[2] ^ h[2]) + (m[9] ^ h[9])
            - (m[11] ^ h[11]) - (m[14] ^ h[14]);
        w[5] = (m[3] ^ h[3]) - (m[2] ^ h[2]) + (m[10] ^ h[10])
            - (m[12] ^ h[12]) + (m[15] ^ h[15]);
        w[6] = (m[4] ^ h[4]) - (m[0] ^ h[0]) - (m[3] ^ h[3])
            - (m[11] ^ h[11]) + (m[13] ^ h[13]);
        w[7] = (m[1] ^ h[1]) - (m[4] ^ h[4]) - (m[5] ^ h[5])
            - (m[12] ^ h[12]) - (m[14] ^ h[14]);
        w[8] = (m[2] ^ h[2]) - (m[5] ^ h[5]) - (m[6] ^ h[6])
            + (m[13] ^ h[13]) - (m[15] ^ h[15]);
        w[9] = (m[0] ^ h[0]) - (m[3] ^ h[3]) + (m[6] ^ h[6])
            - (m[7] ^ h[7]) + (m[14] ^ h[14]);
        w[10] = (m[8] ^ h[8]) - (m[1] ^ h[1]) - (m[4] ^ h[4])
            - (m[7] ^ h[7]) + (m[15] ^ h[15]);
        w[11] = (m[8] ^ h[8]) - (m[0] ^ h[0]) - (m[2] ^ h[2])
            - (m[5] ^ h[5]) + (m[9] ^ h[9]);
        w[12] = (m[1] ^ h[1]) + (m[3] ^ h[3]) - (m[6] ^ h[6])
            - (m[9] ^ h[9]) + (m[10] ^ h[10]);
        w[13] = (m[2] ^ h[2]) + (m[4] ^ h[4]) + (m[7] ^ h[7])
            + (m[10] ^ h[10]) + (m[11] ^ h[11]);
        w[14] = (m[3] ^ h[3]) - (m[5] ^ h[5]) + (m[8] ^ h[8])
            - (m[11] ^ h[11]) - (m[12] ^ h[12]);
        w[15] = (m[12] ^ h[12]) - (m[4] ^ h[4]) - (m[6] ^ h[6])
            - (m[9] ^ h[9]) + (m[13] ^ h[13]);
        for (let u = 0; u < 15; u += 5) {
            q[u + 0] = (urs64(w[u + 0], 1) ^ (w[u + 0] << BigInt(3))
                ^ this.circularLeft(w[u + 0], 4)
                ^ this.circularLeft(w[u + 0], 37)) + h[u + 1];
            q[u + 1] = (urs64(w[u + 1], 1) ^ (w[u + 1] << BigInt(2))
                ^ this.circularLeft(w[u + 1], 13)
                ^ this.circularLeft(w[u + 1], 43)) + h[u + 2];
            q[u + 2] = (urs64(w[u + 2], 2) ^ (w[u + 2] << BigInt(1))
                ^ this.circularLeft(w[u + 2], 19)
                ^ this.circularLeft(w[u + 2], 53)) + h[u + 3];
            q[u + 3] = (urs64(w[u + 3], 2) ^ (w[u + 3] << BigInt(2))
                ^ this.circularLeft(w[u + 3], 28)
                ^ this.circularLeft(w[u + 3], 59)) + h[u + 4];
            q[u + 4] = (urs64(w[u + 4], 1) ^ w[u + 4]) + h[u + 5];
        }
        q[15] = (urs64(w[15], 1) ^ (w[15] << BigInt(3))
            ^ this.circularLeft(w[15], 4) ^ this.circularLeft(w[15], 37))
            + h[0];

        for (let u = 16; u < 18; u++) {
            q[u] = (urs64(q[u - 16], 1) ^ (q[u - 16] << BigInt(2))
                ^ this.circularLeft(q[u - 16], 13)
                ^ this.circularLeft(q[u - 16], 43))
                + (urs64(q[u - 15], 2) ^ (q[u - 15] << BigInt(1))
                ^ this.circularLeft(q[u - 15], 19)
                ^ this.circularLeft(q[u - 15], 53))
                + (urs64(q[u - 14], 2) ^ (q[u - 14] << BigInt(2))
                ^ this.circularLeft(q[u - 14], 28)
                ^ this.circularLeft(q[u - 14], 59))
                + (urs64(q[u - 13], 1) ^ (q[u - 13] << BigInt(3))
                ^ this.circularLeft(q[u - 13], 4)
                ^ this.circularLeft(q[u - 13], 37))
                + (urs64(q[u - 12], 1) ^ (q[u - 12] << BigInt(2))
                ^ this.circularLeft(q[u - 12], 13)
                ^ this.circularLeft(q[u - 12], 43))
                + (urs64(q[u - 11], 2) ^ (q[u - 11] << BigInt(1))
                ^ this.circularLeft(q[u - 11], 19)
                ^ this.circularLeft(q[u - 11], 53))
                + (urs64(q[u - 10], 2) ^ (q[u - 10] << BigInt(2))
                ^ this.circularLeft(q[u - 10], 28)
                ^ this.circularLeft(q[u - 10], 59))
                + (urs64(q[u - 9], 1) ^ (q[u - 9] << BigInt(3))
                ^ this.circularLeft(q[u - 9], 4)
                ^ this.circularLeft(q[u - 9], 37))
                + (urs64(q[u - 8], 1) ^ (q[u - 8] << BigInt(2))
                ^ this.circularLeft(q[u - 8], 13)
                ^ this.circularLeft(q[u - 8], 43))
                + (urs64(q[u - 7], 2) ^ (q[u - 7] << BigInt(1))
                ^ this.circularLeft(q[u - 7], 19)
                ^ this.circularLeft(q[u - 7], 53))
                + (urs64(q[u - 6], 2) ^ (q[u - 6] << BigInt(2))
                ^ this.circularLeft(q[u - 6], 28)
                ^ this.circularLeft(q[u - 6], 59))
                + (urs64(q[u - 5], 1) ^ (q[u - 5] << BigInt(3))
                ^ this.circularLeft(q[u - 5], 4)
                ^ this.circularLeft(q[u - 5], 37))
                + (urs64(q[u - 4], 1) ^ (q[u - 4] << BigInt(2))
                ^ this.circularLeft(q[u - 4], 13)
                ^ this.circularLeft(q[u - 4], 43))
                + (urs64(q[u - 3], 2) ^ (q[u - 3] << BigInt(1))
                ^ this.circularLeft(q[u - 3], 19)
                ^ this.circularLeft(q[u - 3], 53))
                + (urs64(q[u - 2], 2) ^ (q[u - 2] << BigInt(2))
                ^ this.circularLeft(q[u - 2], 28)
                ^ this.circularLeft(q[u - 2], 59))
                + (urs64(q[u - 1], 1) ^ (q[u - 1] << BigInt(3))
                ^ this.circularLeft(q[u - 1], 4)
                ^ this.circularLeft(q[u - 1], 37))
                + ((this.circularLeft(m[(u - 16 + 0) & 15],
                    ((u - 16 + 0) & 15) + 1)
                + this.circularLeft(m[(u - 16 + 3) & 15],
                    ((u - 16 + 3) & 15) + 1)
                - this.circularLeft(m[(u - 16 + 10) & 15],
                    ((u - 16 + 10) & 15) + 1)
                + BMWBigCore.K[u - 16]) ^ h[(u - 16 + 7) & 15]);
        }
        for (let u = 18; u < 32; u++) {
            q[u] = q[u - 16] + this.circularLeft(q[u - 15], 5)
                 + q[u - 14] + this.circularLeft(q[u - 13], 11)
                 + q[u - 12] + this.circularLeft(q[u - 11], 27)
                 + q[u - 10] + this.circularLeft(q[u - 9], 32)
                 + q[u - 8] +  this.circularLeft(q[u - 7], 37)
                 + q[u - 6] +  this.circularLeft(q[u - 5], 43)
                 + q[u - 4] +  this.circularLeft(q[u - 3], 53)
                 + (urs64(q[u - 2], 1) ^ q[u - 2])
                 + (urs64(q[u - 1], 2) ^ q[u - 1])
                 + ((this.circularLeft(m[(u - 16 + 0) & 15],
                     ((u - 16 + 0) & 15) + 1)
                 + this.circularLeft(m[(u - 16 + 3) & 15],
                     ((u - 16 + 3) & 15) + 1)
                 - this.circularLeft(m[(u - 16 + 10) & 15],
                     ((u - 16 + 10) & 15) + 1)
                 + BMWBigCore.K[u - 16]) ^ h[(u - 16 + 7) & 15]);
        }

        const xl = q[16] ^ q[17] ^ q[18] ^ q[19]
             ^ q[20] ^ q[21] ^ q[22] ^ q[23];
        const xh = xl ^ q[24] ^ q[25] ^ q[26] ^ q[27]
             ^ q[28] ^ q[29] ^ q[30] ^ q[31];
        h[0] = ((xh << BigInt(5)) ^ urs64(q[16], 5) ^ m[0]) + (xl ^ q[24] ^ q[0]);
        h[1] = (urs64(xh, 7) ^ (q[17] << BigInt(8)) ^ m[1]) + (xl ^ q[25] ^ q[1]);
        h[2] = (urs64(xh, 5) ^ (q[18] << BigInt(5)) ^ m[2]) + (xl ^ q[26] ^ q[2]);
        h[3] = (urs64(xh, 1) ^ (q[19] << BigInt(5)) ^ m[3]) + (xl ^ q[27] ^ q[3]);
        h[4] = (urs64(xh, 3) ^ (q[20] << BigInt(0)) ^ m[4]) + (xl ^ q[28] ^ q[4]);
        h[5] = ((xh << BigInt(6)) ^ urs64(q[21], 6) ^ m[5]) + (xl ^ q[29] ^ q[5]);
        h[6] = (urs64(xh, 4) ^ (q[22] << BigInt(6)) ^ m[6]) + (xl ^ q[30] ^ q[6]);
        h[7] = (urs64(xh, 11) ^ (q[23] << BigInt(2)) ^ m[7])
            + (xl ^ q[31] ^ q[7]);
        h[8] = this.circularLeft(h[4], 9) + (xh ^ q[24] ^ m[8])
            + ((xl << BigInt(8)) ^ q[23] ^ q[8]);
        h[9] = this.circularLeft(h[5], 10) + (xh ^ q[25] ^ m[9])
            + (urs64(xl, 6) ^ q[16] ^ q[9]);
        h[10] = this.circularLeft(h[6], 11) + (xh ^ q[26] ^ m[10])
            + ((xl << BigInt(6)) ^ q[17] ^ q[10]);
        h[11] = this.circularLeft(h[7], 12) + (xh ^ q[27] ^ m[11])
            + ((xl << BigInt(4)) ^ q[18] ^ q[11]);
        h[12] = this.circularLeft(h[0], 13) + (xh ^ q[28] ^ m[12])
            + (urs64(xl, 3) ^ q[19] ^ q[12]);
        h[13] = this.circularLeft(h[1], 14) + (xh ^ q[29] ^ m[13])
            + (urs64(xl, 4) ^ q[20] ^ q[13]);
        h[14] = this.circularLeft(h[2], 15) + (xh ^ q[30] ^ m[14])
            + (urs64(xl, 7) ^ q[21] ^ q[14]);
        h[15] = this.circularLeft(h[3], 16) + (xh ^ q[31] ^ m[15])
            + (urs64(xl, 2) ^ q[22] ^ q[15]);
    }

    /** @see DigestEngine */
    protected doPadding(output: Uint8Array, outputOffset: number) {
        const buf = this.getBlockBuffer();
        var ptr = this.flush();
        const bitLen = (this.getBlockCount() << BigInt(10)) + BigInt(ptr << 3);
        buf[ptr++] = 0x80;
        if (ptr > 120) {
            for (let i = ptr; i < 128; i++) {
                buf[i] = 0;
            }
            this.processBlock(buf);
            ptr = 0;
        }
        for (let i = ptr; i < 120; i++) {
            buf[i] = 0;
        }
        this.encodeLELong(bitLen, buf, 120);
        this.processBlock(buf);
        const tmp = this.H;
        this.H = this.H2;
        this.H2 = tmp;
        arraycopy(BMWBigCore.FINAL, 0, this.H, 0, 16 * 8);
        this.compress(this.H2);
        const outLen = this.getDigestLength() >>> 3;
        for (let i = 0, j = 16 - outLen; i < outLen; i++, j++) {
            this.encodeLELong(this.H[j], output, outputOffset + 8 * i);
        }
    }

    /** @see DigestEngine */
    protected doInit() {
        this.M = new BigInt64Array(16);
        this.H = new BigInt64Array(16);
        this.H2 = new BigInt64Array(16);
        this.W = new BigInt64Array(16);
        this.Q = new BigInt64Array(32);
        this.engineReset();
    }

    /**
     * Encode the 64-bit word {@code val} into the array
     * {@code buf} at offset {@code off}, in little-endian
     * convention (least significant byte first).
     *
     * @param val   the value to encode
     * @param buf   the destination buffer
     * @param off   the destination offset
     */
    private encodeLELong(val: bigint, buf: Uint8Array, off: number) {
        let endian = "little";
        let unsigned: boolean = false;
        const bigIntArray = new BigInt64Array(1);
        bigIntArray[0] = BigInt(val);
        // Use two 32-bit views to write the Int64
        const int32Array = new Int32Array(bigIntArray.buffer);
        for (let i = 0; i < 2; i++) {
            if (endian == "little") {
                if (unsigned == false) {
                    buf[off + i * 4 + 0] = int32Array[i];
                    buf[off + i * 4 + 1] = (int32Array[i] >> 8);
                    buf[off + i * 4 + 2] = (int32Array[i] >> 16);
                    buf[off + i * 4 + 3] = (int32Array[i] >> 24);
                } else {
                    buf[off + i * 4 + 0] = int32Array[i] & 0xFF;
                    buf[off + i * 4 + 1] = (int32Array[i] >> 8) & 0xFF;
                    buf[off + i * 4 + 2] = (int32Array[i] >> 16) & 0xFF;
                    buf[off + i * 4 + 3] = (int32Array[i] >> 24) & 0xFF;
                }
            } else {
                if (unsigned == undefined || unsigned == false) {
                    buf[off + (1 - i) * 4 + 3] = int32Array[i];
                    buf[off + (1 - i) * 4 + 2] = (int32Array[i] >> 8);
                    buf[off + (1 - i) * 4 + 1] = (int32Array[i] >> 16);
                    buf[off + (1 - i) * 4 + 0] = (int32Array[i] >> 24);
                } else {
                    buf[off + (1 - i) * 4 + 3] = int32Array[i] & 0xFF;
                    buf[off + (1 - i) * 4 + 2] = (int32Array[i] >> 8) & 0xFF;
                    buf[off + (1 - i) * 4 + 1] = (int32Array[i] >> 16) & 0xFF;
                    buf[off + (1 - i) * 4 + 0] = (int32Array[i] >> 24) & 0xFF;
                }
            }
        }
    }

    /**
     * Decode a 64-bit little-endian word from the array {@code buf}
     * at offset {@code off}.
     *
     * @param buf   the source buffer
     * @param off   the source offset
     * @return  the decoded value
     */
    private decodeLELong(buf: Uint8Array, off: number) {
        let value = BigInt(0);
        let endian = "little";
        let unsigned: boolean = false;
        if (endian == "little") {
            for (let i = 0; i < 8; i++) {
                value = value | BigInt(buf[off]) << BigInt(8 * i);
                off++;
            }
            if (unsigned == false) {
                if (value & (BigInt(1) << BigInt(63))) {
                    value -= BigInt(1) << BigInt(64);
                }
            }
        }
        else {
            for (let i = 0; i < 8; i++) {
                value = (value << BigInt(8)) | BigInt(buf[off]);
                off++;
            }
            if (unsigned == false) {
                if (value & (BigInt(1) << BigInt(63))) {
                    value -= BigInt(1) << BigInt(64);
                }
            }
        }
        return value;
    }

    /**
     * Perform a circular rotation by {@code n} to the left
     * of the 64-bit word {@code x}. The {@code n} parameter
     * must lie between 1 and 63 (inclusive).
     *
     * @param x   the value to rotate
     * @param n   the rotation count (between 1 and 63)
     * @return  the rotated value
    */
    private circularLeft(x: bigint, n: number) {
        const mask = (BigInt(1) << BigInt(64)) - BigInt(1);
        const s = BigInt(n & 63);
        const ux = x & mask; // unsigned 64-bit
        const rotated = ((ux << s) | (ux >> (BigInt(64) - s))) & mask;
        const value = rotated >= (BigInt(1) << BigInt(63)) ? rotated - (BigInt(1) << BigInt(64)) : rotated;
        return value;
    }

    /** @see DigestEngine */
    protected processBlock(data: Uint8Array) {
        for (let i = 0; i < 16; i++) {
            this.M[i] = this.decodeLELong(data, i * 8);
        }
        this.compress(this.M);
    }

    /** @see Digest */
    public toString() {
        return "BMW-" + (this.getDigestLength() << 3);
    }
}

/**
 * This class implements BMW-224 and BMW-256.
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

abstract class BMWSmallCore extends DigestEngine {

	private M!: Int32Array;
    private H!: Int32Array;
    private H2!: Int32Array;
    private Q!: Int32Array;

	/**
	 * Create the object.
	 */
	constructor()
	{
        super();
	}

	/** @see Digest */
	public getBlockLength()
	{
		return 64;
	}

	/** @see DigestEngine */
	protected copyState<T>(dst:BMWSmallCore): T
	{
		arraycopy(this.H, 0, dst.H, 0, this.H.byteLength);
		return super.copyState(dst) as T;
	}

	/** @see DigestEngine */
	protected engineReset()
	{
		const iv = this.getInitVal();
		arraycopy(iv, 0, this.H, 0, iv.byteLength);
	}

	abstract getInitVal(): Int32Array;

	static FINAL = new Int32Array([
		0xaaaaaaa0, 0xaaaaaaa1, 0xaaaaaaa2, 0xaaaaaaa3,
		0xaaaaaaa4, 0xaaaaaaa5, 0xaaaaaaa6, 0xaaaaaaa7,
		0xaaaaaaa8, 0xaaaaaaa9, 0xaaaaaaaa, 0xaaaaaaab,
		0xaaaaaaac, 0xaaaaaaad, 0xaaaaaaae, 0xaaaaaaaf
    ]);

	private compress(m: Int32Array)
	{
		const h = this.H;
		const q = this.Q;
		q[0] = ((((m[5] ^ h[5]) - (m[7] ^ h[7]) + (m[10] ^ h[10])
			+ (m[13] ^ h[13]) + (m[14] ^ h[14])) >>> 1)
			^ (((m[5] ^ h[5]) - (m[7] ^ h[7]) + (m[10] ^ h[10])
			+ (m[13] ^ h[13]) + (m[14] ^ h[14])) << 3)
			^ this.circularLeft(((m[5] ^ h[5]) - (m[7] ^ h[7])
				+ (m[10] ^ h[10]) + (m[13] ^ h[13])
				+ (m[14] ^ h[14])), 4)
			^ this.circularLeft(((m[5] ^ h[5]) - (m[7] ^ h[7])
				+ (m[10] ^ h[10]) + (m[13] ^ h[13])
				+ (m[14] ^ h[14])), 19))
			+ h[1];
		q[1] = ((((m[6] ^ h[6]) - (m[8] ^ h[8]) + (m[11] ^ h[11])
			+ (m[14] ^ h[14]) - (m[15] ^ h[15])) >>> 1)
			^ (((m[6] ^ h[6]) - (m[8] ^ h[8]) + (m[11] ^ h[11])
			+ (m[14] ^ h[14]) - (m[15] ^ h[15])) << 2)
			^ this.circularLeft(((m[6] ^ h[6]) - (m[8] ^ h[8])
				+ (m[11] ^ h[11]) + (m[14] ^ h[14])
				- (m[15] ^ h[15])), 8)
			^ this.circularLeft(((m[6] ^ h[6]) - (m[8] ^ h[8])
				+ (m[11] ^ h[11]) + (m[14] ^ h[14])
				- (m[15] ^ h[15])), 23))
			+ h[2];
		q[2] = ((((m[0] ^ h[0]) + (m[7] ^ h[7]) + (m[9] ^ h[9])
			- (m[12] ^ h[12]) + (m[15] ^ h[15])) >>> 2)
			^ (((m[0] ^ h[0]) + (m[7] ^ h[7]) + (m[9] ^ h[9])
			- (m[12] ^ h[12]) + (m[15] ^ h[15])) << 1)
			^ this.circularLeft(((m[0] ^ h[0]) + (m[7] ^ h[7])
				+ (m[9] ^ h[9]) - (m[12] ^ h[12])
				+ (m[15] ^ h[15])), 12)
			^ this.circularLeft(((m[0] ^ h[0]) + (m[7] ^ h[7])
				+ (m[9] ^ h[9]) - (m[12] ^ h[12])
				+ (m[15] ^ h[15])), 25))
			+ h[3];
		q[3] = ((((m[0] ^ h[0]) - (m[1] ^ h[1]) + (m[8] ^ h[8])
			- (m[10] ^ h[10]) + (m[13] ^ h[13])) >>> 2)
			^ (((m[0] ^ h[0]) - (m[1] ^ h[1]) + (m[8] ^ h[8])
			- (m[10] ^ h[10]) + (m[13] ^ h[13])) << 2)
			^ this.circularLeft(((m[0] ^ h[0]) - (m[1] ^ h[1])
				+ (m[8] ^ h[8]) - (m[10] ^ h[10])
				+ (m[13] ^ h[13])), 15)
			^ this.circularLeft(((m[0] ^ h[0]) - (m[1] ^ h[1])
				+ (m[8] ^ h[8]) - (m[10] ^ h[10])
				+ (m[13] ^ h[13])), 29))
			+ h[4];
		q[4] = ((((m[1] ^ h[1]) + (m[2] ^ h[2]) + (m[9] ^ h[9])
			- (m[11] ^ h[11]) - (m[14] ^ h[14])) >>> 1)
			^ ((m[1] ^ h[1]) + (m[2] ^ h[2]) + (m[9] ^ h[9])
			- (m[11] ^ h[11]) - (m[14] ^ h[14]))) + h[5];
		q[5] = ((((m[3] ^ h[3]) - (m[2] ^ h[2]) + (m[10] ^ h[10])
			- (m[12] ^ h[12]) + (m[15] ^ h[15])) >>> 1)
			^ (((m[3] ^ h[3]) - (m[2] ^ h[2]) + (m[10] ^ h[10])
			- (m[12] ^ h[12]) + (m[15] ^ h[15])) << 3)
			^ this.circularLeft(((m[3] ^ h[3]) - (m[2] ^ h[2])
				+ (m[10] ^ h[10]) - (m[12] ^ h[12])
				+ (m[15] ^ h[15])), 4)
			^ this.circularLeft(((m[3] ^ h[3]) - (m[2] ^ h[2])
				+ (m[10] ^ h[10]) - (m[12] ^ h[12])
				+ (m[15] ^ h[15])), 19))
			+ h[6];
		q[6] = ((((m[4] ^ h[4]) - (m[0] ^ h[0]) - (m[3] ^ h[3])
			- (m[11] ^ h[11]) + (m[13] ^ h[13])) >>> 1)
			^ (((m[4] ^ h[4]) - (m[0] ^ h[0]) - (m[3] ^ h[3])
			- (m[11] ^ h[11]) + (m[13] ^ h[13])) << 2)
			^ this.circularLeft(((m[4] ^ h[4]) - (m[0] ^ h[0])
				- (m[3] ^ h[3]) - (m[11] ^ h[11])
				+ (m[13] ^ h[13])), 8)
			^ this.circularLeft(((m[4] ^ h[4]) - (m[0] ^ h[0])
				- (m[3] ^ h[3]) - (m[11] ^ h[11])
				+ (m[13] ^ h[13])), 23))
			+ h[7];
		q[7] = ((((m[1] ^ h[1]) - (m[4] ^ h[4]) - (m[5] ^ h[5])
			- (m[12] ^ h[12]) - (m[14] ^ h[14])) >>> 2)
			^ (((m[1] ^ h[1]) - (m[4] ^ h[4]) - (m[5] ^ h[5])
			- (m[12] ^ h[12]) - (m[14] ^ h[14])) << 1)
			^ this.circularLeft(((m[1] ^ h[1]) - (m[4] ^ h[4])
				- (m[5] ^ h[5]) - (m[12] ^ h[12])
				- (m[14] ^ h[14])), 12)
			^ this.circularLeft(((m[1] ^ h[1]) - (m[4] ^ h[4])
				- (m[5] ^ h[5]) - (m[12] ^ h[12])
				- (m[14] ^ h[14])), 25))
			+ h[8];
		q[8] = ((((m[2] ^ h[2]) - (m[5] ^ h[5]) - (m[6] ^ h[6])
			+ (m[13] ^ h[13]) - (m[15] ^ h[15])) >>> 2)
			^ (((m[2] ^ h[2]) - (m[5] ^ h[5]) - (m[6] ^ h[6])
			+ (m[13] ^ h[13]) - (m[15] ^ h[15])) << 2)
			^ this.circularLeft(((m[2] ^ h[2]) - (m[5] ^ h[5])
				- (m[6] ^ h[6]) + (m[13] ^ h[13])
				- (m[15] ^ h[15])), 15)
			^ this.circularLeft(((m[2] ^ h[2]) - (m[5] ^ h[5])
				- (m[6] ^ h[6]) + (m[13] ^ h[13])
				- (m[15] ^ h[15])), 29))
			+ h[9];
		q[9] = ((((m[0] ^ h[0]) - (m[3] ^ h[3]) + (m[6] ^ h[6])
			- (m[7] ^ h[7]) + (m[14] ^ h[14])) >>> 1)
			^ ((m[0] ^ h[0]) - (m[3] ^ h[3]) + (m[6] ^ h[6])
			- (m[7] ^ h[7]) + (m[14] ^ h[14]))) + h[10];
		q[10] = ((((m[8] ^ h[8]) - (m[1] ^ h[1]) - (m[4] ^ h[4])
			- (m[7] ^ h[7]) + (m[15] ^ h[15])) >>> 1)
			^ (((m[8] ^ h[8]) - (m[1] ^ h[1]) - (m[4] ^ h[4])
			- (m[7] ^ h[7]) + (m[15] ^ h[15])) << 3)
			^ this.circularLeft(((m[8] ^ h[8]) - (m[1] ^ h[1])
				- (m[4] ^ h[4]) - (m[7] ^ h[7])
				+ (m[15] ^ h[15])), 4)
			^ this.circularLeft(((m[8] ^ h[8]) - (m[1] ^ h[1])
				- (m[4] ^ h[4]) - (m[7] ^ h[7])
				+ (m[15] ^ h[15])), 19))
			+ h[11];
		q[11] = ((((m[8] ^ h[8]) - (m[0] ^ h[0]) - (m[2] ^ h[2])
			- (m[5] ^ h[5]) + (m[9] ^ h[9])) >>> 1)
			^ (((m[8] ^ h[8]) - (m[0] ^ h[0]) - (m[2] ^ h[2])
			- (m[5] ^ h[5]) + (m[9] ^ h[9])) << 2)
			^ this.circularLeft(((m[8] ^ h[8]) - (m[0] ^ h[0])
				- (m[2] ^ h[2]) - (m[5] ^ h[5])
				+ (m[9] ^ h[9])), 8)
			^ this.circularLeft(((m[8] ^ h[8]) - (m[0] ^ h[0])
				- (m[2] ^ h[2]) - (m[5] ^ h[5])
				+ (m[9] ^ h[9])), 23))
			+ h[12];
		q[12] = ((((m[1] ^ h[1]) + (m[3] ^ h[3]) - (m[6] ^ h[6])
			- (m[9] ^ h[9]) + (m[10] ^ h[10])) >>> 2)
			^ (((m[1] ^ h[1]) + (m[3] ^ h[3]) - (m[6] ^ h[6])
			- (m[9] ^ h[9]) + (m[10] ^ h[10])) << 1)
			^ this.circularLeft(((m[1] ^ h[1]) + (m[3] ^ h[3])
				- (m[6] ^ h[6]) - (m[9] ^ h[9])
				+ (m[10] ^ h[10])), 12)
			^ this.circularLeft(((m[1] ^ h[1]) + (m[3] ^ h[3])
				- (m[6] ^ h[6]) - (m[9] ^ h[9])
				+ (m[10] ^ h[10])), 25))
			+ h[13];
		q[13] = ((((m[2] ^ h[2]) + (m[4] ^ h[4]) + (m[7] ^ h[7])
			+ (m[10] ^ h[10]) + (m[11] ^ h[11])) >>> 2)
			^ (((m[2] ^ h[2]) + (m[4] ^ h[4]) + (m[7] ^ h[7])
			+ (m[10] ^ h[10]) + (m[11] ^ h[11])) << 2)
			^ this.circularLeft(((m[2] ^ h[2]) + (m[4] ^ h[4])
				+ (m[7] ^ h[7]) + (m[10] ^ h[10])
				+ (m[11] ^ h[11])), 15)
			^ this.circularLeft(((m[2] ^ h[2]) + (m[4] ^ h[4])
				+ (m[7] ^ h[7]) + (m[10] ^ h[10])
				+ (m[11] ^ h[11])), 29))
			+ h[14];
		q[14] = ((((m[3] ^ h[3]) - (m[5] ^ h[5]) + (m[8] ^ h[8])
			- (m[11] ^ h[11]) - (m[12] ^ h[12])) >>> 1)
			^ ((m[3] ^ h[3]) - (m[5] ^ h[5]) + (m[8] ^ h[8])
			- (m[11] ^ h[11]) - (m[12] ^ h[12]))) + h[15];
		q[15] = ((((m[12] ^ h[12]) - (m[4] ^ h[4]) - (m[6] ^ h[6])
			- (m[9] ^ h[9]) + (m[13] ^ h[13])) >>> 1)
			^ (((m[12] ^ h[12]) - (m[4] ^ h[4]) - (m[6] ^ h[6])
			- (m[9] ^ h[9]) + (m[13] ^ h[13])) << 3)
			^ this.circularLeft(((m[12] ^ h[12]) - (m[4] ^ h[4])
				- (m[6] ^ h[6]) - (m[9] ^ h[9])
				+ (m[13] ^ h[13])), 4)
			^ this.circularLeft(((m[12] ^ h[12]) - (m[4] ^ h[4])
				- (m[6] ^ h[6]) - (m[9] ^ h[9])
				+ (m[13] ^ h[13])), 19))
			+ h[0];
		q[16] = (((q[0] >>> 1) ^ (q[0] << 2)
			^ this.circularLeft(q[0], 8) ^ this.circularLeft(q[0], 23))
			+ ((q[1] >>> 2) ^ (q[1] << 1)
			^ this.circularLeft(q[1], 12) ^ this.circularLeft(q[1], 25))
			+ ((q[2] >>> 2) ^ (q[2] << 2)
			^ this.circularLeft(q[2], 15) ^ this.circularLeft(q[2], 29))
			+ ((q[3] >>> 1) ^ (q[3] << 3)
			^ this.circularLeft(q[3], 4) ^ this.circularLeft(q[3], 19))
			+ ((q[4] >>> 1) ^ (q[4] << 2)
			^ this.circularLeft(q[4], 8) ^ this.circularLeft(q[4], 23))
			+ ((q[5] >>> 2) ^ (q[5] << 1)
			^ this.circularLeft(q[5], 12) ^ this.circularLeft(q[5], 25))
			+ ((q[6] >>> 2) ^ (q[6] << 2)
			^ this.circularLeft(q[6], 15) ^ this.circularLeft(q[6], 29))
			+ ((q[7] >>> 1) ^ (q[7] << 3)
			^ this.circularLeft(q[7], 4) ^ this.circularLeft(q[7], 19))
			+ ((q[8] >>> 1) ^ (q[8] << 2)
			^ this.circularLeft(q[8], 8) ^ this.circularLeft(q[8], 23))
			+ ((q[9] >>> 2) ^ (q[9] << 1)
			^ this.circularLeft(q[9], 12) ^ this.circularLeft(q[9], 25))
			+ ((q[10] >>> 2) ^ (q[10] << 2)
			^ this.circularLeft(q[10], 15) ^ this.circularLeft(q[10], 29))
			+ ((q[11] >>> 1) ^ (q[11] << 3)
			^ this.circularLeft(q[11], 4) ^ this.circularLeft(q[11], 19))
			+ ((q[12] >>> 1) ^ (q[12] << 2)
			^ this.circularLeft(q[12], 8) ^ this.circularLeft(q[12], 23))
			+ ((q[13] >>> 2) ^ (q[13] << 1)
			^ this.circularLeft(q[13], 12) ^ this.circularLeft(q[13], 25))
			+ ((q[14] >>> 2) ^ (q[14] << 2)
			^ this.circularLeft(q[14], 15) ^ this.circularLeft(q[14], 29))
			+ ((q[15] >>> 1) ^ (q[15] << 3)
			^ this.circularLeft(q[15], 4) ^ this.circularLeft(q[15], 19))
			+ ((this.circularLeft(m[0], 1) + this.circularLeft(m[3], 4)
			- this.circularLeft(m[10], 11) + (16 * 0x05555555)) ^ h[7]));
		q[17] = (((q[1] >>> 1) ^ (q[1] << 2)
			^ this.circularLeft(q[1], 8) ^ this.circularLeft(q[1], 23))
			+ ((q[2] >>> 2) ^ (q[2] << 1)
			^ this.circularLeft(q[2], 12) ^ this.circularLeft(q[2], 25))
			+ ((q[3] >>> 2) ^ (q[3] << 2)
			^ this.circularLeft(q[3], 15) ^ this.circularLeft(q[3], 29))
			+ ((q[4] >>> 1) ^ (q[4] << 3)
			^ this.circularLeft(q[4], 4) ^ this.circularLeft(q[4], 19))
			+ ((q[5] >>> 1) ^ (q[5] << 2)
			^ this.circularLeft(q[5], 8) ^ this.circularLeft(q[5], 23))
			+ ((q[6] >>> 2) ^ (q[6] << 1)
			^ this.circularLeft(q[6], 12) ^ this.circularLeft(q[6], 25))
			+ ((q[7] >>> 2) ^ (q[7] << 2)
			^ this.circularLeft(q[7], 15) ^ this.circularLeft(q[7], 29))
			+ ((q[8] >>> 1) ^ (q[8] << 3)
			^ this.circularLeft(q[8], 4) ^ this.circularLeft(q[8], 19))
			+ ((q[9] >>> 1) ^ (q[9] << 2)
			^ this.circularLeft(q[9], 8) ^ this.circularLeft(q[9], 23))
			+ ((q[10] >>> 2) ^ (q[10] << 1)
			^ this.circularLeft(q[10], 12) ^ this.circularLeft(q[10], 25))
			+ ((q[11] >>> 2) ^ (q[11] << 2)
			^ this.circularLeft(q[11], 15) ^ this.circularLeft(q[11], 29))
			+ ((q[12] >>> 1) ^ (q[12] << 3)
			^ this.circularLeft(q[12], 4) ^ this.circularLeft(q[12], 19))
			+ ((q[13] >>> 1) ^ (q[13] << 2)
			^ this.circularLeft(q[13], 8) ^ this.circularLeft(q[13], 23))
			+ ((q[14] >>> 2) ^ (q[14] << 1)
			^ this.circularLeft(q[14], 12) ^ this.circularLeft(q[14], 25))
			+ ((q[15] >>> 2) ^ (q[15] << 2)
			^ this.circularLeft(q[15], 15) ^ this.circularLeft(q[15], 29))
			+ ((q[16] >>> 1) ^ (q[16] << 3)
			^ this.circularLeft(q[16], 4) ^ this.circularLeft(q[16], 19))
			+ ((this.circularLeft(m[1], 2) + this.circularLeft(m[4], 5)
			- this.circularLeft(m[11], 12) + (17 * 0x05555555)) ^ h[8]));
		q[18] = (q[2] + this.circularLeft(q[3], 3)
			+ q[4] + this.circularLeft(q[5], 7)
			+ q[6] + this.circularLeft(q[7], 13)
			+ q[8] + this.circularLeft(q[9], 16)
			+ q[10] + this.circularLeft(q[11], 19)
			+ q[12] + this.circularLeft(q[13], 23)
			+ q[14] + this.circularLeft(q[15], 27)
			+ ((q[16] >>> 1) ^ q[16]) + ((q[17] >>> 2) ^ q[17])
			+ ((this.circularLeft(m[2], 3) + this.circularLeft(m[5], 6)
			- this.circularLeft(m[12], 13)
			+ (18 * 0x05555555)) ^ h[9]));
		q[19] = (q[3] + this.circularLeft(q[4], 3)
			+ q[5] + this.circularLeft(q[6], 7)
			+ q[7] + this.circularLeft(q[8], 13)
			+ q[9] + this.circularLeft(q[10], 16)
			+ q[11] + this.circularLeft(q[12], 19)
			+ q[13] + this.circularLeft(q[14], 23)
			+ q[15] + this.circularLeft(q[16], 27)
			+ ((q[17] >>> 1) ^ q[17]) + ((q[18] >>> 2) ^ q[18])
			+ ((this.circularLeft(m[3], 4) + this.circularLeft(m[6], 7)
			- this.circularLeft(m[13], 14)
			+ (19 * 0x05555555)) ^ h[10]));
		q[20] = (q[4] + this.circularLeft(q[5], 3)
			+ q[6] + this.circularLeft(q[7], 7)
			+ q[8] + this.circularLeft(q[9], 13)
			+ q[10] + this.circularLeft(q[11], 16)
			+ q[12] + this.circularLeft(q[13], 19)
			+ q[14] + this.circularLeft(q[15], 23)
			+ q[16] + this.circularLeft(q[17], 27)
			+ ((q[18] >>> 1) ^ q[18]) + ((q[19] >>> 2) ^ q[19])
			+ ((this.circularLeft(m[4], 5) + this.circularLeft(m[7], 8)
			- this.circularLeft(m[14], 15)
			+ (20 * 0x05555555)) ^ h[11]));
		q[21] = (q[5] + this.circularLeft(q[6], 3)
			+ q[7] + this.circularLeft(q[8], 7)
			+ q[9] + this.circularLeft(q[10], 13)
			+ q[11] + this.circularLeft(q[12], 16)
			+ q[13] + this.circularLeft(q[14], 19)
			+ q[15] + this.circularLeft(q[16], 23)
			+ q[17] + this.circularLeft(q[18], 27)
			+ ((q[19] >>> 1) ^ q[19]) + ((q[20] >>> 2) ^ q[20])
			+ ((this.circularLeft(m[5], 6) + this.circularLeft(m[8], 9)
			- this.circularLeft(m[15], 16)
			+ (21 * 0x05555555)) ^ h[12]));
		q[22] = (q[6] + this.circularLeft(q[7], 3)
			+ q[8] + this.circularLeft(q[9], 7)
			+ q[10] + this.circularLeft(q[11], 13)
			+ q[12] + this.circularLeft(q[13], 16)
			+ q[14] + this.circularLeft(q[15], 19)
			+ q[16] + this.circularLeft(q[17], 23)
			+ q[18] + this.circularLeft(q[19], 27)
			+ ((q[20] >>> 1) ^ q[20]) + ((q[21] >>> 2) ^ q[21])
			+ ((this.circularLeft(m[6], 7) + this.circularLeft(m[9], 10)
			- this.circularLeft(m[0], 1)
			+ (22 * 0x05555555)) ^ h[13]));
		q[23] = (q[7] + this.circularLeft(q[8], 3)
			+ q[9] + this.circularLeft(q[10], 7)
			+ q[11] + this.circularLeft(q[12], 13)
			+ q[13] + this.circularLeft(q[14], 16)
			+ q[15] + this.circularLeft(q[16], 19)
			+ q[17] + this.circularLeft(q[18], 23)
			+ q[19] + this.circularLeft(q[20], 27)
			+ ((q[21] >>> 1) ^ q[21]) + ((q[22] >>> 2) ^ q[22])
			+ ((this.circularLeft(m[7], 8) + this.circularLeft(m[10], 11)
			- this.circularLeft(m[1], 2)
			+ (23 * 0x05555555)) ^ h[14]));
		q[24] = (q[8] + this.circularLeft(q[9], 3)
			+ q[10] + this.circularLeft(q[11], 7)
			+ q[12] + this.circularLeft(q[13], 13)
			+ q[14] + this.circularLeft(q[15], 16)
			+ q[16] + this.circularLeft(q[17], 19)
			+ q[18] + this.circularLeft(q[19], 23)
			+ q[20] + this.circularLeft(q[21], 27)
			+ ((q[22] >>> 1) ^ q[22]) + ((q[23] >>> 2) ^ q[23])
			+ ((this.circularLeft(m[8], 9) + this.circularLeft(m[11], 12)
			- this.circularLeft(m[2], 3)
			+ (24 * 0x05555555)) ^ h[15]));
		q[25] = (q[9] + this.circularLeft(q[10], 3)
			+ q[11] + this.circularLeft(q[12], 7)
			+ q[13] + this.circularLeft(q[14], 13)
			+ q[15] + this.circularLeft(q[16], 16)
			+ q[17] + this.circularLeft(q[18], 19)
			+ q[19] + this.circularLeft(q[20], 23)
			+ q[21] + this.circularLeft(q[22], 27)
			+ ((q[23] >>> 1) ^ q[23]) + ((q[24] >>> 2) ^ q[24])
			+ ((this.circularLeft(m[9], 10) + this.circularLeft(m[12], 13)
			- this.circularLeft(m[3], 4)
			+ (25 * 0x05555555)) ^ h[0]));
		q[26] = (q[10] + this.circularLeft(q[11], 3)
			+ q[12] + this.circularLeft(q[13], 7)
			+ q[14] + this.circularLeft(q[15], 13)
			+ q[16] + this.circularLeft(q[17], 16)
			+ q[18] + this.circularLeft(q[19], 19)
			+ q[20] + this.circularLeft(q[21], 23)
			+ q[22] + this.circularLeft(q[23], 27)
			+ ((q[24] >>> 1) ^ q[24]) + ((q[25] >>> 2) ^ q[25])
			+ ((this.circularLeft(m[10], 11) + this.circularLeft(m[13], 14)
			- this.circularLeft(m[4], 5)
			+ (26 * 0x05555555)) ^ h[1]));
		q[27] = (q[11] + this.circularLeft(q[12], 3)
			+ q[13] + this.circularLeft(q[14], 7)
			+ q[15] + this.circularLeft(q[16], 13)
			+ q[17] + this.circularLeft(q[18], 16)
			+ q[19] + this.circularLeft(q[20], 19)
			+ q[21] + this.circularLeft(q[22], 23)
			+ q[23] + this.circularLeft(q[24], 27)
			+ ((q[25] >>> 1) ^ q[25]) + ((q[26] >>> 2) ^ q[26])
			+ ((this.circularLeft(m[11], 12) + this.circularLeft(m[14], 15)
			- this.circularLeft(m[5], 6)
			+ (27 * 0x05555555)) ^ h[2]));
		q[28] = (q[12] + this.circularLeft(q[13], 3)
			+ q[14] + this.circularLeft(q[15], 7)
			+ q[16] + this.circularLeft(q[17], 13)
			+ q[18] + this.circularLeft(q[19], 16)
			+ q[20] + this.circularLeft(q[21], 19)
			+ q[22] + this.circularLeft(q[23], 23)
			+ q[24] + this.circularLeft(q[25], 27)
			+ ((q[26] >>> 1) ^ q[26]) + ((q[27] >>> 2) ^ q[27])
			+ ((this.circularLeft(m[12], 13) + this.circularLeft(m[15], 16)
			- this.circularLeft(m[6], 7)
			+ (28 * 0x05555555)) ^ h[3]));
		q[29] = (q[13] + this.circularLeft(q[14], 3)
			+ q[15] + this.circularLeft(q[16], 7)
			+ q[17] + this.circularLeft(q[18], 13)
			+ q[19] + this.circularLeft(q[20], 16)
			+ q[21] + this.circularLeft(q[22], 19)
			+ q[23] + this.circularLeft(q[24], 23)
			+ q[25] + this.circularLeft(q[26], 27)
			+ ((q[27] >>> 1) ^ q[27]) + ((q[28] >>> 2) ^ q[28])
			+ ((this.circularLeft(m[13], 14) + this.circularLeft(m[0], 1)
			- this.circularLeft(m[7], 8)
			+ (29 * 0x05555555)) ^ h[4]));
		q[30] = (q[14] + this.circularLeft(q[15], 3)
			+ q[16] + this.circularLeft(q[17], 7)
			+ q[18] + this.circularLeft(q[19], 13)
			+ q[20] + this.circularLeft(q[21], 16)
			+ q[22] + this.circularLeft(q[23], 19)
			+ q[24] + this.circularLeft(q[25], 23)
			+ q[26] + this.circularLeft(q[27], 27)
			+ ((q[28] >>> 1) ^ q[28]) + ((q[29] >>> 2) ^ q[29])
			+ ((this.circularLeft(m[14], 15) + this.circularLeft(m[1], 2)
			- this.circularLeft(m[8], 9)
			+ (30 * 0x05555555)) ^ h[5]));
		q[31] = (q[15] + this.circularLeft(q[16], 3)
			+ q[17] + this.circularLeft(q[18], 7)
			+ q[19] + this.circularLeft(q[20], 13)
			+ q[21] + this.circularLeft(q[22], 16)
			+ q[23] + this.circularLeft(q[24], 19)
			+ q[25] + this.circularLeft(q[26], 23)
			+ q[27] + this.circularLeft(q[28], 27)
			+ ((q[29] >>> 1) ^ q[29]) + ((q[30] >>> 2) ^ q[30])
			+ ((this.circularLeft(m[15], 16) + this.circularLeft(m[2], 3)
			- this.circularLeft(m[9], 10)
			+ (31 * 0x05555555)) ^ h[6]));
		const xl = q[16] ^ q[17] ^ q[18] ^ q[19]
			^ q[20] ^ q[21] ^ q[22] ^ q[23];
		const xh = xl ^ q[24] ^ q[25] ^ q[26] ^ q[27]
			^ q[28] ^ q[29] ^ q[30] ^ q[31];
		h[0] = ((xh << 5) ^ (q[16] >>> 5) ^ m[0]) + (xl ^ q[24] ^ q[0]);
		h[1] = ((xh >>> 7) ^ (q[17] << 8) ^ m[1]) + (xl ^ q[25] ^ q[1]);
		h[2] = ((xh >>> 5) ^ (q[18] << 5) ^ m[2]) + (xl ^ q[26] ^ q[2]);
		h[3] = ((xh >>> 1) ^ (q[19] << 5) ^ m[3]) + (xl ^ q[27] ^ q[3]);
		h[4] = ((xh >>> 3) ^ (q[20] << 0) ^ m[4]) + (xl ^ q[28] ^ q[4]);
		h[5] = ((xh << 6) ^ (q[21] >>> 6) ^ m[5]) + (xl ^ q[29] ^ q[5]);
		h[6] = ((xh >>> 4) ^ (q[22] << 6) ^ m[6]) + (xl ^ q[30] ^ q[6]);
		h[7] = ((xh >>> 11) ^ (q[23] << 2) ^ m[7])
			+ (xl ^ q[31] ^ q[7]);
		h[8] = this.circularLeft(h[4], 9) + (xh ^ q[24] ^ m[8])
			+ ((xl << 8) ^ q[23] ^ q[8]);
		h[9] = this.circularLeft(h[5], 10) + (xh ^ q[25] ^ m[9])
			+ ((xl >>> 6) ^ q[16] ^ q[9]);
		h[10] = this.circularLeft(h[6], 11) + (xh ^ q[26] ^ m[10])
			+ ((xl << 6) ^ q[17] ^ q[10]);
		h[11] = this.circularLeft(h[7], 12) + (xh ^ q[27] ^ m[11])
			+ ((xl << 4) ^ q[18] ^ q[11]);
		h[12] = this.circularLeft(h[0], 13) + (xh ^ q[28] ^ m[12])
			+ ((xl >>> 3) ^ q[19] ^ q[12]);
		h[13] = this.circularLeft(h[1], 14) + (xh ^ q[29] ^ m[13])
			+ ((xl >>> 4) ^ q[20] ^ q[13]);
		h[14] = this.circularLeft(h[2], 15) + (xh ^ q[30] ^ m[14])
			+ ((xl >>> 7) ^ q[21] ^ q[14]);
		h[15] = this.circularLeft(h[3], 16) + (xh ^ q[31] ^ m[15])
			+ ((xl >>> 2) ^ q[22] ^ q[15]);
	}

	/** @see DigestEngine */
	protected doPadding(output:Uint8Array, outputOffset: number)
	{
		const buf = this.getBlockBuffer();
		var ptr = this.flush();
		const bitLen = (this.getBlockCount() << BigInt(9)) + BigInt(ptr << 3);
		buf[ptr ++] = 0x80;
		if (ptr > 56) {
			for (let i = ptr; i < 64; i ++){
				buf[i] = 0;
            }
			this.processBlock(buf);
			ptr = 0;
		}
		for (let i = ptr; i < 56; i ++){
			buf[i] = 0;
        }
		this.encodeLEInt(Number(bitLen) >>> 0, buf, 56);
		this.encodeLEInt(Number(urs64(bitLen, 32)) >>> 0, buf, 60);
		this.processBlock(buf);
		const tmp = this.H;
		this.H = this.H2;
		this.H2 = tmp;
		arraycopy(BMWSmallCore.FINAL, 0, this.H, 0, 16 * 4);
		this.compress(this.H2);
		const outLen = this.getDigestLength() >>> 2;
		for (let i = 0, j = 16 - outLen; i < outLen; i ++, j ++){
			this.encodeLEInt(this.H[j], output, outputOffset + 4 * i);
        }
	}

	/** @see DigestEngine */
	protected doInit()
	{
		this.M = new Int32Array(16);
		this.H = new Int32Array(16);
		this.H2 = new Int32Array(16);
		this.Q = new Int32Array(32);
		this.engineReset();
	}

	/**
	 * Encode the 32-bit word {@code val} into the array
	 * {@code buf} at offset {@code off}, in little-endian
	 * convention (least significant byte first).
	 *
	 * @param val   the value to encode
	 * @param buf   the destination buffer
	 * @param off   the destination offset
	 */
	private encodeLEInt(val:number, buf: Uint8Array, off: number)
	{
		buf[off + 0] = val;
		buf[off + 1] = (val >>> 8);
		buf[off + 2] = (val >>> 16);
		buf[off + 3] = (val >>> 24);
	}

	/**
	 * Decode a 32-bit little-endian word from the array {@code buf}
	 * at offset {@code off}.
	 *
	 * @param buf   the source buffer
	 * @param off   the source offset
	 * @return  the decoded value
	 */
	private decodeLEInt(buf:Uint8Array,  off: number)
	{
		return ((buf[off + 3] & 0xFF) << 24)
			| ((buf[off + 2] & 0xFF) << 16)
			| ((buf[off + 1] & 0xFF) << 8)
			| (buf[off + 0] & 0xFF);
	}

	/**
	 * Perform a circular rotation by {@code n} to the left
	 * of the 32-bit word {@code x}. The {@code n} parameter
	 * must lie between 1 and 31 (inclusive).
	 *
	 * @param x   the value to rotate
	 * @param n   the rotation count (between 1 and 31)
	 * @return  the rotated value
	*/
	private circularLeft(x:number, n:number)
	{
		return (x << n) | (x >>> (32 - n));
	}

	/** @see DigestEngine */
	protected processBlock( data:Uint8Array)
	{
		for (let i = 0; i < 16; i ++){
			this.M[i] = this.decodeLEInt(data, i * 4);
        }
		this.compress(this.M);
	}

	/** @see Digest */
	public toString():string
	{
		return "BMW-" + (this.getDigestLength() << 3);
	}
}

/**
 * <p>This class implements the HMAC message authentication algorithm,
 * under the {@link Digest} API, using the {@link DigestEngine} class.
 * HMAC is defined in RFC 2104 (also FIPS 198a). This implementation
 * uses an underlying digest algorithm, provided as parameter to the
 * constructor.</p>
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

class HMAC extends DigestEngine {

    private dig!: Digest;
    private kipad!:Uint8Array
    private kopad!:Uint8Array;
    private outputLength!:number;
    private tmpOut!:Uint8Array;
    private onlyThis = 0;
    private static zeroPad = new Uint8Array(64);

    /**
     * Build the object. The provided digest algorithm will be used
     * internally; it MUST NOT be directly accessed afterwards. The
     * {@code key} array holds the MAC key; the key is copied
     * internally, which means that the caller may modify the {@code
     * key} array afterwards.
     *
     * @param dig   the underlying hash function
     * @param key   the MAC key
     * @param outputLength   the HMAC output length (in bytes)
     */
    constructor(dig:Digest, key:Uint8Array, outputLength?:number)
    {
        super();
        dig.reset();
        this.dig = dig;
        var B = dig.getBlockLength();
        if (B < 0) {
            /*
             * Virtual block length: inferred from the key
             * length, with rounding (used for Fugue-xxx).
             */
            let n = -B;
            B = n * ((key.length + (n - 1)) / n);
        }
        const keyB = new Uint8Array(B);
        var len = key.length;
        if (len > B) {
            key = dig.digest(key);
            len = key.length;
            if (len > B){
                len = B;
            }
        }
        arraycopy(key, 0, keyB, 0, len);
        /*
         * Newly created arrays are guaranteed filled with zeroes,
         * hence the key padding is already done.
         */
        this.processKey(keyB);

        this.outputLength = -1;
        this.tmpOut = new Uint8Array(dig.getDigestLength());
        this.reset();
        if (outputLength && outputLength < dig.getDigestLength()){
            this.outputLength = outputLength;
        }
    }

    /**
     * Internal constructor, used for cloning. The key is referenced,
     * not copied.
     *
     * @param dig            the digest
     * @param kipad          the (internal) ipad key
     * @param kopad          the (internal) opad key
     * @param outputLength   the output length, or -1
     */
    private _HMAC(dig:Digest, kipad:Uint8Array, kopad:Uint8Array, outputLength:number)
    {
        this.dig = dig;
        this.kipad = kipad;
        this.kopad = kopad;
        this.outputLength = outputLength;
        this.tmpOut = new Uint8Array(dig.getDigestLength());
        return this;
    }

    private processKey(keyB:Uint8Array)
    {
        var B = keyB.length;
        this.kipad = new Uint8Array(B);
        this.kopad = new Uint8Array(B);
        for (let i = 0; i < B; i ++) {
            var x = keyB[i];
            this.kipad[i] = (x ^ 0x36);
            this.kopad[i] = (x ^ 0x5C);
        }
    }

    /** @see Digest */
    public copy(): Digest
    {
        const h = this._HMAC(this.dig.copy(), this.kipad, this.kopad, this.outputLength);
        return this.copyState(h);
    }

    /** @see Digest */
    public getDigestLength(): number
    {
        /*
         * At construction time, outputLength is first set to 0,
         * which means that this method will return 0, which is
         * appropriate since at that time "dig" has not yet been
         * set.
         */
        return this.outputLength < 0 ? this.dig.getDigestLength() : this.outputLength;
    }

    /** @see Digest */
    public getBlockLength(): number
    {
        /*
         * Internal block length is not defined for HMAC, which
         * is not, stricto-sensu, an iterated hash function.
         * The value 64 should provide correct buffering. Do NOT
         * change this value without checking doPadding().
         */
        return 64;
    }

    /** @see DigestEngine */
    protected engineReset()
    {
        this.dig.reset();
        this.dig.update(this.kipad);
    }

    /** @see DigestEngine */
    protected processBlock(data:Uint8Array)
    {
        if (this.onlyThis > 0) {
            this.dig.update(data, 0, this.onlyThis);
            this.onlyThis = 0;
        } else {
            this.dig.update(data);
        }
    }

    /** @see DigestEngine */
    protected doPadding(output:Uint8Array, outputOffset:number)
    {
        /*
         * This is slightly ugly... we need to get the still
         * buffered data, but the only way to get it from
         * DigestEngine is to input some more bytes and wait
         * for the processBlock() call. We set a variable
         * with the count of actual data bytes, so that
         * processBlock() knows what to do.
         */
        this.onlyThis = this.flush();
        if (this.onlyThis > 0){
            this.update(HMAC.zeroPad, 0, 64 - this.onlyThis);
        }
        var olen = this.tmpOut.length;
        this.dig.digest(this.tmpOut, 0, olen);
        this.dig.update(this.kopad);
        this.dig.update(this.tmpOut);
        this.dig.digest(this.tmpOut, 0, olen);
        if (this.outputLength >= 0){
            olen = this.outputLength;
        }
        arraycopy(this.tmpOut, 0, output, outputOffset, olen);
    }

    /** @see DigestEngine */
    protected doInit()
    {
        /*
         * Empty: we do not want to do anything here because
         * it would prevent correct cloning. The initialization
         * job is done in the constructor.
         */
    }

    /** @see Digest */
    public toString(): string
    {
        return "HMAC/" + this.dig.toString();
    }
}

/**
 * <p>This class implements the BMW-224 ("Blue Midnight Wish") digest
 * algorithm under the {@link Digest} API.</p>
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
 * @version   $Revision: 166 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

class Bmw224 extends BMWSmallCore {

	/**
	 * Create the engine.
	 */
	constructor()
	{
		super();
	}

	/** The initial value for BMW-224. */
	private static initVal = new Int32Array([
		0x00010203, 0x04050607, 0x08090A0B, 0x0C0D0E0F,
		0x10111213, 0x14151617, 0x18191A1B, 0x1C1D1E1F,
		0x20212223, 0x24252627, 0x28292A2B, 0x2C2D2E2F,
		0x30313233, 0x34353637, 0x38393A3B, 0x3C3D3E3F
    ]);

	/** @see BMWSmallCore */
	getInitVal()
	{
		return Bmw224.initVal;
	}

	/** @see Digest */
	public getDigestLength()
	{
		return 28;
	}

	/** @see Digest */
	public copy(): Digest
	{
		return this.copyState(new Bmw224());
	}
}


/**
 * <p>This class implements the BMW-256 ("Blue Midnight Wish") digest
 * algorithm under the {@link Digest} API.</p>
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
 * @version   $Revision: 166 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

class Bmw256 extends BMWSmallCore {

	/**
	 * Create the engine.
	 */
	constructor()
	{
		super();
	}

	/** The initial value for BMW-256. */
	private static initVal = new Int32Array([
		0x40414243, 0x44454647, 0x48494A4B, 0x4C4D4E4F,
		0x50515253, 0x54555657, 0x58595A5B, 0x5C5D5E5F,
		0x60616263, 0x64656667, 0x68696A6B, 0x6C6D6E6F,
		0x70717273, 0x74757677, 0x78797A7B, 0x7C7D7E7F
    ]);

	/** @see BMWSmallCore */
	getInitVal()
	{
		return Bmw256.initVal;
	}

	/** @see Digest */
	public getDigestLength()
	{
		return 32;
	}

	/** @see Digest */
	public  copy(): Digest
	{
		return this.copyState(new Bmw256());
	}
}


/**
 * <p>This class implements the BMW-384 ("Blue Midnight Wish") digest
 * algorithm under the {@link Digest} API.</p>
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
 * @version   $Revision: 166 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

class Bmw384 extends BMWBigCore {

	/**
	 * Create the engine.
	 */
	constructor()
	{
		super();
	}

	/** The initial value for BMW-384. */
	private static initVal = new BigInt64Array([
		BigInt("0x0001020304050607"), BigInt("0x08090A0B0C0D0E0F"),
		BigInt("0x1011121314151617"), BigInt("0x18191A1B1C1D1E1F"),
		BigInt("0x2021222324252627"), BigInt("0x28292A2B2C2D2E2F"),
		BigInt("0x3031323334353637"), BigInt("0x38393A3B3C3D3E3F"),
		BigInt("0x4041424344454647"), BigInt("0x48494A4B4C4D4E4F"),
		BigInt("0x5051525354555657"), BigInt("0x58595A5B5C5D5E5F"),
		BigInt("0x6061626364656667"), BigInt("0x68696A6B6C6D6E6F"),
		BigInt("0x7071727374757677"), BigInt("0x78797A7B7C7D7E7F")
    ]);

	/** @see BMWSmallCore */
	getInitVal()
	{
		return Bmw384.initVal;
	}

	/** @see Digest */
	public getDigestLength()
	{
		return 48;
	}

	/** @see Digest */
	public copy(): Digest
	{
		return this.copyState(new Bmw384());
	}
}

/**
 * <p>This class implements the BMW-512 ("Blue Midnight Wish") digest
 * algorithm under the {@link Digest} API.</p>
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
 * @version   $Revision: 166 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

class Bmw512 extends BMWBigCore {

	/**
	 * Create the engine.
	 */
	constructor()
	{
		super();
	}

	/** The initial value for BMW-512. */
	private static initVal = new BigInt64Array([
		BigInt("0x8081828384858687"), BigInt("0x88898A8B8C8D8E8F"),
		BigInt("0x9091929394959697"), BigInt("0x98999A9B9C9D9E9F"),
		BigInt("0xA0A1A2A3A4A5A6A7"), BigInt("0xA8A9AAABACADAEAF"),
		BigInt("0xB0B1B2B3B4B5B6B7"), BigInt("0xB8B9BABBBCBDBEBF"),
		BigInt("0xC0C1C2C3C4C5C6C7"), BigInt("0xC8C9CACBCCCDCECF"),
		BigInt("0xD0D1D2D3D4D5D6D7"), BigInt("0xD8D9DADBDCDDDEDF"),
		BigInt("0xE0E1E2E3E4E5E6E7"), BigInt("0xE8E9EAEBECEDEEEF"),
		BigInt("0xF0F1F2F3F4F5F6F7"), BigInt("0xF8F9FAFBFCFDFEFF")
    ]);

	/** @see BMWSmallCore */
	getInitVal()
	{
		return Bmw512.initVal;
	}

	/** @see Digest */
	public getDigestLength()
	{
		return 64;
	}

	/** @see Digest */
	public copy() : Digest
	{
		return this.copyState(new Bmw512());
	}
}

function toHex(bytes: Uint8Array): string {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
};

function strToUint8Array(str: string): Uint8Array {
    // Check if the browser supports TextDecoder API
    try {
        const encoder = new TextEncoder();

        // Encode the string and return as a Uint8Array
        return encoder.encode(str);
    } catch (e) { }

    // Fallback for older systems without TextDecoder support
    let result = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
        const codePoint = str.charCodeAt(i);
        if (codePoint <= 255) {
            result[i] = codePoint;
        } else {
            result.set([codePoint >> 8, codePoint & 0xFF], i * 2);
        }
    }
    return result;
}

function formatMessage(message?: InputData): Uint8Array {
    if (message === undefined) {
        return new Uint8Array(0);
    }

    if (typeof message === 'string') {
        return strToUint8Array(message);
    }

    if (Buffer.isBuffer(message)) {
        return new Uint8Array(message);
    }

    if (message instanceof Uint8Array) {
        return message as Uint8Array;
    }

    throw new Error('input is invalid type');
}

export class Bmw {
    class: Bmw512 | Bmw384 | Bmw256 | Bmw224;
    constructor(bits:512|384|256|224){
        switch (bits) {
            case 512:
                this.class = new Bmw512();
                break;
            case 384:
                this.class = new Bmw384();
                break;
            case 256:
                this.class = new Bmw256();
                break;
            case 224:
                this.class = new Bmw224();
                break;
            default:
                this.class = new Bmw512();
                break;
        }
    }

    update(message: InputData) {
        message = formatMessage(message);
        this.class.update(message);
    }

    digest(format: OutputFormat) {
        if (format == "hex") {
            return toHex(this.class.digest());
        } else if (format == "buffer") {
            return Buffer.from(this.class.digest());
        }
        return this.class.digest();
    }
}

// Input types
type InputData = string | Uint8Array | Buffer;

// Output formats
type OutputFormat = 'hex' | 'array' | 'buffer';

function arrayType():OutputFormat{
	if (typeof window !== 'undefined') {
		return "array" as OutputFormat;
	} else {
    return "buffer" as OutputFormat;
	}
};

/**
 * Creates a vary byte BMW of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {224 | 256 | 384 | 512} bitLen - bit length of hash (default 512 or 64 bytes) 
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function _BMW(message: InputData, bitLen: 224 | 256 | 384 | 512 = 512, format: OutputFormat = arrayType()) {
    const hash = new Bmw(bitLen);
    hash.update(message);
    return hash.digest(format);
}

/**
 * Creates a 28 byte BMW of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function BMW224(message: InputData, format: OutputFormat = arrayType()) {
    const hash = new Bmw(224);
    hash.update(message);
    return hash.digest(format);
};

/**
 * Creates a 28 byte keyed BMW of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function BMW224_HMAC(message: InputData, key?: InputData, format: OutputFormat = arrayType()) {
    const hash = new Bmw(224);
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    } else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
};

/**
 * Creates a 32 byte BMW of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function BMW256(message: InputData, format: OutputFormat = arrayType()) {
    const hash = new Bmw(256);
    hash.update(message);
    return hash.digest(format);
};

/**
 * Creates a 32 byte keyed BMW of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function BMW256_HMAC(message: InputData, key?: InputData, format: OutputFormat = arrayType()) {
    const hash = new Bmw(256);
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    } else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
};

/**
 * Creates a 48 byte BMW of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function BMW384(message: InputData, format: OutputFormat = arrayType()) {
    const hash = new Bmw(384);
    hash.update(message);
    return hash.digest(format);
};

/**
 * Creates a 48 byte keyed BMW of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function BMW384_HMAC(message: InputData, key?: InputData, format: OutputFormat = arrayType()) {
    const hash = new Bmw(384);
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    } else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
};

/**
 * Creates a 64 byte BMW of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function BMW512(message: InputData, format: OutputFormat = arrayType()) {
    const hash = new Bmw(512);
    hash.update(message);
    return hash.digest(format);
};

/**
 * Creates a 64 byte keyed BMW of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function BMW512_HMAC(message: InputData, key?: InputData, format: OutputFormat = arrayType()) {
    const hash = new Bmw(512);
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    } else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
};

/**
 * Creates a vary byte keyed BMW of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {224 | 256 | 384 | 512} bitLen - bit length of hash (default 512 or 64 bytes) 
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function BMW_HMAC(message: InputData, key: InputData, bitLen: 224 | 256 | 384 | 512 = 512, format: OutputFormat = arrayType()) {
    const hash = new Bmw(bitLen);
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    } else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
}

/**
 * Static class of all Blue Midnight Wish functions and classes
 */
export class BMW {
    static Bmw = Bmw;
    static BMW = _BMW;
    static BMW224 = BMW224;
    static BMW224_HMAC = BMW224_HMAC;
    static BMW256 = BMW256;
    static BMW256_HMAC = BMW256_HMAC;
    static BMW384 = BMW384;
    static BMW384_HMAC = BMW384_HMAC;
    static BMW512 = BMW512;
    static BMW512_HMAC = BMW512_HMAC;
    static BMW_HMAC = BMW_HMAC;
    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST() {
        return [
            "BMW",
            "BMW224",
            "BMW224_HMAC",
            "BMW256",
            "BMW256_HMAC",
            "BMW384",
            "BMW384_HMAC",
            "BMW512",
            "BMW512_HMAC",
            "BMW_HMAC",
        ]
    }
};