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

    protected copyState<T>(dest: DigestEngine):T {
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
    src: Uint8Array | Uint16Array | Int32Array | Uint32Array | Float32Array | Uint8ClampedArray,
    srcPos: number = 0,
    dst: Uint8Array | Uint16Array | Int32Array | Uint32Array | Float32Array | Uint8ClampedArray,
    destPos: number = 0,
    length: number) {
    const src2 = [];
    for (let i = 0; i < length; i++) {
        src2.push(src[srcPos + i]);
    }
    for (let i = 0; i < length; i++) {
        dst[destPos + i] = src2[i];
    }
};

function arrayType():OutputFormat{
	if (typeof window !== 'undefined') {
		return "array" as OutputFormat;
	} else {
    return "buffer" as OutputFormat;
	}
};

/**
 * This class implements Hamsi-224 and Hamsi-256.
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
 * @version   $Revision: 239 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

abstract class HamsiSmallCore implements Digest {

    private h!: Int32Array;
    private bitCount!: bigint;
    private partial = 0;
    private partialLen!: number;

    /**
     * Create the object.
     */
    constructor() {
        this.h = new Int32Array(8);
        this.reset();
    }

    /** @see Digest */
    public update(inbuf: Uint8Array | number, off?: number, len?: number) {
        if (typeof inbuf == "number") {
            this.bitCount += BigInt(8);
            this.partial = (this.partial << 8) | (inbuf & 0xFF);
            this.partialLen++;
            if (this.partialLen == 4) {
                this.process(this.partial >>> 24, (this.partial >>> 16) & 0xFF,
                    (this.partial >>> 8) & 0xFF, this.partial & 0xFF);
                this.partialLen = 0;
            }
        } else if (off == undefined || len == undefined) {
            this.update(inbuf, 0, inbuf.length);
        } else {
            this.bitCount += BigInt(len << 3);
            if (this.partialLen != 0) {
                while (this.partialLen < 4 && len > 0) {
                    this.partial = (this.partial << 8) | (inbuf[off++] & 0xFF);
                    this.partialLen++;
                    len--;
                }
                if (this.partialLen < 4) {
                    return;
                }
                this.process(this.partial >>> 24, (this.partial >>> 16) & 0xFF,
                    (this.partial >>> 8) & 0xFF, this.partial & 0xFF);
                this.partialLen = 0;
            }
            while (len >= 4) {
                this.process(inbuf[off + 0] & 0xFF,
                    inbuf[off + 1] & 0xFF,
                    inbuf[off + 2] & 0xFF,
                    inbuf[off + 3] & 0xFF);
                off += 4;
                len -= 4;
            }
            this.partialLen = len;
            while (len-- > 0) {
                this.partial = (this.partial << 8) | (inbuf[off++] & 0xFF);
            }
        }
    }

    digest(): Uint8Array;
    digest(input: Uint8Array): Uint8Array;
    digest(input: Uint8Array, offset: number, len: number): number;
    digest(outbuf?: Uint8Array, off?: number, len?: number): Uint8Array | number {
        if (outbuf == undefined) {
            const n = this.getDigestLength();
            const out = new Uint8Array(n);
            this.digest(out, 0, n);
            return out;
        } else if (off == undefined || len == undefined) {
            this.update(outbuf, 0, outbuf.length);
            return this.digest();
        } else {
            const bitCount = this.bitCount;
            this.update(0x80);
            while (this.partialLen != 0) {
                this.update(0x00);
            }
            this.process(
                Number(bitCount >> BigInt(56)) & 0xFF,
                Number(bitCount >> BigInt(48)) & 0xFF,
                Number(bitCount >> BigInt(40)) & 0xFF,
                Number(bitCount >> BigInt(32)) & 0xFF
            );
            this.processFinal(
                Number(bitCount >> BigInt(24)) & 0xFF,
                Number(bitCount >> BigInt(16)) & 0xFF,
                Number(bitCount >> BigInt(8)) & 0xFF,
                Number(bitCount) & 0xFF
            );
            var n = this.getDigestLength();
            if (len > n) {
                len = n;
            }
            var ch = 0;
            for (let i = 0, j = 0; i < len; i++) {
                if ((i & 3) == 0) {
                    ch = this.h[j++];
                }
                outbuf[off + i] = (ch >>> 24) & 0xFF;
                ch <<= 8;
            }
            this.reset();
            return len;
        }
    }

    /** @see Digest */
    public reset() {
        arraycopy(this.getIV(), 0, this.h, 0, this.h.length);
        this.bitCount = BigInt(0);
        this.partialLen = 0;
    }

    /** @see Digest */
    public copy(): Digest {
        const d = this.dup();
        arraycopy(this.h, 0, d.h, 0, this.h.length);
        d.bitCount = this.bitCount;
        d.partial = this.partial;
        d.partialLen = this.partialLen;
        return d;
    }

    /** @see Digest */
    public getBlockLength() {
        /*
         * Private communication from Hamsi designer Ozgul Kucuk:
         *
         * << For HMAC you can calculate B = 256*ceil(k / 256)
         *    (same as CubeHash). >>
         */
        return -32;
    }

    /**
     * Get the IV.
     *
     * @return  the IV (initial values for the state words)
     */
    abstract getIV(): Int32Array;

    /**
     * Create a new instance of the same runtime class than this object.
     *
     * @return  the duplicate
     */
    abstract dup(): HamsiSmallCore;

    private static Tsrc = [
        new Int32Array([
            0x045f0000, 0x9c4a93c9, 0x62fc79d0, 0x731ebdc2,
            0xe0278000, 0x19dce008, 0xd7075d82, 0x5ad2e31d]),
        new Int32Array([
            0xe4788000, 0x859673c1, 0xb5fb2452, 0x29cc5edf,
            0x045f0000, 0x9c4a93c9, 0x62fc79d0, 0x731ebdc2]),
        new Int32Array([
            0xe6570000, 0x4bb33a25, 0x848598ba, 0x1041003e,
            0xf44c4000, 0x10a4e3cd, 0x097f5711, 0xde77cc4c]),
        new Int32Array([
            0x121b4000, 0x5b17d9e8, 0x8dfacfab, 0xce36cc72,
            0xe6570000, 0x4bb33a25, 0x848598ba, 0x1041003e]),
        new Int32Array([
            0x97530000, 0x204f6ed3, 0x77b9e80f, 0xa1ec5ec1,
            0x7e792000, 0x9418e22f, 0x6643d258, 0x9c255be5]),
        new Int32Array([
            0xe92a2000, 0xb4578cfc, 0x11fa3a57, 0x3dc90524,
            0x97530000, 0x204f6ed3, 0x77b9e80f, 0xa1ec5ec1]),
        new Int32Array([
            0xcba90000, 0x90273769, 0xbbdcf407, 0xd0f4af61,
            0xbf3c1000, 0xca0c7117, 0x3321e92c, 0xce122df3]),
        new Int32Array([
            0x74951000, 0x5a2b467e, 0x88fd1d2b, 0x1ee68292,
            0xcba90000, 0x90273769, 0xbbdcf407, 0xd0f4af61]),
        new Int32Array([
            0xe18b0000, 0x5459887d, 0xbf1283d3, 0x1b666a73,
            0x3fb90800, 0x7cdad883, 0xce97a914, 0xbdd9f5e5]),
        new Int32Array([
            0xde320800, 0x288350fe, 0x71852ac7, 0xa6bf9f96,
            0xe18b0000, 0x5459887d, 0xbf1283d3, 0x1b666a73]),
        new Int32Array([
            0x14bd0000, 0x2fba37ff, 0x6a72e5bb, 0x247febe6,
            0x9b830400, 0x2227ff88, 0x05b7ad5a, 0xadf2c730]),
        new Int32Array([
            0x8f3e0400, 0x0d9dc877, 0x6fc548e1, 0x898d2cd6,
            0x14bd0000, 0x2fba37ff, 0x6a72e5bb, 0x247febe6]),
        new Int32Array([
            0xee260000, 0x124b683e, 0x80c2d68f, 0x3bf3ab2c,
            0x499e0200, 0x0d59ec0d, 0xe0272f7d, 0xa5e7de5a]),
        new Int32Array([
            0xa7b80200, 0x1f128433, 0x60e5f9f2, 0x9e147576,
            0xee260000, 0x124b683e, 0x80c2d68f, 0x3bf3ab2c]),
        new Int32Array([
            0x734c0000, 0x956fa7d6, 0xa29d1297, 0x6ee56854,
            0xc4e80100, 0x1f70960e, 0x2714ca3c, 0x88210c30]),
        new Int32Array([
            0xb7a40100, 0x8a1f31d8, 0x8589d8ab, 0xe6c46464,
            0x734c0000, 0x956fa7d6, 0xa29d1297, 0x6ee56854]),
        new Int32Array([
            0x39a60000, 0x4ab753eb, 0xd14e094b, 0xb772b42b,
            0x62740080, 0x0fb84b07, 0x138a651e, 0x44100618]),
        new Int32Array([
            0x5bd20080, 0x450f18ec, 0xc2c46c55, 0xf362b233,
            0x39a60000, 0x4ab753eb, 0xd14e094b, 0xb772b42b]),
        new Int32Array([
            0x78ab0000, 0xa0cd5a34, 0x5d5ca0f7, 0x727784cb,
            0x35650040, 0x9b96b64a, 0x6b39cb5f, 0x5114bece]),
        new Int32Array([
            0x4dce0040, 0x3b5bec7e, 0x36656ba8, 0x23633a05,
            0x78ab0000, 0xa0cd5a34, 0x5d5ca0f7, 0x727784cb]),
        new Int32Array([
            0x5c720000, 0xc9bacd12, 0x79a90df9, 0x63e92178,
            0xfeca0020, 0x485d28e4, 0x806741fd, 0x814681b8]),
        new Int32Array([
            0xa2b80020, 0x81e7e5f6, 0xf9ce4c04, 0xe2afa0c0,
            0x5c720000, 0xc9bacd12, 0x79a90df9, 0x63e92178]),
        new Int32Array([
            0x2e390000, 0x64dd6689, 0x3cd406fc, 0xb1f490bc,
            0x7f650010, 0x242e1472, 0xc03320fe, 0xc0a3c0dd]),
        new Int32Array([
            0x515c0010, 0x40f372fb, 0xfce72602, 0x71575061,
            0x2e390000, 0x64dd6689, 0x3cd406fc, 0xb1f490bc]),
        new Int32Array([
            0x171c0000, 0xb26e3344, 0x9e6a837e, 0x58f8485f,
            0xbfb20008, 0x92170a39, 0x6019107f, 0xe051606e]),
        new Int32Array([
            0xa8ae0008, 0x2079397d, 0xfe739301, 0xb8a92831,
            0x171c0000, 0xb26e3344, 0x9e6a837e, 0x58f8485f]),
        new Int32Array([
            0x6ba90000, 0x40ebf9aa, 0x98321c3d, 0x76acc733,
            0xbba10004, 0xcc9d76dd, 0x05f7ac6d, 0xd9e6eee9]),
        new Int32Array([
            0xd0080004, 0x8c768f77, 0x9dc5b050, 0xaf4a29da,
            0x6ba90000, 0x40ebf9aa, 0x98321c3d, 0x76acc733]),
        new Int32Array([
            0x51ac0000, 0x25e30f14, 0x79e22a4c, 0x1298bd46,
            0xd98f0002, 0x7a04a8a7, 0xe007afe6, 0x9fed4ab7]),
        new Int32Array([
            0x88230002, 0x5fe7a7b3, 0x99e585aa, 0x8d75f7f1,
            0x51ac0000, 0x25e30f14, 0x79e22a4c, 0x1298bd46]),
        new Int32Array([
            0xc8f10000, 0x0b2de782, 0x6bf648a4, 0x539cbdbf,
            0x08bf0001, 0x38942792, 0xc5f8f3a1, 0xe6387b84]),
        new Int32Array([
            0xc04e0001, 0x33b9c010, 0xae0ebb05, 0xb5a4c63b,
            0xc8f10000, 0x0b2de782, 0x6bf648a4, 0x539cbdbf])
    ];

    private static makeT(x: number): Int32Array[] {
        const T = new Array(256);
        for (let i = 0; i < T.length; i++) {
            T[i] = new Int32Array(8);
        }
        for (let y = 0; y < 256; y++) {
            for (let z = 0; z < 8; z++) {
                let a = 0;
                for (let k = 0; k < 8; k++) {
                    if ((y & (1 << (7 - k))) != 0){
                        a ^= HamsiSmallCore.Tsrc[x + k][z];
                    }
                }
                T[y][z] = a;
            }
        }
        return T;
    }

    private static T256_0 = HamsiSmallCore.makeT(0);
    private static T256_1 = HamsiSmallCore.makeT(8);
    private static T256_2 = HamsiSmallCore.makeT(16);
    private static T256_3 = HamsiSmallCore.makeT(24);

    private static ALPHA_N = new Int32Array([
        0xff00f0f0, 0xccccaaaa, 0xf0f0cccc, 0xff00aaaa,
        0xccccaaaa, 0xf0f0ff00, 0xaaaacccc, 0xf0f0ff00,
        0xf0f0cccc, 0xaaaaff00, 0xccccff00, 0xaaaaf0f0,
        0xaaaaf0f0, 0xff00cccc, 0xccccf0f0, 0xff00aaaa,
        0xccccaaaa, 0xff00f0f0, 0xff00aaaa, 0xf0f0cccc,
        0xf0f0ff00, 0xccccaaaa, 0xf0f0ff00, 0xaaaacccc,
        0xaaaaff00, 0xf0f0cccc, 0xaaaaf0f0, 0xccccff00,
        0xff00cccc, 0xaaaaf0f0, 0xff00aaaa, 0xccccf0f0
    ]);

    private static ALPHA_F = new Int32Array([
        0xcaf9639c, 0x0ff0f9c0, 0x639c0ff0, 0xcaf9f9c0,
        0x0ff0f9c0, 0x639ccaf9, 0xf9c00ff0, 0x639ccaf9,
        0x639c0ff0, 0xf9c0caf9, 0x0ff0caf9, 0xf9c0639c,
        0xf9c0639c, 0xcaf90ff0, 0x0ff0639c, 0xcaf9f9c0,
        0x0ff0f9c0, 0xcaf9639c, 0xcaf9f9c0, 0x639c0ff0,
        0x639ccaf9, 0x0ff0f9c0, 0x639ccaf9, 0xf9c00ff0,
        0xf9c0caf9, 0x639c0ff0, 0xf9c0639c, 0x0ff0caf9,
        0xcaf90ff0, 0xf9c0639c, 0xcaf9f9c0, 0x0ff0639c
    ]);

    private process(b0: number, b1: number, b2: number, b3: number) {
        const m = new Int32Array(8);
        const c = new Int32Array(8);
        var rp = HamsiSmallCore.T256_0[b0];
        m[0] = rp[0];
        m[1] = rp[1];
        m[2] = rp[2];
        m[3] = rp[3];
        m[4] = rp[4];
        m[5] = rp[5];
        m[6] = rp[6];
        m[7] = rp[7];
        rp = HamsiSmallCore.T256_1[b1];
        m[0] ^= rp[0];
        m[1] ^= rp[1];
        m[2] ^= rp[2];
        m[3] ^= rp[3];
        m[4] ^= rp[4];
        m[5] ^= rp[5];
        m[6] ^= rp[6];
        m[7] ^= rp[7];
        
        rp = HamsiSmallCore.T256_2[b2];
        m[0] ^= rp[0];
        m[1] ^= rp[1];
        m[2] ^= rp[2];
        m[3] ^= rp[3];
        m[4] ^= rp[4];
        m[5] ^= rp[5];
        m[6] ^= rp[6];
        m[7] ^= rp[7];
        rp = HamsiSmallCore.T256_3[b3];
        m[0] ^= rp[0];
        m[1] ^= rp[1];
        m[2] ^= rp[2];
        m[3] ^= rp[3];
        m[4] ^= rp[4];
        m[5] ^= rp[5];
        m[6] ^= rp[6];
        m[7] ^= rp[7];
        
        c[0] = this.h[0];
        c[1] = this.h[1];
        c[2] = this.h[2];
        c[3] = this.h[3];
        c[4] = this.h[4];
        c[5] = this.h[5];
        c[6] = this.h[6];
        c[7] = this.h[7];
        var t;

        m[0] ^= HamsiSmallCore.ALPHA_N[0x00];
        m[1] ^= HamsiSmallCore.ALPHA_N[0x01] ^ 0;
        c[0] ^= HamsiSmallCore.ALPHA_N[0x02];
        c[1] ^= HamsiSmallCore.ALPHA_N[0x03];
        c[2] ^= HamsiSmallCore.ALPHA_N[0x08];
        c[3] ^= HamsiSmallCore.ALPHA_N[0x09];
        m[2] ^= HamsiSmallCore.ALPHA_N[0x0A];
        m[3] ^= HamsiSmallCore.ALPHA_N[0x0B];
        m[4] ^= HamsiSmallCore.ALPHA_N[0x10];
        m[5] ^= HamsiSmallCore.ALPHA_N[0x11];
        c[4] ^= HamsiSmallCore.ALPHA_N[0x12];
        c[5] ^= HamsiSmallCore.ALPHA_N[0x13];
        c[6] ^= HamsiSmallCore.ALPHA_N[0x18];
        c[7] ^= HamsiSmallCore.ALPHA_N[0x19];
        m[6] ^= HamsiSmallCore.ALPHA_N[0x1A];
        m[7] ^= HamsiSmallCore.ALPHA_N[0x1B];
        t = m[0];
        m[0] &= m[4];
        m[0] ^= c[6];
        m[4] ^= c[2];
        m[4] ^= m[0];
        c[6] |= t;
        c[6] ^= c[2];
        t ^= m[4];
        c[2] = c[6];
        c[6] |= t;
        c[6] ^= m[0];
        m[0] &= c[2];
        t ^= m[0];
        c[2] ^= c[6];
        c[2] ^= t;
        m[0] = m[4];
        m[4] = c[2];
        c[2] = c[6];
        c[6] = ~t;
        t = m[1];
        m[1] &= m[5];
        m[1] ^= c[7];
        m[5] ^= c[3];
        m[5] ^= m[1];
        c[7] |= t;
        c[7] ^= c[3];
        t ^= m[5];
        c[3] = c[7];
        c[7] |= t;
        c[7] ^= m[1];
        m[1] &= c[3];
        t ^= m[1];
        c[3] ^= c[7];
        c[3] ^= t;
        m[1] = m[5];
        m[5] = c[3];
        c[3] = c[7];
        c[7] = ~t;
        t = c[0];
        c[0] &= c[4];
        c[0] ^= m[6];
        c[4] ^= m[2];
        c[4] ^= c[0];
        m[6] |= t;
        m[6] ^= m[2];
        t ^= c[4];
        m[2] = m[6];
        m[6] |= t;
        m[6] ^= c[0];
        c[0] &= m[2];
        t ^= c[0];
        m[2] ^= m[6];
        m[2] ^= t;
        c[0] = c[4];
        c[4] = m[2];
        m[2] = m[6];
        m[6] = ~t;
        t = c[1];
        c[1] &= c[5];
        c[1] ^= m[7];
        c[5] ^= m[3];
        c[5] ^= c[1];
        m[7] |= t;
        m[7] ^= m[3];
        t ^= c[5];
        m[3] = m[7];
        m[7] |= t;
        m[7] ^= c[1];
        c[1] &= m[3];
        t ^= c[1];
        m[3] ^= m[7];
        m[3] ^= t;
        c[1] = c[5];
        c[5] = m[3];
        m[3] = m[7];
        m[7] = ~t;
        m[0] = (m[0] << 13) | (m[0] >>> (32 - 13));
        c[4] = (c[4] << 3) | (c[4] >>> (32 - 3));
        c[3] ^= m[0] ^ c[4];
        m[7] ^= c[4] ^ (m[0] << 3);
        c[3] = (c[3] << 1) | (c[3] >>> (32 - 1));
        m[7] = (m[7] << 7) | (m[7] >>> (32 - 7));
        m[0] ^= c[3] ^ m[7];
        c[4] ^= m[7] ^ (c[3] << 7);
        m[0] = (m[0] << 5) | (m[0] >>> (32 - 5));
        c[4] = (c[4] << 22) | (c[4] >>> (32 - 22));
        m[1] = (m[1] << 13) | (m[1] >>> (32 - 13));
        c[5] = (c[5] << 3) | (c[5] >>> (32 - 3));
        m[2] ^= m[1] ^ c[5];
        c[6] ^= c[5] ^ (m[1] << 3);
        m[2] = (m[2] << 1) | (m[2] >>> (32 - 1));
        c[6] = (c[6] << 7) | (c[6] >>> (32 - 7));
        m[1] ^= m[2] ^ c[6];
        c[5] ^= c[6] ^ (m[2] << 7);
        m[1] = (m[1] << 5) | (m[1] >>> (32 - 5));
        c[5] = (c[5] << 22) | (c[5] >>> (32 - 22));
        c[0] = (c[0] << 13) | (c[0] >>> (32 - 13));
        m[4] = (m[4] << 3) | (m[4] >>> (32 - 3));
        m[3] ^= c[0] ^ m[4];
        c[7] ^= m[4] ^ (c[0] << 3);
        m[3] = (m[3] << 1) | (m[3] >>> (32 - 1));
        c[7] = (c[7] << 7) | (c[7] >>> (32 - 7));
        c[0] ^= m[3] ^ c[7];
        m[4] ^= c[7] ^ (m[3] << 7);
        c[0] = (c[0] << 5) | (c[0] >>> (32 - 5));
        m[4] = (m[4] << 22) | (m[4] >>> (32 - 22));
        c[1] = (c[1] << 13) | (c[1] >>> (32 - 13));
        m[5] = (m[5] << 3) | (m[5] >>> (32 - 3));
        c[2] ^= c[1] ^ m[5];
        m[6] ^= m[5] ^ (c[1] << 3);
        c[2] = (c[2] << 1) | (c[2] >>> (32 - 1));
        m[6] = (m[6] << 7) | (m[6] >>> (32 - 7));
        c[1] ^= c[2] ^ m[6];
        m[5] ^= m[6] ^ (c[2] << 7);
        c[1] = (c[1] << 5) | (c[1] >>> (32 - 5));
        m[5] = (m[5] << 22) | (m[5] >>> (32 - 22));
        m[0] ^= HamsiSmallCore.ALPHA_N[0x00];
        m[1] ^= HamsiSmallCore.ALPHA_N[0x01] ^ 1;
        c[0] ^= HamsiSmallCore.ALPHA_N[0x02];
        c[1] ^= HamsiSmallCore.ALPHA_N[0x03];
        c[2] ^= HamsiSmallCore.ALPHA_N[0x08];
        c[3] ^= HamsiSmallCore.ALPHA_N[0x09];
        m[2] ^= HamsiSmallCore.ALPHA_N[0x0A];
        m[3] ^= HamsiSmallCore.ALPHA_N[0x0B];
        m[4] ^= HamsiSmallCore.ALPHA_N[0x10];
        m[5] ^= HamsiSmallCore.ALPHA_N[0x11];
        c[4] ^= HamsiSmallCore.ALPHA_N[0x12];
        c[5] ^= HamsiSmallCore.ALPHA_N[0x13];
        c[6] ^= HamsiSmallCore.ALPHA_N[0x18];
        c[7] ^= HamsiSmallCore.ALPHA_N[0x19];
        m[6] ^= HamsiSmallCore.ALPHA_N[0x1A];
        m[7] ^= HamsiSmallCore.ALPHA_N[0x1B];
        t = m[0];
        m[0] &= m[4];
        m[0] ^= c[6];
        m[4] ^= c[2];
        m[4] ^= m[0];
        c[6] |= t;
        c[6] ^= c[2];
        t ^= m[4];
        c[2] = c[6];
        c[6] |= t;
        c[6] ^= m[0];
        m[0] &= c[2];
        t ^= m[0];
        c[2] ^= c[6];
        c[2] ^= t;
        m[0] = m[4];
        m[4] = c[2];
        c[2] = c[6];
        c[6] = ~t;
        t = m[1];
        m[1] &= m[5];
        m[1] ^= c[7];
        m[5] ^= c[3];
        m[5] ^= m[1];
        c[7] |= t;
        c[7] ^= c[3];
        t ^= m[5];
        c[3] = c[7];
        c[7] |= t;
        c[7] ^= m[1];
        m[1] &= c[3];
        t ^= m[1];
        c[3] ^= c[7];
        c[3] ^= t;
        m[1] = m[5];
        m[5] = c[3];
        c[3] = c[7];
        c[7] = ~t;
        t = c[0];
        c[0] &= c[4];
        c[0] ^= m[6];
        c[4] ^= m[2];
        c[4] ^= c[0];
        m[6] |= t;
        m[6] ^= m[2];
        t ^= c[4];
        m[2] = m[6];
        m[6] |= t;
        m[6] ^= c[0];
        c[0] &= m[2];
        t ^= c[0];
        m[2] ^= m[6];
        m[2] ^= t;
        c[0] = c[4];
        c[4] = m[2];
        m[2] = m[6];
        m[6] = ~t;
        t = c[1];
        c[1] &= c[5];
        c[1] ^= m[7];
        c[5] ^= m[3];
        c[5] ^= c[1];
        m[7] |= t;
        m[7] ^= m[3];
        t ^= c[5];
        m[3] = m[7];
        m[7] |= t;
        m[7] ^= c[1];
        c[1] &= m[3];
        t ^= c[1];
        m[3] ^= m[7];
        m[3] ^= t;
        c[1] = c[5];
        c[5] = m[3];
        m[3] = m[7];
        m[7] = ~t;
        m[0] = (m[0] << 13) | (m[0] >>> (32 - 13));
        c[4] = (c[4] << 3) | (c[4] >>> (32 - 3));
        c[3] ^= m[0] ^ c[4];
        m[7] ^= c[4] ^ (m[0] << 3);
        c[3] = (c[3] << 1) | (c[3] >>> (32 - 1));
        m[7] = (m[7] << 7) | (m[7] >>> (32 - 7));
        m[0] ^= c[3] ^ m[7];
        c[4] ^= m[7] ^ (c[3] << 7);
        m[0] = (m[0] << 5) | (m[0] >>> (32 - 5));
        c[4] = (c[4] << 22) | (c[4] >>> (32 - 22));
        m[1] = (m[1] << 13) | (m[1] >>> (32 - 13));
        c[5] = (c[5] << 3) | (c[5] >>> (32 - 3));
        m[2] ^= m[1] ^ c[5];
        c[6] ^= c[5] ^ (m[1] << 3);
        m[2] = (m[2] << 1) | (m[2] >>> (32 - 1));
        c[6] = (c[6] << 7) | (c[6] >>> (32 - 7));
        m[1] ^= m[2] ^ c[6];
        c[5] ^= c[6] ^ (m[2] << 7);
        m[1] = (m[1] << 5) | (m[1] >>> (32 - 5));
        c[5] = (c[5] << 22) | (c[5] >>> (32 - 22));
        c[0] = (c[0] << 13) | (c[0] >>> (32 - 13));
        m[4] = (m[4] << 3) | (m[4] >>> (32 - 3));
        m[3] ^= c[0] ^ m[4];
        c[7] ^= m[4] ^ (c[0] << 3);
        m[3] = (m[3] << 1) | (m[3] >>> (32 - 1));
        c[7] = (c[7] << 7) | (c[7] >>> (32 - 7));
        c[0] ^= m[3] ^ c[7];
        m[4] ^= c[7] ^ (m[3] << 7);
        c[0] = (c[0] << 5) | (c[0] >>> (32 - 5));
        m[4] = (m[4] << 22) | (m[4] >>> (32 - 22));
        c[1] = (c[1] << 13) | (c[1] >>> (32 - 13));
        m[5] = (m[5] << 3) | (m[5] >>> (32 - 3));
        c[2] ^= c[1] ^ m[5];
        m[6] ^= m[5] ^ (c[1] << 3);
        c[2] = (c[2] << 1) | (c[2] >>> (32 - 1));
        m[6] = (m[6] << 7) | (m[6] >>> (32 - 7));
        c[1] ^= c[2] ^ m[6];
        m[5] ^= m[6] ^ (c[2] << 7);
        c[1] = (c[1] << 5) | (c[1] >>> (32 - 5));
        m[5] = (m[5] << 22) | (m[5] >>> (32 - 22));
        m[0] ^= HamsiSmallCore.ALPHA_N[0x00];
        m[1] ^= HamsiSmallCore.ALPHA_N[0x01] ^ 2;
        c[0] ^= HamsiSmallCore.ALPHA_N[0x02];
        c[1] ^= HamsiSmallCore.ALPHA_N[0x03];
        c[2] ^= HamsiSmallCore.ALPHA_N[0x08];
        c[3] ^= HamsiSmallCore.ALPHA_N[0x09];
        m[2] ^= HamsiSmallCore.ALPHA_N[0x0A];
        m[3] ^= HamsiSmallCore.ALPHA_N[0x0B];
        m[4] ^= HamsiSmallCore.ALPHA_N[0x10];
        m[5] ^= HamsiSmallCore.ALPHA_N[0x11];
        c[4] ^= HamsiSmallCore.ALPHA_N[0x12];
        c[5] ^= HamsiSmallCore.ALPHA_N[0x13];
        c[6] ^= HamsiSmallCore.ALPHA_N[0x18];
        c[7] ^= HamsiSmallCore.ALPHA_N[0x19];
        m[6] ^= HamsiSmallCore.ALPHA_N[0x1A];
        m[7] ^= HamsiSmallCore.ALPHA_N[0x1B];
        t = m[0];
        m[0] &= m[4];
        m[0] ^= c[6];
        m[4] ^= c[2];
        m[4] ^= m[0];
        c[6] |= t;
        c[6] ^= c[2];
        t ^= m[4];
        c[2] = c[6];
        c[6] |= t;
        c[6] ^= m[0];
        m[0] &= c[2];
        t ^= m[0];
        c[2] ^= c[6];
        c[2] ^= t;
        m[0] = m[4];
        m[4] = c[2];
        c[2] = c[6];
        c[6] = ~t;
        t = m[1];
        m[1] &= m[5];
        m[1] ^= c[7];
        m[5] ^= c[3];
        m[5] ^= m[1];
        c[7] |= t;
        c[7] ^= c[3];
        t ^= m[5];
        c[3] = c[7];
        c[7] |= t;
        c[7] ^= m[1];
        m[1] &= c[3];
        t ^= m[1];
        c[3] ^= c[7];
        c[3] ^= t;
        m[1] = m[5];
        m[5] = c[3];
        c[3] = c[7];
        c[7] = ~t;
        t = c[0];
        c[0] &= c[4];
        c[0] ^= m[6];
        c[4] ^= m[2];
        c[4] ^= c[0];
        m[6] |= t;
        m[6] ^= m[2];
        t ^= c[4];
        m[2] = m[6];
        m[6] |= t;
        m[6] ^= c[0];
        c[0] &= m[2];
        t ^= c[0];
        m[2] ^= m[6];
        m[2] ^= t;
        c[0] = c[4];
        c[4] = m[2];
        m[2] = m[6];
        m[6] = ~t;
        t = c[1];
        c[1] &= c[5];
        c[1] ^= m[7];
        c[5] ^= m[3];
        c[5] ^= c[1];
        m[7] |= t;
        m[7] ^= m[3];
        t ^= c[5];
        m[3] = m[7];
        m[7] |= t;
        m[7] ^= c[1];
        c[1] &= m[3];
        t ^= c[1];
        m[3] ^= m[7];
        m[3] ^= t;
        c[1] = c[5];
        c[5] = m[3];
        m[3] = m[7];
        m[7] = ~t;
        m[0] = (m[0] << 13) | (m[0] >>> (32 - 13));
        c[4] = (c[4] << 3) | (c[4] >>> (32 - 3));
        c[3] ^= m[0] ^ c[4];
        m[7] ^= c[4] ^ (m[0] << 3);
        c[3] = (c[3] << 1) | (c[3] >>> (32 - 1));
        m[7] = (m[7] << 7) | (m[7] >>> (32 - 7));
        m[0] ^= c[3] ^ m[7];
        c[4] ^= m[7] ^ (c[3] << 7);
        m[0] = (m[0] << 5) | (m[0] >>> (32 - 5));
        c[4] = (c[4] << 22) | (c[4] >>> (32 - 22));
        m[1] = (m[1] << 13) | (m[1] >>> (32 - 13));
        c[5] = (c[5] << 3) | (c[5] >>> (32 - 3));
        m[2] ^= m[1] ^ c[5];
        c[6] ^= c[5] ^ (m[1] << 3);
        m[2] = (m[2] << 1) | (m[2] >>> (32 - 1));
        c[6] = (c[6] << 7) | (c[6] >>> (32 - 7));
        m[1] ^= m[2] ^ c[6];
        c[5] ^= c[6] ^ (m[2] << 7);
        m[1] = (m[1] << 5) | (m[1] >>> (32 - 5));
        c[5] = (c[5] << 22) | (c[5] >>> (32 - 22));
        c[0] = (c[0] << 13) | (c[0] >>> (32 - 13));
        m[4] = (m[4] << 3) | (m[4] >>> (32 - 3));
        m[3] ^= c[0] ^ m[4];
        c[7] ^= m[4] ^ (c[0] << 3);
        m[3] = (m[3] << 1) | (m[3] >>> (32 - 1));
        c[7] = (c[7] << 7) | (c[7] >>> (32 - 7));
        c[0] ^= m[3] ^ c[7];
        m[4] ^= c[7] ^ (m[3] << 7);
        c[0] = (c[0] << 5) | (c[0] >>> (32 - 5));
        m[4] = (m[4] << 22) | (m[4] >>> (32 - 22));
        c[1] = (c[1] << 13) | (c[1] >>> (32 - 13));
        m[5] = (m[5] << 3) | (m[5] >>> (32 - 3));
        c[2] ^= c[1] ^ m[5];
        m[6] ^= m[5] ^ (c[1] << 3);
        c[2] = (c[2] << 1) | (c[2] >>> (32 - 1));
        m[6] = (m[6] << 7) | (m[6] >>> (32 - 7));
        c[1] ^= c[2] ^ m[6];
        m[5] ^= m[6] ^ (c[2] << 7);
        c[1] = (c[1] << 5) | (c[1] >>> (32 - 5));
        m[5] = (m[5] << 22) | (m[5] >>> (32 - 22));

        this.h[7] ^= c[5];
        this.h[6] ^= c[4];
        this.h[5] ^= m[5];
        this.h[4] ^= m[4];
        this.h[3] ^= c[1];
        this.h[2] ^= c[0];
        this.h[1] ^= m[1];
        this.h[0] ^= m[0];
    }

    private processFinal(b0: number, b1: number, b2: number, b3: number) {
        const m = new Int32Array(8);
        const c = new Int32Array(8);
        var rp = HamsiSmallCore.T256_0[b0];
        m[0] = rp[0];
        m[1] = rp[1];
        m[2] = rp[2];
        m[3] = rp[3];
        m[4] = rp[4];
        m[5] = rp[5];
        m[6] = rp[6];
        m[7] = rp[7];
        rp = HamsiSmallCore.T256_1[b1];
        m[0] ^= rp[0];
        m[1] ^= rp[1];
        m[2] ^= rp[2];
        m[3] ^= rp[3];
        m[4] ^= rp[4];
        m[5] ^= rp[5];
        m[6] ^= rp[6];
        m[7] ^= rp[7];
        rp = HamsiSmallCore.T256_2[b2];
        m[0] ^= rp[0];
        m[1] ^= rp[1];
        m[2] ^= rp[2];
        m[3] ^= rp[3];
        m[4] ^= rp[4];
        m[5] ^= rp[5];
        m[6] ^= rp[6];
        m[7] ^= rp[7];
        rp = HamsiSmallCore.T256_3[b3];
        m[0] ^= rp[0];
        m[1] ^= rp[1];
        m[2] ^= rp[2];
        m[3] ^= rp[3];
        m[4] ^= rp[4];
        m[5] ^= rp[5];
        m[6] ^= rp[6];
        m[7] ^= rp[7];

        c[0] = this.h[0];
        c[1] = this.h[1];
        c[2] = this.h[2];
        c[3] = this.h[3];
        c[4] = this.h[4];
        c[5] = this.h[5];
        c[6] = this.h[6];
        c[7] = this.h[7];
        var t;

        for (let r = 0; r < 6; r++) {
            m[0] ^= HamsiSmallCore.ALPHA_F[0x00];
            m[1] ^= HamsiSmallCore.ALPHA_F[0x01] ^ r;
            c[0] ^= HamsiSmallCore.ALPHA_F[0x02];
            c[1] ^= HamsiSmallCore.ALPHA_F[0x03];
            c[2] ^= HamsiSmallCore.ALPHA_F[0x08];
            c[3] ^= HamsiSmallCore.ALPHA_F[0x09];
            m[2] ^= HamsiSmallCore.ALPHA_F[0x0A];
            m[3] ^= HamsiSmallCore.ALPHA_F[0x0B];
            m[4] ^= HamsiSmallCore.ALPHA_F[0x10];
            m[5] ^= HamsiSmallCore.ALPHA_F[0x11];
            c[4] ^= HamsiSmallCore.ALPHA_F[0x12];
            c[5] ^= HamsiSmallCore.ALPHA_F[0x13];
            c[6] ^= HamsiSmallCore.ALPHA_F[0x18];
            c[7] ^= HamsiSmallCore.ALPHA_F[0x19];
            m[6] ^= HamsiSmallCore.ALPHA_F[0x1A];
            m[7] ^= HamsiSmallCore.ALPHA_F[0x1B];
            t = m[0];
            m[0] &= m[4];
            m[0] ^= c[6];
            m[4] ^= c[2];
            m[4] ^= m[0];
            c[6] |= t;
            c[6] ^= c[2];
            t ^= m[4];
            c[2] = c[6];
            c[6] |= t;
            c[6] ^= m[0];
            m[0] &= c[2];
            t ^= m[0];
            c[2] ^= c[6];
            c[2] ^= t;
            m[0] = m[4];
            m[4] = c[2];
            c[2] = c[6];
            c[6] = ~t;
            t = m[1];
            m[1] &= m[5];
            m[1] ^= c[7];
            m[5] ^= c[3];
            m[5] ^= m[1];
            c[7] |= t;
            c[7] ^= c[3];
            t ^= m[5];
            c[3] = c[7];
            c[7] |= t;
            c[7] ^= m[1];
            m[1] &= c[3];
            t ^= m[1];
            c[3] ^= c[7];
            c[3] ^= t;
            m[1] = m[5];
            m[5] = c[3];
            c[3] = c[7];
            c[7] = ~t;
            t = c[0];
            c[0] &= c[4];
            c[0] ^= m[6];
            c[4] ^= m[2];
            c[4] ^= c[0];
            m[6] |= t;
            m[6] ^= m[2];
            t ^= c[4];
            m[2] = m[6];
            m[6] |= t;
            m[6] ^= c[0];
            c[0] &= m[2];
            t ^= c[0];
            m[2] ^= m[6];
            m[2] ^= t;
            c[0] = c[4];
            c[4] = m[2];
            m[2] = m[6];
            m[6] = ~t;
            t = c[1];
            c[1] &= c[5];
            c[1] ^= m[7];
            c[5] ^= m[3];
            c[5] ^= c[1];
            m[7] |= t;
            m[7] ^= m[3];
            t ^= c[5];
            m[3] = m[7];
            m[7] |= t;
            m[7] ^= c[1];
            c[1] &= m[3];
            t ^= c[1];
            m[3] ^= m[7];
            m[3] ^= t;
            c[1] = c[5];
            c[5] = m[3];
            m[3] = m[7];
            m[7] = ~t;
            m[0] = (m[0] << 13) | (m[0] >>> (32 - 13));
            c[4] = (c[4] << 3) | (c[4] >>> (32 - 3));
            c[3] ^= m[0] ^ c[4];
            m[7] ^= c[4] ^ (m[0] << 3);
            c[3] = (c[3] << 1) | (c[3] >>> (32 - 1));
            m[7] = (m[7] << 7) | (m[7] >>> (32 - 7));
            m[0] ^= c[3] ^ m[7];
            c[4] ^= m[7] ^ (c[3] << 7);
            m[0] = (m[0] << 5) | (m[0] >>> (32 - 5));
            c[4] = (c[4] << 22) | (c[4] >>> (32 - 22));
            m[1] = (m[1] << 13) | (m[1] >>> (32 - 13));
            c[5] = (c[5] << 3) | (c[5] >>> (32 - 3));
            m[2] ^= m[1] ^ c[5];
            c[6] ^= c[5] ^ (m[1] << 3);
            m[2] = (m[2] << 1) | (m[2] >>> (32 - 1));
            c[6] = (c[6] << 7) | (c[6] >>> (32 - 7));
            m[1] ^= m[2] ^ c[6];
            c[5] ^= c[6] ^ (m[2] << 7);
            m[1] = (m[1] << 5) | (m[1] >>> (32 - 5));
            c[5] = (c[5] << 22) | (c[5] >>> (32 - 22));
            c[0] = (c[0] << 13) | (c[0] >>> (32 - 13));
            m[4] = (m[4] << 3) | (m[4] >>> (32 - 3));
            m[3] ^= c[0] ^ m[4];
            c[7] ^= m[4] ^ (c[0] << 3);
            m[3] = (m[3] << 1) | (m[3] >>> (32 - 1));
            c[7] = (c[7] << 7) | (c[7] >>> (32 - 7));
            c[0] ^= m[3] ^ c[7];
            m[4] ^= c[7] ^ (m[3] << 7);
            c[0] = (c[0] << 5) | (c[0] >>> (32 - 5));
            m[4] = (m[4] << 22) | (m[4] >>> (32 - 22));
            c[1] = (c[1] << 13) | (c[1] >>> (32 - 13));
            m[5] = (m[5] << 3) | (m[5] >>> (32 - 3));
            c[2] ^= c[1] ^ m[5];
            m[6] ^= m[5] ^ (c[1] << 3);
            c[2] = (c[2] << 1) | (c[2] >>> (32 - 1));
            m[6] = (m[6] << 7) | (m[6] >>> (32 - 7));
            c[1] ^= c[2] ^ m[6];
            m[5] ^= m[6] ^ (c[2] << 7);
            c[1] = (c[1] << 5) | (c[1] >>> (32 - 5));
            m[5] = (m[5] << 22) | (m[5] >>> (32 - 22));
        }

        this.h[7] ^= c[5];
        this.h[6] ^= c[4];
        this.h[5] ^= m[5];
        this.h[4] ^= m[4];
        this.h[3] ^= c[1];
        this.h[2] ^= c[0];
        this.h[1] ^= m[1];
        this.h[0] ^= m[0];
    }

    /** @see Digest */
    public toString() {
        return "Hamsi-" + (this.getDigestLength() << 3);
    }

    getDigestLength() {
        return 0;
    }
}

/**
 * This class implements Hamsi-384 and Hamsi-512.
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
 * @version   $Revision: 239 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

abstract class HamsiBigCore implements Digest {

	private h!: Int32Array;
	private bitCount!: bigint;
	private partial = BigInt(0);
	private partialLen!: number;

	/**
	 * Create the object.
	 */
	constructor()
	{
		this.h = new Int32Array(16);
		this.reset();
	}

	/** @see Digest */
	public update(inbuf: number | Uint8Array, off?:number, len?:number)
	{
        if (typeof inbuf == "number") {
            this.bitCount += BigInt(8);
            this.partial = BigInt(this.partial << BigInt(8)) | BigInt(inbuf & 0xFF);
            this.partialLen++;
            if (this.partialLen == 8) {
                this.process(
                    Number(this.partial >> BigInt(56) & BigInt(0xFF)),
                    Number(this.partial >> BigInt(48) & BigInt(0xFF)),
                    Number(this.partial >> BigInt(40) & BigInt(0xFF)),
                    Number(this.partial >> BigInt(32) & BigInt(0xFF)),
                    Number(this.partial >> BigInt(24) & BigInt(0xFF)),
                    Number(this.partial >> BigInt(16) & BigInt(0xFF)),
                    Number(this.partial >> BigInt(8 ) & BigInt(0xFF)),
                    Number(this.partial & BigInt(0xFF)));
                this.partialLen = 0;
            }
        } else if(off == undefined || len == undefined){
            this.update(inbuf, 0, inbuf.length);
        } else {
            this.bitCount += BigInt(len << 3);
            if (this.partialLen != 0) {
                while (this.partialLen < 8 && len > 0) {
                    this.partial = (this.partial << BigInt(8)) | BigInt(inbuf[off ++] & 0xFF);
                    this.partialLen++;
                    len--;
                }
                if (this.partialLen < 8)
                    return;
                this.process(
                    Number((this.partial >> BigInt(56))) & 0xFF,
                    Number((this.partial >> BigInt(48))) & 0xFF,
                    Number((this.partial >> BigInt(40))) & 0xFF,
                    Number((this.partial >> BigInt(32))) & 0xFF,
                    Number((this.partial >> BigInt(24))) & 0xFF,
                    Number((this.partial >> BigInt(16))) & 0xFF,
                    Number((this.partial >> BigInt(8 ))) & 0xFF,
                    Number(this.partial) & 0xFF);
                this.partialLen = 0;
            }
            while (len >= 8) {
                this.process(
                    inbuf[off + 0] & 0xFF,
                    inbuf[off + 1] & 0xFF,
                    inbuf[off + 2] & 0xFF,
                    inbuf[off + 3] & 0xFF,
                    inbuf[off + 4] & 0xFF,
                    inbuf[off + 5] & 0xFF,
                    inbuf[off + 6] & 0xFF,
                    inbuf[off + 7] & 0xFF);
                off += 8;
                len -= 8;
            }
            this.partialLen = len;
            while (len -- > 0){
                this.partial = (this.partial <<  BigInt(8)) | BigInt(inbuf[off ++] & 0xFF);
            }
        }
	}

	/** @see Digest */
    digest(): Uint8Array;
    digest(input: Uint8Array): Uint8Array;
    digest(input: Uint8Array, offset: number, len: number): number;
	digest(outbuf?:Uint8Array, off?:number, len?:number): Uint8Array | number
	{
        if (outbuf == undefined) {
            const n = this.getDigestLength();
            const out = new Uint8Array(n);
            this.digest(out, 0, n);
            return out;
        } else if (off == undefined || len == undefined) {
            this.update(outbuf, 0, outbuf.length);
		    return this.digest();
        } else {
            const bitCount = this.bitCount;
            this.update(0x80);
            while (this.partialLen != 0){
                this.update(0x00);
            }
            this.processFinal(
                Number(bitCount >> BigInt(56)) & 0xFF,
                Number(bitCount >> BigInt(48)) & 0xFF,
                Number(bitCount >> BigInt(40)) & 0xFF,
                Number(bitCount >> BigInt(32)) & 0xFF,
                Number(bitCount >> BigInt(24)) & 0xFF,
                Number(bitCount >> BigInt(16)) & 0xFF,
                Number(bitCount >> BigInt(8 )) & 0xFF,
                Number(bitCount) & 0xFF);
            var n = this.getDigestLength();
            if (len > n)
                len = n;
            var ch = 0;
            const hoff = (n == 48) ? HamsiBigCore.HOFF384 : HamsiBigCore.HOFF512;
            for (let i = 0, j = 0; i < len; i ++) {
                if ((i & 3) == 0){
                    ch = this.h[hoff[j++]];
                }
                outbuf[off + i] = (ch >>> 24) & 0xFF;
                ch <<= 8;
            }
            this.reset();
            return len;
        }
	}

	private static HOFF384 = new Int32Array([
		0, 1, 3, 4, 5, 6, 8, 9, 10, 12, 13, 15
    ]);

	private static  HOFF512 = new Int32Array([
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
	]);

	/** @see Digest */
	public reset()
	{
		arraycopy(this.getIV(), 0, this.h, 0, this.h.length);
		this.bitCount = BigInt(0);
		this.partialLen = 0;
	}

	/** @see Digest */
	public copy(): Digest
	{
		const d = this.dup();
		arraycopy(this.h, 0, d.h, 0, this.h.length);
		d.bitCount = this.bitCount;
		d.partial = this.partial;
		d.partialLen = this.partialLen;
		return d;
	}

	/** @see Digest */
	public getBlockLength()
	{
		/*
		 * Private communication from Hamsi designer Ozgul Kucuk:
		 *
		 * << For HMAC you can calculate B = 256*ceil(k / 256)
		 *    (same as CubeHash). >>
		 */
		return -32;
	}

	/**
	 * Get the IV.
	 *
	 * @return  the IV (initial values for the state words)
	 */
	abstract getIV(): Int32Array;

	/**
	 * Create a new instance of the same runtime class than this object.
	 *
	 * @return  the duplicate
	 */
	abstract dup(): HamsiBigCore;

	private static Tsrc = [
		new Int32Array([
          0x466d0c00, 0x08620000, 0xdd5d0000, 0xbadd0000,
		  0x6a927942, 0x441f2b93, 0x218ace6f, 0xbf2c0be2,
		  0x6f299000, 0x6c850000, 0x2f160000, 0x782e0000,
		  0x644c37cd, 0x12dd1cd6, 0xd26a8c36, 0x32219526 ]),
		new Int32Array([
          0x29449c00, 0x64e70000, 0xf24b0000, 0xc2f30000,
		  0x0ede4e8f, 0x56c23745, 0xf3e04259, 0x8d0d9ec4,
		  0x466d0c00, 0x08620000, 0xdd5d0000, 0xbadd0000,
		  0x6a927942, 0x441f2b93, 0x218ace6f, 0xbf2c0be2 ]),
		new Int32Array([
          0x9cbb1800, 0xb0d30000, 0x92510000, 0xed930000,
		  0x593a4345, 0xe114d5f4, 0x430633da, 0x78cace29,
		  0xc8934400, 0x5a3e0000, 0x57870000, 0x4c560000,
		  0xea982435, 0x75b11115, 0x28b67247, 0x2dd1f9ab ]),
		new Int32Array([
          0x54285c00, 0xeaed0000, 0xc5d60000, 0xa1c50000,
		  0xb3a26770, 0x94a5c4e1, 0x6bb0419d, 0x551b3782,
		  0x9cbb1800, 0xb0d30000, 0x92510000, 0xed930000,
		  0x593a4345, 0xe114d5f4, 0x430633da, 0x78cace29 ]),
		new Int32Array([
          0x23671400, 0xc8b90000, 0xf4c70000, 0xfb750000,
		  0x73cd2465, 0xf8a6a549, 0x02c40a3f, 0xdc24e61f,
		  0x373d2800, 0x71500000, 0x95e00000, 0x0a140000,
		  0xbdac1909, 0x48ef9831, 0x456d6d1f, 0x3daac2da ]),
		new Int32Array([
          0x145a3c00, 0xb9e90000, 0x61270000, 0xf1610000,
		  0xce613d6c, 0xb0493d78, 0x47a96720, 0xe18e24c5,
		  0x23671400, 0xc8b90000, 0xf4c70000, 0xfb750000,
		  0x73cd2465, 0xf8a6a549, 0x02c40a3f, 0xdc24e61f ]),
		new Int32Array([
          0xc96b0030, 0xe7250000, 0x2f840000, 0x264f0000,
		  0x08695bf9, 0x6dfcf137, 0x509f6984, 0x9e69af68,
		  0x26600240, 0xddd80000, 0x722a0000, 0x4f060000,
		  0x936667ff, 0x29f944ce, 0x368b63d5, 0x0c26f262 ]),
		new Int32Array([
          0xef0b0270, 0x3afd0000, 0x5dae0000, 0x69490000,
		  0x9b0f3c06, 0x4405b5f9, 0x66140a51, 0x924f5d0a,
		  0xc96b0030, 0xe7250000, 0x2f840000, 0x264f0000,
		  0x08695bf9, 0x6dfcf137, 0x509f6984, 0x9e69af68 ]),
		new Int32Array([
          0xb4370060, 0x0c4c0000, 0x56c20000, 0x5cae0000,
		  0x94541f3f, 0x3b3ef825, 0x1b365f3d, 0xf3d45758,
		  0x5cb00110, 0x913e0000, 0x44190000, 0x888c0000,
		  0x66dc7418, 0x921f1d66, 0x55ceea25, 0x925c44e9 ]),
		new Int32Array([
          0xe8870170, 0x9d720000, 0x12db0000, 0xd4220000,
		  0xf2886b27, 0xa921e543, 0x4ef8b518, 0x618813b1,
		  0xb4370060, 0x0c4c0000, 0x56c20000, 0x5cae0000,
		  0x94541f3f, 0x3b3ef825, 0x1b365f3d, 0xf3d45758 ]),
		new Int32Array([
          0xf46c0050, 0x96180000, 0x14a50000, 0x031f0000,
		  0x42947eb8, 0x66bf7e19, 0x9ca470d2, 0x8a341574,
		  0x832800a0, 0x67420000, 0xe1170000, 0x370b0000,
		  0xcba30034, 0x3c34923c, 0x9767bdcc, 0x450360bf ]),
		new Int32Array([
          0x774400f0, 0xf15a0000, 0xf5b20000, 0x34140000,
		  0x89377e8c, 0x5a8bec25, 0x0bc3cd1e, 0xcf3775cb,
		  0xf46c0050, 0x96180000, 0x14a50000, 0x031f0000,
		  0x42947eb8, 0x66bf7e19, 0x9ca470d2, 0x8a341574 ]),
		new Int32Array([
          0xd46a0000, 0x8dc8c000, 0xa5af0000, 0x4a290000,
		  0xfc4e427a, 0xc9b4866c, 0x98369604, 0xf746c320,
		  0x231f0009, 0x42f40000, 0x66790000, 0x4ebb0000,
		  0xfedb5bd3, 0x315cb0d6, 0xe2b1674a, 0x69505b3a ]),
		new Int32Array([
          0xf7750009, 0xcf3cc000, 0xc3d60000, 0x04920000,
		  0x029519a9, 0xf8e836ba, 0x7a87f14e, 0x9e16981a,
		  0xd46a0000, 0x8dc8c000, 0xa5af0000, 0x4a290000,
		  0xfc4e427a, 0xc9b4866c, 0x98369604, 0xf746c320 ]),
		new Int32Array([
          0xa67f0001, 0x71378000, 0x19fc0000, 0x96db0000,
		  0x3a8b6dfd, 0xebcaaef3, 0x2c6d478f, 0xac8e6c88,
		  0x50ff0004, 0x45744000, 0x3dfb0000, 0x19e60000,
		  0x1bbc5606, 0xe1727b5d, 0xe1a8cc96, 0x7b1bd6b9 ]),
		new Int32Array([
          0xf6800005, 0x3443c000, 0x24070000, 0x8f3d0000,
		  0x21373bfb, 0x0ab8d5ae, 0xcdc58b19, 0xd795ba31,
		  0xa67f0001, 0x71378000, 0x19fc0000, 0x96db0000,
		  0x3a8b6dfd, 0xebcaaef3, 0x2c6d478f, 0xac8e6c88 ]),
		new Int32Array([
          0xeecf0001, 0x6f564000, 0xf33e0000, 0xa79e0000,
		  0xbdb57219, 0xb711ebc5, 0x4a3b40ba, 0xfeabf254,
		  0x9b060002, 0x61468000, 0x221e0000, 0x1d740000,
		  0x36715d27, 0x30495c92, 0xf11336a7, 0xfe1cdc7f ]),
		new Int32Array([
          0x75c90003, 0x0e10c000, 0xd1200000, 0xbaea0000,
		  0x8bc42f3e, 0x8758b757, 0xbb28761d, 0x00b72e2b,
		  0xeecf0001, 0x6f564000, 0xf33e0000, 0xa79e0000,
		  0xbdb57219, 0xb711ebc5, 0x4a3b40ba, 0xfeabf254 ]),
		new Int32Array([
          0xd1660000, 0x1bbc0300, 0x9eec0000, 0xf6940000,
		  0x03024527, 0xcf70fcf2, 0xb4431b17, 0x857f3c2b,
		  0xa4c20000, 0xd9372400, 0x0a480000, 0x66610000,
		  0xf87a12c7, 0x86bef75c, 0xa324df94, 0x2ba05a55 ]),
		new Int32Array([
          0x75a40000, 0xc28b2700, 0x94a40000, 0x90f50000,
		  0xfb7857e0, 0x49ce0bae, 0x1767c483, 0xaedf667e,
		  0xd1660000, 0x1bbc0300, 0x9eec0000, 0xf6940000,
		  0x03024527, 0xcf70fcf2, 0xb4431b17, 0x857f3c2b ]),
		new Int32Array([
          0xb83d0000, 0x16710600, 0x379a0000, 0xf5b10000,
		  0x228161ac, 0xae48f145, 0x66241616, 0xc5c1eb3e,
		  0xfd250000, 0xb3c41100, 0xcef00000, 0xcef90000,
		  0x3c4d7580, 0x8d5b6493, 0x7098b0a6, 0x1af21fe1 ]),
		new Int32Array([
          0x45180000, 0xa5b51700, 0xf96a0000, 0x3b480000,
		  0x1ecc142c, 0x231395d6, 0x16bca6b0, 0xdf33f4df,
		  0xb83d0000, 0x16710600, 0x379a0000, 0xf5b10000,
		  0x228161ac, 0xae48f145, 0x66241616, 0xc5c1eb3e ]),
		new Int32Array([
          0xfe220000, 0xa7580500, 0x25d10000, 0xf7600000,
		  0x893178da, 0x1fd4f860, 0x4ed0a315, 0xa123ff9f,
		  0xf2500000, 0xeebd0a00, 0x67a80000, 0xab8a0000,
		  0xba9b48c0, 0x0a56dd74, 0xdb73e86e, 0x1568ff0f ]),
		new Int32Array([
          0x0c720000, 0x49e50f00, 0x42790000, 0x5cea0000,
		  0x33aa301a, 0x15822514, 0x95a34b7b, 0xb44b0090,
		  0xfe220000, 0xa7580500, 0x25d10000, 0xf7600000,
		  0x893178da, 0x1fd4f860, 0x4ed0a315, 0xa123ff9f ]),
		new Int32Array([
          0xc6730000, 0xaf8d000c, 0xa4c10000, 0x218d0000,
		  0x23111587, 0x7913512f, 0x1d28ac88, 0x378dd173,
		  0xaf220000, 0x7b6c0090, 0x67e20000, 0x8da20000,
		  0xc7841e29, 0xb7b744f3, 0x9ac484f4, 0x8b6c72bd ]),
		new Int32Array([
          0x69510000, 0xd4e1009c, 0xc3230000, 0xac2f0000,
		  0xe4950bae, 0xcea415dc, 0x87ec287c, 0xbce1a3ce,
		  0xc6730000, 0xaf8d000c, 0xa4c10000, 0x218d0000,
		  0x23111587, 0x7913512f, 0x1d28ac88, 0x378dd173 ]),
		new Int32Array([
          0xbc8d0000, 0xfc3b0018, 0x19830000, 0xd10b0000,
		  0xae1878c4, 0x42a69856, 0x0012da37, 0x2c3b504e,
		  0xe8dd0000, 0xfa4a0044, 0x3c2d0000, 0xbb150000,
		  0x80bd361b, 0x24e81d44, 0xbfa8c2f4, 0x524a0d59 ]),
		new Int32Array([
          0x54500000, 0x0671005c, 0x25ae0000, 0x6a1e0000,
		  0x2ea54edf, 0x664e8512, 0xbfba18c3, 0x7e715d17,
		  0xbc8d0000, 0xfc3b0018, 0x19830000, 0xd10b0000,
		  0xae1878c4, 0x42a69856, 0x0012da37, 0x2c3b504e ]),
		new Int32Array([
          0xe3430000, 0x3a4e0014, 0xf2c60000, 0xaa4e0000,
		  0xdb1e42a6, 0x256bbe15, 0x123db156, 0x3a4e99d7,
		  0xf75a0000, 0x19840028, 0xa2190000, 0xeef80000,
		  0xc0722516, 0x19981260, 0x73dba1e6, 0xe1844257 ]),
		new Int32Array([
          0x14190000, 0x23ca003c, 0x50df0000, 0x44b60000,
		  0x1b6c67b0, 0x3cf3ac75, 0x61e610b0, 0xdbcadb80,
		  0xe3430000, 0x3a4e0014, 0xf2c60000, 0xaa4e0000,
		  0xdb1e42a6, 0x256bbe15, 0x123db156, 0x3a4e99d7 ]),
		new Int32Array([
          0x30b70000, 0xe5d00000, 0xf4f46000, 0x42c40000,
		  0x63b83d6a, 0x78ba9460, 0x21afa1ea, 0xb0a51834,
		  0xb6ce0000, 0xdae90002, 0x156e8000, 0xda920000,
		  0xf6dd5a64, 0x36325c8a, 0xf272e8ae, 0xa6b8c28d ]),
		new Int32Array([
          0x86790000, 0x3f390002, 0xe19ae000, 0x98560000,
		  0x9565670e, 0x4e88c8ea, 0xd3dd4944, 0x161ddab9,
		  0x30b70000, 0xe5d00000, 0xf4f46000, 0x42c40000,
		  0x63b83d6a, 0x78ba9460, 0x21afa1ea, 0xb0a51834 ]),
		new Int32Array([
          0xdb250000, 0x09290000, 0x49aac000, 0x81e10000,
		  0xcafe6b59, 0x42793431, 0x43566b76, 0xe86cba2e,
		  0x75e60000, 0x95660001, 0x307b2000, 0xadf40000,
		  0x8f321eea, 0x24298307, 0xe8c49cf9, 0x4b7eec55 ]),
		new Int32Array([
          0xaec30000, 0x9c4f0001, 0x79d1e000, 0x2c150000,
		  0x45cc75b3, 0x6650b736, 0xab92f78f, 0xa312567b,
		  0xdb250000, 0x09290000, 0x49aac000, 0x81e10000,
		  0xcafe6b59, 0x42793431, 0x43566b76, 0xe86cba2e ]),
		new Int32Array([
          0x1e4e0000, 0xdecf0000, 0x6df80180, 0x77240000,
		  0xec47079e, 0xf4a0694e, 0xcda31812, 0x98aa496e,
		  0xb2060000, 0xc5690000, 0x28031200, 0x74670000,
		  0xb6c236f4, 0xeb1239f8, 0x33d1dfec, 0x094e3198 ]),
		new Int32Array([
          0xac480000, 0x1ba60000, 0x45fb1380, 0x03430000,
		  0x5a85316a, 0x1fb250b6, 0xfe72c7fe, 0x91e478f6,
		  0x1e4e0000, 0xdecf0000, 0x6df80180, 0x77240000,
		  0xec47079e, 0xf4a0694e, 0xcda31812, 0x98aa496e ]),
		new Int32Array([
          0x02af0000, 0xb7280000, 0xba1c0300, 0x56980000,
		  0xba8d45d3, 0x8048c667, 0xa95c149a, 0xf4f6ea7b,
		  0x7a8c0000, 0xa5d40000, 0x13260880, 0xc63d0000,
		  0xcbb36daa, 0xfea14f43, 0x59d0b4f8, 0x979961d0 ]),
		new Int32Array([
          0x78230000, 0x12fc0000, 0xa93a0b80, 0x90a50000,
		  0x713e2879, 0x7ee98924, 0xf08ca062, 0x636f8bab,
		  0x02af0000, 0xb7280000, 0xba1c0300, 0x56980000,
		  0xba8d45d3, 0x8048c667, 0xa95c149a, 0xf4f6ea7b ]),
		new Int32Array([
          0x819e0000, 0xec570000, 0x66320280, 0x95f30000,
		  0x5da92802, 0x48f43cbc, 0xe65aa22d, 0x8e67b7fa,
		  0x4d8a0000, 0x49340000, 0x3c8b0500, 0xaea30000,
		  0x16793bfd, 0xcf6f08a4, 0x8f19eaec, 0x443d3004 ]),
		new Int32Array([
          0xcc140000, 0xa5630000, 0x5ab90780, 0x3b500000,
		  0x4bd013ff, 0x879b3418, 0x694348c1, 0xca5a87fe,
		  0x819e0000, 0xec570000, 0x66320280, 0x95f30000,
		  0x5da92802, 0x48f43cbc, 0xe65aa22d, 0x8e67b7fa ]),
		new Int32Array([
          0x538d0000, 0xa9fc0000, 0x9ef70006, 0x56ff0000,
		  0x0ae4004e, 0x92c5cdf9, 0xa9444018, 0x7f975691,
		  0x01dd0000, 0x80a80000, 0xf4960048, 0xa6000000,
		  0x90d57ea2, 0xd7e68c37, 0x6612cffd, 0x2c94459e ]),
		new Int32Array([
          0x52500000, 0x29540000, 0x6a61004e, 0xf0ff0000,
		  0x9a317eec, 0x452341ce, 0xcf568fe5, 0x5303130f,
		  0x538d0000, 0xa9fc0000, 0x9ef70006, 0x56ff0000,
		  0x0ae4004e, 0x92c5cdf9, 0xa9444018, 0x7f975691 ]),
		new Int32Array([
          0x0bc20000, 0xdb630000, 0x7e88000c, 0x15860000,
		  0x91fd48f3, 0x7581bb43, 0xf460449e, 0xd8b61463,
		  0x835a0000, 0xc4f70000, 0x01470022, 0xeec80000,
		  0x60a54f69, 0x142f2a24, 0x5cf534f2, 0x3ea660f7 ]),
		new Int32Array([
          0x88980000, 0x1f940000, 0x7fcf002e, 0xfb4e0000,
		  0xf158079a, 0x61ae9167, 0xa895706c, 0xe6107494,
		  0x0bc20000, 0xdb630000, 0x7e88000c, 0x15860000,
		  0x91fd48f3, 0x7581bb43, 0xf460449e, 0xd8b61463 ]),
		new Int32Array([
          0x07ed0000, 0xb2500000, 0x8774000a, 0x970d0000,
		  0x437223ae, 0x48c76ea4, 0xf4786222, 0x9075b1ce,
		  0xa2d60000, 0xa6760000, 0xc9440014, 0xeba30000,
		  0xccec2e7b, 0x3018c499, 0x03490afa, 0x9b6ef888 ]),
		new Int32Array([
          0xa53b0000, 0x14260000, 0x4e30001e, 0x7cae0000,
		  0x8f9e0dd5, 0x78dfaa3d, 0xf73168d8, 0x0b1b4946,
		  0x07ed0000, 0xb2500000, 0x8774000a, 0x970d0000,
		  0x437223ae, 0x48c76ea4, 0xf4786222, 0x9075b1ce ]),
		new Int32Array([
          0x1d5a0000, 0x2b720000, 0x488d0000, 0xaf611800,
		  0x25cb2ec5, 0xc879bfd0, 0x81a20429, 0x1e7536a6,
		  0x45190000, 0xab0c0000, 0x30be0001, 0x690a2000,
		  0xc2fc7219, 0xb1d4800d, 0x2dd1fa46, 0x24314f17 ]),
		new Int32Array([
          0x58430000, 0x807e0000, 0x78330001, 0xc66b3800,
		  0xe7375cdc, 0x79ad3fdd, 0xac73fe6f, 0x3a4479b1,
		  0x1d5a0000, 0x2b720000, 0x488d0000, 0xaf611800,
		  0x25cb2ec5, 0xc879bfd0, 0x81a20429, 0x1e7536a6 ]),
		new Int32Array([
          0x92560000, 0x1eda0000, 0xea510000, 0xe8b13000,
		  0xa93556a5, 0xebfb6199, 0xb15c2254, 0x33c5244f,
		  0x8c3a0000, 0xda980000, 0x607f0000, 0x54078800,
		  0x85714513, 0x6006b243, 0xdb50399c, 0x8a58e6a4 ]),
		new Int32Array([
          0x1e6c0000, 0xc4420000, 0x8a2e0000, 0xbcb6b800,
		  0x2c4413b6, 0x8bfdd3da, 0x6a0c1bc8, 0xb99dc2eb,
		  0x92560000, 0x1eda0000, 0xea510000, 0xe8b13000,
		  0xa93556a5, 0xebfb6199, 0xb15c2254, 0x33c5244f ]),
		new Int32Array([
          0xbadd0000, 0x13ad0000, 0xb7e70000, 0xf7282800,
		  0xdf45144d, 0x361ac33a, 0xea5a8d14, 0x2a2c18f0,
		  0xb82f0000, 0xb12c0000, 0x30d80000, 0x14445000,
		  0xc15860a2, 0x3127e8ec, 0x2e98bf23, 0x551e3d6e ]),
		new Int32Array([
          0x02f20000, 0xa2810000, 0x873f0000, 0xe36c7800,
		  0x1e1d74ef, 0x073d2bd6, 0xc4c23237, 0x7f32259e,
		  0xbadd0000, 0x13ad0000, 0xb7e70000, 0xf7282800,
		  0xdf45144d, 0x361ac33a, 0xea5a8d14, 0x2a2c18f0 ]),
		new Int32Array([
          0xe3060000, 0xbdc10000, 0x87130000, 0xbff20060,
		  0x2eba0a1a, 0x8db53751, 0x73c5ab06, 0x5bd61539,
		  0x57370000, 0xcaf20000, 0x364e0000, 0xc0220480,
		  0x56186b22, 0x5ca3f40c, 0xa1937f8f, 0x15b961e7 ]),
		new Int32Array([
          0xb4310000, 0x77330000, 0xb15d0000, 0x7fd004e0,
		  0x78a26138, 0xd116c35d, 0xd256d489, 0x4e6f74de,
		  0xe3060000, 0xbdc10000, 0x87130000, 0xbff20060,
		  0x2eba0a1a, 0x8db53751, 0x73c5ab06, 0x5bd61539 ]),
		new Int32Array([
          0xf0c50000, 0x59230000, 0x45820000, 0xe18d00c0,
		  0x3b6d0631, 0xc2ed5699, 0xcbe0fe1c, 0x56a7b19f,
		  0x16ed0000, 0x15680000, 0xedd70000, 0x325d0220,
		  0xe30c3689, 0x5a4ae643, 0xe375f8a8, 0x81fdf908 ]),
		new Int32Array([
          0xe6280000, 0x4c4b0000, 0xa8550000, 0xd3d002e0,
		  0xd86130b8, 0x98a7b0da, 0x289506b4, 0xd75a4897,
		  0xf0c50000, 0x59230000, 0x45820000, 0xe18d00c0,
		  0x3b6d0631, 0xc2ed5699, 0xcbe0fe1c, 0x56a7b19f ]),
		new Int32Array([
          0x7b280000, 0x57420000, 0xa9e50000, 0x634300a0,
		  0x9edb442f, 0x6d9995bb, 0x27f83b03, 0xc7ff60f0,
		  0x95bb0000, 0x81450000, 0x3b240000, 0x48db0140,
		  0x0a8a6c53, 0x56f56eec, 0x62c91877, 0xe7e00a94 ]),
		new Int32Array([
          0xee930000, 0xd6070000, 0x92c10000, 0x2b9801e0,
		  0x9451287c, 0x3b6cfb57, 0x45312374, 0x201f6a64,
		  0x7b280000, 0x57420000, 0xa9e50000, 0x634300a0,
		  0x9edb442f, 0x6d9995bb, 0x27f83b03, 0xc7ff60f0 ]),
		new Int32Array([
          0x00440000, 0x7f480000, 0xda7c0000, 0x2a230001,
		  0x3badc9cc, 0xa9b69c87, 0x030a9e60, 0xbe0a679e,
		  0x5fec0000, 0x294b0000, 0x99d20000, 0x4ed00012,
		  0x1ed34f73, 0xbaa708c9, 0x57140bdf, 0x30aebcf7 ]),
		new Int32Array([
          0x5fa80000, 0x56030000, 0x43ae0000, 0x64f30013,
		  0x257e86bf, 0x1311944e, 0x541e95bf, 0x8ea4db69,
		  0x00440000, 0x7f480000, 0xda7c0000, 0x2a230001,
		  0x3badc9cc, 0xa9b69c87, 0x030a9e60, 0xbe0a679e ]),
		new Int32Array([
          0x92280000, 0xdc850000, 0x57fa0000, 0x56dc0003,
		  0xbae92316, 0x5aefa30c, 0x90cef752, 0x7b1675d7,
		  0x93bb0000, 0x3b070000, 0xba010000, 0x99d00008,
		  0x3739ae4e, 0xe64c1722, 0x96f896b3, 0x2879ebac ]),
		new Int32Array([
          0x01930000, 0xe7820000, 0xedfb0000, 0xcf0c000b,
		  0x8dd08d58, 0xbca3b42e, 0x063661e1, 0x536f9e7b,
		  0x92280000, 0xdc850000, 0x57fa0000, 0x56dc0003,
		  0xbae92316, 0x5aefa30c, 0x90cef752, 0x7b1675d7 ]),
		new Int32Array([
          0xa8da0000, 0x96be0000, 0x5c1d0000, 0x07da0002,
		  0x7d669583, 0x1f98708a, 0xbb668808, 0xda878000,
		  0xabe70000, 0x9e0d0000, 0xaf270000, 0x3d180005,
		  0x2c4f1fd3, 0x74f61695, 0xb5c347eb, 0x3c5dfffe ]),
		new Int32Array([
          0x033d0000, 0x08b30000, 0xf33a0000, 0x3ac20007,
		  0x51298a50, 0x6b6e661f, 0x0ea5cfe3, 0xe6da7ffe,
		  0xa8da0000, 0x96be0000, 0x5c1d0000, 0x07da0002,
		  0x7d669583, 0x1f98708a, 0xbb668808, 0xda878000 ])
        ];

	private static  makeT(x:number)
	{
        const T = new Array(256);
        for (let i = 0; i < T.length; i++) {
            T[i] = new Int32Array(16);
        }
		for (let y = 0; y < 256; y ++) {
			for (let z = 0; z < 16; z ++) {
				let a = 0;
				for (let k = 0; k < 8; k ++) {
					if ((y & (1 << (7 - k))) != 0){
						a ^= this.Tsrc[x + k][z];
                    }
				}
				T[y][z] = a;
			}
		}
		return T;
	}

	private static T512_0 = HamsiBigCore.makeT(0);
	private static T512_1 = HamsiBigCore.makeT(8);
	private static T512_2 = HamsiBigCore.makeT(16);
	private static T512_3 = HamsiBigCore.makeT(24);
	private static T512_4 = HamsiBigCore.makeT(32);
	private static T512_5 = HamsiBigCore.makeT(40);
	private static T512_6 = HamsiBigCore.makeT(48);
	private static T512_7 = HamsiBigCore.makeT(56);

	private static ALPHA_N = new Int32Array([
		0xff00f0f0, 0xccccaaaa, 0xf0f0cccc, 0xff00aaaa,
		0xccccaaaa, 0xf0f0ff00, 0xaaaacccc, 0xf0f0ff00,
		0xf0f0cccc, 0xaaaaff00, 0xccccff00, 0xaaaaf0f0,
		0xaaaaf0f0, 0xff00cccc, 0xccccf0f0, 0xff00aaaa,
		0xccccaaaa, 0xff00f0f0, 0xff00aaaa, 0xf0f0cccc,
		0xf0f0ff00, 0xccccaaaa, 0xf0f0ff00, 0xaaaacccc,
		0xaaaaff00, 0xf0f0cccc, 0xaaaaf0f0, 0xccccff00,
		0xff00cccc, 0xaaaaf0f0, 0xff00aaaa, 0xccccf0f0
    ]);

	private static ALPHA_F = new Int32Array([
		0xcaf9639c, 0x0ff0f9c0, 0x639c0ff0, 0xcaf9f9c0,
		0x0ff0f9c0, 0x639ccaf9, 0xf9c00ff0, 0x639ccaf9,
		0x639c0ff0, 0xf9c0caf9, 0x0ff0caf9, 0xf9c0639c,
		0xf9c0639c, 0xcaf90ff0, 0x0ff0639c, 0xcaf9f9c0,
		0x0ff0f9c0, 0xcaf9639c, 0xcaf9f9c0, 0x639c0ff0,
		0x639ccaf9, 0x0ff0f9c0, 0x639ccaf9, 0xf9c00ff0,
		0xf9c0caf9, 0x639c0ff0, 0xf9c0639c, 0x0ff0caf9,
		0xcaf90ff0, 0xf9c0639c, 0xcaf9f9c0, 0x0ff0639c
    ]);

	private process(b0: number, b1: number, b2: number, b3: number,
		b4: number,  b5: number,  b6: number,  b7: number)
	{
        const m = new Int32Array(16);
        const c = new Int32Array(16);
        const A = 10;
        const B = 11;
        const C = 12;
        const D = 13;
        const E = 14;
        const F = 15;

		var rp = HamsiBigCore.T512_0[b0];
		m[0] = rp[0x0];
		m[1] = rp[0x1];
		m[2] = rp[0x2];
		m[3] = rp[0x3];
		m[4] = rp[0x4];
		m[5] = rp[0x5];
		m[6] = rp[0x6];
		m[7] = rp[0x7];
		m[8] = rp[0x8];
		m[9] = rp[0x9];
		m[A] = rp[0xA];
		m[B] = rp[0xB];
		m[C] = rp[0xC];
		m[D] = rp[0xD];
		m[E] = rp[0xE];
		m[F] = rp[0xF];
		rp = HamsiBigCore.T512_1[b1];
		m[0] ^= rp[0x0];
		m[1] ^= rp[0x1];
		m[2] ^= rp[0x2];
		m[3] ^= rp[0x3];
		m[4] ^= rp[0x4];
		m[5] ^= rp[0x5];
		m[6] ^= rp[0x6];
		m[7] ^= rp[0x7];
		m[8] ^= rp[0x8];
		m[9] ^= rp[0x9];
		m[A] ^= rp[0xA];
		m[B] ^= rp[0xB];
		m[C] ^= rp[0xC];
		m[D] ^= rp[0xD];
		m[E] ^= rp[0xE];
		m[F] ^= rp[0xF];
		rp = HamsiBigCore.T512_2[b2];
		m[0] ^= rp[0x0];
		m[1] ^= rp[0x1];
		m[2] ^= rp[0x2];
		m[3] ^= rp[0x3];
		m[4] ^= rp[0x4];
		m[5] ^= rp[0x5];
		m[6] ^= rp[0x6];
		m[7] ^= rp[0x7];
		m[8] ^= rp[0x8];
		m[9] ^= rp[0x9];
		m[A] ^= rp[0xA];
		m[B] ^= rp[0xB];
		m[C] ^= rp[0xC];
		m[D] ^= rp[0xD];
		m[E] ^= rp[0xE];
		m[F] ^= rp[0xF];
		rp = HamsiBigCore.T512_3[b3];
		m[0] ^= rp[0x0];
		m[1] ^= rp[0x1];
		m[2] ^= rp[0x2];
		m[3] ^= rp[0x3];
		m[4] ^= rp[0x4];
		m[5] ^= rp[0x5];
		m[6] ^= rp[0x6];
		m[7] ^= rp[0x7];
		m[8] ^= rp[0x8];
		m[9] ^= rp[0x9];
		m[A] ^= rp[0xA];
		m[B] ^= rp[0xB];
		m[C] ^= rp[0xC];
		m[D] ^= rp[0xD];
		m[E] ^= rp[0xE];
		m[F] ^= rp[0xF];
		rp = HamsiBigCore.T512_4[b4];
		m[0] ^= rp[0x0];
		m[1] ^= rp[0x1];
		m[2] ^= rp[0x2];
		m[3] ^= rp[0x3];
		m[4] ^= rp[0x4];
		m[5] ^= rp[0x5];
		m[6] ^= rp[0x6];
		m[7] ^= rp[0x7];
		m[8] ^= rp[0x8];
		m[9] ^= rp[0x9];
		m[A] ^= rp[0xA];
		m[B] ^= rp[0xB];
		m[C] ^= rp[0xC];
		m[D] ^= rp[0xD];
		m[E] ^= rp[0xE];
		m[F] ^= rp[0xF];
		rp = HamsiBigCore.T512_5[b5];
		m[0] ^= rp[0x0];
		m[1] ^= rp[0x1];
		m[2] ^= rp[0x2];
		m[3] ^= rp[0x3];
		m[4] ^= rp[0x4];
		m[5] ^= rp[0x5];
		m[6] ^= rp[0x6];
		m[7] ^= rp[0x7];
		m[8] ^= rp[0x8];
		m[9] ^= rp[0x9];
		m[A] ^= rp[0xA];
		m[B] ^= rp[0xB];
		m[C] ^= rp[0xC];
		m[D] ^= rp[0xD];
		m[E] ^= rp[0xE];
		m[F] ^= rp[0xF];
		rp = HamsiBigCore.T512_6[b6];
		m[0] ^= rp[0x0];
		m[1] ^= rp[0x1];
		m[2] ^= rp[0x2];
		m[3] ^= rp[0x3];
		m[4] ^= rp[0x4];
		m[5] ^= rp[0x5];
		m[6] ^= rp[0x6];
		m[7] ^= rp[0x7];
		m[8] ^= rp[0x8];
		m[9] ^= rp[0x9];
		m[A] ^= rp[0xA];
		m[B] ^= rp[0xB];
		m[C] ^= rp[0xC];
		m[D] ^= rp[0xD];
		m[E] ^= rp[0xE];
		m[F] ^= rp[0xF];
		rp = HamsiBigCore.T512_7[b7];
		m[0] ^= rp[0x0];
		m[1] ^= rp[0x1];
		m[2] ^= rp[0x2];
		m[3] ^= rp[0x3];
		m[4] ^= rp[0x4];
		m[5] ^= rp[0x5];
		m[6] ^= rp[0x6];
		m[7] ^= rp[0x7];
		m[8] ^= rp[0x8];
		m[9] ^= rp[0x9];
		m[A] ^= rp[0xA];
		m[B] ^= rp[0xB];
		m[C] ^= rp[0xC];
		m[D] ^= rp[0xD];
		m[E] ^= rp[0xE];
		m[F] ^= rp[0xF];

		c[0] = this.h[0x0];
		c[1] = this.h[0x1];
		c[2] = this.h[0x2];
		c[3] = this.h[0x3];
		c[4] = this.h[0x4];
		c[5] = this.h[0x5];
		c[6] = this.h[0x6];
		c[7] = this.h[0x7];
		c[8] = this.h[0x8];
		c[9] = this.h[0x9];
		c[A] = this.h[0xA];
		c[B] = this.h[0xB];
		c[C] = this.h[0xC];
		c[D] = this.h[0xD];
		c[E] = this.h[0xE];
		c[F] = this.h[0xF];
		var t;

		for (let r = 0; r < 6; r ++) {
			m[0] ^= HamsiBigCore.ALPHA_N[0x00];
			m[1] ^= HamsiBigCore.ALPHA_N[0x01] ^ r;
			c[0] ^= HamsiBigCore.ALPHA_N[0x02];
			c[1] ^= HamsiBigCore.ALPHA_N[0x03];
			m[2] ^= HamsiBigCore.ALPHA_N[0x04];
			m[3] ^= HamsiBigCore.ALPHA_N[0x05];
			c[2] ^= HamsiBigCore.ALPHA_N[0x06];
			c[3] ^= HamsiBigCore.ALPHA_N[0x07];
			c[4] ^= HamsiBigCore.ALPHA_N[0x08];
			c[5] ^= HamsiBigCore.ALPHA_N[0x09];
			m[4] ^= HamsiBigCore.ALPHA_N[0x0A];
			m[5] ^= HamsiBigCore.ALPHA_N[0x0B];
			c[6] ^= HamsiBigCore.ALPHA_N[0x0C];
			c[7] ^= HamsiBigCore.ALPHA_N[0x0D];
			m[6] ^= HamsiBigCore.ALPHA_N[0x0E];
			m[7] ^= HamsiBigCore.ALPHA_N[0x0F];
			m[8] ^= HamsiBigCore.ALPHA_N[0x10];
			m[9] ^= HamsiBigCore.ALPHA_N[0x11];
			c[8] ^= HamsiBigCore.ALPHA_N[0x12];
			c[9] ^= HamsiBigCore.ALPHA_N[0x13];
			m[A] ^= HamsiBigCore.ALPHA_N[0x14];
			m[B] ^= HamsiBigCore.ALPHA_N[0x15];
			c[A] ^= HamsiBigCore.ALPHA_N[0x16];
			c[B] ^= HamsiBigCore.ALPHA_N[0x17];
			c[C] ^= HamsiBigCore.ALPHA_N[0x18];
			c[D] ^= HamsiBigCore.ALPHA_N[0x19];
			m[C] ^= HamsiBigCore.ALPHA_N[0x1A];
			m[D] ^= HamsiBigCore.ALPHA_N[0x1B];
			c[E] ^= HamsiBigCore.ALPHA_N[0x1C];
			c[F] ^= HamsiBigCore.ALPHA_N[0x1D];
			m[E] ^= HamsiBigCore.ALPHA_N[0x1E];
			m[F] ^= HamsiBigCore.ALPHA_N[0x1F];
			t = m[0];
			m[0] &= m[8];
			m[0] ^= c[C];
			m[8] ^= c[4];
			m[8] ^= m[0];
			c[C] |= t;
			c[C] ^= c[4];
			t ^= m[8];
			c[4] = c[C];
			c[C] |= t;
			c[C] ^= m[0];
			m[0] &= c[4];
			t ^= m[0];
			c[4] ^= c[C];
			c[4] ^= t;
			m[0] = m[8];
			m[8] = c[4];
			c[4] = c[C];
			c[C] = ~t;
			t = m[1];
			m[1] &= m[9];
			m[1] ^= c[D];
			m[9] ^= c[5];
			m[9] ^= m[1];
			c[D] |= t;
			c[D] ^= c[5];
			t ^= m[9];
			c[5] = c[D];
			c[D] |= t;
			c[D] ^= m[1];
			m[1] &= c[5];
			t ^= m[1];
			c[5] ^= c[D];
			c[5] ^= t;
			m[1] = m[9];
			m[9] = c[5];
			c[5] = c[D];
			c[D] = ~t;
			t = c[0];
			c[0] &= c[8];
			c[0] ^= m[C];
			c[8] ^= m[4];
			c[8] ^= c[0];
			m[C] |= t;
			m[C] ^= m[4];
			t ^= c[8];
			m[4] = m[C];
			m[C] |= t;
			m[C] ^= c[0];
			c[0] &= m[4];
			t ^= c[0];
			m[4] ^= m[C];
			m[4] ^= t;
			c[0] = c[8];
			c[8] = m[4];
			m[4] = m[C];
			m[C] = ~t;
			t = c[1];
			c[1] &= c[9];
			c[1] ^= m[D];
			c[9] ^= m[5];
			c[9] ^= c[1];
			m[D] |= t;
			m[D] ^= m[5];
			t ^= c[9];
			m[5] = m[D];
			m[D] |= t;
			m[D] ^= c[1];
			c[1] &= m[5];
			t ^= c[1];
			m[5] ^= m[D];
			m[5] ^= t;
			c[1] = c[9];
			c[9] = m[5];
			m[5] = m[D];
			m[D] = ~t;
			t = m[2];
			m[2] &= m[A];
			m[2] ^= c[E];
			m[A] ^= c[6];
			m[A] ^= m[2];
			c[E] |= t;
			c[E] ^= c[6];
			t ^= m[A];
			c[6] = c[E];
			c[E] |= t;
			c[E] ^= m[2];
			m[2] &= c[6];
			t ^= m[2];
			c[6] ^= c[E];
			c[6] ^= t;
			m[2] = m[A];
			m[A] = c[6];
			c[6] = c[E];
			c[E] = ~t;
			t = m[3];
			m[3] &= m[B];
			m[3] ^= c[F];
			m[B] ^= c[7];
			m[B] ^= m[3];
			c[F] |= t;
			c[F] ^= c[7];
			t ^= m[B];
			c[7] = c[F];
			c[F] |= t;
			c[F] ^= m[3];
			m[3] &= c[7];
			t ^= m[3];
			c[7] ^= c[F];
			c[7] ^= t;
			m[3] = m[B];
			m[B] = c[7];
			c[7] = c[F];
			c[F] = ~t;
			t = c[2];
			c[2] &= c[A];
			c[2] ^= m[E];
			c[A] ^= m[6];
			c[A] ^= c[2];
			m[E] |= t;
			m[E] ^= m[6];
			t ^= c[A];
			m[6] = m[E];
			m[E] |= t;
			m[E] ^= c[2];
			c[2] &= m[6];
			t ^= c[2];
			m[6] ^= m[E];
			m[6] ^= t;
			c[2] = c[A];
			c[A] = m[6];
			m[6] = m[E];
			m[E] = ~t;
			t = c[3];
			c[3] &= c[B];
			c[3] ^= m[F];
			c[B] ^= m[7];
			c[B] ^= c[3];
			m[F] |= t;
			m[F] ^= m[7];
			t ^= c[B];
			m[7] = m[F];
			m[F] |= t;
			m[F] ^= c[3];
			c[3] &= m[7];
			t ^= c[3];
			m[7] ^= m[F];
			m[7] ^= t;
			c[3] = c[B];
			c[B] = m[7];
			m[7] = m[F];
			m[F] = ~t;
			m[0] = (m[0] << 13) | (m[0] >>> (32 - 13));
			c[8] = (c[8] << 3) | (c[8] >>> (32 - 3));
			c[5] ^= m[0] ^ c[8];
			m[D] ^= c[8] ^ (m[0] << 3);
			c[5] = (c[5] << 1) | (c[5] >>> (32 - 1));
			m[D] = (m[D] << 7) | (m[D] >>> (32 - 7));
			m[0] ^= c[5] ^ m[D];
			c[8] ^= m[D] ^ (c[5] << 7);
			m[0] = (m[0] << 5) | (m[0] >>> (32 - 5));
			c[8] = (c[8] << 22) | (c[8] >>> (32 - 22));
			m[1] = (m[1] << 13) | (m[1] >>> (32 - 13));
			c[9] = (c[9] << 3) | (c[9] >>> (32 - 3));
			m[4] ^= m[1] ^ c[9];
			c[E] ^= c[9] ^ (m[1] << 3);
			m[4] = (m[4] << 1) | (m[4] >>> (32 - 1));
			c[E] = (c[E] << 7) | (c[E] >>> (32 - 7));
			m[1] ^= m[4] ^ c[E];
			c[9] ^= c[E] ^ (m[4] << 7);
			m[1] = (m[1] << 5) | (m[1] >>> (32 - 5));
			c[9] = (c[9] << 22) | (c[9] >>> (32 - 22));
			c[0] = (c[0] << 13) | (c[0] >>> (32 - 13));
			m[A] = (m[A] << 3) | (m[A] >>> (32 - 3));
			m[5] ^= c[0] ^ m[A];
			c[F] ^= m[A] ^ (c[0] << 3);
			m[5] = (m[5] << 1) | (m[5] >>> (32 - 1));
			c[F] = (c[F] << 7) | (c[F] >>> (32 - 7));
			c[0] ^= m[5] ^ c[F];
			m[A] ^= c[F] ^ (m[5] << 7);
			c[0] = (c[0] << 5) | (c[0] >>> (32 - 5));
			m[A] = (m[A] << 22) | (m[A] >>> (32 - 22));
			c[1] = (c[1] << 13) | (c[1] >>> (32 - 13));
			m[B] = (m[B] << 3) | (m[B] >>> (32 - 3));
			c[6] ^= c[1] ^ m[B];
			m[E] ^= m[B] ^ (c[1] << 3);
			c[6] = (c[6] << 1) | (c[6] >>> (32 - 1));
			m[E] = (m[E] << 7) | (m[E] >>> (32 - 7));
			c[1] ^= c[6] ^ m[E];
			m[B] ^= m[E] ^ (c[6] << 7);
			c[1] = (c[1] << 5) | (c[1] >>> (32 - 5));
			m[B] = (m[B] << 22) | (m[B] >>> (32 - 22));
			m[2] = (m[2] << 13) | (m[2] >>> (32 - 13));
			c[A] = (c[A] << 3) | (c[A] >>> (32 - 3));
			c[7] ^= m[2] ^ c[A];
			m[F] ^= c[A] ^ (m[2] << 3);
			c[7] = (c[7] << 1) | (c[7] >>> (32 - 1));
			m[F] = (m[F] << 7) | (m[F] >>> (32 - 7));
			m[2] ^= c[7] ^ m[F];
			c[A] ^= m[F] ^ (c[7] << 7);
			m[2] = (m[2] << 5) | (m[2] >>> (32 - 5));
			c[A] = (c[A] << 22) | (c[A] >>> (32 - 22));
			m[3] = (m[3] << 13) | (m[3] >>> (32 - 13));
			c[B] = (c[B] << 3) | (c[B] >>> (32 - 3));
			m[6] ^= m[3] ^ c[B];
			c[C] ^= c[B] ^ (m[3] << 3);
			m[6] = (m[6] << 1) | (m[6] >>> (32 - 1));
			c[C] = (c[C] << 7) | (c[C] >>> (32 - 7));
			m[3] ^= m[6] ^ c[C];
			c[B] ^= c[C] ^ (m[6] << 7);
			m[3] = (m[3] << 5) | (m[3] >>> (32 - 5));
			c[B] = (c[B] << 22) | (c[B] >>> (32 - 22));
			c[2] = (c[2] << 13) | (c[2] >>> (32 - 13));
			m[8] = (m[8] << 3) | (m[8] >>> (32 - 3));
			m[7] ^= c[2] ^ m[8];
			c[D] ^= m[8] ^ (c[2] << 3);
			m[7] = (m[7] << 1) | (m[7] >>> (32 - 1));
			c[D] = (c[D] << 7) | (c[D] >>> (32 - 7));
			c[2] ^= m[7] ^ c[D];
			m[8] ^= c[D] ^ (m[7] << 7);
			c[2] = (c[2] << 5) | (c[2] >>> (32 - 5));
			m[8] = (m[8] << 22) | (m[8] >>> (32 - 22));
			c[3] = (c[3] << 13) | (c[3] >>> (32 - 13));
			m[9] = (m[9] << 3) | (m[9] >>> (32 - 3));
			c[4] ^= c[3] ^ m[9];
			m[C] ^= m[9] ^ (c[3] << 3);
			c[4] = (c[4] << 1) | (c[4] >>> (32 - 1));
			m[C] = (m[C] << 7) | (m[C] >>> (32 - 7));
			c[3] ^= c[4] ^ m[C];
			m[9] ^= m[C] ^ (c[4] << 7);
			c[3] = (c[3] << 5) | (c[3] >>> (32 - 5));
			m[9] = (m[9] << 22) | (m[9] >>> (32 - 22));
			m[0] = (m[0] << 13) | (m[0] >>> (32 - 13));
			m[3] = (m[3] << 3) | (m[3] >>> (32 - 3));
			c[0] ^= m[0] ^ m[3];
			c[3] ^= m[3] ^ (m[0] << 3);
			c[0] = (c[0] << 1) | (c[0] >>> (32 - 1));
			c[3] = (c[3] << 7) | (c[3] >>> (32 - 7));
			m[0] ^= c[0] ^ c[3];
			m[3] ^= c[3] ^ (c[0] << 7);
			m[0] = (m[0] << 5) | (m[0] >>> (32 - 5));
			m[3] = (m[3] << 22) | (m[3] >>> (32 - 22));
			m[8] = (m[8] << 13) | (m[8] >>> (32 - 13));
			m[B] = (m[B] << 3) | (m[B] >>> (32 - 3));
			c[9] ^= m[8] ^ m[B];
			c[A] ^= m[B] ^ (m[8] << 3);
			c[9] = (c[9] << 1) | (c[9] >>> (32 - 1));
			c[A] = (c[A] << 7) | (c[A] >>> (32 - 7));
			m[8] ^= c[9] ^ c[A];
			m[B] ^= c[A] ^ (c[9] << 7);
			m[8] = (m[8] << 5) | (m[8] >>> (32 - 5));
			m[B] = (m[B] << 22) | (m[B] >>> (32 - 22));
			c[5] = (c[5] << 13) | (c[5] >>> (32 - 13));
			c[6] = (c[6] << 3) | (c[6] >>> (32 - 3));
			m[5] ^= c[5] ^ c[6];
			m[6] ^= c[6] ^ (c[5] << 3);
			m[5] = (m[5] << 1) | (m[5] >>> (32 - 1));
			m[6] = (m[6] << 7) | (m[6] >>> (32 - 7));
			c[5] ^= m[5] ^ m[6];
			c[6] ^= m[6] ^ (m[5] << 7);
			c[5] = (c[5] << 5) | (c[5] >>> (32 - 5));
			c[6] = (c[6] << 22) | (c[6] >>> (32 - 22));
			c[D] = (c[D] << 13) | (c[D] >>> (32 - 13));
			c[E] = (c[E] << 3) | (c[E] >>> (32 - 3));
			m[C] ^= c[D] ^ c[E];
			m[F] ^= c[E] ^ (c[D] << 3);
			m[C] = (m[C] << 1) | (m[C] >>> (32 - 1));
			m[F] = (m[F] << 7) | (m[F] >>> (32 - 7));
			c[D] ^= m[C] ^ m[F];
			c[E] ^= m[F] ^ (m[C] << 7);
			c[D] = (c[D] << 5) | (c[D] >>> (32 - 5));
			c[E] = (c[E] << 22) | (c[E] >>> (32 - 22));
		}

		this.h[0xF] ^= c[B];
		this.h[0xE] ^= c[A];
		this.h[0xD] ^= m[B];
		this.h[0xC] ^= m[A];
		this.h[0xB] ^= c[9];
		this.h[0xA] ^= c[8];
		this.h[0x9] ^= m[9];
		this.h[0x8] ^= m[8];
		this.h[0x7] ^= c[3];
		this.h[0x6] ^= c[2];
		this.h[0x5] ^= m[3];
		this.h[0x4] ^= m[2];
		this.h[0x3] ^= c[1];
		this.h[0x2] ^= c[0];
		this.h[0x1] ^= m[1];
		this.h[0x0] ^= m[0];
	}

	private processFinal(b0: number, b1: number, b2: number, b3: number,
		b4: number,  b5: number,  b6: number,  b7: number)
	{
        const m = new Int32Array(16);
        const c = new Int32Array(16);
        const A = 10;
        const B = 11;
        const C = 12;
        const D = 13;
        const E = 14;
        const F = 15;

		var rp = HamsiBigCore.T512_0[b0];
		m[0] = rp[0x0];
		m[1] = rp[0x1];
		m[2] = rp[0x2];
		m[3] = rp[0x3];
		m[4] = rp[0x4];
		m[5] = rp[0x5];
		m[6] = rp[0x6];
		m[7] = rp[0x7];
		m[8] = rp[0x8];
		m[9] = rp[0x9];
		m[A] = rp[0xA];
		m[B] = rp[0xB];
		m[C] = rp[0xC];
		m[D] = rp[0xD];
		m[E] = rp[0xE];
		m[F] = rp[0xF];
		rp = HamsiBigCore.T512_1[b1];
		m[0] ^= rp[0x0];
		m[1] ^= rp[0x1];
		m[2] ^= rp[0x2];
		m[3] ^= rp[0x3];
		m[4] ^= rp[0x4];
		m[5] ^= rp[0x5];
		m[6] ^= rp[0x6];
		m[7] ^= rp[0x7];
		m[8] ^= rp[0x8];
		m[9] ^= rp[0x9];
		m[A] ^= rp[0xA];
		m[B] ^= rp[0xB];
		m[C] ^= rp[0xC];
		m[D] ^= rp[0xD];
		m[E] ^= rp[0xE];
		m[F] ^= rp[0xF];
		rp = HamsiBigCore.T512_2[b2];
		m[0] ^= rp[0x0];
		m[1] ^= rp[0x1];
		m[2] ^= rp[0x2];
		m[3] ^= rp[0x3];
		m[4] ^= rp[0x4];
		m[5] ^= rp[0x5];
		m[6] ^= rp[0x6];
		m[7] ^= rp[0x7];
		m[8] ^= rp[0x8];
		m[9] ^= rp[0x9];
		m[A] ^= rp[0xA];
		m[B] ^= rp[0xB];
		m[C] ^= rp[0xC];
		m[D] ^= rp[0xD];
		m[E] ^= rp[0xE];
		m[F] ^= rp[0xF];
		rp = HamsiBigCore.T512_3[b3];
		m[0] ^= rp[0x0];
		m[1] ^= rp[0x1];
		m[2] ^= rp[0x2];
		m[3] ^= rp[0x3];
		m[4] ^= rp[0x4];
		m[5] ^= rp[0x5];
		m[6] ^= rp[0x6];
		m[7] ^= rp[0x7];
		m[8] ^= rp[0x8];
		m[9] ^= rp[0x9];
		m[A] ^= rp[0xA];
		m[B] ^= rp[0xB];
		m[C] ^= rp[0xC];
		m[D] ^= rp[0xD];
		m[E] ^= rp[0xE];
		m[F] ^= rp[0xF];
		rp = HamsiBigCore.T512_4[b4];
		m[0] ^= rp[0x0];
		m[1] ^= rp[0x1];
		m[2] ^= rp[0x2];
		m[3] ^= rp[0x3];
		m[4] ^= rp[0x4];
		m[5] ^= rp[0x5];
		m[6] ^= rp[0x6];
		m[7] ^= rp[0x7];
		m[8] ^= rp[0x8];
		m[9] ^= rp[0x9];
		m[A] ^= rp[0xA];
		m[B] ^= rp[0xB];
		m[C] ^= rp[0xC];
		m[D] ^= rp[0xD];
		m[E] ^= rp[0xE];
		m[F] ^= rp[0xF];
		rp = HamsiBigCore.T512_5[b5];
		m[0] ^= rp[0x0];
		m[1] ^= rp[0x1];
		m[2] ^= rp[0x2];
		m[3] ^= rp[0x3];
		m[4] ^= rp[0x4];
		m[5] ^= rp[0x5];
		m[6] ^= rp[0x6];
		m[7] ^= rp[0x7];
		m[8] ^= rp[0x8];
		m[9] ^= rp[0x9];
		m[A] ^= rp[0xA];
		m[B] ^= rp[0xB];
		m[C] ^= rp[0xC];
		m[D] ^= rp[0xD];
		m[E] ^= rp[0xE];
		m[F] ^= rp[0xF];
		rp = HamsiBigCore.T512_6[b6];
		m[0] ^= rp[0x0];
		m[1] ^= rp[0x1];
		m[2] ^= rp[0x2];
		m[3] ^= rp[0x3];
		m[4] ^= rp[0x4];
		m[5] ^= rp[0x5];
		m[6] ^= rp[0x6];
		m[7] ^= rp[0x7];
		m[8] ^= rp[0x8];
		m[9] ^= rp[0x9];
		m[A] ^= rp[0xA];
		m[B] ^= rp[0xB];
		m[C] ^= rp[0xC];
		m[D] ^= rp[0xD];
		m[E] ^= rp[0xE];
		m[F] ^= rp[0xF];
		rp = HamsiBigCore.T512_7[b7];
		m[0] ^= rp[0x0];
		m[1] ^= rp[0x1];
		m[2] ^= rp[0x2];
		m[3] ^= rp[0x3];
		m[4] ^= rp[0x4];
		m[5] ^= rp[0x5];
		m[6] ^= rp[0x6];
		m[7] ^= rp[0x7];
		m[8] ^= rp[0x8];
		m[9] ^= rp[0x9];
		m[A] ^= rp[0xA];
		m[B] ^= rp[0xB];
		m[C] ^= rp[0xC];
		m[D] ^= rp[0xD];
		m[E] ^= rp[0xE];
		m[F] ^= rp[0xF];

		c[0] = this.h[0x0];
		c[1] = this.h[0x1];
		c[2] = this.h[0x2];
		c[3] = this.h[0x3];
		c[4] = this.h[0x4];
		c[5] = this.h[0x5];
		c[6] = this.h[0x6];
		c[7] = this.h[0x7];
		c[8] = this.h[0x8];
		c[9] = this.h[0x9];
		c[A] = this.h[0xA];
		c[B] = this.h[0xB];
		c[C] = this.h[0xC];
		c[D] = this.h[0xD];
		c[E] = this.h[0xE];
		c[F] = this.h[0xF];
		var t;

		for (let r = 0; r < 12; r ++) {
			m[0] ^= HamsiBigCore.ALPHA_F[0x00];
			m[1] ^= HamsiBigCore.ALPHA_F[0x01] ^ r;
			c[0] ^= HamsiBigCore.ALPHA_F[0x02];
			c[1] ^= HamsiBigCore.ALPHA_F[0x03];
			m[2] ^= HamsiBigCore.ALPHA_F[0x04];
			m[3] ^= HamsiBigCore.ALPHA_F[0x05];
			c[2] ^= HamsiBigCore.ALPHA_F[0x06];
			c[3] ^= HamsiBigCore.ALPHA_F[0x07];
			c[4] ^= HamsiBigCore.ALPHA_F[0x08];
			c[5] ^= HamsiBigCore.ALPHA_F[0x09];
			m[4] ^= HamsiBigCore.ALPHA_F[0x0A];
			m[5] ^= HamsiBigCore.ALPHA_F[0x0B];
			c[6] ^= HamsiBigCore.ALPHA_F[0x0C];
			c[7] ^= HamsiBigCore.ALPHA_F[0x0D];
			m[6] ^= HamsiBigCore.ALPHA_F[0x0E];
			m[7] ^= HamsiBigCore.ALPHA_F[0x0F];
			m[8] ^= HamsiBigCore.ALPHA_F[0x10];
			m[9] ^= HamsiBigCore.ALPHA_F[0x11];
			c[8] ^= HamsiBigCore.ALPHA_F[0x12];
			c[9] ^= HamsiBigCore.ALPHA_F[0x13];
			m[A] ^= HamsiBigCore.ALPHA_F[0x14];
			m[B] ^= HamsiBigCore.ALPHA_F[0x15];
			c[A] ^= HamsiBigCore.ALPHA_F[0x16];
			c[B] ^= HamsiBigCore.ALPHA_F[0x17];
			c[C] ^= HamsiBigCore.ALPHA_F[0x18];
			c[D] ^= HamsiBigCore.ALPHA_F[0x19];
			m[C] ^= HamsiBigCore.ALPHA_F[0x1A];
			m[D] ^= HamsiBigCore.ALPHA_F[0x1B];
			c[E] ^= HamsiBigCore.ALPHA_F[0x1C];
			c[F] ^= HamsiBigCore.ALPHA_F[0x1D];
			m[E] ^= HamsiBigCore.ALPHA_F[0x1E];
			m[F] ^= HamsiBigCore.ALPHA_F[0x1F];
			t = m[0];
			m[0] &= m[8];
			m[0] ^= c[C];
			m[8] ^= c[4];
			m[8] ^= m[0];
			c[C] |= t;
			c[C] ^= c[4];
			t ^= m[8];
			c[4] = c[C];
			c[C] |= t;
			c[C] ^= m[0];
			m[0] &= c[4];
			t ^= m[0];
			c[4] ^= c[C];
			c[4] ^= t;
			m[0] = m[8];
			m[8] = c[4];
			c[4] = c[C];
			c[C] = ~t;
			t = m[1];
			m[1] &= m[9];
			m[1] ^= c[D];
			m[9] ^= c[5];
			m[9] ^= m[1];
			c[D] |= t;
			c[D] ^= c[5];
			t ^= m[9];
			c[5] = c[D];
			c[D] |= t;
			c[D] ^= m[1];
			m[1] &= c[5];
			t ^= m[1];
			c[5] ^= c[D];
			c[5] ^= t;
			m[1] = m[9];
			m[9] = c[5];
			c[5] = c[D];
			c[D] = ~t;
			t = c[0];
			c[0] &= c[8];
			c[0] ^= m[C];
			c[8] ^= m[4];
			c[8] ^= c[0];
			m[C] |= t;
			m[C] ^= m[4];
			t ^= c[8];
			m[4] = m[C];
			m[C] |= t;
			m[C] ^= c[0];
			c[0] &= m[4];
			t ^= c[0];
			m[4] ^= m[C];
			m[4] ^= t;
			c[0] = c[8];
			c[8] = m[4];
			m[4] = m[C];
			m[C] = ~t;
			t = c[1];
			c[1] &= c[9];
			c[1] ^= m[D];
			c[9] ^= m[5];
			c[9] ^= c[1];
			m[D] |= t;
			m[D] ^= m[5];
			t ^= c[9];
			m[5] = m[D];
			m[D] |= t;
			m[D] ^= c[1];
			c[1] &= m[5];
			t ^= c[1];
			m[5] ^= m[D];
			m[5] ^= t;
			c[1] = c[9];
			c[9] = m[5];
			m[5] = m[D];
			m[D] = ~t;
			t = m[2];
			m[2] &= m[A];
			m[2] ^= c[E];
			m[A] ^= c[6];
			m[A] ^= m[2];
			c[E] |= t;
			c[E] ^= c[6];
			t ^= m[A];
			c[6] = c[E];
			c[E] |= t;
			c[E] ^= m[2];
			m[2] &= c[6];
			t ^= m[2];
			c[6] ^= c[E];
			c[6] ^= t;
			m[2] = m[A];
			m[A] = c[6];
			c[6] = c[E];
			c[E] = ~t;
			t = m[3];
			m[3] &= m[B];
			m[3] ^= c[F];
			m[B] ^= c[7];
			m[B] ^= m[3];
			c[F] |= t;
			c[F] ^= c[7];
			t ^= m[B];
			c[7] = c[F];
			c[F] |= t;
			c[F] ^= m[3];
			m[3] &= c[7];
			t ^= m[3];
			c[7] ^= c[F];
			c[7] ^= t;
			m[3] = m[B];
			m[B] = c[7];
			c[7] = c[F];
			c[F] = ~t;
			t = c[2];
			c[2] &= c[A];
			c[2] ^= m[E];
			c[A] ^= m[6];
			c[A] ^= c[2];
			m[E] |= t;
			m[E] ^= m[6];
			t ^= c[A];
			m[6] = m[E];
			m[E] |= t;
			m[E] ^= c[2];
			c[2] &= m[6];
			t ^= c[2];
			m[6] ^= m[E];
			m[6] ^= t;
			c[2] = c[A];
			c[A] = m[6];
			m[6] = m[E];
			m[E] = ~t;
			t = c[3];
			c[3] &= c[B];
			c[3] ^= m[F];
			c[B] ^= m[7];
			c[B] ^= c[3];
			m[F] |= t;
			m[F] ^= m[7];
			t ^= c[B];
			m[7] = m[F];
			m[F] |= t;
			m[F] ^= c[3];
			c[3] &= m[7];
			t ^= c[3];
			m[7] ^= m[F];
			m[7] ^= t;
			c[3] = c[B];
			c[B] = m[7];
			m[7] = m[F];
			m[F] = ~t;
			m[0] = (m[0] << 13) | (m[0] >>> (32 - 13));
			c[8] = (c[8] << 3) | (c[8] >>> (32 - 3));
			c[5] ^= m[0] ^ c[8];
			m[D] ^= c[8] ^ (m[0] << 3);
			c[5] = (c[5] << 1) | (c[5] >>> (32 - 1));
			m[D] = (m[D] << 7) | (m[D] >>> (32 - 7));
			m[0] ^= c[5] ^ m[D];
			c[8] ^= m[D] ^ (c[5] << 7);
			m[0] = (m[0] << 5) | (m[0] >>> (32 - 5));
			c[8] = (c[8] << 22) | (c[8] >>> (32 - 22));
			m[1] = (m[1] << 13) | (m[1] >>> (32 - 13));
			c[9] = (c[9] << 3) | (c[9] >>> (32 - 3));
			m[4] ^= m[1] ^ c[9];
			c[E] ^= c[9] ^ (m[1] << 3);
			m[4] = (m[4] << 1) | (m[4] >>> (32 - 1));
			c[E] = (c[E] << 7) | (c[E] >>> (32 - 7));
			m[1] ^= m[4] ^ c[E];
			c[9] ^= c[E] ^ (m[4] << 7);
			m[1] = (m[1] << 5) | (m[1] >>> (32 - 5));
			c[9] = (c[9] << 22) | (c[9] >>> (32 - 22));
			c[0] = (c[0] << 13) | (c[0] >>> (32 - 13));
			m[A] = (m[A] << 3) | (m[A] >>> (32 - 3));
			m[5] ^= c[0] ^ m[A];
			c[F] ^= m[A] ^ (c[0] << 3);
			m[5] = (m[5] << 1) | (m[5] >>> (32 - 1));
			c[F] = (c[F] << 7) | (c[F] >>> (32 - 7));
			c[0] ^= m[5] ^ c[F];
			m[A] ^= c[F] ^ (m[5] << 7);
			c[0] = (c[0] << 5) | (c[0] >>> (32 - 5));
			m[A] = (m[A] << 22) | (m[A] >>> (32 - 22));
			c[1] = (c[1] << 13) | (c[1] >>> (32 - 13));
			m[B] = (m[B] << 3) | (m[B] >>> (32 - 3));
			c[6] ^= c[1] ^ m[B];
			m[E] ^= m[B] ^ (c[1] << 3);
			c[6] = (c[6] << 1) | (c[6] >>> (32 - 1));
			m[E] = (m[E] << 7) | (m[E] >>> (32 - 7));
			c[1] ^= c[6] ^ m[E];
			m[B] ^= m[E] ^ (c[6] << 7);
			c[1] = (c[1] << 5) | (c[1] >>> (32 - 5));
			m[B] = (m[B] << 22) | (m[B] >>> (32 - 22));
			m[2] = (m[2] << 13) | (m[2] >>> (32 - 13));
			c[A] = (c[A] << 3) | (c[A] >>> (32 - 3));
			c[7] ^= m[2] ^ c[A];
			m[F] ^= c[A] ^ (m[2] << 3);
			c[7] = (c[7] << 1) | (c[7] >>> (32 - 1));
			m[F] = (m[F] << 7) | (m[F] >>> (32 - 7));
			m[2] ^= c[7] ^ m[F];
			c[A] ^= m[F] ^ (c[7] << 7);
			m[2] = (m[2] << 5) | (m[2] >>> (32 - 5));
			c[A] = (c[A] << 22) | (c[A] >>> (32 - 22));
			m[3] = (m[3] << 13) | (m[3] >>> (32 - 13));
			c[B] = (c[B] << 3) | (c[B] >>> (32 - 3));
			m[6] ^= m[3] ^ c[B];
			c[C] ^= c[B] ^ (m[3] << 3);
			m[6] = (m[6] << 1) | (m[6] >>> (32 - 1));
			c[C] = (c[C] << 7) | (c[C] >>> (32 - 7));
			m[3] ^= m[6] ^ c[C];
			c[B] ^= c[C] ^ (m[6] << 7);
			m[3] = (m[3] << 5) | (m[3] >>> (32 - 5));
			c[B] = (c[B] << 22) | (c[B] >>> (32 - 22));
			c[2] = (c[2] << 13) | (c[2] >>> (32 - 13));
			m[8] = (m[8] << 3) | (m[8] >>> (32 - 3));
			m[7] ^= c[2] ^ m[8];
			c[D] ^= m[8] ^ (c[2] << 3);
			m[7] = (m[7] << 1) | (m[7] >>> (32 - 1));
			c[D] = (c[D] << 7) | (c[D] >>> (32 - 7));
			c[2] ^= m[7] ^ c[D];
			m[8] ^= c[D] ^ (m[7] << 7);
			c[2] = (c[2] << 5) | (c[2] >>> (32 - 5));
			m[8] = (m[8] << 22) | (m[8] >>> (32 - 22));
			c[3] = (c[3] << 13) | (c[3] >>> (32 - 13));
			m[9] = (m[9] << 3) | (m[9] >>> (32 - 3));
			c[4] ^= c[3] ^ m[9];
			m[C] ^= m[9] ^ (c[3] << 3);
			c[4] = (c[4] << 1) | (c[4] >>> (32 - 1));
			m[C] = (m[C] << 7) | (m[C] >>> (32 - 7));
			c[3] ^= c[4] ^ m[C];
			m[9] ^= m[C] ^ (c[4] << 7);
			c[3] = (c[3] << 5) | (c[3] >>> (32 - 5));
			m[9] = (m[9] << 22) | (m[9] >>> (32 - 22));
			m[0] = (m[0] << 13) | (m[0] >>> (32 - 13));
			m[3] = (m[3] << 3) | (m[3] >>> (32 - 3));
			c[0] ^= m[0] ^ m[3];
			c[3] ^= m[3] ^ (m[0] << 3);
			c[0] = (c[0] << 1) | (c[0] >>> (32 - 1));
			c[3] = (c[3] << 7) | (c[3] >>> (32 - 7));
			m[0] ^= c[0] ^ c[3];
			m[3] ^= c[3] ^ (c[0] << 7);
			m[0] = (m[0] << 5) | (m[0] >>> (32 - 5));
			m[3] = (m[3] << 22) | (m[3] >>> (32 - 22));
			m[8] = (m[8] << 13) | (m[8] >>> (32 - 13));
			m[B] = (m[B] << 3) | (m[B] >>> (32 - 3));
			c[9] ^= m[8] ^ m[B];
			c[A] ^= m[B] ^ (m[8] << 3);
			c[9] = (c[9] << 1) | (c[9] >>> (32 - 1));
			c[A] = (c[A] << 7) | (c[A] >>> (32 - 7));
			m[8] ^= c[9] ^ c[A];
			m[B] ^= c[A] ^ (c[9] << 7);
			m[8] = (m[8] << 5) | (m[8] >>> (32 - 5));
			m[B] = (m[B] << 22) | (m[B] >>> (32 - 22));
			c[5] = (c[5] << 13) | (c[5] >>> (32 - 13));
			c[6] = (c[6] << 3) | (c[6] >>> (32 - 3));
			m[5] ^= c[5] ^ c[6];
			m[6] ^= c[6] ^ (c[5] << 3);
			m[5] = (m[5] << 1) | (m[5] >>> (32 - 1));
			m[6] = (m[6] << 7) | (m[6] >>> (32 - 7));
			c[5] ^= m[5] ^ m[6];
			c[6] ^= m[6] ^ (m[5] << 7);
			c[5] = (c[5] << 5) | (c[5] >>> (32 - 5));
			c[6] = (c[6] << 22) | (c[6] >>> (32 - 22));
			c[D] = (c[D] << 13) | (c[D] >>> (32 - 13));
			c[E] = (c[E] << 3) | (c[E] >>> (32 - 3));
			m[C] ^= c[D] ^ c[E];
			m[F] ^= c[E] ^ (c[D] << 3);
			m[C] = (m[C] << 1) | (m[C] >>> (32 - 1));
			m[F] = (m[F] << 7) | (m[F] >>> (32 - 7));
			c[D] ^= m[C] ^ m[F];
			c[E] ^= m[F] ^ (m[C] << 7);
			c[D] = (c[D] << 5) | (c[D] >>> (32 - 5));
			c[E] = (c[E] << 22) | (c[E] >>> (32 - 22));
		}

		this.h[0xF] ^= c[B];
		this.h[0xE] ^= c[A];
		this.h[0xD] ^= m[B];
		this.h[0xC] ^= m[A];
		this.h[0xB] ^= c[9];
		this.h[0xA] ^= c[8];
		this.h[0x9] ^= m[9];
		this.h[0x8] ^= m[8];
		this.h[0x7] ^= c[3];
		this.h[0x6] ^= c[2];
		this.h[0x5] ^= m[3];
		this.h[0x4] ^= m[2];
		this.h[0x3] ^= c[1];
		this.h[0x2] ^= c[0];
		this.h[0x1] ^= m[1];
		this.h[0x0] ^= m[0];
	}

	/** @see Digest */
	public toString()
	{
		return "Hamsi-" + (this.getDigestLength() << 3);
	}

    getDigestLength() {
        return 0;
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
 * <p>This class implements the Hamsi-224 digest algorithm under the
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
 * @version   $Revision: 236 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

export class Hamsi224 extends HamsiSmallCore {

    /**
     * Create the engine.
     */
    constructor() {
        super();
    }

    /** @see Digest */
    public getDigestLength() {
        return 28;
    }

    private static IV = new Int32Array([
        0xc3967a67, 0xc3bc6c20, 0x4bc3bcc3, 0xa7c3bc6b,
        0x2c204b61, 0x74686f6c, 0x69656b65, 0x20556e69
    ]);

    /** @see HamsiSmallCore */
    getIV() {
        return Hamsi224.IV;
    }

    /** @see HamsiSmallCore */
    dup(): HamsiSmallCore {
        return new Hamsi224();
    }
}

/**
 * <p>This class implements the Hamsi-256 digest algorithm under the
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
 * @version   $Revision: 206 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

export class Hamsi256 extends HamsiSmallCore {

	/**
	 * Create the engine.
	 */
	constructor()
	{
		super();
	}

	/** @see Digest */
	public getDigestLength()
	{
		return 32;
	}

	private static IV = new Int32Array([
		0x76657273, 0x69746569, 0x74204c65, 0x7576656e,
		0x2c204465, 0x70617274, 0x656d656e, 0x7420456c
    ]);

	/** @see HamsiSmallCore */
	getIV()
	{
		return Hamsi256.IV;
	}

	/** @see HamsiSmallCore */
	dup(): HamsiSmallCore
	{
		return new Hamsi256();
	}
};

/**
 * <p>This class implements the Hamsi-384 digest algorithm under the
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
 * @version   $Revision: 206 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

export class Hamsi384 extends HamsiBigCore {

	/**
	 * Create the engine.
	 */
	constructor()
	{
		super();
	}

	/** @see Digest */
	public getDigestLength()
	{
		return 48;
	}

	private static IV = new Int32Array([
		0x656b7472, 0x6f746563, 0x686e6965, 0x6b2c2043,
		0x6f6d7075, 0x74657220, 0x53656375, 0x72697479,
		0x20616e64, 0x20496e64, 0x75737472, 0x69616c20,
		0x43727970, 0x746f6772, 0x61706879, 0x2c204b61
    ]);

	/** @see HamsiBigCore */
	getIV()
	{
		return Hamsi384.IV;
	}

	/** @see HamsiBigCore */
	dup(): HamsiBigCore
	{
		return new Hamsi384();
	}
}

/**
 * <p>This class implements the Hamsi-512 digest algorithm under the
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
 * @version   $Revision: 206 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

export class Hamsi512 extends HamsiBigCore {

	/**
	 * Create the engine.
	 */
	constructor()
	{
		super();
	}

	/** @see Digest */
	public getDigestLength()
	{
		return 64;
	}

	private static IV = new Int32Array([
		0x73746565, 0x6c706172, 0x6b204172, 0x656e6265,
		0x72672031, 0x302c2062, 0x75732032, 0x3434362c,
		0x20422d33, 0x30303120, 0x4c657576, 0x656e2d48,
		0x65766572, 0x6c65652c, 0x2042656c, 0x6769756d
    ]);

	/** @see HamsiBigCore */
	getIV()
	{
		return Hamsi512.IV;
	}

	/** @see HamsiBigCore */
	dup(): HamsiBigCore
	{
		return new Hamsi512();
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

// Input types
type InputData = string | Uint8Array | Buffer;

// Output formats
type OutputFormat = 'hex' | 'array' | 'buffer';

/**
 * Creates a vary byte length Hamsi of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {224 | 256 | 384 | 512} bitLen - length of hash (default 512 bits AKA 64 bytes)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function _HAMSI(message: InputData, bitLen: 224 | 256 | 384 | 512 = 512, format: OutputFormat = arrayType()) {
    var hash;
    switch (bitLen) {
        case 224:
            hash = new Hamsi224();
            break;
        case 256:
            hash = new Hamsi256();
            break;
        case 384:
            hash = new Hamsi384();
            break;
        case 512:
            hash = new Hamsi512();
            break;
        default:
            hash = new Hamsi512();
            break;
    }
    hash.update(formatMessage(message));
    const digestbytes = hash.digest() as Uint8Array;
    if(format == "buffer"){
        return Buffer.from(digestbytes);
    } else if(format == "hex"){
        return toHex(digestbytes);
    }
    return digestbytes;
};

/**
 * Creates a vary byte length keyed Hamsi of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {224 | 256 | 384 | 512} bitLen - length of hash (default 512 bits AKA 64 bytes)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function HAMSI_HMAC(message: InputData, key: InputData, bitLen: 224 | 256 | 384 | 512 = 512, format: OutputFormat = arrayType()) {
    var hash;
    switch (bitLen) {
        case 224:
            hash = new Hamsi224();
            break;
        case 256:
            hash = new Hamsi256();
            break;
        case 384:
            hash = new Hamsi384();
            break;
        case 512:
            hash = new Hamsi512();
            break;
        default:
            hash = new Hamsi512();
            break;
    }
    const mac = new HMAC(hash, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    } else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
};

/**
 * Creates a 28 byte Hamsi of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function HAMSI224(message: InputData, format: OutputFormat = arrayType()) {
    const hash = new Hamsi224();
    hash.update(formatMessage(message));
    const digestbytes = hash.digest() as Uint8Array;
    if(format == "buffer"){
        return Buffer.from(digestbytes);
    } else if(format == "hex"){
        return toHex(digestbytes);
    }
    return digestbytes;
};

/**
 * Creates a 28 byte keyed Hamsi of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function HAMSI224_HMAC(message: InputData, key?: InputData, format: OutputFormat = arrayType()) {
    const hash = new Hamsi224();
    const mac = new HMAC(hash, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    } else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
};

/**
 * Creates a 32 byte Hamsi of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function HAMSI256(message: InputData, format: OutputFormat = arrayType()) {
    const hash = new Hamsi256();
    hash.update(formatMessage(message));
    const digestbytes = hash.digest() as Uint8Array;
    if(format == "buffer"){
        return Buffer.from(digestbytes);
    } else if(format == "hex"){
        return toHex(digestbytes);
    }
    return digestbytes;
};

/**
 * Creates a 32 byte keyed Hamsi of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function HAMSI256_HMAC(message: InputData, key?: InputData, format: OutputFormat = arrayType()) {
    const hash = new Hamsi256();
    const mac = new HMAC(hash, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    } else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
};

/**
 * Creates a 48 byte Hamsi of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function HAMSI384(message: InputData, format: OutputFormat = arrayType()) {
    const hash = new Hamsi384();
    hash.update(formatMessage(message));
    const digestbytes = hash.digest() as Uint8Array;
    if(format == "buffer"){
        return Buffer.from(digestbytes);
    } else if(format == "hex"){
        return toHex(digestbytes);
    }
    return digestbytes;
};

/**
 * Creates a 48 byte keyed Hamsi of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function HAMSI384_HMAC(message: InputData, key?: InputData, format: OutputFormat = arrayType()) {
    const hash = new Hamsi384();
    const mac = new HMAC(hash, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    } else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
};

/**
 * Creates a 64 byte Hamsi of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function HAMSI512(message: InputData, format: OutputFormat = arrayType()) {
    const hash = new Hamsi512();
    hash.update(formatMessage(message));
    const digestbytes = hash.digest() as Uint8Array;
    if(format == "buffer"){
        return Buffer.from(digestbytes);
    } else if(format == "hex"){
        return toHex(digestbytes);
    }
    return digestbytes;
};

/**
 * Creates a 64 byte keyed Hamsi of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function HAMSI512_HMAC(message: InputData, key?: InputData, format: OutputFormat = arrayType()) {
    const hash = new Hamsi512();
    const mac = new HMAC(hash, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    } else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
};

/**
 * Static class of all Hamsi functions and classes
 */
export class HAMSI{
    static HAMSI = _HAMSI;

    static Hamsi224 = Hamsi224;
    static HAMSI224 = HAMSI224;
    static HAMSI224_HMAC = HAMSI224_HMAC;

    static Hamsi256 = Hamsi256;
    static HAMSI256 = HAMSI256;
    static HAMSI256_HMAC = HAMSI256_HMAC;

    static Hamsi384 = Hamsi384;
    static HAMSI384 = HAMSI384;
    static HAMSI384_HMAC = HAMSI384_HMAC;

    static Hamsi512 = Hamsi512;
    static HAMSI512 = HAMSI512;
    static HAMSI512_HMAC = HAMSI512_HMAC;
    
    static HAMSI_HMAC = HAMSI_HMAC;

    /**
     * List of all hashes in class
     */
    static get FUNCTION_LIST() {
        return [
            "HAMSI",

            "HAMSI224",
            "HAMSI224_HMAC",

            "HAMSI256",
            "HAMSI256_HMAC",

            "HAMSI384",
            "HAMSI384_HMAC",

            "HAMSI512",
            "HAMSI512_HMAC",

            "HAMSI_HMAC"
        ]
    }
}