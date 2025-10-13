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
    const src2 = [];
    for (let i = 0; i < length; i++) {
        src2.push(src[srcPos + i]);
    }
    for (let i = 0; i < length; i++) {
        dst[destPos + i] = src2[i];
    }
};

/**
 * This class implements the core operations for the JH digest
 * algorithm.
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
 * @version   $Revision: 255 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

abstract class JHCore extends DigestEngine {

    private h!: BigInt64Array;
    private tmpBuf!: Uint8Array;

    private static C = new BigInt64Array([
        BigInt("0x72d5dea2df15f867"), BigInt("0x7b84150ab7231557"),
        BigInt("0x81abd6904d5a87f6"), BigInt("0x4e9f4fc5c3d12b40"),
        BigInt("0xea983ae05c45fa9c"), BigInt("0x03c5d29966b2999a"),
        BigInt("0x660296b4f2bb538a"), BigInt("0xb556141a88dba231"),
        BigInt("0x03a35a5c9a190edb"), BigInt("0x403fb20a87c14410"),
        BigInt("0x1c051980849e951d"), BigInt("0x6f33ebad5ee7cddc"),
        BigInt("0x10ba139202bf6b41"), BigInt("0xdc786515f7bb27d0"),
        BigInt("0x0a2c813937aa7850"), BigInt("0x3f1abfd2410091d3"),
        BigInt("0x422d5a0df6cc7e90"), BigInt("0xdd629f9c92c097ce"),
        BigInt("0x185ca70bc72b44ac"), BigInt("0xd1df65d663c6fc23"),
        BigInt("0x976e6c039ee0b81a"), BigInt("0x2105457e446ceca8"),
        BigInt("0xeef103bb5d8e61fa"), BigInt("0xfd9697b294838197"),
        BigInt("0x4a8e8537db03302f"), BigInt("0x2a678d2dfb9f6a95"),
        BigInt("0x8afe7381f8b8696c"), BigInt("0x8ac77246c07f4214"),
        BigInt("0xc5f4158fbdc75ec4"), BigInt("0x75446fa78f11bb80"),
        BigInt("0x52de75b7aee488bc"), BigInt("0x82b8001e98a6a3f4"),
        BigInt("0x8ef48f33a9a36315"), BigInt("0xaa5f5624d5b7f989"),
        BigInt("0xb6f1ed207c5ae0fd"), BigInt("0x36cae95a06422c36"),
        BigInt("0xce2935434efe983d"), BigInt("0x533af974739a4ba7"),
        BigInt("0xd0f51f596f4e8186"), BigInt("0x0e9dad81afd85a9f"),
        BigInt("0xa7050667ee34626a"), BigInt("0x8b0b28be6eb91727"),
        BigInt("0x47740726c680103f"), BigInt("0xe0a07e6fc67e487b"),
        BigInt("0x0d550aa54af8a4c0"), BigInt("0x91e3e79f978ef19e"),
        BigInt("0x8676728150608dd4"), BigInt("0x7e9e5a41f3e5b062"),
        BigInt("0xfc9f1fec4054207a"), BigInt("0xe3e41a00cef4c984"),
        BigInt("0x4fd794f59dfa95d8"), BigInt("0x552e7e1124c354a5"),
        BigInt("0x5bdf7228bdfe6e28"), BigInt("0x78f57fe20fa5c4b2"),
        BigInt("0x05897cefee49d32e"), BigInt("0x447e9385eb28597f"),
        BigInt("0x705f6937b324314a"), BigInt("0x5e8628f11dd6e465"),
        BigInt("0xc71b770451b920e7"), BigInt("0x74fe43e823d4878a"),
        BigInt("0x7d29e8a3927694f2"), BigInt("0xddcb7a099b30d9c1"),
        BigInt("0x1d1b30fb5bdc1be0"), BigInt("0xda24494ff29c82bf"),
        BigInt("0xa4e7ba31b470bfff"), BigInt("0x0d324405def8bc48"),
        BigInt("0x3baefc3253bbd339"), BigInt("0x459fc3c1e0298ba0"),
        BigInt("0xe5c905fdf7ae090f"), BigInt("0x947034124290f134"),
        BigInt("0xa271b701e344ed95"), BigInt("0xe93b8e364f2f984a"),
        BigInt("0x88401d63a06cf615"), BigInt("0x47c1444b8752afff"),
        BigInt("0x7ebb4af1e20ac630"), BigInt("0x4670b6c5cc6e8ce6"),
        BigInt("0xa4d5a456bd4fca00"), BigInt("0xda9d844bc83e18ae"),
        BigInt("0x7357ce453064d1ad"), BigInt("0xe8a6ce68145c2567"),
        BigInt("0xa3da8cf2cb0ee116"), BigInt("0x33e906589a94999a"),
        BigInt("0x1f60b220c26f847b"), BigInt("0xd1ceac7fa0d18518"),
        BigInt("0x32595ba18ddd19d3"), BigInt("0x509a1cc0aaa5b446"),
        BigInt("0x9f3d6367e4046bba"), BigInt("0xf6ca19ab0b56ee7e"),
        BigInt("0x1fb179eaa9282174"), BigInt("0xe9bdf7353b3651ee"),
        BigInt("0x1d57ac5a7550d376"), BigInt("0x3a46c2fea37d7001"),
        BigInt("0xf735c1af98a4d842"), BigInt("0x78edec209e6b6779"),
        BigInt("0x41836315ea3adba8"), BigInt("0xfac33b4d32832c83"),
        BigInt("0xa7403b1f1c2747f3"), BigInt("0x5940f034b72d769a"),
        BigInt("0xe73e4e6cd2214ffd"), BigInt("0xb8fd8d39dc5759ef"),
        BigInt("0x8d9b0c492b49ebda"), BigInt("0x5ba2d74968f3700d"),
        BigInt("0x7d3baed07a8d5584"), BigInt("0xf5a5e9f0e4f88e65"),
        BigInt("0xa0b8a2f436103b53"), BigInt("0x0ca8079e753eec5a"),
        BigInt("0x9168949256e8884f"), BigInt("0x5bb05c55f8babc4c"),
        BigInt("0xe3bb3b99f387947b"), BigInt("0x75daf4d6726b1c5d"),
        BigInt("0x64aeac28dc34b36d"), BigInt("0x6c34a550b828db71"),
        BigInt("0xf861e2f2108d512a"), BigInt("0xe3db643359dd75fc"),
        BigInt("0x1cacbcf143ce3fa2"), BigInt("0x67bbd13c02e843b0"),
        BigInt("0x330a5bca8829a175"), BigInt("0x7f34194db416535c"),
        BigInt("0x923b94c30e794d1e"), BigInt("0x797475d7b6eeaf3f"),
        BigInt("0xeaa8d4f7be1a3921"), BigInt("0x5cf47e094c232751"),
        BigInt("0x26a32453ba323cd2"), BigInt("0x44a3174a6da6d5ad"),
        BigInt("0xb51d3ea6aff2c908"), BigInt("0x83593d98916b3c56"),
        BigInt("0x4cf87ca17286604d"), BigInt("0x46e23ecc086ec7f6"),
        BigInt("0x2f9833b3b1bc765e"), BigInt("0x2bd666a5efc4e62a"),
        BigInt("0x06f4b6e8bec1d436"), BigInt("0x74ee8215bcef2163"),
        BigInt("0xfdc14e0df453c969"), BigInt("0xa77d5ac406585826"),
        BigInt("0x7ec1141606e0fa16"), BigInt("0x7e90af3d28639d3f"),
        BigInt("0xd2c9f2e3009bd20c"), BigInt("0x5faace30b7d40c30"),
        BigInt("0x742a5116f2e03298"), BigInt("0x0deb30d8e3cef89a"),
        BigInt("0x4bc59e7bb5f17992"), BigInt("0xff51e66e048668d3"),
        BigInt("0x9b234d57e6966731"), BigInt("0xcce6a6f3170a7505"),
        BigInt("0xb17681d913326cce"), BigInt("0x3c175284f805a262"),
        BigInt("0xf42bcbb378471547"), BigInt("0xff46548223936a48"),
        BigInt("0x38df58074e5e6565"), BigInt("0xf2fc7c89fc86508e"),
        BigInt("0x31702e44d00bca86"), BigInt("0xf04009a23078474e"),
        BigInt("0x65a0ee39d1f73883"), BigInt("0xf75ee937e42c3abd"),
        BigInt("0x2197b2260113f86f"), BigInt("0xa344edd1ef9fdee7"),
        BigInt("0x8ba0df15762592d9"), BigInt("0x3c85f7f612dc42be"),
        BigInt("0xd8a7ec7cab27b07e"), BigInt("0x538d7ddaaa3ea8de"),
        BigInt("0xaa25ce93bd0269d8"), BigInt("0x5af643fd1a7308f9"),
        BigInt("0xc05fefda174a19a5"), BigInt("0x974d66334cfd216a"),
        BigInt("0x35b49831db411570"), BigInt("0xea1e0fbbedcd549b"),
        BigInt("0x9ad063a151974072"), BigInt("0xf6759dbf91476fe2")
    ]);

    /**
     * Encode the 64-bit word {@code val} into the array
     * {@code buf} at offset {@code off}, in big-endian
     * convention (least significant byte first).
     *
     * @param val   the value to encode
     * @param buf   the destination buffer
     * @param off   the destination offset
     */
    private encodeBELong(val: bigint, buf: Uint8Array, off: number) {
        console.log(val)
        let endian = "big";
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
     * Decode a 64-bit big-endian word from the array {@code buf}
     * at offset {@code off}.
     *
     * @param buf   the source buffer
     * @param off   the source offset
     * @return  the decoded value
     */
    private decodeBELong(buf: Uint8Array, off: number) {
        let value = BigInt(0);
        let endian = "big";
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

    /** @see DigestEngine */
    protected engineReset() {
        this.doReset();
    }

    private doS(r: number) {
        const x = new BigInt64Array(4);
        var cc, tmp;

        cc = JHCore.C[(r << 2) + 0];
        x[0] = this.h[0];
        x[1] = this.h[4];
        x[2] = this.h[8];
        x[3] = this.h[12];
        x[3] = ~x[3];
        x[0] ^= cc & ~x[2];
        tmp = cc ^ (x[0] & x[1]);
        x[0] ^= x[2] & x[3];
        x[3] ^= ~x[1] & x[2];
        x[1] ^= x[0] & x[2];
        x[2] ^= x[0] & ~x[3];
        x[0] ^= x[1] | x[3];
        x[3] ^= x[1] & x[2];
        x[1] ^= tmp & x[0];
        x[2] ^= tmp;
        this.h[0] = x[0];
        this.h[4] = x[1];
        this.h[8] = x[2];
        this.h[12] = x[3];

        cc = JHCore.C[(r << 2) + 1];
        x[0] = this.h[1];
        x[1] = this.h[5];
        x[2] = this.h[9];
        x[3] = this.h[13];
        x[3] = ~x[3];
        x[0] ^= cc & ~x[2];
        tmp = cc ^ (x[0] & x[1]);
        x[0] ^= x[2] & x[3];
        x[3] ^= ~x[1] & x[2];
        x[1] ^= x[0] & x[2];
        x[2] ^= x[0] & ~x[3];
        x[0] ^= x[1] | x[3];
        x[3] ^= x[1] & x[2];
        x[1] ^= tmp & x[0];
        x[2] ^= tmp;
        this.h[1] = x[0];
        this.h[5] = x[1];
        this.h[9] = x[2];
        this.h[13] = x[3];

        cc = JHCore.C[(r << 2) + 2];
        x[0] = this.h[2];
        x[1] = this.h[6];
        x[2] = this.h[10];
        x[3] = this.h[14];
        x[3] = ~x[3];
        x[0] ^= cc & ~x[2];
        tmp = cc ^ (x[0] & x[1]);
        x[0] ^= x[2] & x[3];
        x[3] ^= ~x[1] & x[2];
        x[1] ^= x[0] & x[2];
        x[2] ^= x[0] & ~x[3];
        x[0] ^= x[1] | x[3];
        x[3] ^= x[1] & x[2];
        x[1] ^= tmp & x[0];
        x[2] ^= tmp;
        this.h[2] = x[0];
        this.h[6] = x[1];
        this.h[10] = x[2];
        this.h[14] = x[3];

        cc = JHCore.C[(r << 2) + 3];
        x[0] = this.h[3];
        x[1] = this.h[7];
        x[2] = this.h[11];
        x[3] = this.h[15];
        x[3] = ~x[3];
        x[0] ^= cc & ~x[2];
        tmp = cc ^ (x[0] & x[1]);
        x[0] ^= x[2] & x[3];
        x[3] ^= ~x[1] & x[2];
        x[1] ^= x[0] & x[2];
        x[2] ^= x[0] & ~x[3];
        x[0] ^= x[1] | x[3];
        x[3] ^= x[1] & x[2];
        x[1] ^= tmp & x[0];
        x[2] ^= tmp;
        this.h[3] = x[0];
        this.h[7] = x[1];
        this.h[11] = x[2];
        this.h[15] = x[3];
    }

    private doL() {
        const x = new BigInt64Array(8);
        x[0] = this.h[0];
        x[1] = this.h[4];
        x[2] = this.h[8];
        x[3] = this.h[12];
        x[4] = this.h[2];
        x[5] = this.h[6];
        x[6] = this.h[10];
        x[7] = this.h[14];
        x[4] ^= x[1];
        x[5] ^= x[2];
        x[6] ^= x[3] ^ x[0];
        x[7] ^= x[0];
        x[0] ^= x[5];
        x[1] ^= x[6];
        x[2] ^= x[7] ^ x[4];
        x[3] ^= x[4];
        this.h[0] = x[0];
        this.h[4] = x[1];
        this.h[8] = x[2];
        this.h[12] = x[3];
        this.h[2] = x[4];
        this.h[6] = x[5];
        this.h[10] = x[6];
        this.h[14] = x[7];

        x[0] = this.h[1];
        x[1] = this.h[5];
        x[2] = this.h[9];
        x[3] = this.h[13];
        x[4] = this.h[3];
        x[5] = this.h[7];
        x[6] = this.h[11];
        x[7] = this.h[15];
        x[4] ^= x[1];
        x[5] ^= x[2];
        x[6] ^= x[3] ^ x[0];
        x[7] ^= x[0];
        x[0] ^= x[5];
        x[1] ^= x[6];
        x[2] ^= x[7] ^ x[4];
        x[3] ^= x[4];
        this.h[1] = x[0];
        this.h[5] = x[1];
        this.h[9] = x[2];
        this.h[13] = x[3];
        this.h[3] = x[4];
        this.h[7] = x[5];
        this.h[11] = x[6];
        this.h[15] = x[7];
    }

    private doWgen(c: bigint, n: number) {
        this.h[2] = ((this.h[2] & c) << BigInt(n)) | ((this.h[2] >> BigInt(n)) & c);
        this.h[3] = ((this.h[3] & c) << BigInt(n)) | ((this.h[3] >> BigInt(n)) & c);
        this.h[6] = ((this.h[6] & c) << BigInt(n)) | ((this.h[6] >> BigInt(n)) & c);
        this.h[7] = ((this.h[7] & c) << BigInt(n)) | ((this.h[7] >> BigInt(n)) & c);
        this.h[10] = ((this.h[10] & c) << BigInt(n)) | ((this.h[10] >> BigInt(n)) & c);
        this.h[11] = ((this.h[11] & c) << BigInt(n)) | ((this.h[11] >> BigInt(n)) & c);
        this.h[14] = ((this.h[14] & c) << BigInt(n)) | ((this.h[14] >> BigInt(n)) & c);
        this.h[15] = ((this.h[15] & c) << BigInt(n)) | ((this.h[15] >> BigInt(n)) & c);
    }

    private doW6() {
        var t: bigint;
        t = this.h[2]; this.h[2] = this.h[3]; this.h[3] = t;
        t = this.h[6]; this.h[6] = this.h[7]; this.h[7] = t;
        t = this.h[10]; this.h[10] = this.h[11]; this.h[11] = t;
        t = this.h[14]; this.h[14] = this.h[15]; this.h[15] = t;
    }

    /** @see DigestEngine */
    protected processBlock(data: Uint8Array) {
        const m0 = new BigInt64Array(2);
        const m1 = new BigInt64Array(2);
        const m2 = new BigInt64Array(2);
        const m3 = new BigInt64Array(2);
        const h = 0;
        const l = 1;
        m0[h] = this.decodeBELong(data, 0);
        m0[l] = this.decodeBELong(data, 8);
        m1[h] = this.decodeBELong(data, 16);
        m1[l] = this.decodeBELong(data, 24);
        m2[h] = this.decodeBELong(data, 32);
        m2[l] = this.decodeBELong(data, 40);
        m3[h] = this.decodeBELong(data, 48);
        m3[l] = this.decodeBELong(data, 56);
        this.h[0] ^= m0[h];
        this.h[1] ^= m0[l];
        this.h[2] ^= m1[h];
        this.h[3] ^= m1[l];
        this.h[4] ^= m2[h];
        this.h[5] ^= m2[l];
        this.h[6] ^= m3[h];
        this.h[7] ^= m3[l];
        for (let r = 0; r < 42; r += 7) {
            this.doS(r + 0);
            this.doL();
            this.doWgen(BigInt("0x5555555555555555"), 1);
            this.doS(r + 1);
            this.doL();
            this.doWgen(BigInt("0x3333333333333333"), 2);
            this.doS(r + 2);
            this.doL();
            this.doWgen(BigInt("0x0F0F0F0F0F0F0F0F"), 4);
            this.doS(r + 3);
            this.doL();
            this.doWgen(BigInt("0x00FF00FF00FF00FF"), 8);
            this.doS(r + 4);
            this.doL();
            this.doWgen(BigInt("0x0000FFFF0000FFFF"), 16);
            this.doS(r + 5);
            this.doL();
            this.doWgen(BigInt("0x00000000FFFFFFFF"), 32);
            this.doS(r + 6);
            this.doL();
            this.doW6();
        }
        this.h[8] ^= m0[h];
        this.h[9] ^= m0[l];
        this.h[10] ^= m1[h];
        this.h[11] ^= m1[l];
        this.h[12] ^= m2[h];
        this.h[13] ^= m2[l];
        this.h[14] ^= m3[h];
        this.h[15] ^= m3[l];
    }

    /** @see DigestEngine */
    protected doPadding(buf: Uint8Array, off: number) {
        console.log("ran padd")
        var rem = this.flush();
        var bc = this.getBlockCount();
        var numz = (rem == 0) ? 47 : 111 - rem;
        this.tmpBuf[0] = 0x80;
        for (let i = 1; i <= numz; i++) {
            this.tmpBuf[i] = 0x00;
        }
        this.encodeBELong(bc >> BigInt(55), this.tmpBuf, numz + 1);
        this.encodeBELong((bc << BigInt(9)) + BigInt(rem << 3), this.tmpBuf, numz + 9);
        this.update(this.tmpBuf, 0, numz + 17);
        for (let i = 0; i < 8; i++) {
            this.encodeBELong(this.h[i + 8], this.tmpBuf, i << 3);
        }
        var dlen = this.getDigestLength();
        arraycopy(this.tmpBuf, 64 - dlen, buf, off, dlen);
    }

    /** @see DigestEngine */
    protected doInit() {
        this.h = new BigInt64Array(16);
        this.tmpBuf = new Uint8Array(128);
        this.doReset();
    }

    /**
     * Get the initial values.
     *
     * @return  the IV
     */
    abstract getIV(): BigInt64Array;

    /** @see Digest */
    public getBlockLength() {
        return 64;
    }

    private doReset() {
        arraycopy(this.getIV(), 0, this.h, 0, 16);
    }

    /** @see DigestEngine */
    protected copyState<T>(dst: JHCore): T {
        arraycopy(this.h, 0, dst.h, 0, 16);
        return super.copyState(dst);
    }

    /** @see Digest */
    public toString() {
        return "JH-" + (this.getDigestLength() << 3);
    }
}

/**
 * <p>This class implements the JH-224 digest algorithm under the
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
 * @version   $Revision: 255 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

export class Jh224 extends JHCore {

    private static IV = new BigInt64Array([
        BigInt("0x2dfedd62f99a98ac"), BigInt("0xae7cacd619d634e7"),
        BigInt("0xa4831005bc301216"), BigInt("0xb86038c6c9661494"),
        BigInt("0x66d9899f2580706f"), BigInt("0xce9ea31b1d9b1adc"),
        BigInt("0x11e8325f7b366e10"), BigInt("0xf994857f02fa06c1"),
        BigInt("0x1b4f1b5cd8c840b3"), BigInt("0x97f6a17f6e738099"),
        BigInt("0xdcdf93a5adeaa3d3"), BigInt("0xa431e8dec9539a68"),
        BigInt("0x22b4a98aec86a1e4"), BigInt("0xd574ac959ce56cf0"),
        BigInt("0x15960deab5ab2bbf"), BigInt("0x9611dcf0dd64ea6e")
    ]);

    /**
     * Create the engine.
     */
    constructor() {
        super();
    }

    /** @see Digest */
    public copy(): Digest {
        return this.copyState(new Jh224());
    }

    /** @see Digest */
    public getDigestLength() {
        return 28;
    }

    /** @see JHCore */
    getIV() {
        return Jh224.IV;
    }
}

/**
 * <p>This class implements the JH-256 digest algorithm under the
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
 * @version   $Revision: 255 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

export class Jh256 extends JHCore {

    private static IV = new BigInt64Array([
        BigInt("0xeb98a3412c20d3eb"), BigInt("0x92cdbe7b9cb245c1"),
        BigInt("0x1c93519160d4c7fa"), BigInt("0x260082d67e508a03"),
        BigInt("0xa4239e267726b945"), BigInt("0xe0fb1a48d41a9477"),
        BigInt("0xcdb5ab26026b177a"), BigInt("0x56f024420fff2fa8"),
        BigInt("0x71a396897f2e4d75"), BigInt("0x1d144908f77de262"),
        BigInt("0x277695f776248f94"), BigInt("0x87d5b6574780296c"),
        BigInt("0x5c5e272dac8e0d6c"), BigInt("0x518450c657057a0f"),
        BigInt("0x7be4d367702412ea"), BigInt("0x89e3ab13d31cd769")
    ]);

    /**
     * Create the engine.
     */
    constructor() {
        super();
    }

    /** @see Digest */
    public copy(): Digest {
        return this.copyState(new Jh256());
    }

    /** @see Digest */
    public getDigestLength() {
        return 32;
    }

    /** @see JHCore */
    getIV() {
        return Jh256.IV;
    }
}

/**
 * <p>This class implements the JH-384 digest algorithm under the
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
 * @version   $Revision: 255 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

export class Jh384 extends JHCore {

    private static IV = new BigInt64Array([
        BigInt("0x481e3bc6d813398a"), BigInt("0x6d3b5e894ade879b"),
        BigInt("0x63faea68d480ad2e"), BigInt("0x332ccb21480f8267"),
        BigInt("0x98aec84d9082b928"), BigInt("0xd455ea3041114249"),
        BigInt("0x36f555b2924847ec"), BigInt("0xc7250a93baf43ce1"),
        BigInt("0x569b7f8a27db454c"), BigInt("0x9efcbd496397af0e"),
        BigInt("0x589fc27d26aa80cd"), BigInt("0x80c08b8c9deb2eda"),
        BigInt("0x8a7981e8f8d5373a"), BigInt("0xf43967adddd17a71"),
        BigInt("0xa9b4d3bda475d394"), BigInt("0x976c3fba9842737f")
    ]);

    /**
     * Create the engine.
     */
    constructor() {
        super();
    }

    /** @see Digest */
    public copy(): Digest {
        return this.copyState(new Jh384());
    }

    /** @see Digest */
    public getDigestLength() {
        return 48;
    }

    /** @see JHCore */
    getIV() {
        return Jh384.IV;
    }
}

/**
 * <p>This class implements the JH-512 digest algorithm under the
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
 * @version   $Revision: 255 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

export class Jh512 extends JHCore {

    private static IV = new BigInt64Array([
        BigInt("0x6fd14b963e00aa17"), BigInt("0x636a2e057a15d543"),
        BigInt("0x8a225e8d0c97ef0b"), BigInt("0xe9341259f2b3c361"),
        BigInt("0x891da0c1536f801e"), BigInt("0x2aa9056bea2b6d80"),
        BigInt("0x588eccdb2075baa6"), BigInt("0xa90f3a76baf83bf7"),
        BigInt("0x0169e60541e34a69"), BigInt("0x46b58a8e2e6fe65a"),
        BigInt("0x1047a7d0c1843c24"), BigInt("0x3b6e71b12d5ac199"),
        BigInt("0xcf57f6ec9db1f856"), BigInt("0xa706887c5716b156"),
        BigInt("0xe3c2fcdfe68517fb"), BigInt("0x545a4678cc8cdd4b")
    ]);

    /**
     * Create the engine.
     */
    constructor() {
        super();
    }

    /** @see Digest */
    public copy(): Digest {
        return this.copyState(new Jh512());
    }

    /** @see Digest */
    public getDigestLength() {
        return 64;
    }

    /** @see JHCore */
    getIV() {
        return Jh512.IV;
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

function arrayType():OutputFormat{
	if (typeof window !== 'undefined') {
		return "array" as OutputFormat;
	} else {
    return "buffer" as OutputFormat;
	}
};

/**
 * Creates a vary byte length JH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {224 | 256 | 384 | 512} bitLen - length of hash (default 512 bits AKA 64 bytes)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function _JH(message: InputData, bitLen: 224 | 256 | 384 | 512 = 512, format: OutputFormat = arrayType()) {
    var hash;
    switch (bitLen) {
        case 224:
            hash = new Jh224();
            break;
        case 256:
            hash = new Jh256();
            break;
        case 384:
            hash = new Jh384();
            break;
        case 512:
            hash = new Jh512();
            break;
        default:
            hash = new Jh512();
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
 * Creates a vary byte length keyed JH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {224 | 256 | 384 | 512} bitLen - length of hash (default 512 bits AKA 64 bytes)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function JH_HMAC(message: InputData, key: InputData, bitLen: 224 | 256 | 384 | 512 = 512, format: OutputFormat = arrayType()) {
    var hash;
    switch (bitLen) {
        case 224:
            hash = new Jh224();
            break;
        case 256:
            hash = new Jh256();
            break;
        case 384:
            hash = new Jh384();
            break;
        case 512:
            hash = new Jh512();
            break;
        default:
            hash = new Jh512();
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
 * Creates a 28 byte JH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function JH224(message: InputData, format: OutputFormat = arrayType()) {
    const hash = new Jh224();
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
 * Creates a 28 byte keyed JH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function JH224_HMAC(message: InputData, key?: InputData, format: OutputFormat = arrayType()) {
    const hash = new Jh224();
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
 * Creates a 32 byte JH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function JH256(message: InputData, format: OutputFormat = arrayType()) {
    const hash = new Jh256();
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
 * Creates a 32 byte keyed JH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function JH256_HMAC(message: InputData, key?: InputData, format: OutputFormat = arrayType()) {
    const hash = new Jh256();
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
 * Creates a 48 byte JH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function JH384(message: InputData, format: OutputFormat = arrayType()) {
    const hash = new Jh384();
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
 * Creates a 48 byte keyed JH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function JH384_HMAC(message: InputData, key?: InputData, format: OutputFormat = arrayType()) {
    const hash = new Jh384();
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
 * Creates a 64 byte JH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function JH512(message: InputData, format: OutputFormat = arrayType()) {
    const hash = new Jh512();
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
 * Creates a 64 byte keyed JH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function JH512_HMAC(message: InputData, key?: InputData, format: OutputFormat = arrayType()) {
    const hash = new Jh512();
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
 * Static class of all HAVAL functions and classes
 */
export class JH{
    static JH = _JH;
    static Jh224 = Jh224;
    static Jh256 = Jh256;
    static Jh384 = Jh384;
    static Jh512 = Jh512;
    static JH224      = JH224;
    static JH224_HMAC = JH224_HMAC;
    static JH256      = JH256;
    static JH256_HMAC = JH256_HMAC;
    static JH384      = JH384;
    static JH384_HMAC = JH384_HMAC;
    static JH512      = JH512;
    static JH512_HMAC = JH512_HMAC;
    static JH_HMAC    = JH_HMAC;
    /**
     * List of all hashes in class
     */
    static get FUNCTION_LIST() {
        return [
            "JH",
            "JH224",
            "JH224_HMAC",
            "JH256",
            "JH256_HMAC",
            "JH384",
            "JH384_HMAC",
            "JH512",
            "JH512_HMAC",
            "JH_HMAC"
        ]
    }
}