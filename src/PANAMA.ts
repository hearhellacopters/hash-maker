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

function bytesToHex(bytes: number[] | Uint8Array): string {
    for (var hex: string[] = [], i = 0; i < bytes.length; i++) {
        hex.push((bytes[i] >>> 4).toString(16));
        hex.push((bytes[i] & 0xF).toString(16));
    }
    return hex.join("");
}

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
    src: Uint8Array | Uint16Array | Uint32Array | Float32Array | Uint8ClampedArray,
    srcPos: number = 0,
    dst: Uint8Array | Uint16Array | Uint32Array | Float32Array | Uint8ClampedArray,
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

/**
 * This class implements the PANAMA digest algorithm under the
 * {@link Digest} API.
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

class Panama extends DigestEngine {

    /**
     * Create the object.
     */
    constructor() {
        super();
    }

    private buffer?: Uint32Array;
    private bufferPtr?: number;

    private state0 = 0;
    private state1 = 0;
    private state2 = 0;
    private state3 = 0;
    private state4 = 0;
    private state5 = 0;
    private state6 = 0;
    private state7 = 0;
    private state8 = 0;
    private state9 = 0;
    private state10 = 0;
    private state11 = 0;
    private state12 = 0;
    private state13 = 0;
    private state14 = 0;
    private state15 = 0;
    private state16 = 0;

    private inData0 = 0;
    private inData1 = 0;
    private inData2 = 0;
    private inData3 = 0;
    private inData4 = 0;
    private inData5 = 0;
    private inData6 = 0;
    private inData7 = 0;

    /** @see Digest */
    public copy(): Panama {
        const d = new Panama();
        if (this.buffer && d.buffer) {
            arraycopy(this.buffer, 0, d.buffer, 0, this.buffer.length);
        }
        d.bufferPtr = this.bufferPtr;
        d.state0 = this.state0;
        d.state1 = this.state1;
        d.state2 = this.state2;
        d.state3 = this.state3;
        d.state4 = this.state4;
        d.state5 = this.state5;
        d.state6 = this.state6;
        d.state7 = this.state7;
        d.state8 = this.state8;
        d.state9 = this.state9;
        d.state10 = this.state10;
        d.state11 = this.state11;
        d.state12 = this.state12;
        d.state13 = this.state13;
        d.state14 = this.state14;
        d.state15 = this.state15;
        d.state16 = this.state16;
        return this.copyState(d);
    }

    /** @see Digest */
    public getDigestLength() {
        return 32;
    }

    /** @see Digest */
    public getBlockLength() {
        return 32;
    }

    /** @see DigestEngine */
    protected engineReset() {
        if (this.buffer) {
            for (let i = 0; i < this.buffer.length; i++) {
                this.buffer[i] = 0;
            }
        }
        this.bufferPtr = 0;
        this.state0 = 0;
        this.state1 = 0;
        this.state2 = 0;
        this.state3 = 0;
        this.state4 = 0;
        this.state5 = 0;
        this.state6 = 0;
        this.state7 = 0;
        this.state8 = 0;
        this.state9 = 0;
        this.state10 = 0;
        this.state11 = 0;
        this.state12 = 0;
        this.state13 = 0;
        this.state14 = 0;
        this.state15 = 0;
        this.state16 = 0;
    }

    /** @see DigestEngine */
    protected doPadding(output: Uint8Array, outputOffset: number) {
        var pending = this.flush();
        this.update(0x01);
        for (let i = pending + 1; i < 32; i++) {
            this.update(0x00);
        }
        this.flush();
        for (let i = 0; i < 32; i++) {
            this.oneStep(false);
        }
        this.encodeLEInt(this.state9 as number, output, outputOffset + 0);
        this.encodeLEInt(this.state10 as number, output, outputOffset + 4);
        this.encodeLEInt(this.state11 as number, output, outputOffset + 8);
        this.encodeLEInt(this.state12 as number, output, outputOffset + 12);
        this.encodeLEInt(this.state13 as number, output, outputOffset + 16);
        this.encodeLEInt(this.state14 as number, output, outputOffset + 20);
        this.encodeLEInt(this.state15 as number, output, outputOffset + 24);
        this.encodeLEInt(this.state16 as number, output, outputOffset + 28);
    }

    /** @see DigestEngine */
    protected doInit() {
        this.buffer = new Uint32Array(256);
        /*
         * engineReset() is not needed because in Java, "int"
         * variables and arrays of "int" are initialized upon
         * creation to the correct value (full of zeroes).
         */
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
    private encodeLEInt(val: number, buf: Uint8Array, off: number) {
        buf[off + 3] = ((val >> 24) & 0xff);
        buf[off + 2] = ((val >> 16) & 0xff);
        buf[off + 1] = ((val >> 8) & 0xff);
        buf[off + 0] = (val & 0xff);
    }

    /**
     * Decode a 32-bit little-endian word from the array {@code buf}
     * at offset {@code off}.
     *
     * @param buf   the source buffer
     * @param off   the source offset
     * @return  the decoded value
     */
    private decodeLEInt(buf: Uint8Array, off: number) {
        return (buf[off] & 0xFF)
            | ((buf[off + 1] & 0xFF) << 8)
            | ((buf[off + 2] & 0xFF) << 16)
            | ((buf[off + 3] & 0xFF) << 24);
    }

    /** @see DigestEngine */
    protected processBlock(data: Uint8Array) {
        this.inData0 = this.decodeLEInt(data, 0);
        this.inData1 = this.decodeLEInt(data, 4);
        this.inData2 = this.decodeLEInt(data, 8);
        this.inData3 = this.decodeLEInt(data, 12);
        this.inData4 = this.decodeLEInt(data, 16);
        this.inData5 = this.decodeLEInt(data, 20);
        this.inData6 = this.decodeLEInt(data, 24);
        this.inData7 = this.decodeLEInt(data, 28);
        this.oneStep(true);
    }

    private oneStep(push: boolean) {
        /*
         * Buffer update.
         */
        var ptr0 = this.bufferPtr as number; this.buffer = this.buffer as Uint32Array;
        var ptr24 = (ptr0 - 64) & 248;
        var ptr31 = (ptr0 - 8) & 248;
        if (push) {
            this.buffer[ptr24 + 0] ^= this.buffer[ptr31 + 2];
            this.buffer[ptr31 + 2] ^= this.inData2 as number;
            this.buffer[ptr24 + 1] ^= this.buffer[ptr31 + 3];
            this.buffer[ptr31 + 3] ^= this.inData3 as number;
            this.buffer[ptr24 + 2] ^= this.buffer[ptr31 + 4];
            this.buffer[ptr31 + 4] ^= this.inData4 as number;
            this.buffer[ptr24 + 3] ^= this.buffer[ptr31 + 5];
            this.buffer[ptr31 + 5] ^= this.inData5 as number;
            this.buffer[ptr24 + 4] ^= this.buffer[ptr31 + 6];
            this.buffer[ptr31 + 6] ^= this.inData6 as number;
            this.buffer[ptr24 + 5] ^= this.buffer[ptr31 + 7];
            this.buffer[ptr31 + 7] ^= this.inData7 as number;
            this.buffer[ptr24 + 6] ^= this.buffer[ptr31 + 0];
            this.buffer[ptr31 + 0] ^= this.inData0 as number;
            this.buffer[ptr24 + 7] ^= this.buffer[ptr31 + 1];
            this.buffer[ptr31 + 1] ^= this.inData1 as number;
        } else {
            this.buffer[ptr24 + 0] ^= this.buffer[ptr31 + 2];
            this.buffer[ptr31 + 2] ^= this.state3 as number;
            this.buffer[ptr24 + 1] ^= this.buffer[ptr31 + 3];
            this.buffer[ptr31 + 3] ^= this.state4 as number;
            this.buffer[ptr24 + 2] ^= this.buffer[ptr31 + 4];
            this.buffer[ptr31 + 4] ^= this.state5 as number;
            this.buffer[ptr24 + 3] ^= this.buffer[ptr31 + 5];
            this.buffer[ptr31 + 5] ^= this.state6 as number;
            this.buffer[ptr24 + 4] ^= this.buffer[ptr31 + 6];
            this.buffer[ptr31 + 6] ^= this.state7 as number;
            this.buffer[ptr24 + 5] ^= this.buffer[ptr31 + 7];
            this.buffer[ptr31 + 7] ^= this.state8 as number;
            this.buffer[ptr24 + 6] ^= this.buffer[ptr31 + 0];
            this.buffer[ptr31 + 0] ^= this.state1 as number;
            this.buffer[ptr24 + 7] ^= this.buffer[ptr31 + 1];
            this.buffer[ptr31 + 1] ^= this.state2 as number;
        }
        this.bufferPtr = ptr31;

        /*
         * Gamma transform.
         */
        var g0, g1, g2, g3, g4, g5, g6, g7, g8, g9;
        var g10, g11, g12, g13, g14, g15, g16;
        g0 = this.state0 ^ (this.state1 | ~this.state2);
        g1 = this.state1 ^ (this.state2 | ~this.state3);
        g2 = this.state2 ^ (this.state3 | ~this.state4);
        g3 = this.state3 ^ (this.state4 | ~this.state5);
        g4 = this.state4 ^ (this.state5 | ~this.state6);
        g5 = this.state5 ^ (this.state6 | ~this.state7);
        g6 = this.state6 ^ (this.state7 | ~this.state8);
        g7 = this.state7 ^ (this.state8 | ~this.state9);
        g8 = this.state8 ^ (this.state9 | ~this.state10);
        g9 = this.state9 ^ (this.state10 | ~this.state11);
        g10 = this.state10 ^ (this.state11 | ~this.state12);
        g11 = this.state11 ^ (this.state12 | ~this.state13);
        g12 = this.state12 ^ (this.state13 | ~this.state14);
        g13 = this.state13 ^ (this.state14 | ~this.state15);
        g14 = this.state14 ^ (this.state15 | ~this.state16);
        g15 = this.state15 ^ (this.state16 | ~this.state0);
        g16 = this.state16 ^ (this.state0 | ~this.state1);

        /*
         * Pi transform.
         */
        var p0, p1, p2, p3, p4, p5, p6, p7, p8, p9;
        var p10, p11, p12, p13, p14, p15, p16;
        p0 = g0;
        p1 = (g7 << 1) | (g7 >>> (32 - 1));
        p2 = (g14 << 3) | (g14 >>> (32 - 3));
        p3 = (g4 << 6) | (g4 >>> (32 - 6));
        p4 = (g11 << 10) | (g11 >>> (32 - 10));
        p5 = (g1 << 15) | (g1 >>> (32 - 15));
        p6 = (g8 << 21) | (g8 >>> (32 - 21));
        p7 = (g15 << 28) | (g15 >>> (32 - 28));
        p8 = (g5 << 4) | (g5 >>> (32 - 4));
        p9 = (g12 << 13) | (g12 >>> (32 - 13));
        p10 = (g2 << 23) | (g2 >>> (32 - 23));
        p11 = (g9 << 2) | (g9 >>> (32 - 2));
        p12 = (g16 << 14) | (g16 >>> (32 - 14));
        p13 = (g6 << 27) | (g6 >>> (32 - 27));
        p14 = (g13 << 9) | (g13 >>> (32 - 9));
        p15 = (g3 << 24) | (g3 >>> (32 - 24));
        p16 = (g10 << 8) | (g10 >>> (32 - 8));

        /*
         * Theta transform.
         */
        var t0, t1, t2, t3, t4, t5, t6, t7, t8, t9;
        var t10, t11, t12, t13, t14, t15, t16;
        t0 = p0 ^ p1 ^ p4;
        t1 = p1 ^ p2 ^ p5;
        t2 = p2 ^ p3 ^ p6;
        t3 = p3 ^ p4 ^ p7;
        t4 = p4 ^ p5 ^ p8;
        t5 = p5 ^ p6 ^ p9;
        t6 = p6 ^ p7 ^ p10;
        t7 = p7 ^ p8 ^ p11;
        t8 = p8 ^ p9 ^ p12;
        t9 = p9 ^ p10 ^ p13;
        t10 = p10 ^ p11 ^ p14;
        t11 = p11 ^ p12 ^ p15;
        t12 = p12 ^ p13 ^ p16;
        t13 = p13 ^ p14 ^ p0;
        t14 = p14 ^ p15 ^ p1;
        t15 = p15 ^ p16 ^ p2;
        t16 = p16 ^ p0 ^ p3;

        /*
         * Sigma transform.
         */
        var ptr16 = ptr0 ^ 128;
        this.state0 = t0 ^ 1;
        if (push) {
            this.state1 = t1 ^ this.inData0;
            this.state2 = t2 ^ this.inData1;
            this.state3 = t3 ^ this.inData2;
            this.state4 = t4 ^ this.inData3;
            this.state5 = t5 ^ this.inData4;
            this.state6 = t6 ^ this.inData5;
            this.state7 = t7 ^ this.inData6;
            this.state8 = t8 ^ this.inData7;
        } else {
            var ptr4 = (ptr0 + 32) & 248;
            this.state1 = t1 ^ this.buffer[ptr4 + 0];
            this.state2 = t2 ^ this.buffer[ptr4 + 1];
            this.state3 = t3 ^ this.buffer[ptr4 + 2];
            this.state4 = t4 ^ this.buffer[ptr4 + 3];
            this.state5 = t5 ^ this.buffer[ptr4 + 4];
            this.state6 = t6 ^ this.buffer[ptr4 + 5];
            this.state7 = t7 ^ this.buffer[ptr4 + 6];
            this.state8 = t8 ^ this.buffer[ptr4 + 7];
        }
        this.state9 = t9 ^ this.buffer[ptr16 + 0];
        this.state10 = t10 ^ this.buffer[ptr16 + 1];
        this.state11 = t11 ^ this.buffer[ptr16 + 2];
        this.state12 = t12 ^ this.buffer[ptr16 + 3];
        this.state13 = t13 ^ this.buffer[ptr16 + 4];
        this.state14 = t14 ^ this.buffer[ptr16 + 5];
        this.state15 = t15 ^ this.buffer[ptr16 + 6];
        this.state16 = t16 ^ this.buffer[ptr16 + 7];
    }

    /** @see Digest */
    toString() {
        return "PANAMA";
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
    private kipad!: Uint8Array
    private kopad!: Uint8Array;
    private outputLength!: number;
    private tmpOut!: Uint8Array;
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
    constructor(dig: Digest, key: Uint8Array, outputLength?: number) {
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
            if (len > B) {
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
        if (outputLength && outputLength < dig.getDigestLength()) {
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
    private _HMAC(dig: Digest, kipad: Uint8Array, kopad: Uint8Array, outputLength: number) {
        this.dig = dig;
        this.kipad = kipad;
        this.kopad = kopad;
        this.outputLength = outputLength;
        this.tmpOut = new Uint8Array(dig.getDigestLength());
        return this;
    }

    private processKey(keyB: Uint8Array) {
        var B = keyB.length;
        this.kipad = new Uint8Array(B);
        this.kopad = new Uint8Array(B);
        for (let i = 0; i < B; i++) {
            var x = keyB[i];
            this.kipad[i] = (x ^ 0x36);
            this.kopad[i] = (x ^ 0x5C);
        }
    }

    /** @see Digest */
    public copy(): Digest {
        const h = this._HMAC(this.dig.copy(), this.kipad, this.kopad, this.outputLength);
        return this.copyState(h);
    }

    /** @see Digest */
    public getDigestLength(): number {
        /*
         * At construction time, outputLength is first set to 0,
         * which means that this method will return 0, which is
         * appropriate since at that time "dig" has not yet been
         * set.
         */
        return this.outputLength < 0 ? this.dig.getDigestLength() : this.outputLength;
    }

    /** @see Digest */
    public getBlockLength(): number {
        /*
         * Internal block length is not defined for HMAC, which
         * is not, stricto-sensu, an iterated hash function.
         * The value 64 should provide correct buffering. Do NOT
         * change this value without checking doPadding().
         */
        return 64;
    }

    /** @see DigestEngine */
    protected engineReset() {
        this.dig.reset();
        this.dig.update(this.kipad);
    }

    /** @see DigestEngine */
    protected processBlock(data: Uint8Array) {
        if (this.onlyThis > 0) {
            this.dig.update(data, 0, this.onlyThis);
            this.onlyThis = 0;
        } else {
            this.dig.update(data);
        }
    }

    /** @see DigestEngine */
    protected doPadding(output: Uint8Array, outputOffset: number) {
        /*
         * This is slightly ugly... we need to get the still
         * buffered data, but the only way to get it from
         * DigestEngine is to input some more bytes and wait
         * for the processBlock() call. We set a variable
         * with the count of actual data bytes, so that
         * processBlock() knows what to do.
         */
        this.onlyThis = this.flush();
        if (this.onlyThis > 0) {
            this.update(HMAC.zeroPad, 0, 64 - this.onlyThis);
        }
        var olen = this.tmpOut.length;
        this.dig.digest(this.tmpOut, 0, olen);
        this.dig.update(this.kopad);
        this.dig.update(this.tmpOut);
        this.dig.digest(this.tmpOut, 0, olen);
        if (this.outputLength >= 0) {
            olen = this.outputLength;
        }
        arraycopy(this.tmpOut, 0, output, outputOffset, olen);
    }

    /** @see DigestEngine */
    protected doInit() {
        /*
         * Empty: we do not want to do anything here because
         * it would prevent correct cloning. The initialization
         * job is done in the constructor.
         */
    }

    /** @see Digest */
    public toString(): string {
        return "HMAC/" + this.dig.toString();
    }
}

/**
 * Creates a 32 byte PANAMA of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function _PANAMA(message: InputData, format: OutputFormat = arrayType()) {
    const hash = new Panama();
    hash.update(formatMessage(message));
    const digestbytes = hash.digest();
    if (format === "hex") {
        return bytesToHex(digestbytes);
    } else if (format === "buffer") {
        return Buffer.from(digestbytes);
    } else {
        return digestbytes;
    }
}

/**
 * Creates a 32 byte keyed PANAMA of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function PANAMA_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType()) {
    const hash = new Panama();
    const mac = new HMAC(hash, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    } else if (format == 'hex') {
        return bytesToHex(mac.digest());
    }
    return mac.digest();
}

/**
 * Static class of all Panama function
 */
export class PANAMA {
    static Panama = Panama;
    static PANAMA = _PANAMA;
    static PANAMA_HMAC = PANAMA_HMAC;
    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST() {
        return [
            "PANAMA",
            "PANAMA_HMAC"
        ]
    }
}
