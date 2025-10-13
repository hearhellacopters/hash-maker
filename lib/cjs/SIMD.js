"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SIMD = exports.SIMD512_HMAC = exports.SIMD512 = exports.SIMD384_HMAC = exports.SIMD384 = exports.SIMD256_HMAC = exports.SIMD256 = exports.SIMD224_HMAC = exports.SIMD224 = exports.SIMD_HMAC = exports._SIMD = exports.Simd512 = exports.Simd384 = exports.Simd256 = exports.Simd224 = void 0;
function arrayType() {
    if (typeof window !== 'undefined') {
        return "array";
    }
    else {
        return "buffer";
    }
}
;
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
class DigestEngine {
    constructor() {
        this.doInit();
        this.digestLen = this.getDigestLength();
        this.blockLen = this.getInternalBlockLength();
        this.inputBuf = new Uint8Array(this.blockLen);
        this.outputBuf = new Uint8Array(this.digestLen);
        this.inputLen = 0;
        this.blockCount = BigInt(0);
    }
    adjustDigestLen() {
        if (this.digestLen == undefined || this.digestLen === 0) {
            this.digestLen = this.getDigestLength();
            this.outputBuf = new Uint8Array(this.digestLen);
        }
    }
    digest(input, offset, len) {
        if (input === undefined) {
            this.adjustDigestLen();
            const result = new Uint8Array(this.digestLen);
            this.digest(result, 0, this.digestLen);
            return result;
        }
        else if (offset === undefined || len === undefined) {
            this.update(input, 0, input.length);
            return this.digest();
        }
        else {
            this.adjustDigestLen();
            if (len >= this.digestLen) {
                this.doPadding(input, offset);
                this.reset();
                return this.digestLen;
            }
            else {
                this.doPadding(this.outputBuf, 0);
                arraycopy(this.outputBuf, 0, input, offset, len);
                this.reset();
                return len;
            }
        }
    }
    reset() {
        this.engineReset();
        this.inputLen = 0;
        this.blockCount = BigInt(0);
    }
    update(input, offset, len) {
        if (typeof input === 'number') {
            this.inputBuf[this.inputLen++] = input;
            if (this.inputLen === this.blockLen) {
                this.processBlock(this.inputBuf);
                this.blockCount++;
                this.inputLen = 0;
            }
        }
        else if (offset === undefined || len === undefined) {
            this.update(input, 0, input.length);
        }
        else {
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
    getInternalBlockLength() {
        return this.getBlockLength();
    }
    flush() {
        return this.inputLen;
    }
    getBlockBuffer() {
        return this.inputBuf;
    }
    getBlockCount() {
        return this.blockCount;
    }
    copyState(dest) {
        dest.inputLen = this.inputLen;
        dest.blockCount = this.blockCount;
        arraycopy(this.inputBuf, 0, dest.inputBuf, 0, this.inputBuf.length);
        this.adjustDigestLen();
        dest.adjustDigestLen();
        arraycopy(this.outputBuf, 0, dest.outputBuf, 0, this.outputBuf.length);
        return dest;
    }
    getDigestLength() {
        throw new Error('Method not implemented.');
    }
    copy() {
        throw new Error('Method not implemented.');
    }
    getBlockLength() {
        throw new Error('Method not implemented.');
    }
    toString() {
        throw new Error('Method not implemented.');
    }
}
function arraycopy(src, srcPos = 0, dst, destPos = 0, length) {
    const src2 = [];
    for (let i = 0; i < length; i++) {
        src2.push(src[srcPos + i]);
    }
    for (let i = 0; i < length; i++) {
        dst[destPos + i] = src2[i];
    }
}
;
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
    constructor(dig, key, outputLength) {
        super();
        this.onlyThis = 0;
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
    _HMAC(dig, kipad, kopad, outputLength) {
        this.dig = dig;
        this.kipad = kipad;
        this.kopad = kopad;
        this.outputLength = outputLength;
        this.tmpOut = new Uint8Array(dig.getDigestLength());
        return this;
    }
    processKey(keyB) {
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
    copy() {
        const h = this._HMAC(this.dig.copy(), this.kipad, this.kopad, this.outputLength);
        return this.copyState(h);
    }
    /** @see Digest */
    getDigestLength() {
        /*
         * At construction time, outputLength is first set to 0,
         * which means that this method will return 0, which is
         * appropriate since at that time "dig" has not yet been
         * set.
         */
        return this.outputLength < 0 ? this.dig.getDigestLength() : this.outputLength;
    }
    /** @see Digest */
    getBlockLength() {
        /*
         * Internal block length is not defined for HMAC, which
         * is not, stricto-sensu, an iterated hash function.
         * The value 64 should provide correct buffering. Do NOT
         * change this value without checking doPadding().
         */
        return 64;
    }
    /** @see DigestEngine */
    engineReset() {
        this.dig.reset();
        this.dig.update(this.kipad);
    }
    /** @see DigestEngine */
    processBlock(data) {
        if (this.onlyThis > 0) {
            this.dig.update(data, 0, this.onlyThis);
            this.onlyThis = 0;
        }
        else {
            this.dig.update(data);
        }
    }
    /** @see DigestEngine */
    doPadding(output, outputOffset) {
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
    doInit() {
        /*
         * Empty: we do not want to do anything here because
         * it would prevent correct cloning. The initialization
         * job is done in the constructor.
         */
    }
    /** @see Digest */
    toString() {
        return "HMAC/" + this.dig.toString();
    }
}
HMAC.zeroPad = new Uint8Array(64);
/**
 * This class implements SIMD-224 and SIMD-256.
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
 * @version   $Revision: 241 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
class SIMDSmallCore extends DigestEngine {
    /**
     * Create the object.
     */
    constructor() {
        super();
    }
    /** @see Digest */
    getBlockLength() {
        return 64;
    }
    /** @see DigestEngine */
    copyState(dst) {
        arraycopy(this.state, 0, dst.state, 0, 16);
        return super.copyState(dst);
    }
    /** @see DigestEngine */
    engineReset() {
        const iv = this.getInitVal();
        arraycopy(iv, 0, this.state, 0, 16);
    }
    /** @see DigestEngine */
    doPadding(output, outputOffset) {
        var ptr = this.flush();
        const buf = this.getBlockBuffer();
        if (ptr != 0) {
            for (let i = ptr; i < 64; i++) {
                buf[i] = 0x00;
            }
            this.compress(buf, false);
        }
        var count = (this.getBlockCount() << BigInt(9)) + BigInt(ptr << 3);
        this.encodeLEInt(Number(count), buf, 0);
        this.encodeLEInt(Number(count >> BigInt(32)), buf, 4);
        for (let i = 8; i < 64; i++) {
            buf[i] = 0x00;
        }
        this.compress(buf, true);
        var n = this.getDigestLength() >>> 2;
        for (let i = 0; i < n; i++) {
            this.encodeLEInt(this.state[i], output, outputOffset + (i << 2));
        }
    }
    /** @see DigestEngine */
    doInit() {
        this.state = new Int32Array(16);
        this.q = new Int32Array(128);
        this.w = new Int32Array(32);
        this.tmpState = new Int32Array(16);
        this.tA = new Int32Array(4);
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
    encodeLEInt(val, buf, off) {
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
    decodeLEInt(buf, off) {
        return ((buf[off + 3] & 0xFF) << 24)
            | ((buf[off + 2] & 0xFF) << 16)
            | ((buf[off + 1] & 0xFF) << 8)
            | (buf[off] & 0xFF);
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
    circularLeft(x, n) {
        return (x << n) | (x >>> (32 - n));
    }
    /** @see DigestEngine */
    processBlock(data) {
        this.compress(data, false);
    }
    fft32(x, xb, xs, qoff) {
        const d = {
            1: new Int32Array(8),
            2: new Int32Array(8),
        };
        const a = new Int32Array(4);
        const b = new Int32Array(4);
        var x0, x1, x2, x3;
        var xd = xs << 1;
        {
            //int d1_0, d1_1, d1_2, d1_3, d1_4, d1_5, d1_6, d1_7;
            //int d2_0, d2_1, d2_2, d2_3, d2_4, d2_5, d2_6, d2_7;
            {
                x0 = x[xb] & 0xFF;
                x1 = x[xb + 2 * xd] & 0xFF;
                x2 = x[xb + 4 * xd] & 0xFF;
                x3 = x[xb + 6 * xd] & 0xFF;
                a[0] = x0 + x2;
                a[1] = x0 + (x2 << 4);
                a[2] = x0 - x2;
                a[3] = x0 - (x2 << 4);
                b[0] = x1 + x3;
                b[1] = ((((x1 << 2) + (x3 << 6)) & 0xFF)
                    - (((x1 << 2) + (x3 << 6)) >> 8));
                b[2] = (x1 << 4) - (x3 << 4);
                b[3] = ((((x1 << 6) + (x3 << 2)) & 0xFF)
                    - (((x1 << 6) + (x3 << 2)) >> 8));
                d[1][0] = a[0] + b[0];
                d[1][1] = a[1] + b[1];
                d[1][2] = a[2] + b[2];
                d[1][3] = a[3] + b[3];
                d[1][4] = a[0] - b[0];
                d[1][5] = a[1] - b[1];
                d[1][6] = a[2] - b[2];
                d[1][7] = a[3] - b[3];
            }
            {
                x0 = x[xb + xd] & 0xFF;
                x1 = x[xb + 3 * xd] & 0xFF;
                x2 = x[xb + 5 * xd] & 0xFF;
                x3 = x[xb + 7 * xd] & 0xFF;
                a[0] = x0 + x2;
                a[1] = x0 + (x2 << 4);
                a[2] = x0 - x2;
                a[3] = x0 - (x2 << 4);
                b[0] = x1 + x3;
                b[1] = ((((x1 << 2) + (x3 << 6)) & 0xFF)
                    - (((x1 << 2) + (x3 << 6)) >> 8));
                b[2] = (x1 << 4) - (x3 << 4);
                b[3] = ((((x1 << 6) + (x3 << 2)) & 0xFF)
                    - (((x1 << 6) + (x3 << 2)) >> 8));
                d[2][0] = a[0] + b[0];
                d[2][1] = a[1] + b[1];
                d[2][2] = a[2] + b[2];
                d[2][3] = a[3] + b[3];
                d[2][4] = a[0] - b[0];
                d[2][5] = a[1] - b[1];
                d[2][6] = a[2] - b[2];
                d[2][7] = a[3] - b[3];
            }
            this.q[qoff + 0] = d[1][0] + d[2][0];
            this.q[qoff + 1] = d[1][1] + (d[2][1] << 1);
            this.q[qoff + 2] = d[1][2] + (d[2][2] << 2);
            this.q[qoff + 3] = d[1][3] + (d[2][3] << 3);
            this.q[qoff + 4] = d[1][4] + (d[2][4] << 4);
            this.q[qoff + 5] = d[1][5] + (d[2][5] << 5);
            this.q[qoff + 6] = d[1][6] + (d[2][6] << 6);
            this.q[qoff + 7] = d[1][7] + (d[2][7] << 7);
            this.q[qoff + 8] = d[1][0] - d[2][0];
            this.q[qoff + 9] = d[1][1] - (d[2][1] << 1);
            this.q[qoff + 10] = d[1][2] - (d[2][2] << 2);
            this.q[qoff + 11] = d[1][3] - (d[2][3] << 3);
            this.q[qoff + 12] = d[1][4] - (d[2][4] << 4);
            this.q[qoff + 13] = d[1][5] - (d[2][5] << 5);
            this.q[qoff + 14] = d[1][6] - (d[2][6] << 6);
            this.q[qoff + 15] = d[1][7] - (d[2][7] << 7);
        }
        {
            //int d1_0, d1_1, d1_2, d1_3, d1_4, d1_5, d1_6, d1_7;
            //int d2_0, d2_1, d2_2, d2_3, d2_4, d2_5, d2_6, d2_7;
            {
                x0 = x[xb + xs] & 0xFF;
                x1 = x[xb + xs + 2 * xd] & 0xFF;
                x2 = x[xb + xs + 4 * xd] & 0xFF;
                x3 = x[xb + xs + 6 * xd] & 0xFF;
                a[0] = x0 + x2;
                a[1] = x0 + (x2 << 4);
                a[2] = x0 - x2;
                a[3] = x0 - (x2 << 4);
                b[0] = x1 + x3;
                b[1] = ((((x1 << 2) + (x3 << 6)) & 0xFF)
                    - (((x1 << 2) + (x3 << 6)) >> 8));
                b[2] = (x1 << 4) - (x3 << 4);
                b[3] = ((((x1 << 6) + (x3 << 2)) & 0xFF)
                    - (((x1 << 6) + (x3 << 2)) >> 8));
                d[1][0] = a[0] + b[0];
                d[1][1] = a[1] + b[1];
                d[1][2] = a[2] + b[2];
                d[1][3] = a[3] + b[3];
                d[1][4] = a[0] - b[0];
                d[1][5] = a[1] - b[1];
                d[1][6] = a[2] - b[2];
                d[1][7] = a[3] - b[3];
            }
            {
                x0 = x[xb + xs + xd] & 0xFF;
                x1 = x[xb + xs + 3 * xd] & 0xFF;
                x2 = x[xb + xs + 5 * xd] & 0xFF;
                x3 = x[xb + xs + 7 * xd] & 0xFF;
                a[0] = x0 + x2;
                a[1] = x0 + (x2 << 4);
                a[2] = x0 - x2;
                a[3] = x0 - (x2 << 4);
                b[0] = x1 + x3;
                b[1] = ((((x1 << 2) + (x3 << 6)) & 0xFF)
                    - (((x1 << 2) + (x3 << 6)) >> 8));
                b[2] = (x1 << 4) - (x3 << 4);
                b[3] = ((((x1 << 6) + (x3 << 2)) & 0xFF)
                    - (((x1 << 6) + (x3 << 2)) >> 8));
                d[2][0] = a[0] + b[0];
                d[2][1] = a[1] + b[1];
                d[2][2] = a[2] + b[2];
                d[2][3] = a[3] + b[3];
                d[2][4] = a[0] - b[0];
                d[2][5] = a[1] - b[1];
                d[2][6] = a[2] - b[2];
                d[2][7] = a[3] - b[3];
            }
            ;
            this.q[qoff + 16 + 0] = d[1][0] + d[2][0];
            this.q[qoff + 16 + 1] = d[1][1] + (d[2][1] << 1);
            this.q[qoff + 16 + 2] = d[1][2] + (d[2][2] << 2);
            this.q[qoff + 16 + 3] = d[1][3] + (d[2][3] << 3);
            this.q[qoff + 16 + 4] = d[1][4] + (d[2][4] << 4);
            this.q[qoff + 16 + 5] = d[1][5] + (d[2][5] << 5);
            this.q[qoff + 16 + 6] = d[1][6] + (d[2][6] << 6);
            this.q[qoff + 16 + 7] = d[1][7] + (d[2][7] << 7);
            this.q[qoff + 16 + 8] = d[1][0] - d[2][0];
            this.q[qoff + 16 + 9] = d[1][1] - (d[2][1] << 1);
            this.q[qoff + 16 + 10] = d[1][2] - (d[2][2] << 2);
            this.q[qoff + 16 + 11] = d[1][3] - (d[2][3] << 3);
            this.q[qoff + 16 + 12] = d[1][4] - (d[2][4] << 4);
            this.q[qoff + 16 + 13] = d[1][5] - (d[2][5] << 5);
            this.q[qoff + 16 + 14] = d[1][6] - (d[2][6] << 6);
            this.q[qoff + 16 + 15] = d[1][7] - (d[2][7] << 7);
        }
        var m = this.q[qoff];
        var n = this.q[qoff + 16];
        this.q[qoff] = m + n;
        this.q[qoff + 16] = m - n;
        for (let u = 0, v = 0; u < 16; u += 4, v += 4 * 8) {
            var t;
            if (u != 0) {
                m = this.q[qoff + u + 0];
                n = this.q[qoff + u + 0 + 16];
                t = ((n * SIMDSmallCore.alphaTab[v + 0 * 8]) & 0xFFFF)
                    + ((n * SIMDSmallCore.alphaTab[v + 0 * 8]) >> 16);
                this.q[qoff + u + 0] = m + t;
                this.q[qoff + u + 0 + 16] = m - t;
            }
            m = this.q[qoff + u + 1];
            n = this.q[qoff + u + 1 + 16];
            t = (((n * SIMDSmallCore.alphaTab[v + 1 * (8)]) & 0xFFFF)
                + ((n * SIMDSmallCore.alphaTab[v + 1 * (8)]) >> 16));
            this.q[qoff + u + 1] = m + t;
            this.q[qoff + u + 1 + 16] = m - t;
            m = this.q[qoff + u + 2];
            n = this.q[qoff + u + 2 + 16];
            t = (((n * SIMDSmallCore.alphaTab[v + 2 * (8)]) & 0xFFFF)
                + ((n * SIMDSmallCore.alphaTab[v + 2 * (8)]) >> 16));
            this.q[qoff + u + 2] = m + t;
            this.q[qoff + u + 2 + 16] = m - t;
            m = this.q[qoff + u + 3];
            n = this.q[qoff + u + 3 + 16];
            t = (((n * SIMDSmallCore.alphaTab[v + 3 * (8)]) & 0xFFFF)
                + ((n * SIMDSmallCore.alphaTab[v + 3 * (8)]) >> 16));
            this.q[qoff + u + 3] = m + t;
            this.q[qoff + u + 3 + 16] = m - t;
        }
    }
    oneRound(isp, p0, p1, p2, p3) {
        var tmp;
        this.tA[0] = this.circularLeft(this.state[0], p0);
        this.tA[1] = this.circularLeft(this.state[1], p0);
        this.tA[2] = this.circularLeft(this.state[2], p0);
        this.tA[3] = this.circularLeft(this.state[3], p0);
        tmp = this.state[12] + this.w[0]
            + (((this.state[4] ^ this.state[8]) & this.state[0]) ^ this.state[8]);
        this.state[0] = this.circularLeft(tmp, p1) + this.tA[SIMDSmallCore.pp4k[isp + 0] ^ 0];
        this.state[12] = this.state[8];
        this.state[8] = this.state[4];
        this.state[4] = this.tA[0];
        tmp = this.state[13] + this.w[1]
            + (((this.state[5] ^ this.state[9]) & this.state[1]) ^ this.state[9]);
        this.state[1] = this.circularLeft(tmp, p1) + this.tA[SIMDSmallCore.pp4k[isp + 0] ^ 1];
        this.state[13] = this.state[9];
        this.state[9] = this.state[5];
        this.state[5] = this.tA[1];
        tmp = this.state[14] + this.w[2]
            + (((this.state[6] ^ this.state[10]) & this.state[2]) ^ this.state[10]);
        this.state[2] = this.circularLeft(tmp, p1) + this.tA[SIMDSmallCore.pp4k[isp + 0] ^ 2];
        this.state[14] = this.state[10];
        this.state[10] = this.state[6];
        this.state[6] = this.tA[2];
        tmp = this.state[15] + this.w[3]
            + (((this.state[7] ^ this.state[11]) & this.state[3]) ^ this.state[11]);
        this.state[3] = this.circularLeft(tmp, p1) + this.tA[SIMDSmallCore.pp4k[isp + 0] ^ 3];
        this.state[15] = this.state[11];
        this.state[11] = this.state[7];
        this.state[7] = this.tA[3];
        this.tA[0] = this.circularLeft(this.state[0], p1);
        this.tA[1] = this.circularLeft(this.state[1], p1);
        this.tA[2] = this.circularLeft(this.state[2], p1);
        this.tA[3] = this.circularLeft(this.state[3], p1);
        tmp = this.state[12] + this.w[4]
            + (((this.state[4] ^ this.state[8]) & this.state[0]) ^ this.state[8]);
        this.state[0] = this.circularLeft(tmp, p2) + this.tA[SIMDSmallCore.pp4k[isp + 1] ^ 0];
        this.state[12] = this.state[8];
        this.state[8] = this.state[4];
        this.state[4] = this.tA[0];
        tmp = this.state[13] + this.w[5]
            + (((this.state[5] ^ this.state[9]) & this.state[1]) ^ this.state[9]);
        this.state[1] = this.circularLeft(tmp, p2) + this.tA[SIMDSmallCore.pp4k[isp + 1] ^ 1];
        this.state[13] = this.state[9];
        this.state[9] = this.state[5];
        this.state[5] = this.tA[1];
        tmp = this.state[14] + this.w[6]
            + (((this.state[6] ^ this.state[10]) & this.state[2]) ^ this.state[10]);
        this.state[2] = this.circularLeft(tmp, p2) + this.tA[SIMDSmallCore.pp4k[isp + 1] ^ 2];
        this.state[14] = this.state[10];
        this.state[10] = this.state[6];
        this.state[6] = this.tA[2];
        tmp = this.state[15] + this.w[7]
            + (((this.state[7] ^ this.state[11]) & this.state[3]) ^ this.state[11]);
        this.state[3] = this.circularLeft(tmp, p2) + this.tA[SIMDSmallCore.pp4k[isp + 1] ^ 3];
        this.state[15] = this.state[11];
        this.state[11] = this.state[7];
        this.state[7] = this.tA[3];
        this.tA[0] = this.circularLeft(this.state[0], p2);
        this.tA[1] = this.circularLeft(this.state[1], p2);
        this.tA[2] = this.circularLeft(this.state[2], p2);
        this.tA[3] = this.circularLeft(this.state[3], p2);
        tmp = this.state[12] + this.w[8]
            + (((this.state[4] ^ this.state[8]) & this.state[0]) ^ this.state[8]);
        this.state[0] = this.circularLeft(tmp, p3) + this.tA[SIMDSmallCore.pp4k[isp + 2] ^ 0];
        this.state[12] = this.state[8];
        this.state[8] = this.state[4];
        this.state[4] = this.tA[0];
        tmp = this.state[13] + this.w[9]
            + (((this.state[5] ^ this.state[9]) & this.state[1]) ^ this.state[9]);
        this.state[1] = this.circularLeft(tmp, p3) + this.tA[SIMDSmallCore.pp4k[isp + 2] ^ 1];
        this.state[13] = this.state[9];
        this.state[9] = this.state[5];
        this.state[5] = this.tA[1];
        tmp = this.state[14] + this.w[10]
            + (((this.state[6] ^ this.state[10]) & this.state[2]) ^ this.state[10]);
        this.state[2] = this.circularLeft(tmp, p3) + this.tA[SIMDSmallCore.pp4k[isp + 2] ^ 2];
        this.state[14] = this.state[10];
        this.state[10] = this.state[6];
        this.state[6] = this.tA[2];
        tmp = this.state[15] + this.w[11]
            + (((this.state[7] ^ this.state[11]) & this.state[3]) ^ this.state[11]);
        this.state[3] = this.circularLeft(tmp, p3) + this.tA[SIMDSmallCore.pp4k[isp + 2] ^ 3];
        this.state[15] = this.state[11];
        this.state[11] = this.state[7];
        this.state[7] = this.tA[3];
        this.tA[0] = this.circularLeft(this.state[0], p3);
        this.tA[1] = this.circularLeft(this.state[1], p3);
        this.tA[2] = this.circularLeft(this.state[2], p3);
        this.tA[3] = this.circularLeft(this.state[3], p3);
        tmp = this.state[12] + this.w[12]
            + (((this.state[4] ^ this.state[8]) & this.state[0]) ^ this.state[8]);
        this.state[0] = this.circularLeft(tmp, p0) + this.tA[SIMDSmallCore.pp4k[isp + 3] ^ 0];
        this.state[12] = this.state[8];
        this.state[8] = this.state[4];
        this.state[4] = this.tA[0];
        tmp = this.state[13] + this.w[13]
            + (((this.state[5] ^ this.state[9]) & this.state[1]) ^ this.state[9]);
        this.state[1] = this.circularLeft(tmp, p0) + this.tA[SIMDSmallCore.pp4k[isp + 3] ^ 1];
        this.state[13] = this.state[9];
        this.state[9] = this.state[5];
        this.state[5] = this.tA[1];
        tmp = this.state[14] + this.w[14]
            + (((this.state[6] ^ this.state[10]) & this.state[2]) ^ this.state[10]);
        this.state[2] = this.circularLeft(tmp, p0) + this.tA[SIMDSmallCore.pp4k[isp + 3] ^ 2];
        this.state[14] = this.state[10];
        this.state[10] = this.state[6];
        this.state[6] = this.tA[2];
        tmp = this.state[15] + this.w[15]
            + (((this.state[7] ^ this.state[11]) & this.state[3]) ^ this.state[11]);
        this.state[3] = this.circularLeft(tmp, p0) + this.tA[SIMDSmallCore.pp4k[isp + 3] ^ 3];
        this.state[15] = this.state[11];
        this.state[11] = this.state[7];
        this.state[7] = this.tA[3];
        this.tA[0] = this.circularLeft(this.state[0], p0);
        this.tA[1] = this.circularLeft(this.state[1], p0);
        this.tA[2] = this.circularLeft(this.state[2], p0);
        this.tA[3] = this.circularLeft(this.state[3], p0);
        tmp = this.state[12] + this.w[16]
            + ((this.state[0] & this.state[4])
                | ((this.state[0] | this.state[4]) & this.state[8]));
        this.state[0] = this.circularLeft(tmp, p1) + this.tA[SIMDSmallCore.pp4k[isp + 4] ^ 0];
        this.state[12] = this.state[8];
        this.state[8] = this.state[4];
        this.state[4] = this.tA[0];
        tmp = this.state[13] + this.w[17]
            + ((this.state[1] & this.state[5])
                | ((this.state[1] | this.state[5]) & this.state[9]));
        this.state[1] = this.circularLeft(tmp, p1) + this.tA[SIMDSmallCore.pp4k[isp + 4] ^ 1];
        this.state[13] = this.state[9];
        this.state[9] = this.state[5];
        this.state[5] = this.tA[1];
        tmp = this.state[14] + this.w[18]
            + ((this.state[2] & this.state[6])
                | ((this.state[2] | this.state[6]) & this.state[10]));
        this.state[2] = this.circularLeft(tmp, p1) + this.tA[SIMDSmallCore.pp4k[isp + 4] ^ 2];
        this.state[14] = this.state[10];
        this.state[10] = this.state[6];
        this.state[6] = this.tA[2];
        tmp = this.state[15] + this.w[19]
            + ((this.state[3] & this.state[7])
                | ((this.state[3] | this.state[7]) & this.state[11]));
        this.state[3] = this.circularLeft(tmp, p1) + this.tA[SIMDSmallCore.pp4k[isp + 4] ^ 3];
        this.state[15] = this.state[11];
        this.state[11] = this.state[7];
        this.state[7] = this.tA[3];
        this.tA[0] = this.circularLeft(this.state[0], p1);
        this.tA[1] = this.circularLeft(this.state[1], p1);
        this.tA[2] = this.circularLeft(this.state[2], p1);
        this.tA[3] = this.circularLeft(this.state[3], p1);
        tmp = this.state[12] + this.w[20]
            + ((this.state[0] & this.state[4])
                | ((this.state[0] | this.state[4]) & this.state[8]));
        this.state[0] = this.circularLeft(tmp, p2) + this.tA[SIMDSmallCore.pp4k[isp + 5] ^ 0];
        this.state[12] = this.state[8];
        this.state[8] = this.state[4];
        this.state[4] = this.tA[0];
        tmp = this.state[13] + this.w[21]
            + ((this.state[1] & this.state[5])
                | ((this.state[1] | this.state[5]) & this.state[9]));
        this.state[1] = this.circularLeft(tmp, p2) + this.tA[SIMDSmallCore.pp4k[isp + 5] ^ 1];
        this.state[13] = this.state[9];
        this.state[9] = this.state[5];
        this.state[5] = this.tA[1];
        tmp = this.state[14] + this.w[22]
            + ((this.state[2] & this.state[6])
                | ((this.state[2] | this.state[6]) & this.state[10]));
        this.state[2] = this.circularLeft(tmp, p2) + this.tA[SIMDSmallCore.pp4k[isp + 5] ^ 2];
        this.state[14] = this.state[10];
        this.state[10] = this.state[6];
        this.state[6] = this.tA[2];
        tmp = this.state[15] + this.w[23]
            + ((this.state[3] & this.state[7])
                | ((this.state[3] | this.state[7]) & this.state[11]));
        this.state[3] = this.circularLeft(tmp, p2) + this.tA[SIMDSmallCore.pp4k[isp + 5] ^ 3];
        this.state[15] = this.state[11];
        this.state[11] = this.state[7];
        this.state[7] = this.tA[3];
        this.tA[0] = this.circularLeft(this.state[0], p2);
        this.tA[1] = this.circularLeft(this.state[1], p2);
        this.tA[2] = this.circularLeft(this.state[2], p2);
        this.tA[3] = this.circularLeft(this.state[3], p2);
        tmp = this.state[12] + this.w[24]
            + ((this.state[0] & this.state[4])
                | ((this.state[0] | this.state[4]) & this.state[8]));
        this.state[0] = this.circularLeft(tmp, p3) + this.tA[SIMDSmallCore.pp4k[isp + 6] ^ 0];
        this.state[12] = this.state[8];
        this.state[8] = this.state[4];
        this.state[4] = this.tA[0];
        tmp = this.state[13] + this.w[25]
            + ((this.state[1] & this.state[5])
                | ((this.state[1] | this.state[5]) & this.state[9]));
        this.state[1] = this.circularLeft(tmp, p3) + this.tA[SIMDSmallCore.pp4k[isp + 6] ^ 1];
        this.state[13] = this.state[9];
        this.state[9] = this.state[5];
        this.state[5] = this.tA[1];
        tmp = this.state[14] + this.w[26]
            + ((this.state[2] & this.state[6])
                | ((this.state[2] | this.state[6]) & this.state[10]));
        this.state[2] = this.circularLeft(tmp, p3) + this.tA[SIMDSmallCore.pp4k[isp + 6] ^ 2];
        this.state[14] = this.state[10];
        this.state[10] = this.state[6];
        this.state[6] = this.tA[2];
        tmp = this.state[15] + this.w[27]
            + ((this.state[3] & this.state[7])
                | ((this.state[3] | this.state[7]) & this.state[11]));
        this.state[3] = this.circularLeft(tmp, p3) + this.tA[SIMDSmallCore.pp4k[isp + 6] ^ 3];
        this.state[15] = this.state[11];
        this.state[11] = this.state[7];
        this.state[7] = this.tA[3];
        this.tA[0] = this.circularLeft(this.state[0], p3);
        this.tA[1] = this.circularLeft(this.state[1], p3);
        this.tA[2] = this.circularLeft(this.state[2], p3);
        this.tA[3] = this.circularLeft(this.state[3], p3);
        tmp = this.state[12] + this.w[28]
            + ((this.state[0] & this.state[4])
                | ((this.state[0] | this.state[4]) & this.state[8]));
        this.state[0] = this.circularLeft(tmp, p0) + this.tA[SIMDSmallCore.pp4k[isp + 7] ^ 0];
        this.state[12] = this.state[8];
        this.state[8] = this.state[4];
        this.state[4] = this.tA[0];
        tmp = this.state[13] + this.w[29]
            + ((this.state[1] & this.state[5])
                | ((this.state[1] | this.state[5]) & this.state[9]));
        this.state[1] = this.circularLeft(tmp, p0) + this.tA[SIMDSmallCore.pp4k[isp + 7] ^ 1];
        this.state[13] = this.state[9];
        this.state[9] = this.state[5];
        this.state[5] = this.tA[1];
        tmp = this.state[14] + this.w[30]
            + ((this.state[2] & this.state[6])
                | ((this.state[2] | this.state[6]) & this.state[10]));
        this.state[2] = this.circularLeft(tmp, p0) + this.tA[SIMDSmallCore.pp4k[isp + 7] ^ 2];
        this.state[14] = this.state[10];
        this.state[10] = this.state[6];
        this.state[6] = this.tA[2];
        tmp = this.state[15] + this.w[31]
            + ((this.state[3] & this.state[7])
                | ((this.state[3] | this.state[7]) & this.state[11]));
        this.state[3] = this.circularLeft(tmp, p0) + this.tA[SIMDSmallCore.pp4k[isp + 7] ^ 3];
        this.state[15] = this.state[11];
        this.state[11] = this.state[7];
        this.state[7] = this.tA[3];
    }
    compress(x, last) {
        this.fft32(x, 0 + (1 * 0), 1 << 2, 0 + 0);
        this.fft32(x, 0 + (1 * 2), 1 << 2, 0 + 32);
        var m = this.q[0];
        var n = this.q[0 + 32];
        this.q[0] = m + n;
        this.q[0 + 32] = m - n;
        for (let u = 0, v = 0; u < 32; u += 4, v += 4 * 4) {
            var t;
            if (u != 0) {
                m = this.q[0 + u + 0];
                n = this.q[0 + u + 0 + 32];
                t = (((n * SIMDSmallCore.alphaTab[v + 0 * 4]) & 0xFFFF)
                    + ((n * SIMDSmallCore.alphaTab[v + 0 * 4]) >> 16));
                this.q[0 + u + 0] = m + t;
                this.q[0 + u + 0 + 32] = m - t;
            }
            m = this.q[0 + u + 1];
            n = this.q[0 + u + 1 + 32];
            t = (((n * SIMDSmallCore.alphaTab[v + 1 * 4]) & 0xFFFF)
                + ((n * SIMDSmallCore.alphaTab[v + 1 * 4]) >> 16));
            this.q[0 + u + 1] = m + t;
            this.q[0 + u + 1 + 32] = m - t;
            m = this.q[0 + u + 2];
            n = this.q[0 + u + 2 + 32];
            t = (((n * SIMDSmallCore.alphaTab[v + 2 * 4]) & 0xFFFF)
                + ((n * SIMDSmallCore.alphaTab[v + 2 * 4]) >> 16));
            this.q[0 + u + 2] = m + t;
            this.q[0 + u + 2 + 32] = m - t;
            m = this.q[0 + u + 3];
            n = this.q[0 + u + 3 + 32];
            t = (((n * SIMDSmallCore.alphaTab[v + 3 * 4]) & 0xFFFF)
                + ((n * SIMDSmallCore.alphaTab[v + 3 * 4]) >> 16));
            this.q[0 + u + 3] = m + t;
            this.q[0 + u + 3 + 32] = m - t;
        }
        this.fft32(x, 0 + (1 * 1), 1 << 2, 0 + 64);
        this.fft32(x, 0 + (1 * 3), 1 << 2, 0 + 96);
        m = this.q[(0 + 64)];
        n = this.q[(0 + 64) + 32];
        this.q[(0 + 64)] = m + n;
        this.q[(0 + 64) + 32] = m - n;
        for (let u = 0, v = 0; u < 32; u += 4, v += 4 * 4) {
            var t;
            if (u != 0) {
                m = this.q[(0 + 64) + u + 0];
                n = this.q[(0 + 64) + u + 0 + 32];
                t = (((n * SIMDSmallCore.alphaTab[v + 0 * 4]) & 0xFFFF)
                    + ((n * SIMDSmallCore.alphaTab[v + 0 * 4]) >> 16));
                this.q[(0 + 64) + u + 0] = m + t;
                this.q[(0 + 64) + u + 0 + 32] = m - t;
            }
            m = this.q[(0 + 64) + u + 1];
            n = this.q[(0 + 64) + u + 1 + 32];
            t = (((n * SIMDSmallCore.alphaTab[v + 1 * 4]) & 0xFFFF)
                + ((n * SIMDSmallCore.alphaTab[v + 1 * 4]) >> 16));
            this.q[(0 + 64) + u + 1] = m + t;
            this.q[(0 + 64) + u + 1 + 32] = m - t;
            m = this.q[(0 + 64) + u + 2];
            n = this.q[(0 + 64) + u + 2 + 32];
            t = (((n * SIMDSmallCore.alphaTab[v + 2 * 4]) & 0xFFFF)
                + ((n * SIMDSmallCore.alphaTab[v + 2 * 4]) >> 16));
            this.q[(0 + 64) + u + 2] = m + t;
            this.q[(0 + 64) + u + 2 + 32] = m - t;
            m = this.q[(0 + 64) + u + 3];
            n = this.q[(0 + 64) + u + 3 + 32];
            t = (((n * SIMDSmallCore.alphaTab[v + 3 * 4]) & 0xFFFF)
                + ((n * SIMDSmallCore.alphaTab[v + 3 * 4]) >> 16));
            this.q[(0 + 64) + u + 3] = m + t;
            this.q[(0 + 64) + u + 3 + 32] = m - t;
        }
        m = this.q[0];
        n = this.q[0 + 64];
        this.q[0] = m + n;
        this.q[0 + 64] = m - n;
        for (let u = 0, v = 0; u < 64; u += 4, v += 4 * 2) {
            var t;
            if (u != 0) {
                m = this.q[0 + u + 0];
                n = this.q[0 + u + 0 + 64];
                t = (((n * SIMDSmallCore.alphaTab[v + 0 * 2]) & 0xFFFF)
                    + ((n * SIMDSmallCore.alphaTab[v + 0 * 2]) >> 16));
                this.q[0 + u + 0] = m + t;
                this.q[0 + u + 0 + 64] = m - t;
            }
            m = this.q[0 + u + 1];
            n = this.q[0 + u + 1 + 64];
            t = (((n * SIMDSmallCore.alphaTab[v + 1 * 2]) & 0xFFFF)
                + ((n * SIMDSmallCore.alphaTab[v + 1 * 2]) >> 16));
            this.q[0 + u + 1] = m + t;
            this.q[0 + u + 1 + 64] = m - t;
            m = this.q[0 + u + 2];
            n = this.q[0 + u + 2 + 64];
            t = (((n * SIMDSmallCore.alphaTab[v + 2 * 2]) & 0xFFFF)
                + ((n * SIMDSmallCore.alphaTab[v + 2 * 2]) >> 16));
            this.q[0 + u + 2] = m + t;
            this.q[0 + u + 2 + 64] = m - t;
            m = this.q[0 + u + 3];
            n = this.q[0 + u + 3 + 64];
            t = (((n * SIMDSmallCore.alphaTab[v + 3 * 2]) & 0xFFFF)
                + ((n * SIMDSmallCore.alphaTab[v + 3 * 2]) >> 16));
            this.q[0 + u + 3] = m + t;
            this.q[0 + u + 3 + 64] = m - t;
        }
        if (last) {
            for (let i = 0; i < 128; i++) {
                var tq;
                tq = this.q[i] + SIMDSmallCore.yoffF[i];
                tq = ((tq & 0xFFFF) + (tq >> 16));
                tq = ((tq & 0xFF) - (tq >> 8));
                tq = ((tq & 0xFF) - (tq >> 8));
                this.q[i] = (tq <= 128 ? tq : tq - 257);
            }
        }
        else {
            for (let i = 0; i < 128; i++) {
                var tq;
                tq = this.q[i] + SIMDSmallCore.yoffN[i];
                tq = ((tq & 0xFFFF) + (tq >> 16));
                tq = ((tq & 0xFF) - (tq >> 8));
                tq = ((tq & 0xFF) - (tq >> 8));
                this.q[i] = (tq <= 128 ? tq : tq - 257);
            }
        }
        arraycopy(this.state, 0, this.tmpState, 0, 16);
        for (let i = 0; i < 16; i += 4) {
            this.state[i + 0] ^= this.decodeLEInt(x, 4 * (i + 0));
            this.state[i + 1] ^= this.decodeLEInt(x, 4 * (i + 1));
            this.state[i + 2] ^= this.decodeLEInt(x, 4 * (i + 2));
            this.state[i + 3] ^= this.decodeLEInt(x, 4 * (i + 3));
        }
        for (let u = 0; u < 32; u += 4) {
            var v = SIMDSmallCore.wsp[(u >> 2) + 0];
            this.w[u + 0] = ((((this.q[v + 2 * 0 + 0]) * 185) & 0xFFFF)
                + (((this.q[v + 2 * 0 + 1]) * 185) << 16));
            this.w[u + 1] = ((((this.q[v + 2 * 1 + 0]) * 185) & 0xFFFF)
                + (((this.q[v + 2 * 1 + 1]) * 185) << 16));
            this.w[u + 2] = ((((this.q[v + 2 * 2 + 0]) * 185) & 0xFFFF)
                + (((this.q[v + 2 * 2 + 1]) * 185) << 16));
            this.w[u + 3] = ((((this.q[v + 2 * 3 + 0]) * 185) & 0xFFFF)
                + (((this.q[v + 2 * 3 + 1]) * 185) << 16));
        }
        ;
        this.oneRound(0, 3, 23, 17, 27);
        for (let u = 0; u < 32; u += 4) {
            var v = SIMDSmallCore.wsp[(u >> 2) + 8];
            this.w[u + 0] = ((((this.q[v + 2 * 0 + 0]) * 185) & 0xFFFF)
                + (((this.q[v + 2 * 0 + 1]) * 185) << 16));
            this.w[u + 1] = ((((this.q[v + 2 * 1 + 0]) * 185) & 0xFFFF)
                + (((this.q[v + 2 * 1 + 1]) * 185) << 16));
            this.w[u + 2] = ((((this.q[v + 2 * 2 + 0]) * 185) & 0xFFFF)
                + (((this.q[v + 2 * 2 + 1]) * 185) << 16));
            this.w[u + 3] = ((((this.q[v + 2 * 3 + 0]) * 185) & 0xFFFF)
                + (((this.q[v + 2 * 3 + 1]) * 185) << 16));
        }
        ;
        this.oneRound(2, 28, 19, 22, 7);
        for (let u = 0; u < 32; u += 4) {
            var v = SIMDSmallCore.wsp[(u >> 2) + 16];
            this.w[u + 0] = ((((this.q[v + 2 * 0 + -128]) * 233) & 0xFFFF)
                + (((this.q[v + 2 * 0 + -64]) * 233) << 16));
            this.w[u + 1] = ((((this.q[v + 2 * 1 + -128]) * 233) & 0xFFFF)
                + (((this.q[v + 2 * 1 + -64]) * 233) << 16));
            this.w[u + 2] = ((((this.q[v + 2 * 2 + -128]) * 233) & 0xFFFF)
                + (((this.q[v + 2 * 2 + -64]) * 233) << 16));
            this.w[u + 3] = ((((this.q[v + 2 * 3 + -128]) * 233) & 0xFFFF)
                + (((this.q[v + 2 * 3 + -64]) * 233) << 16));
        }
        ;
        this.oneRound(1, 29, 9, 15, 5);
        for (let u = 0; u < 32; u += 4) {
            var v = SIMDSmallCore.wsp[(u >> 2) + 24];
            this.w[u + 0] = ((((this.q[v + 2 * 0 + -191]) * 233) & 0xFFFF)
                + (((this.q[v + 2 * 0 + -127]) * 233) << 16));
            this.w[u + 1] = ((((this.q[v + 2 * 1 + -191]) * 233) & 0xFFFF)
                + (((this.q[v + 2 * 1 + -127]) * 233) << 16));
            this.w[u + 2] = ((((this.q[v + 2 * 2 + -191]) * 233) & 0xFFFF)
                + (((this.q[v + 2 * 2 + -127]) * 233) << 16));
            this.w[u + 3] = ((((this.q[v + 2 * 3 + -191]) * 233) & 0xFFFF)
                + (((this.q[v + 2 * 3 + -127]) * 233) << 16));
        }
        ;
        this.oneRound(0, 4, 13, 10, 25);
        var tA0, tA1, tA2, tA3, tmp;
        {
            tA0 = this.circularLeft(this.state[0], 4);
            tA1 = this.circularLeft(this.state[1], 4);
            tA2 = this.circularLeft(this.state[2], 4);
            tA3 = this.circularLeft(this.state[3], 4);
            tmp = this.state[12] + (this.tmpState[0]) + (((this.state[4]
                ^ this.state[8]) & this.state[0]) ^ this.state[8]);
            this.state[0] = this.circularLeft(tmp, 13) + tA3;
            this.state[12] = this.state[8];
            this.state[8] = this.state[4];
            this.state[4] = tA0;
            tmp = this.state[13] + (this.tmpState[1]) + (((this.state[5]
                ^ this.state[9]) & this.state[1]) ^ this.state[9]);
            this.state[1] = this.circularLeft(tmp, 13) + tA2;
            this.state[13] = this.state[9];
            this.state[9] = this.state[5];
            this.state[5] = tA1;
            tmp = this.state[14] + (this.tmpState[2]) + (((this.state[6]
                ^ this.state[10]) & this.state[2]) ^ this.state[10]);
            this.state[2] = this.circularLeft(tmp, 13) + tA1;
            this.state[14] = this.state[10];
            this.state[10] = this.state[6];
            this.state[6] = tA2;
            tmp = this.state[15] + (this.tmpState[3]) + (((this.state[7]
                ^ this.state[11]) & this.state[3]) ^ this.state[11]);
            this.state[3] = this.circularLeft(tmp, 13) + tA0;
            this.state[15] = this.state[11];
            this.state[11] = this.state[7];
            this.state[7] = tA3;
        }
        {
            tA0 = this.circularLeft(this.state[0], 13);
            tA1 = this.circularLeft(this.state[1], 13);
            tA2 = this.circularLeft(this.state[2], 13);
            tA3 = this.circularLeft(this.state[3], 13);
            tmp = this.state[12] + (this.tmpState[4]) + (((this.state[4]
                ^ this.state[8]) & this.state[0]) ^ this.state[8]);
            this.state[0] = this.circularLeft(tmp, 10) + tA1;
            this.state[12] = this.state[8];
            this.state[8] = this.state[4];
            this.state[4] = tA0;
            tmp = this.state[13] + (this.tmpState[5]) + (((this.state[5]
                ^ this.state[9]) & this.state[1]) ^ this.state[9]);
            this.state[1] = this.circularLeft(tmp, 10) + tA0;
            this.state[13] = this.state[9];
            this.state[9] = this.state[5];
            this.state[5] = tA1;
            tmp = this.state[14] + (this.tmpState[6]) + (((this.state[6]
                ^ this.state[10]) & this.state[2]) ^ this.state[10]);
            this.state[2] = this.circularLeft(tmp, 10) + tA3;
            this.state[14] = this.state[10];
            this.state[10] = this.state[6];
            this.state[6] = tA2;
            tmp = this.state[15] + (this.tmpState[7]) + (((this.state[7]
                ^ this.state[11]) & this.state[3]) ^ this.state[11]);
            this.state[3] = this.circularLeft(tmp, 10) + tA2;
            this.state[15] = this.state[11];
            this.state[11] = this.state[7];
            this.state[7] = tA3;
        }
        {
            tA0 = this.circularLeft(this.state[0], 10);
            tA1 = this.circularLeft(this.state[1], 10);
            tA2 = this.circularLeft(this.state[2], 10);
            tA3 = this.circularLeft(this.state[3], 10);
            tmp = this.state[12] + (this.tmpState[8]) + (((this.state[4]
                ^ this.state[8]) & this.state[0]) ^ this.state[8]);
            this.state[0] = this.circularLeft(tmp, 25) + tA2;
            this.state[12] = this.state[8];
            this.state[8] = this.state[4];
            this.state[4] = tA0;
            tmp = this.state[13] + (this.tmpState[9]) + (((this.state[5]
                ^ this.state[9]) & this.state[1]) ^ this.state[9]);
            this.state[1] = this.circularLeft(tmp, 25) + tA3;
            this.state[13] = this.state[9];
            this.state[9] = this.state[5];
            this.state[5] = tA1;
            tmp = this.state[14] + (this.tmpState[10]) + (((this.state[6]
                ^ this.state[10]) & this.state[2]) ^ this.state[10]);
            this.state[2] = this.circularLeft(tmp, 25) + tA0;
            this.state[14] = this.state[10];
            this.state[10] = this.state[6];
            this.state[6] = tA2;
            tmp = this.state[15] + (this.tmpState[11]) + (((this.state[7]
                ^ this.state[11]) & this.state[3]) ^ this.state[11]);
            this.state[3] = this.circularLeft(tmp, 25) + tA1;
            this.state[15] = this.state[11];
            this.state[11] = this.state[7];
            this.state[7] = tA3;
        }
        {
            tA0 = this.circularLeft(this.state[0], 25);
            tA1 = this.circularLeft(this.state[1], 25);
            tA2 = this.circularLeft(this.state[2], 25);
            tA3 = this.circularLeft(this.state[3], 25);
            tmp = this.state[12] + (this.tmpState[12]) + (((this.state[4]
                ^ this.state[8]) & this.state[0]) ^ this.state[8]);
            this.state[0] = this.circularLeft(tmp, 4) + tA3;
            this.state[12] = this.state[8];
            this.state[8] = this.state[4];
            this.state[4] = tA0;
            tmp = this.state[13] + (this.tmpState[13]) + (((this.state[5]
                ^ this.state[9]) & this.state[1]) ^ this.state[9]);
            this.state[1] = this.circularLeft(tmp, 4) + tA2;
            this.state[13] = this.state[9];
            this.state[9] = this.state[5];
            this.state[5] = tA1;
            tmp = this.state[14] + (this.tmpState[14]) + (((this.state[6]
                ^ this.state[10]) & this.state[2]) ^ this.state[10]);
            this.state[2] = this.circularLeft(tmp, 4) + tA1;
            this.state[14] = this.state[10];
            this.state[10] = this.state[6];
            this.state[6] = tA2;
            tmp = this.state[15] + (this.tmpState[15]) + (((this.state[7]
                ^ this.state[11]) & this.state[3]) ^ this.state[11]);
            this.state[3] = this.circularLeft(tmp, 4) + tA0;
            this.state[15] = this.state[11];
            this.state[11] = this.state[7];
            this.state[7] = tA3;
        }
    }
    /** @see Digest */
    toString() {
        return "SIMD-" + (this.getDigestLength() << 3);
    }
}
SIMDSmallCore.alphaTab = new Int32Array([
    1, 41, 139, 45, 46, 87, 226, 14, 60, 147, 116, 130,
    190, 80, 196, 69, 2, 82, 21, 90, 92, 174, 195, 28,
    120, 37, 232, 3, 123, 160, 135, 138, 4, 164, 42, 180,
    184, 91, 133, 56, 240, 74, 207, 6, 246, 63, 13, 19,
    8, 71, 84, 103, 111, 182, 9, 112, 223, 148, 157, 12,
    235, 126, 26, 38, 16, 142, 168, 206, 222, 107, 18, 224,
    189, 39, 57, 24, 213, 252, 52, 76, 32, 27, 79, 155,
    187, 214, 36, 191, 121, 78, 114, 48, 169, 247, 104, 152,
    64, 54, 158, 53, 117, 171, 72, 125, 242, 156, 228, 96,
    81, 237, 208, 47, 128, 108, 59, 106, 234, 85, 144, 250,
    227, 55, 199, 192, 162, 217, 159, 94, 256, 216, 118, 212,
    211, 170, 31, 243, 197, 110, 141, 127, 67, 177, 61, 188,
    255, 175, 236, 167, 165, 83, 62, 229, 137, 220, 25, 254,
    134, 97, 122, 119, 253, 93, 215, 77, 73, 166, 124, 201,
    17, 183, 50, 251, 11, 194, 244, 238, 249, 186, 173, 154,
    146, 75, 248, 145, 34, 109, 100, 245, 22, 131, 231, 219,
    241, 115, 89, 51, 35, 150, 239, 33, 68, 218, 200, 233,
    44, 5, 205, 181, 225, 230, 178, 102, 70, 43, 221, 66,
    136, 179, 143, 209, 88, 10, 153, 105, 193, 203, 99, 204,
    140, 86, 185, 132, 15, 101, 29, 161, 176, 20, 49, 210,
    129, 149, 198, 151, 23, 172, 113, 7, 30, 202, 58, 65,
    95, 40, 98, 163
]);
SIMDSmallCore.yoffN = new Int32Array([
    1, 98, 95, 58, 30, 113, 23, 198, 129, 49, 176, 29,
    15, 185, 140, 99, 193, 153, 88, 143, 136, 221, 70, 178,
    225, 205, 44, 200, 68, 239, 35, 89, 241, 231, 22, 100,
    34, 248, 146, 173, 249, 244, 11, 50, 17, 124, 73, 215,
    253, 122, 134, 25, 137, 62, 165, 236, 255, 61, 67, 141,
    197, 31, 211, 118, 256, 159, 162, 199, 227, 144, 234, 59,
    128, 208, 81, 228, 242, 72, 117, 158, 64, 104, 169, 114,
    121, 36, 187, 79, 32, 52, 213, 57, 189, 18, 222, 168,
    16, 26, 235, 157, 223, 9, 111, 84, 8, 13, 246, 207,
    240, 133, 184, 42, 4, 135, 123, 232, 120, 195, 92, 21,
    2, 196, 190, 116, 60, 226, 46, 139
]);
SIMDSmallCore.yoffF = new Int32Array([
    2, 156, 118, 107, 45, 212, 111, 162, 97, 249, 211, 3,
    49, 101, 151, 223, 189, 178, 253, 204, 76, 82, 232, 65,
    96, 176, 161, 47, 189, 61, 248, 107, 0, 131, 133, 113,
    17, 33, 12, 111, 251, 103, 57, 148, 47, 65, 249, 143,
    189, 8, 204, 230, 205, 151, 187, 227, 247, 111, 140, 6,
    77, 10, 21, 149, 255, 101, 139, 150, 212, 45, 146, 95,
    160, 8, 46, 254, 208, 156, 106, 34, 68, 79, 4, 53,
    181, 175, 25, 192, 161, 81, 96, 210, 68, 196, 9, 150,
    0, 126, 124, 144, 240, 224, 245, 146, 6, 154, 200, 109,
    210, 192, 8, 114, 68, 249, 53, 27, 52, 106, 70, 30,
    10, 146, 117, 251, 180, 247, 236, 108
]);
SIMDSmallCore.pp4k = new Int32Array([
    1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2
]);
SIMDSmallCore.wsp = new Int32Array([
    32, 48, 0, 16, 56, 40, 24, 8,
    120, 88, 96, 64, 72, 104, 80, 112,
    136, 144, 184, 160, 176, 168, 128, 152,
    240, 192, 200, 248, 216, 232, 224, 208
]);
/**
 * This class implements SIMD-384 and SIMD-512.
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
class SIMDBigCore extends DigestEngine {
    /**
     * Create the object.
     */
    constructor() {
        super();
    }
    /** @see Digest */
    getBlockLength() {
        return 128;
    }
    /** @see DigestEngine */
    copyState(dst) {
        arraycopy(this.state, 0, dst.state, 0, 32);
        return super.copyState(dst);
    }
    /** @see DigestEngine */
    engineReset() {
        const iv = this.getInitVal();
        arraycopy(iv, 0, this.state, 0, 32);
    }
    /** @see DigestEngine */
    doPadding(output, outputOffset) {
        var ptr = this.flush();
        const buf = this.getBlockBuffer();
        if (ptr != 0) {
            for (let i = ptr; i < 128; i++) {
                buf[i] = 0x00;
            }
            this.compress(buf, false);
        }
        var count = (this.getBlockCount() << BigInt(10)) + BigInt(ptr << 3);
        this.encodeLEInt(Number(count), buf, 0);
        this.encodeLEInt(Number(count >> BigInt(32)), buf, 4);
        for (let i = 8; i < 128; i++) {
            buf[i] = 0x00;
        }
        this.compress(buf, true);
        var n = this.getDigestLength() >>> 2;
        for (let i = 0; i < n; i++) {
            this.encodeLEInt(this.state[i], output, outputOffset + (i << 2));
        }
    }
    /** @see DigestEngine */
    doInit() {
        this.state = new Int32Array(32);
        this.q = new Int32Array(256);
        this.w = new Int32Array(64);
        this.tmpState = new Int32Array(32);
        this.tA = new Int32Array(8);
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
    encodeLEInt(val, buf, off) {
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
    decodeLEInt(buf, off) {
        return ((buf[off + 3] & 0xFF) << 24)
            | ((buf[off + 2] & 0xFF) << 16)
            | ((buf[off + 1] & 0xFF) << 8)
            | (buf[off] & 0xFF);
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
    circularLeft(x, n) {
        return (x << n) | (x >>> (32 - n));
    }
    /** @see DigestEngine */
    processBlock(data) {
        this.compress(data, false);
    }
    fft64(x, xb, xs, qoff) {
        const d = {
            1: new Int32Array(8),
            2: new Int32Array(8),
        };
        const a = new Int32Array(4);
        const b = new Int32Array(4);
        var x0, x1, x2, x3;
        var xd = xs << 1;
        {
            //int d1_0, d1_1, d1_2, d1_3, d1_4, d1_5, d1_6, d1_7;
            //int d2_0, d2_1, d2_2, d2_3, d2_4, d2_5, d2_6, d2_7;
            {
                x0 = x[xb + 0 * xd] & 0xFF;
                x1 = x[xb + 4 * xd] & 0xFF;
                x2 = x[xb + 8 * xd] & 0xFF;
                x3 = x[xb + 12 * xd] & 0xFF;
                a[0] = x0 + x2;
                a[1] = x0 + (x2 << 4);
                a[2] = x0 - x2;
                a[3] = x0 - (x2 << 4);
                b[0] = x1 + x3;
                b[1] = ((((x1 << 2) + (x3 << 6)) & 0xFF)
                    - (((x1 << 2) + (x3 << 6)) >> 8));
                b[2] = (x1 << 4) - (x3 << 4);
                b[3] = ((((x1 << 6) + (x3 << 2)) & 0xFF)
                    - (((x1 << 6) + (x3 << 2)) >> 8));
                d[1][0] = a[0] + b[0];
                d[1][1] = a[1] + b[1];
                d[1][2] = a[2] + b[2];
                d[1][3] = a[3] + b[3];
                d[1][4] = a[0] - b[0];
                d[1][5] = a[1] - b[1];
                d[1][6] = a[2] - b[2];
                d[1][7] = a[3] - b[3];
            }
            {
                x0 = x[xb + 2 * xd] & 0xFF;
                x1 = x[xb + 6 * xd] & 0xFF;
                x2 = x[xb + 10 * xd] & 0xFF;
                x3 = x[xb + 14 * xd] & 0xFF;
                a[0] = x0 + x2;
                a[1] = x0 + (x2 << 4);
                a[2] = x0 - x2;
                a[3] = x0 - (x2 << 4);
                b[0] = x1 + x3;
                b[1] = ((((x1 << 2) + (x3 << 6)) & 0xFF)
                    - (((x1 << 2) + (x3 << 6)) >> 8));
                b[2] = (x1 << 4) - (x3 << 4);
                b[3] = ((((x1 << 6) + (x3 << 2)) & 0xFF)
                    - (((x1 << 6) + (x3 << 2)) >> 8));
                d[2][0] = a[0] + b[0];
                d[2][1] = a[1] + b[1];
                d[2][2] = a[2] + b[2];
                d[2][3] = a[3] + b[3];
                d[2][4] = a[0] - b[0];
                d[2][5] = a[1] - b[1];
                d[2][6] = a[2] - b[2];
                d[2][7] = a[3] - b[3];
            }
            this.q[qoff + 0] = d[1][0] + d[2][0];
            this.q[qoff + 1] = d[1][1] + (d[2][1] << 1);
            this.q[qoff + 2] = d[1][2] + (d[2][2] << 2);
            this.q[qoff + 3] = d[1][3] + (d[2][3] << 3);
            this.q[qoff + 4] = d[1][4] + (d[2][4] << 4);
            this.q[qoff + 5] = d[1][5] + (d[2][5] << 5);
            this.q[qoff + 6] = d[1][6] + (d[2][6] << 6);
            this.q[qoff + 7] = d[1][7] + (d[2][7] << 7);
            this.q[qoff + 8] = d[1][0] - d[2][0];
            this.q[qoff + 9] = d[1][1] - (d[2][1] << 1);
            this.q[qoff + 10] = d[1][2] - (d[2][2] << 2);
            this.q[qoff + 11] = d[1][3] - (d[2][3] << 3);
            this.q[qoff + 12] = d[1][4] - (d[2][4] << 4);
            this.q[qoff + 13] = d[1][5] - (d[2][5] << 5);
            this.q[qoff + 14] = d[1][6] - (d[2][6] << 6);
            this.q[qoff + 15] = d[1][7] - (d[2][7] << 7);
        }
        {
            //int d1_0, d1_1, d1_2, d1_3, d1_4, d1_5, d1_6, d1_7;
            //int d2_0, d2_1, d2_2, d2_3, d2_4, d2_5, d2_6, d2_7;
            {
                x0 = x[xb + 1 * xd] & 0xFF;
                x1 = x[xb + 5 * xd] & 0xFF;
                x2 = x[xb + 9 * xd] & 0xFF;
                x3 = x[xb + 13 * xd] & 0xFF;
                a[0] = x0 + x2;
                a[1] = x0 + (x2 << 4);
                a[2] = x0 - x2;
                a[3] = x0 - (x2 << 4);
                b[0] = x1 + x3;
                b[1] = ((((x1 << 2) + (x3 << 6)) & 0xFF)
                    - (((x1 << 2) + (x3 << 6)) >> 8));
                b[2] = (x1 << 4) - (x3 << 4);
                b[3] = ((((x1 << 6) + (x3 << 2)) & 0xFF)
                    - (((x1 << 6) + (x3 << 2)) >> 8));
                d[1][0] = a[0] + b[0];
                d[1][1] = a[1] + b[1];
                d[1][2] = a[2] + b[2];
                d[1][3] = a[3] + b[3];
                d[1][4] = a[0] - b[0];
                d[1][5] = a[1] - b[1];
                d[1][6] = a[2] - b[2];
                d[1][7] = a[3] - b[3];
            }
            {
                x0 = x[xb + 3 * xd] & 0xFF;
                x1 = x[xb + 7 * xd] & 0xFF;
                x2 = x[xb + 11 * xd] & 0xFF;
                x3 = x[xb + 15 * xd] & 0xFF;
                a[0] = x0 + x2;
                a[1] = x0 + (x2 << 4);
                a[2] = x0 - x2;
                a[3] = x0 - (x2 << 4);
                b[0] = x1 + x3;
                b[1] = ((((x1 << 2) + (x3 << 6)) & 0xFF)
                    - (((x1 << 2) + (x3 << 6)) >> 8));
                b[2] = (x1 << 4) - (x3 << 4);
                b[3] = ((((x1 << 6) + (x3 << 2)) & 0xFF)
                    - (((x1 << 6) + (x3 << 2)) >> 8));
                d[2][0] = a[0] + b[0];
                d[2][1] = a[1] + b[1];
                d[2][2] = a[2] + b[2];
                d[2][3] = a[3] + b[3];
                d[2][4] = a[0] - b[0];
                d[2][5] = a[1] - b[1];
                d[2][6] = a[2] - b[2];
                d[2][7] = a[3] - b[3];
            }
            this.q[qoff + 16 + 0] = d[1][0] + d[2][0];
            this.q[qoff + 16 + 1] = d[1][1] + (d[2][1] << 1);
            this.q[qoff + 16 + 2] = d[1][2] + (d[2][2] << 2);
            this.q[qoff + 16 + 3] = d[1][3] + (d[2][3] << 3);
            this.q[qoff + 16 + 4] = d[1][4] + (d[2][4] << 4);
            this.q[qoff + 16 + 5] = d[1][5] + (d[2][5] << 5);
            this.q[qoff + 16 + 6] = d[1][6] + (d[2][6] << 6);
            this.q[qoff + 16 + 7] = d[1][7] + (d[2][7] << 7);
            this.q[qoff + 16 + 8] = d[1][0] - d[2][0];
            this.q[qoff + 16 + 9] = d[1][1] - (d[2][1] << 1);
            this.q[qoff + 16 + 10] = d[1][2] - (d[2][2] << 2);
            this.q[qoff + 16 + 11] = d[1][3] - (d[2][3] << 3);
            this.q[qoff + 16 + 12] = d[1][4] - (d[2][4] << 4);
            this.q[qoff + 16 + 13] = d[1][5] - (d[2][5] << 5);
            this.q[qoff + 16 + 14] = d[1][6] - (d[2][6] << 6);
            this.q[qoff + 16 + 15] = d[1][7] - (d[2][7] << 7);
        }
        var m = this.q[qoff];
        var n = this.q[qoff + 16];
        this.q[qoff] = m + n;
        this.q[qoff + 16] = m - n;
        for (let u = 0, v = 0; u < 16; u += 4, v += 4 * 8) {
            var t;
            if (u != 0) {
                m = this.q[qoff + u + 0];
                n = this.q[qoff + u + 0 + 16];
                t = ((n * SIMDBigCore.alphaTab[v + 0 * 8]) & 0xFFFF)
                    + ((n * SIMDBigCore.alphaTab[v + 0 * 8]) >> 16);
                this.q[qoff + u + 0] = m + t;
                this.q[qoff + u + 0 + 16] = m - t;
            }
            m = this.q[qoff + u + 1];
            n = this.q[qoff + u + 1 + 16];
            t = ((n * SIMDBigCore.alphaTab[v + 1 * 8]) & 0xFFFF)
                + ((n * SIMDBigCore.alphaTab[v + 1 * 8]) >> 16);
            this.q[qoff + u + 1] = m + t;
            this.q[qoff + u + 1 + 16] = m - t;
            m = this.q[qoff + u + 2];
            n = this.q[qoff + u + 2 + 16];
            t = ((n * SIMDBigCore.alphaTab[v + 2 * 8]) & 0xFFFF)
                + ((n * SIMDBigCore.alphaTab[v + 2 * 8]) >> 16);
            this.q[qoff + u + 2] = m + t;
            this.q[qoff + u + 2 + 16] = m - t;
            m = this.q[qoff + u + 3];
            n = this.q[qoff + u + 3 + 16];
            t = ((n * SIMDBigCore.alphaTab[v + 3 * 8]) & 0xFFFF)
                + ((n * SIMDBigCore.alphaTab[v + 3 * 8]) >> 16);
            this.q[qoff + u + 3] = m + t;
            this.q[qoff + u + 3 + 16] = m - t;
        }
        {
            //int d1_0, d1_1, d1_2, d1_3, d1_4, d1_5, d1_6, d1_7;
            //int d2_0, d2_1, d2_2, d2_3, d2_4, d2_5, d2_6, d2_7;
            {
                x0 = x[xb + xs + 0 * xd] & 0xFF;
                x1 = x[xb + xs + 4 * xd] & 0xFF;
                x2 = x[xb + xs + 8 * xd] & 0xFF;
                x3 = x[xb + xs + 12 * xd] & 0xFF;
                a[0] = x0 + x2;
                a[1] = x0 + (x2 << 4);
                a[2] = x0 - x2;
                a[3] = x0 - (x2 << 4);
                b[0] = x1 + x3;
                b[1] = ((((x1 << 2) + (x3 << 6)) & 0xFF)
                    - (((x1 << 2) + (x3 << 6)) >> 8));
                b[2] = (x1 << 4) - (x3 << 4);
                b[3] = ((((x1 << 6) + (x3 << 2)) & 0xFF)
                    - (((x1 << 6) + (x3 << 2)) >> 8));
                d[1][0] = a[0] + b[0];
                d[1][1] = a[1] + b[1];
                d[1][2] = a[2] + b[2];
                d[1][3] = a[3] + b[3];
                d[1][4] = a[0] - b[0];
                d[1][5] = a[1] - b[1];
                d[1][6] = a[2] - b[2];
                d[1][7] = a[3] - b[3];
            }
            {
                x0 = x[xb + xs + 2 * xd] & 0xFF;
                x1 = x[xb + xs + 6 * xd] & 0xFF;
                x2 = x[xb + xs + 10 * xd] & 0xFF;
                x3 = x[xb + xs + 14 * xd] & 0xFF;
                a[0] = x0 + x2;
                a[1] = x0 + (x2 << 4);
                a[2] = x0 - x2;
                a[3] = x0 - (x2 << 4);
                b[0] = x1 + x3;
                b[1] = ((((x1 << 2) + (x3 << 6)) & 0xFF)
                    - (((x1 << 2) + (x3 << 6)) >> 8));
                b[2] = (x1 << 4) - (x3 << 4);
                b[3] = ((((x1 << 6) + (x3 << 2)) & 0xFF)
                    - (((x1 << 6) + (x3 << 2)) >> 8));
                d[2][0] = a[0] + b[0];
                d[2][1] = a[1] + b[1];
                d[2][2] = a[2] + b[2];
                d[2][3] = a[3] + b[3];
                d[2][4] = a[0] - b[0];
                d[2][5] = a[1] - b[1];
                d[2][6] = a[2] - b[2];
                d[2][7] = a[3] - b[3];
            }
            this.q[qoff + 32 + 0] = d[1][0] + d[2][0];
            this.q[qoff + 32 + 1] = d[1][1] + (d[2][1] << 1);
            this.q[qoff + 32 + 2] = d[1][2] + (d[2][2] << 2);
            this.q[qoff + 32 + 3] = d[1][3] + (d[2][3] << 3);
            this.q[qoff + 32 + 4] = d[1][4] + (d[2][4] << 4);
            this.q[qoff + 32 + 5] = d[1][5] + (d[2][5] << 5);
            this.q[qoff + 32 + 6] = d[1][6] + (d[2][6] << 6);
            this.q[qoff + 32 + 7] = d[1][7] + (d[2][7] << 7);
            this.q[qoff + 32 + 8] = d[1][0] - d[2][0];
            this.q[qoff + 32 + 9] = d[1][1] - (d[2][1] << 1);
            this.q[qoff + 32 + 10] = d[1][2] - (d[2][2] << 2);
            this.q[qoff + 32 + 11] = d[1][3] - (d[2][3] << 3);
            this.q[qoff + 32 + 12] = d[1][4] - (d[2][4] << 4);
            this.q[qoff + 32 + 13] = d[1][5] - (d[2][5] << 5);
            this.q[qoff + 32 + 14] = d[1][6] - (d[2][6] << 6);
            this.q[qoff + 32 + 15] = d[1][7] - (d[2][7] << 7);
        }
        {
            //int d1_0, d1_1, d1_2, d1_3, d1_4, d1_5, d1_6, d1_7;
            //int d2_0, d2_1, d2_2, d2_3, d2_4, d2_5, d2_6, d2_7;
            {
                x0 = x[xb + xs + 1 * xd] & 0xFF;
                x1 = x[xb + xs + 5 * xd] & 0xFF;
                x2 = x[xb + xs + 9 * xd] & 0xFF;
                x3 = x[xb + xs + 13 * xd] & 0xFF;
                a[0] = x0 + x2;
                a[1] = x0 + (x2 << 4);
                a[2] = x0 - x2;
                a[3] = x0 - (x2 << 4);
                b[0] = x1 + x3;
                b[1] = ((((x1 << 2) + (x3 << 6)) & 0xFF)
                    - (((x1 << 2) + (x3 << 6)) >> 8));
                b[2] = (x1 << 4) - (x3 << 4);
                b[3] = ((((x1 << 6) + (x3 << 2)) & 0xFF)
                    - (((x1 << 6) + (x3 << 2)) >> 8));
                d[1][0] = a[0] + b[0];
                d[1][1] = a[1] + b[1];
                d[1][2] = a[2] + b[2];
                d[1][3] = a[3] + b[3];
                d[1][4] = a[0] - b[0];
                d[1][5] = a[1] - b[1];
                d[1][6] = a[2] - b[2];
                d[1][7] = a[3] - b[3];
            }
            {
                x0 = x[xb + xs + 3 * xd] & 0xFF;
                x1 = x[xb + xs + 7 * xd] & 0xFF;
                x2 = x[xb + xs + 11 * xd] & 0xFF;
                x3 = x[xb + xs + 15 * xd] & 0xFF;
                a[0] = x0 + x2;
                a[1] = x0 + (x2 << 4);
                a[2] = x0 - x2;
                a[3] = x0 - (x2 << 4);
                b[0] = x1 + x3;
                b[1] = ((((x1 << 2) + (x3 << 6)) & 0xFF)
                    - (((x1 << 2) + (x3 << 6)) >> 8));
                b[2] = (x1 << 4) - (x3 << 4);
                b[3] = ((((x1 << 6) + (x3 << 2)) & 0xFF)
                    - (((x1 << 6) + (x3 << 2)) >> 8));
                d[2][0] = a[0] + b[0];
                d[2][1] = a[1] + b[1];
                d[2][2] = a[2] + b[2];
                d[2][3] = a[3] + b[3];
                d[2][4] = a[0] - b[0];
                d[2][5] = a[1] - b[1];
                d[2][6] = a[2] - b[2];
                d[2][7] = a[3] - b[3];
            }
            this.q[qoff + 32 + 16 + 0] = d[1][0] + d[2][0];
            this.q[qoff + 32 + 16 + 1] = d[1][1] + (d[2][1] << 1);
            this.q[qoff + 32 + 16 + 2] = d[1][2] + (d[2][2] << 2);
            this.q[qoff + 32 + 16 + 3] = d[1][3] + (d[2][3] << 3);
            this.q[qoff + 32 + 16 + 4] = d[1][4] + (d[2][4] << 4);
            this.q[qoff + 32 + 16 + 5] = d[1][5] + (d[2][5] << 5);
            this.q[qoff + 32 + 16 + 6] = d[1][6] + (d[2][6] << 6);
            this.q[qoff + 32 + 16 + 7] = d[1][7] + (d[2][7] << 7);
            this.q[qoff + 32 + 16 + 8] = d[1][0] - d[2][0];
            this.q[qoff + 32 + 16 + 9] = d[1][1] - (d[2][1] << 1);
            this.q[qoff + 32 + 16 + 10] = d[1][2] - (d[2][2] << 2);
            this.q[qoff + 32 + 16 + 11] = d[1][3] - (d[2][3] << 3);
            this.q[qoff + 32 + 16 + 12] = d[1][4] - (d[2][4] << 4);
            this.q[qoff + 32 + 16 + 13] = d[1][5] - (d[2][5] << 5);
            this.q[qoff + 32 + 16 + 14] = d[1][6] - (d[2][6] << 6);
            this.q[qoff + 32 + 16 + 15] = d[1][7] - (d[2][7] << 7);
        }
        m = this.q[qoff + 32];
        n = this.q[qoff + 32 + 16];
        this.q[qoff + 32] = m + n;
        this.q[qoff + 32 + 16] = m - n;
        for (let u = 0, v = 0; u < 16; u += 4, v += 4 * 8) {
            var t;
            if (u != 0) {
                m = this.q[(qoff + 32) + u + 0];
                n = this.q[(qoff + 32) + u + 0 + 16];
                t = ((n * SIMDBigCore.alphaTab[v + 0 * 8]) & 0xFFFF)
                    + ((n * SIMDBigCore.alphaTab[v + 0 * 8]) >> 16);
                this.q[(qoff + 32) + u + 0] = m + t;
                this.q[(qoff + 32) + u + 0 + 16] = m - t;
            }
            m = this.q[(qoff + 32) + u + 1];
            n = this.q[(qoff + 32) + u + 1 + 16];
            t = ((n * SIMDBigCore.alphaTab[v + 1 * 8]) & 0xFFFF)
                + ((n * SIMDBigCore.alphaTab[v + 1 * 8]) >> 16);
            this.q[(qoff + 32) + u + 1] = m + t;
            this.q[(qoff + 32) + u + 1 + 16] = m - t;
            m = this.q[(qoff + 32) + u + 2];
            n = this.q[(qoff + 32) + u + 2 + 16];
            t = ((n * SIMDBigCore.alphaTab[v + 2 * 8]) & 0xFFFF)
                + ((n * SIMDBigCore.alphaTab[v + 2 * 8]) >> 16);
            this.q[(qoff + 32) + u + 2] = m + t;
            this.q[(qoff + 32) + u + 2 + 16] = m - t;
            m = this.q[(qoff + 32) + u + 3];
            n = this.q[(qoff + 32) + u + 3 + 16];
            t = ((n * SIMDBigCore.alphaTab[v + 3 * 8]) & 0xFFFF)
                + ((n * SIMDBigCore.alphaTab[v + 3 * 8]) >> 16);
            this.q[(qoff + 32) + u + 3] = m + t;
            this.q[(qoff + 32) + u + 3 + 16] = m - t;
        }
        m = this.q[qoff];
        n = this.q[qoff + 32];
        this.q[qoff] = m + n;
        this.q[qoff + 32] = m - n;
        for (let u = 0, v = 0; u < 32; u += 4, v += 4 * 4) {
            var t;
            if (u != 0) {
                m = this.q[qoff + u + 0];
                n = this.q[qoff + u + 0 + 32];
                t = ((n * SIMDBigCore.alphaTab[v + 0 * 4]) & 0xFFFF)
                    + ((n * SIMDBigCore.alphaTab[v + 0 * 4]) >> 16);
                this.q[qoff + u + 0] = m + t;
                this.q[qoff + u + 0 + 32] = m - t;
            }
            m = this.q[qoff + u + 1];
            n = this.q[qoff + u + 1 + 32];
            t = ((n * SIMDBigCore.alphaTab[v + 1 * 4]) & 0xFFFF)
                + ((n * SIMDBigCore.alphaTab[v + 1 * 4]) >> 16);
            this.q[qoff + u + 1] = m + t;
            this.q[qoff + u + 1 + 32] = m - t;
            m = this.q[qoff + u + 2];
            n = this.q[qoff + u + 2 + 32];
            t = ((n * SIMDBigCore.alphaTab[v + 2 * 4]) & 0xFFFF)
                + ((n * SIMDBigCore.alphaTab[v + 2 * 4]) >> 16);
            this.q[qoff + u + 2] = m + t;
            this.q[qoff + u + 2 + 32] = m - t;
            m = this.q[qoff + u + 3];
            n = this.q[qoff + u + 3 + 32];
            t = ((n * SIMDBigCore.alphaTab[v + 3 * 4]) & 0xFFFF)
                + ((n * SIMDBigCore.alphaTab[v + 3 * 4]) >> 16);
            this.q[qoff + u + 3] = m + t;
            this.q[qoff + u + 3 + 32] = m - t;
        }
    }
    oneRound(isp, p0, p1, p2, p3) {
        var tmp;
        this.tA[0] = this.circularLeft(this.state[0], p0);
        this.tA[1] = this.circularLeft(this.state[1], p0);
        this.tA[2] = this.circularLeft(this.state[2], p0);
        this.tA[3] = this.circularLeft(this.state[3], p0);
        this.tA[4] = this.circularLeft(this.state[4], p0);
        this.tA[5] = this.circularLeft(this.state[5], p0);
        this.tA[6] = this.circularLeft(this.state[6], p0);
        this.tA[7] = this.circularLeft(this.state[7], p0);
        tmp = this.state[24] + (this.w[0])
            + (((this.state[8] ^ this.state[16]) & this.state[0]) ^ this.state[16]);
        this.state[0] = this.circularLeft(tmp, p1) + this.tA[(SIMDBigCore.pp8k[isp + 0]) ^ 0];
        this.state[24] = this.state[16];
        this.state[16] = this.state[8];
        this.state[8] = this.tA[0];
        tmp = this.state[25] + (this.w[1])
            + (((this.state[9] ^ this.state[17]) & this.state[1]) ^ this.state[17]);
        this.state[1] = this.circularLeft(tmp, p1) + this.tA[(SIMDBigCore.pp8k[isp + 0]) ^ 1];
        this.state[25] = this.state[17];
        this.state[17] = this.state[9];
        this.state[9] = this.tA[1];
        tmp = this.state[26] + (this.w[2])
            + (((this.state[10] ^ this.state[18]) & this.state[2]) ^ this.state[18]);
        this.state[2] = this.circularLeft(tmp, p1) + this.tA[(SIMDBigCore.pp8k[isp + 0]) ^ 2];
        this.state[26] = this.state[18];
        this.state[18] = this.state[10];
        this.state[10] = this.tA[2];
        tmp = this.state[27] + (this.w[3])
            + (((this.state[11] ^ this.state[19]) & this.state[3]) ^ this.state[19]);
        this.state[3] = this.circularLeft(tmp, p1) + this.tA[(SIMDBigCore.pp8k[isp + 0]) ^ 3];
        this.state[27] = this.state[19];
        this.state[19] = this.state[11];
        this.state[11] = this.tA[3];
        tmp = this.state[28] + (this.w[4])
            + (((this.state[12] ^ this.state[20]) & this.state[4]) ^ this.state[20]);
        this.state[4] = this.circularLeft(tmp, p1) + this.tA[(SIMDBigCore.pp8k[isp + 0]) ^ 4];
        this.state[28] = this.state[20];
        this.state[20] = this.state[12];
        this.state[12] = this.tA[4];
        tmp = this.state[29] + (this.w[5])
            + (((this.state[13] ^ this.state[21]) & this.state[5]) ^ this.state[21]);
        this.state[5] = this.circularLeft(tmp, p1) + this.tA[(SIMDBigCore.pp8k[isp + 0]) ^ 5];
        this.state[29] = this.state[21];
        this.state[21] = this.state[13];
        this.state[13] = this.tA[5];
        tmp = this.state[30] + (this.w[6])
            + (((this.state[14] ^ this.state[22]) & this.state[6]) ^ this.state[22]);
        this.state[6] = this.circularLeft(tmp, p1) + this.tA[(SIMDBigCore.pp8k[isp + 0]) ^ 6];
        this.state[30] = this.state[22];
        this.state[22] = this.state[14];
        this.state[14] = this.tA[6];
        tmp = this.state[31] + (this.w[7])
            + (((this.state[15] ^ this.state[23]) & this.state[7]) ^ this.state[23]);
        this.state[7] = this.circularLeft(tmp, p1) + this.tA[(SIMDBigCore.pp8k[isp + 0]) ^ 7];
        this.state[31] = this.state[23];
        this.state[23] = this.state[15];
        this.state[15] = this.tA[7];
        this.tA[0] = this.circularLeft(this.state[0], p1);
        this.tA[1] = this.circularLeft(this.state[1], p1);
        this.tA[2] = this.circularLeft(this.state[2], p1);
        this.tA[3] = this.circularLeft(this.state[3], p1);
        this.tA[4] = this.circularLeft(this.state[4], p1);
        this.tA[5] = this.circularLeft(this.state[5], p1);
        this.tA[6] = this.circularLeft(this.state[6], p1);
        this.tA[7] = this.circularLeft(this.state[7], p1);
        tmp = this.state[24] + (this.w[8])
            + (((this.state[8] ^ this.state[16]) & this.state[0]) ^ this.state[16]);
        this.state[0] = this.circularLeft(tmp, p2) + this.tA[(SIMDBigCore.pp8k[isp + 1]) ^ 0];
        this.state[24] = this.state[16];
        this.state[16] = this.state[8];
        this.state[8] = this.tA[0];
        tmp = this.state[25] + (this.w[9])
            + (((this.state[9] ^ this.state[17]) & this.state[1]) ^ this.state[17]);
        this.state[1] = this.circularLeft(tmp, p2) + this.tA[(SIMDBigCore.pp8k[isp + 1]) ^ 1];
        this.state[25] = this.state[17];
        this.state[17] = this.state[9];
        this.state[9] = this.tA[1];
        tmp = this.state[26] + (this.w[10])
            + (((this.state[10] ^ this.state[18]) & this.state[2]) ^ this.state[18]);
        this.state[2] = this.circularLeft(tmp, p2) + this.tA[(SIMDBigCore.pp8k[isp + 1]) ^ 2];
        this.state[26] = this.state[18];
        this.state[18] = this.state[10];
        this.state[10] = this.tA[2];
        tmp = this.state[27] + (this.w[11])
            + (((this.state[11] ^ this.state[19]) & this.state[3]) ^ this.state[19]);
        this.state[3] = this.circularLeft(tmp, p2) + this.tA[(SIMDBigCore.pp8k[isp + 1]) ^ 3];
        this.state[27] = this.state[19];
        this.state[19] = this.state[11];
        this.state[11] = this.tA[3];
        tmp = this.state[28] + (this.w[12])
            + (((this.state[12] ^ this.state[20]) & this.state[4]) ^ this.state[20]);
        this.state[4] = this.circularLeft(tmp, p2) + this.tA[(SIMDBigCore.pp8k[isp + 1]) ^ 4];
        this.state[28] = this.state[20];
        this.state[20] = this.state[12];
        this.state[12] = this.tA[4];
        tmp = this.state[29] + (this.w[13])
            + (((this.state[13] ^ this.state[21]) & this.state[5]) ^ this.state[21]);
        this.state[5] = this.circularLeft(tmp, p2) + this.tA[(SIMDBigCore.pp8k[isp + 1]) ^ 5];
        this.state[29] = this.state[21];
        this.state[21] = this.state[13];
        this.state[13] = this.tA[5];
        tmp = this.state[30] + (this.w[14])
            + (((this.state[14] ^ this.state[22]) & this.state[6]) ^ this.state[22]);
        this.state[6] = this.circularLeft(tmp, p2) + this.tA[(SIMDBigCore.pp8k[isp + 1]) ^ 6];
        this.state[30] = this.state[22];
        this.state[22] = this.state[14];
        this.state[14] = this.tA[6];
        tmp = this.state[31] + (this.w[15])
            + (((this.state[15] ^ this.state[23]) & this.state[7]) ^ this.state[23]);
        this.state[7] = this.circularLeft(tmp, p2) + this.tA[(SIMDBigCore.pp8k[isp + 1]) ^ 7];
        this.state[31] = this.state[23];
        this.state[23] = this.state[15];
        this.state[15] = this.tA[7];
        this.tA[0] = this.circularLeft(this.state[0], p2);
        this.tA[1] = this.circularLeft(this.state[1], p2);
        this.tA[2] = this.circularLeft(this.state[2], p2);
        this.tA[3] = this.circularLeft(this.state[3], p2);
        this.tA[4] = this.circularLeft(this.state[4], p2);
        this.tA[5] = this.circularLeft(this.state[5], p2);
        this.tA[6] = this.circularLeft(this.state[6], p2);
        this.tA[7] = this.circularLeft(this.state[7], p2);
        tmp = this.state[24] + (this.w[16])
            + (((this.state[8] ^ this.state[16]) & this.state[0]) ^ this.state[16]);
        this.state[0] = this.circularLeft(tmp, p3) + this.tA[(SIMDBigCore.pp8k[isp + 2]) ^ 0];
        this.state[24] = this.state[16];
        this.state[16] = this.state[8];
        this.state[8] = this.tA[0];
        tmp = this.state[25] + (this.w[17])
            + (((this.state[9] ^ this.state[17]) & this.state[1]) ^ this.state[17]);
        this.state[1] = this.circularLeft(tmp, p3) + this.tA[(SIMDBigCore.pp8k[isp + 2]) ^ 1];
        this.state[25] = this.state[17];
        this.state[17] = this.state[9];
        this.state[9] = this.tA[1];
        tmp = this.state[26] + (this.w[18])
            + (((this.state[10] ^ this.state[18]) & this.state[2]) ^ this.state[18]);
        this.state[2] = this.circularLeft(tmp, p3) + this.tA[(SIMDBigCore.pp8k[isp + 2]) ^ 2];
        this.state[26] = this.state[18];
        this.state[18] = this.state[10];
        this.state[10] = this.tA[2];
        tmp = this.state[27] + (this.w[19])
            + (((this.state[11] ^ this.state[19]) & this.state[3]) ^ this.state[19]);
        this.state[3] = this.circularLeft(tmp, p3) + this.tA[(SIMDBigCore.pp8k[isp + 2]) ^ 3];
        this.state[27] = this.state[19];
        this.state[19] = this.state[11];
        this.state[11] = this.tA[3];
        tmp = this.state[28] + (this.w[20])
            + (((this.state[12] ^ this.state[20]) & this.state[4]) ^ this.state[20]);
        this.state[4] = this.circularLeft(tmp, p3) + this.tA[(SIMDBigCore.pp8k[isp + 2]) ^ 4];
        this.state[28] = this.state[20];
        this.state[20] = this.state[12];
        this.state[12] = this.tA[4];
        tmp = this.state[29] + (this.w[21])
            + (((this.state[13] ^ this.state[21]) & this.state[5]) ^ this.state[21]);
        this.state[5] = this.circularLeft(tmp, p3) + this.tA[(SIMDBigCore.pp8k[isp + 2]) ^ 5];
        this.state[29] = this.state[21];
        this.state[21] = this.state[13];
        this.state[13] = this.tA[5];
        tmp = this.state[30] + (this.w[22])
            + (((this.state[14] ^ this.state[22]) & this.state[6]) ^ this.state[22]);
        this.state[6] = this.circularLeft(tmp, p3) + this.tA[(SIMDBigCore.pp8k[isp + 2]) ^ 6];
        this.state[30] = this.state[22];
        this.state[22] = this.state[14];
        this.state[14] = this.tA[6];
        tmp = this.state[31] + (this.w[23])
            + (((this.state[15] ^ this.state[23]) & this.state[7]) ^ this.state[23]);
        this.state[7] = this.circularLeft(tmp, p3) + this.tA[(SIMDBigCore.pp8k[isp + 2]) ^ 7];
        this.state[31] = this.state[23];
        this.state[23] = this.state[15];
        this.state[15] = this.tA[7];
        this.tA[0] = this.circularLeft(this.state[0], p3);
        this.tA[1] = this.circularLeft(this.state[1], p3);
        this.tA[2] = this.circularLeft(this.state[2], p3);
        this.tA[3] = this.circularLeft(this.state[3], p3);
        this.tA[4] = this.circularLeft(this.state[4], p3);
        this.tA[5] = this.circularLeft(this.state[5], p3);
        this.tA[6] = this.circularLeft(this.state[6], p3);
        this.tA[7] = this.circularLeft(this.state[7], p3);
        tmp = this.state[24] + (this.w[24])
            + (((this.state[8] ^ this.state[16]) & this.state[0]) ^ this.state[16]);
        this.state[0] = this.circularLeft(tmp, p0) + this.tA[(SIMDBigCore.pp8k[isp + 3]) ^ 0];
        this.state[24] = this.state[16];
        this.state[16] = this.state[8];
        this.state[8] = this.tA[0];
        tmp = this.state[25] + (this.w[25])
            + (((this.state[9] ^ this.state[17]) & this.state[1]) ^ this.state[17]);
        this.state[1] = this.circularLeft(tmp, p0) + this.tA[(SIMDBigCore.pp8k[isp + 3]) ^ 1];
        this.state[25] = this.state[17];
        this.state[17] = this.state[9];
        this.state[9] = this.tA[1];
        tmp = this.state[26] + (this.w[26])
            + (((this.state[10] ^ this.state[18]) & this.state[2]) ^ this.state[18]);
        this.state[2] = this.circularLeft(tmp, p0) + this.tA[(SIMDBigCore.pp8k[isp + 3]) ^ 2];
        this.state[26] = this.state[18];
        this.state[18] = this.state[10];
        this.state[10] = this.tA[2];
        tmp = this.state[27] + (this.w[27])
            + (((this.state[11] ^ this.state[19]) & this.state[3]) ^ this.state[19]);
        this.state[3] = this.circularLeft(tmp, p0) + this.tA[(SIMDBigCore.pp8k[isp + 3]) ^ 3];
        this.state[27] = this.state[19];
        this.state[19] = this.state[11];
        this.state[11] = this.tA[3];
        tmp = this.state[28] + (this.w[28])
            + (((this.state[12] ^ this.state[20]) & this.state[4]) ^ this.state[20]);
        this.state[4] = this.circularLeft(tmp, p0) + this.tA[(SIMDBigCore.pp8k[isp + 3]) ^ 4];
        this.state[28] = this.state[20];
        this.state[20] = this.state[12];
        this.state[12] = this.tA[4];
        tmp = this.state[29] + (this.w[29])
            + (((this.state[13] ^ this.state[21]) & this.state[5]) ^ this.state[21]);
        this.state[5] = this.circularLeft(tmp, p0) + this.tA[(SIMDBigCore.pp8k[isp + 3]) ^ 5];
        this.state[29] = this.state[21];
        this.state[21] = this.state[13];
        this.state[13] = this.tA[5];
        tmp = this.state[30] + (this.w[30])
            + (((this.state[14] ^ this.state[22]) & this.state[6]) ^ this.state[22]);
        this.state[6] = this.circularLeft(tmp, p0) + this.tA[(SIMDBigCore.pp8k[isp + 3]) ^ 6];
        this.state[30] = this.state[22];
        this.state[22] = this.state[14];
        this.state[14] = this.tA[6];
        tmp = this.state[31] + (this.w[31])
            + (((this.state[15] ^ this.state[23]) & this.state[7]) ^ this.state[23]);
        this.state[7] = this.circularLeft(tmp, p0) + this.tA[(SIMDBigCore.pp8k[isp + 3]) ^ 7];
        this.state[31] = this.state[23];
        this.state[23] = this.state[15];
        this.state[15] = this.tA[7];
        this.tA[0] = this.circularLeft(this.state[0], p0);
        this.tA[1] = this.circularLeft(this.state[1], p0);
        this.tA[2] = this.circularLeft(this.state[2], p0);
        this.tA[3] = this.circularLeft(this.state[3], p0);
        this.tA[4] = this.circularLeft(this.state[4], p0);
        this.tA[5] = this.circularLeft(this.state[5], p0);
        this.tA[6] = this.circularLeft(this.state[6], p0);
        this.tA[7] = this.circularLeft(this.state[7], p0);
        tmp = this.state[24] + (this.w[32])
            + ((this.state[0] & this.state[8])
                | ((this.state[0] | this.state[8]) & this.state[16]));
        this.state[0] = this.circularLeft(tmp, p1) + this.tA[(SIMDBigCore.pp8k[isp + 4]) ^ 0];
        this.state[24] = this.state[16];
        this.state[16] = this.state[8];
        this.state[8] = this.tA[0];
        tmp = this.state[25] + (this.w[33])
            + ((this.state[1] & this.state[9])
                | ((this.state[1] | this.state[9]) & this.state[17]));
        this.state[1] = this.circularLeft(tmp, p1) + this.tA[(SIMDBigCore.pp8k[isp + 4]) ^ 1];
        this.state[25] = this.state[17];
        this.state[17] = this.state[9];
        this.state[9] = this.tA[1];
        tmp = this.state[26] + (this.w[34])
            + ((this.state[2] & this.state[10])
                | ((this.state[2] | this.state[10]) & this.state[18]));
        this.state[2] = this.circularLeft(tmp, p1) + this.tA[(SIMDBigCore.pp8k[isp + 4]) ^ 2];
        this.state[26] = this.state[18];
        this.state[18] = this.state[10];
        this.state[10] = this.tA[2];
        tmp = this.state[27] + (this.w[35])
            + ((this.state[3] & this.state[11])
                | ((this.state[3] | this.state[11]) & this.state[19]));
        this.state[3] = this.circularLeft(tmp, p1) + this.tA[(SIMDBigCore.pp8k[isp + 4]) ^ 3];
        this.state[27] = this.state[19];
        this.state[19] = this.state[11];
        this.state[11] = this.tA[3];
        tmp = this.state[28] + (this.w[36])
            + ((this.state[4] & this.state[12])
                | ((this.state[4] | this.state[12]) & this.state[20]));
        this.state[4] = this.circularLeft(tmp, p1) + this.tA[(SIMDBigCore.pp8k[isp + 4]) ^ 4];
        this.state[28] = this.state[20];
        this.state[20] = this.state[12];
        this.state[12] = this.tA[4];
        tmp = this.state[29] + (this.w[37])
            + ((this.state[5] & this.state[13])
                | ((this.state[5] | this.state[13]) & this.state[21]));
        this.state[5] = this.circularLeft(tmp, p1) + this.tA[(SIMDBigCore.pp8k[isp + 4]) ^ 5];
        this.state[29] = this.state[21];
        this.state[21] = this.state[13];
        this.state[13] = this.tA[5];
        tmp = this.state[30] + (this.w[38])
            + ((this.state[6] & this.state[14])
                | ((this.state[6] | this.state[14]) & this.state[22]));
        this.state[6] = this.circularLeft(tmp, p1) + this.tA[(SIMDBigCore.pp8k[isp + 4]) ^ 6];
        this.state[30] = this.state[22];
        this.state[22] = this.state[14];
        this.state[14] = this.tA[6];
        tmp = this.state[31] + (this.w[39])
            + ((this.state[7] & this.state[15])
                | ((this.state[7] | this.state[15]) & this.state[23]));
        this.state[7] = this.circularLeft(tmp, p1) + this.tA[(SIMDBigCore.pp8k[isp + 4]) ^ 7];
        this.state[31] = this.state[23];
        this.state[23] = this.state[15];
        this.state[15] = this.tA[7];
        this.tA[0] = this.circularLeft(this.state[0], p1);
        this.tA[1] = this.circularLeft(this.state[1], p1);
        this.tA[2] = this.circularLeft(this.state[2], p1);
        this.tA[3] = this.circularLeft(this.state[3], p1);
        this.tA[4] = this.circularLeft(this.state[4], p1);
        this.tA[5] = this.circularLeft(this.state[5], p1);
        this.tA[6] = this.circularLeft(this.state[6], p1);
        this.tA[7] = this.circularLeft(this.state[7], p1);
        tmp = this.state[24] + (this.w[40])
            + ((this.state[0] & this.state[8])
                | ((this.state[0] | this.state[8]) & this.state[16]));
        this.state[0] = this.circularLeft(tmp, p2) + this.tA[(SIMDBigCore.pp8k[isp + 5]) ^ 0];
        this.state[24] = this.state[16];
        this.state[16] = this.state[8];
        this.state[8] = this.tA[0];
        tmp = this.state[25] + (this.w[41])
            + ((this.state[1] & this.state[9])
                | ((this.state[1] | this.state[9]) & this.state[17]));
        this.state[1] = this.circularLeft(tmp, p2) + this.tA[(SIMDBigCore.pp8k[isp + 5]) ^ 1];
        this.state[25] = this.state[17];
        this.state[17] = this.state[9];
        this.state[9] = this.tA[1];
        tmp = this.state[26] + (this.w[42])
            + ((this.state[2] & this.state[10])
                | ((this.state[2] | this.state[10]) & this.state[18]));
        this.state[2] = this.circularLeft(tmp, p2) + this.tA[(SIMDBigCore.pp8k[isp + 5]) ^ 2];
        this.state[26] = this.state[18];
        this.state[18] = this.state[10];
        this.state[10] = this.tA[2];
        tmp = this.state[27] + (this.w[43])
            + ((this.state[3] & this.state[11])
                | ((this.state[3] | this.state[11]) & this.state[19]));
        this.state[3] = this.circularLeft(tmp, p2) + this.tA[(SIMDBigCore.pp8k[isp + 5]) ^ 3];
        this.state[27] = this.state[19];
        this.state[19] = this.state[11];
        this.state[11] = this.tA[3];
        tmp = this.state[28] + (this.w[44])
            + ((this.state[4] & this.state[12])
                | ((this.state[4] | this.state[12]) & this.state[20]));
        this.state[4] = this.circularLeft(tmp, p2) + this.tA[(SIMDBigCore.pp8k[isp + 5]) ^ 4];
        this.state[28] = this.state[20];
        this.state[20] = this.state[12];
        this.state[12] = this.tA[4];
        tmp = this.state[29] + (this.w[45])
            + ((this.state[5] & this.state[13])
                | ((this.state[5] | this.state[13]) & this.state[21]));
        this.state[5] = this.circularLeft(tmp, p2) + this.tA[(SIMDBigCore.pp8k[isp + 5]) ^ 5];
        this.state[29] = this.state[21];
        this.state[21] = this.state[13];
        this.state[13] = this.tA[5];
        tmp = this.state[30] + (this.w[46])
            + ((this.state[6] & this.state[14])
                | ((this.state[6] | this.state[14]) & this.state[22]));
        this.state[6] = this.circularLeft(tmp, p2) + this.tA[(SIMDBigCore.pp8k[isp + 5]) ^ 6];
        this.state[30] = this.state[22];
        this.state[22] = this.state[14];
        this.state[14] = this.tA[6];
        tmp = this.state[31] + (this.w[47])
            + ((this.state[7] & this.state[15])
                | ((this.state[7] | this.state[15]) & this.state[23]));
        this.state[7] = this.circularLeft(tmp, p2) + this.tA[(SIMDBigCore.pp8k[isp + 5]) ^ 7];
        this.state[31] = this.state[23];
        this.state[23] = this.state[15];
        this.state[15] = this.tA[7];
        this.tA[0] = this.circularLeft(this.state[0], p2);
        this.tA[1] = this.circularLeft(this.state[1], p2);
        this.tA[2] = this.circularLeft(this.state[2], p2);
        this.tA[3] = this.circularLeft(this.state[3], p2);
        this.tA[4] = this.circularLeft(this.state[4], p2);
        this.tA[5] = this.circularLeft(this.state[5], p2);
        this.tA[6] = this.circularLeft(this.state[6], p2);
        this.tA[7] = this.circularLeft(this.state[7], p2);
        tmp = this.state[24] + (this.w[48])
            + ((this.state[0] & this.state[8])
                | ((this.state[0] | this.state[8]) & this.state[16]));
        this.state[0] = this.circularLeft(tmp, p3) + this.tA[(SIMDBigCore.pp8k[isp + 6]) ^ 0];
        this.state[24] = this.state[16];
        this.state[16] = this.state[8];
        this.state[8] = this.tA[0];
        tmp = this.state[25] + (this.w[49])
            + ((this.state[1] & this.state[9])
                | ((this.state[1] | this.state[9]) & this.state[17]));
        this.state[1] = this.circularLeft(tmp, p3) + this.tA[(SIMDBigCore.pp8k[isp + 6]) ^ 1];
        this.state[25] = this.state[17];
        this.state[17] = this.state[9];
        this.state[9] = this.tA[1];
        tmp = this.state[26] + (this.w[50])
            + ((this.state[2] & this.state[10])
                | ((this.state[2] | this.state[10]) & this.state[18]));
        this.state[2] = this.circularLeft(tmp, p3) + this.tA[(SIMDBigCore.pp8k[isp + 6]) ^ 2];
        this.state[26] = this.state[18];
        this.state[18] = this.state[10];
        this.state[10] = this.tA[2];
        tmp = this.state[27] + (this.w[51])
            + ((this.state[3] & this.state[11])
                | ((this.state[3] | this.state[11]) & this.state[19]));
        this.state[3] = this.circularLeft(tmp, p3) + this.tA[(SIMDBigCore.pp8k[isp + 6]) ^ 3];
        this.state[27] = this.state[19];
        this.state[19] = this.state[11];
        this.state[11] = this.tA[3];
        tmp = this.state[28] + (this.w[52])
            + ((this.state[4] & this.state[12])
                | ((this.state[4] | this.state[12]) & this.state[20]));
        this.state[4] = this.circularLeft(tmp, p3) + this.tA[(SIMDBigCore.pp8k[isp + 6]) ^ 4];
        this.state[28] = this.state[20];
        this.state[20] = this.state[12];
        this.state[12] = this.tA[4];
        tmp = this.state[29] + (this.w[53])
            + ((this.state[5] & this.state[13])
                | ((this.state[5] | this.state[13]) & this.state[21]));
        this.state[5] = this.circularLeft(tmp, p3) + this.tA[(SIMDBigCore.pp8k[isp + 6]) ^ 5];
        this.state[29] = this.state[21];
        this.state[21] = this.state[13];
        this.state[13] = this.tA[5];
        tmp = this.state[30] + (this.w[54])
            + ((this.state[6] & this.state[14])
                | ((this.state[6] | this.state[14]) & this.state[22]));
        this.state[6] = this.circularLeft(tmp, p3) + this.tA[(SIMDBigCore.pp8k[isp + 6]) ^ 6];
        this.state[30] = this.state[22];
        this.state[22] = this.state[14];
        this.state[14] = this.tA[6];
        tmp = this.state[31] + (this.w[55])
            + ((this.state[7] & this.state[15])
                | ((this.state[7] | this.state[15]) & this.state[23]));
        this.state[7] = this.circularLeft(tmp, p3) + this.tA[(SIMDBigCore.pp8k[isp + 6]) ^ 7];
        this.state[31] = this.state[23];
        this.state[23] = this.state[15];
        this.state[15] = this.tA[7];
        this.tA[0] = this.circularLeft(this.state[0], p3);
        this.tA[1] = this.circularLeft(this.state[1], p3);
        this.tA[2] = this.circularLeft(this.state[2], p3);
        this.tA[3] = this.circularLeft(this.state[3], p3);
        this.tA[4] = this.circularLeft(this.state[4], p3);
        this.tA[5] = this.circularLeft(this.state[5], p3);
        this.tA[6] = this.circularLeft(this.state[6], p3);
        this.tA[7] = this.circularLeft(this.state[7], p3);
        tmp = this.state[24] + (this.w[56])
            + ((this.state[0] & this.state[8])
                | ((this.state[0] | this.state[8]) & this.state[16]));
        this.state[0] = this.circularLeft(tmp, p0) + this.tA[(SIMDBigCore.pp8k[isp + 7]) ^ 0];
        this.state[24] = this.state[16];
        this.state[16] = this.state[8];
        this.state[8] = this.tA[0];
        tmp = this.state[25] + (this.w[57])
            + ((this.state[1] & this.state[9])
                | ((this.state[1] | this.state[9]) & this.state[17]));
        this.state[1] = this.circularLeft(tmp, p0) + this.tA[(SIMDBigCore.pp8k[isp + 7]) ^ 1];
        this.state[25] = this.state[17];
        this.state[17] = this.state[9];
        this.state[9] = this.tA[1];
        tmp = this.state[26] + (this.w[58])
            + ((this.state[2] & this.state[10])
                | ((this.state[2] | this.state[10]) & this.state[18]));
        this.state[2] = this.circularLeft(tmp, p0) + this.tA[(SIMDBigCore.pp8k[isp + 7]) ^ 2];
        this.state[26] = this.state[18];
        this.state[18] = this.state[10];
        this.state[10] = this.tA[2];
        tmp = this.state[27] + (this.w[59])
            + ((this.state[3] & this.state[11])
                | ((this.state[3] | this.state[11]) & this.state[19]));
        this.state[3] = this.circularLeft(tmp, p0) + this.tA[(SIMDBigCore.pp8k[isp + 7]) ^ 3];
        this.state[27] = this.state[19];
        this.state[19] = this.state[11];
        this.state[11] = this.tA[3];
        tmp = this.state[28] + (this.w[60])
            + ((this.state[4] & this.state[12])
                | ((this.state[4] | this.state[12]) & this.state[20]));
        this.state[4] = this.circularLeft(tmp, p0) + this.tA[(SIMDBigCore.pp8k[isp + 7]) ^ 4];
        this.state[28] = this.state[20];
        this.state[20] = this.state[12];
        this.state[12] = this.tA[4];
        tmp = this.state[29] + (this.w[61])
            + ((this.state[5] & this.state[13])
                | ((this.state[5] | this.state[13]) & this.state[21]));
        this.state[5] = this.circularLeft(tmp, p0) + this.tA[(SIMDBigCore.pp8k[isp + 7]) ^ 5];
        this.state[29] = this.state[21];
        this.state[21] = this.state[13];
        this.state[13] = this.tA[5];
        tmp = this.state[30] + (this.w[62])
            + ((this.state[6] & this.state[14])
                | ((this.state[6] | this.state[14]) & this.state[22]));
        this.state[6] = this.circularLeft(tmp, p0) + this.tA[(SIMDBigCore.pp8k[isp + 7]) ^ 6];
        this.state[30] = this.state[22];
        this.state[22] = this.state[14];
        this.state[14] = this.tA[6];
        tmp = this.state[31] + (this.w[63])
            + ((this.state[7] & this.state[15])
                | ((this.state[7] | this.state[15]) & this.state[23]));
        this.state[7] = this.circularLeft(tmp, p0) + this.tA[(SIMDBigCore.pp8k[isp + 7]) ^ 7];
        this.state[31] = this.state[23];
        this.state[23] = this.state[15];
        this.state[15] = this.tA[7];
    }
    compress(x, last) {
        var tmp;
        this.fft64(x, 0 + (1 * 0), 1 << 2, 0 + 0);
        this.fft64(x, 0 + (1 * 2), 1 << 2, 0 + 64);
        var m = this.q[0];
        var n = this.q[0 + 64];
        this.q[0] = m + n;
        this.q[0 + 64] = m - n;
        for (let u = 0, v = 0; u < 64; u += 4, v += 4 * 2) {
            var t;
            if (u != 0) {
                m = this.q[0 + u + 0];
                n = this.q[0 + u + 0 + 64];
                t = ((n * SIMDBigCore.alphaTab[v + 0 * 2]) & 0xFFFF)
                    + ((n * SIMDBigCore.alphaTab[v + 0 * 2]) >> 16);
                this.q[0 + u + 0] = m + t;
                this.q[0 + u + 0 + 64] = m - t;
            }
            m = this.q[0 + u + 1];
            n = this.q[0 + u + 1 + 64];
            t = ((n * SIMDBigCore.alphaTab[v + 1 * 2]) & 0xFFFF)
                + ((n * SIMDBigCore.alphaTab[v + 1 * 2]) >> 16);
            this.q[0 + u + 1] = m + t;
            this.q[0 + u + 1 + 64] = m - t;
            m = this.q[0 + u + 2];
            n = this.q[0 + u + 2 + 64];
            t = ((n * SIMDBigCore.alphaTab[v + 2 * 2]) & 0xFFFF)
                + ((n * SIMDBigCore.alphaTab[v + 2 * 2]) >> 16);
            this.q[0 + u + 2] = m + t;
            this.q[0 + u + 2 + 64] = m - t;
            m = this.q[0 + u + 3];
            n = this.q[0 + u + 3 + 64];
            t = ((n * SIMDBigCore.alphaTab[v + 3 * 2]) & 0xFFFF)
                + ((n * SIMDBigCore.alphaTab[v + 3 * 2]) >> 16);
            this.q[0 + u + 3] = m + t;
            this.q[0 + u + 3 + 64] = m - t;
        }
        this.fft64(x, 0 + (1 * 1), 1 << 2, 0 + 128);
        this.fft64(x, 0 + (1 * 3), 1 << 2, 0 + 192);
        m = this.q[0 + 128];
        n = this.q[0 + 128 + 64];
        this.q[0 + 128] = m + n;
        this.q[0 + 128 + 64] = m - n;
        for (let u = 0, v = 0; u < 64; u += 4, v += 4 * 2) {
            var t;
            if (u != 0) {
                m = this.q[(0 + 128) + u + 0];
                n = this.q[(0 + 128) + u + 0 + 64];
                t = ((n * SIMDBigCore.alphaTab[v + 0 * 2]) & 0xFFFF)
                    + ((n * SIMDBigCore.alphaTab[v + 0 * 2]) >> 16);
                this.q[(0 + 128) + u + 0] = m + t;
                this.q[(0 + 128) + u + 0 + 64] = m - t;
            }
            m = this.q[(0 + 128) + u + 1];
            n = this.q[(0 + 128) + u + 1 + 64];
            t = ((n * SIMDBigCore.alphaTab[v + 1 * 2]) & 0xFFFF)
                + ((n * SIMDBigCore.alphaTab[v + 1 * 2]) >> 16);
            this.q[(0 + 128) + u + 1] = m + t;
            this.q[(0 + 128) + u + 1 + 64] = m - t;
            m = this.q[(0 + 128) + u + 2];
            n = this.q[(0 + 128) + u + 2 + 64];
            t = ((n * SIMDBigCore.alphaTab[v + 2 * 2]) & 0xFFFF)
                + ((n * SIMDBigCore.alphaTab[v + 2 * 2]) >> 16);
            this.q[(0 + 128) + u + 2] = m + t;
            this.q[(0 + 128) + u + 2 + 64] = m - t;
            m = this.q[(0 + 128) + u + 3];
            n = this.q[(0 + 128) + u + 3 + 64];
            t = ((n * SIMDBigCore.alphaTab[v + 3 * 2]) & 0xFFFF)
                + ((n * SIMDBigCore.alphaTab[v + 3 * 2]) >> 16);
            this.q[(0 + 128) + u + 3] = m + t;
            this.q[(0 + 128) + u + 3 + 64] = m - t;
        }
        m = this.q[0];
        n = this.q[0 + 128];
        this.q[0] = m + n;
        this.q[0 + 128] = m - n;
        for (let u = 0, v = 0; u < 128; u += 4, v += 4 * 1) {
            var t;
            if (u != 0) {
                m = this.q[0 + u + 0];
                n = this.q[0 + u + 0 + 128];
                t = ((n * SIMDBigCore.alphaTab[v + 0 * 1]) & 0xFFFF)
                    + ((n * SIMDBigCore.alphaTab[v + 0 * 1]) >> 16);
                this.q[0 + u + 0] = m + t;
                this.q[0 + u + 0 + 128] = m - t;
            }
            m = this.q[0 + u + 1];
            n = this.q[0 + u + 1 + 128];
            t = ((n * SIMDBigCore.alphaTab[v + 1 * 1]) & 0xFFFF)
                + ((n * SIMDBigCore.alphaTab[v + 1 * 1]) >> 16);
            this.q[0 + u + 1] = m + t;
            this.q[0 + u + 1 + 128] = m - t;
            m = this.q[0 + u + 2];
            n = this.q[0 + u + 2 + 128];
            t = ((n * SIMDBigCore.alphaTab[v + 2 * 1]) & 0xFFFF)
                + ((n * SIMDBigCore.alphaTab[v + 2 * 1]) >> 16);
            this.q[0 + u + 2] = m + t;
            this.q[0 + u + 2 + 128] = m - t;
            m = this.q[0 + u + 3];
            n = this.q[0 + u + 3 + 128];
            t = ((n * SIMDBigCore.alphaTab[v + 3 * 1]) & 0xFFFF)
                + ((n * SIMDBigCore.alphaTab[v + 3 * 1]) >> 16);
            this.q[0 + u + 3] = m + t;
            this.q[0 + u + 3 + 128] = m - t;
        }
        if (last) {
            for (let i = 0; i < 256; i++) {
                var tq = this.q[i] + SIMDBigCore.yoffF[i];
                tq = ((tq & 0xFFFF) + (tq >> 16));
                tq = ((tq & 0xFF) - (tq >> 8));
                tq = ((tq & 0xFF) - (tq >> 8));
                this.q[i] = (tq <= 128 ? tq : tq - 257);
            }
        }
        else {
            for (let i = 0; i < 256; i++) {
                var tq = this.q[i] + SIMDBigCore.yoffN[i];
                tq = ((tq & 0xFFFF) + (tq >> 16));
                tq = ((tq & 0xFF) - (tq >> 8));
                tq = ((tq & 0xFF) - (tq >> 8));
                this.q[i] = (tq <= 128 ? tq : tq - 257);
            }
        }
        arraycopy(this.state, 0, this.tmpState, 0, 32);
        for (let i = 0; i < 32; i += 8) {
            this.state[i + 0] ^= this.decodeLEInt(x, 4 * (i + 0));
            this.state[i + 1] ^= this.decodeLEInt(x, 4 * (i + 1));
            this.state[i + 2] ^= this.decodeLEInt(x, 4 * (i + 2));
            this.state[i + 3] ^= this.decodeLEInt(x, 4 * (i + 3));
            this.state[i + 4] ^= this.decodeLEInt(x, 4 * (i + 4));
            this.state[i + 5] ^= this.decodeLEInt(x, 4 * (i + 5));
            this.state[i + 6] ^= this.decodeLEInt(x, 4 * (i + 6));
            this.state[i + 7] ^= this.decodeLEInt(x, 4 * (i + 7));
        }
        for (let u = 0; u < 64; u += 8) {
            var v = SIMDBigCore.wbp[(u >> 3) + 0];
            this.w[u + 0] = (((this.q[v + 2 * 0 + 0]) * 185) & 0xFFFF)
                + (((this.q[v + 2 * 0 + 1]) * 185) << 16);
            this.w[u + 1] = (((this.q[v + 2 * 1 + 0]) * 185) & 0xFFFF)
                + (((this.q[v + 2 * 1 + 1]) * 185) << 16);
            this.w[u + 2] = (((this.q[v + 2 * 2 + 0]) * 185) & 0xFFFF)
                + (((this.q[v + 2 * 2 + 1]) * 185) << 16);
            this.w[u + 3] = (((this.q[v + 2 * 3 + 0]) * 185) & 0xFFFF)
                + (((this.q[v + 2 * 3 + 1]) * 185) << 16);
            this.w[u + 4] = (((this.q[v + 2 * 4 + 0]) * 185) & 0xFFFF)
                + (((this.q[v + 2 * 4 + 1]) * 185) << 16);
            this.w[u + 5] = (((this.q[v + 2 * 5 + 0]) * 185) & 0xFFFF)
                + (((this.q[v + 2 * 5 + 1]) * 185) << 16);
            this.w[u + 6] = (((this.q[v + 2 * 6 + 0]) * 185) & 0xFFFF)
                + (((this.q[v + 2 * 6 + 1]) * 185) << 16);
            this.w[u + 7] = (((this.q[v + 2 * 7 + 0]) * 185) & 0xFFFF)
                + (((this.q[v + 2 * 7 + 1]) * 185) << 16);
        }
        this.oneRound(0, 3, 23, 17, 27);
        for (let u = 0; u < 64; u += 8) {
            var v = SIMDBigCore.wbp[(u >> 3) + 8];
            this.w[u + 0] = (((this.q[v + 2 * 0 + 0]) * 185) & 0xFFFF)
                + (((this.q[v + 2 * 0 + 1]) * 185) << 16);
            this.w[u + 1] = (((this.q[v + 2 * 1 + 0]) * 185) & 0xFFFF)
                + (((this.q[v + 2 * 1 + 1]) * 185) << 16);
            this.w[u + 2] = (((this.q[v + 2 * 2 + 0]) * 185) & 0xFFFF)
                + (((this.q[v + 2 * 2 + 1]) * 185) << 16);
            this.w[u + 3] = (((this.q[v + 2 * 3 + 0]) * 185) & 0xFFFF)
                + (((this.q[v + 2 * 3 + 1]) * 185) << 16);
            this.w[u + 4] = (((this.q[v + 2 * 4 + 0]) * 185) & 0xFFFF)
                + (((this.q[v + 2 * 4 + 1]) * 185) << 16);
            this.w[u + 5] = (((this.q[v + 2 * 5 + 0]) * 185) & 0xFFFF)
                + (((this.q[v + 2 * 5 + 1]) * 185) << 16);
            this.w[u + 6] = (((this.q[v + 2 * 6 + 0]) * 185) & 0xFFFF)
                + (((this.q[v + 2 * 6 + 1]) * 185) << 16);
            this.w[u + 7] = (((this.q[v + 2 * 7 + 0]) * 185) & 0xFFFF)
                + (((this.q[v + 2 * 7 + 1]) * 185) << 16);
        }
        this.oneRound(1, 28, 19, 22, 7);
        for (let u = 0; u < 64; u += 8) {
            var v = SIMDBigCore.wbp[(u >> 3) + 16];
            this.w[u + 0] = (((this.q[v + 2 * 0 + (-256)]) * 233) & 0xFFFF)
                + (((this.q[v + 2 * 0 + (-128)]) * 233) << 16);
            this.w[u + 1] = (((this.q[v + 2 * 1 + (-256)]) * 233) & 0xFFFF)
                + (((this.q[v + 2 * 1 + (-128)]) * 233) << 16);
            this.w[u + 2] = (((this.q[v + 2 * 2 + (-256)]) * 233) & 0xFFFF)
                + (((this.q[v + 2 * 2 + (-128)]) * 233) << 16);
            this.w[u + 3] = (((this.q[v + 2 * 3 + (-256)]) * 233) & 0xFFFF)
                + (((this.q[v + 2 * 3 + (-128)]) * 233) << 16);
            this.w[u + 4] = (((this.q[v + 2 * 4 + (-256)]) * 233) & 0xFFFF)
                + (((this.q[v + 2 * 4 + (-128)]) * 233) << 16);
            this.w[u + 5] = (((this.q[v + 2 * 5 + (-256)]) * 233) & 0xFFFF)
                + (((this.q[v + 2 * 5 + (-128)]) * 233) << 16);
            this.w[u + 6] = (((this.q[v + 2 * 6 + (-256)]) * 233) & 0xFFFF)
                + (((this.q[v + 2 * 6 + (-128)]) * 233) << 16);
            this.w[u + 7] = (((this.q[v + 2 * 7 + (-256)]) * 233) & 0xFFFF)
                + (((this.q[v + 2 * 7 + (-128)]) * 233) << 16);
        }
        this.oneRound(2, 29, 9, 15, 5);
        for (let u = 0; u < 64; u += 8) {
            var v = SIMDBigCore.wbp[(u >> 3) + 24];
            this.w[u + 0] = (((this.q[v + 2 * 0 + (-383)]) * 233) & 0xFFFF)
                + (((this.q[v + 2 * 0 + (-255)]) * 233) << 16);
            this.w[u + 1] = (((this.q[v + 2 * 1 + (-383)]) * 233) & 0xFFFF)
                + (((this.q[v + 2 * 1 + (-255)]) * 233) << 16);
            this.w[u + 2] = (((this.q[v + 2 * 2 + (-383)]) * 233) & 0xFFFF)
                + (((this.q[v + 2 * 2 + (-255)]) * 233) << 16);
            this.w[u + 3] = (((this.q[v + 2 * 3 + (-383)]) * 233) & 0xFFFF)
                + (((this.q[v + 2 * 3 + (-255)]) * 233) << 16);
            this.w[u + 4] = (((this.q[v + 2 * 4 + (-383)]) * 233) & 0xFFFF)
                + (((this.q[v + 2 * 4 + (-255)]) * 233) << 16);
            this.w[u + 5] = (((this.q[v + 2 * 5 + (-383)]) * 233) & 0xFFFF)
                + (((this.q[v + 2 * 5 + (-255)]) * 233) << 16);
            this.w[u + 6] = (((this.q[v + 2 * 6 + (-383)]) * 233) & 0xFFFF)
                + (((this.q[v + 2 * 6 + (-255)]) * 233) << 16);
            this.w[u + 7] = (((this.q[v + 2 * 7 + (-383)]) * 233) & 0xFFFF)
                + (((this.q[v + 2 * 7 + (-255)]) * 233) << 16);
        }
        this.oneRound(3, 4, 13, 10, 25);
        {
            var tA0 = this.circularLeft(this.state[0], 4);
            var tA1 = this.circularLeft(this.state[1], 4);
            var tA2 = this.circularLeft(this.state[2], 4);
            var tA3 = this.circularLeft(this.state[3], 4);
            var tA4 = this.circularLeft(this.state[4], 4);
            var tA5 = this.circularLeft(this.state[5], 4);
            var tA6 = this.circularLeft(this.state[6], 4);
            var tA7 = this.circularLeft(this.state[7], 4);
            tmp = this.state[24] + (this.tmpState[0]) + (((this.state[8]
                ^ this.state[16]) & this.state[0]) ^ this.state[16]);
            this.state[0] = this.circularLeft(tmp, 13) + tA5;
            this.state[24] = this.state[16];
            this.state[16] = this.state[8];
            this.state[8] = tA0;
            tmp = this.state[25] + (this.tmpState[1]) + (((this.state[9]
                ^ this.state[17]) & this.state[1]) ^ this.state[17]);
            this.state[1] = this.circularLeft(tmp, 13) + tA4;
            this.state[25] = this.state[17];
            this.state[17] = this.state[9];
            this.state[9] = tA1;
            tmp = this.state[26] + (this.tmpState[2]) + (((this.state[10]
                ^ this.state[18]) & this.state[2]) ^ this.state[18]);
            this.state[2] = this.circularLeft(tmp, 13) + tA7;
            this.state[26] = this.state[18];
            this.state[18] = this.state[10];
            this.state[10] = tA2;
            tmp = this.state[27] + (this.tmpState[3]) + (((this.state[11]
                ^ this.state[19]) & this.state[3]) ^ this.state[19]);
            this.state[3] = this.circularLeft(tmp, 13) + tA6;
            this.state[27] = this.state[19];
            this.state[19] = this.state[11];
            this.state[11] = tA3;
            tmp = this.state[28] + (this.tmpState[4]) + (((this.state[12]
                ^ this.state[20]) & this.state[4]) ^ this.state[20]);
            this.state[4] = this.circularLeft(tmp, 13) + tA1;
            this.state[28] = this.state[20];
            this.state[20] = this.state[12];
            this.state[12] = tA4;
            tmp = this.state[29] + (this.tmpState[5]) + (((this.state[13]
                ^ this.state[21]) & this.state[5]) ^ this.state[21]);
            this.state[5] = this.circularLeft(tmp, 13) + tA0;
            this.state[29] = this.state[21];
            this.state[21] = this.state[13];
            this.state[13] = tA5;
            tmp = this.state[30] + (this.tmpState[6]) + (((this.state[14]
                ^ this.state[22]) & this.state[6]) ^ this.state[22]);
            this.state[6] = this.circularLeft(tmp, 13) + tA3;
            this.state[30] = this.state[22];
            this.state[22] = this.state[14];
            this.state[14] = tA6;
            tmp = this.state[31] + (this.tmpState[7]) + (((this.state[15]
                ^ this.state[23]) & this.state[7]) ^ this.state[23]);
            this.state[7] = this.circularLeft(tmp, 13) + tA2;
            this.state[31] = this.state[23];
            this.state[23] = this.state[15];
            this.state[15] = tA7;
        }
        {
            var tA0 = this.circularLeft(this.state[0], 13);
            var tA1 = this.circularLeft(this.state[1], 13);
            var tA2 = this.circularLeft(this.state[2], 13);
            var tA3 = this.circularLeft(this.state[3], 13);
            var tA4 = this.circularLeft(this.state[4], 13);
            var tA5 = this.circularLeft(this.state[5], 13);
            var tA6 = this.circularLeft(this.state[6], 13);
            var tA7 = this.circularLeft(this.state[7], 13);
            tmp = this.state[24] + (this.tmpState[8]) + (((this.state[8]
                ^ this.state[16]) & this.state[0]) ^ this.state[16]);
            this.state[0] = this.circularLeft(tmp, 10) + tA7;
            this.state[24] = this.state[16];
            this.state[16] = this.state[8];
            this.state[8] = tA0;
            tmp = this.state[25] + (this.tmpState[9]) + (((this.state[9]
                ^ this.state[17]) & this.state[1]) ^ this.state[17]);
            this.state[1] = this.circularLeft(tmp, 10) + tA6;
            this.state[25] = this.state[17];
            this.state[17] = this.state[9];
            this.state[9] = tA1;
            tmp = this.state[26] + (this.tmpState[10]) + (((this.state[10]
                ^ this.state[18]) & this.state[2]) ^ this.state[18]);
            this.state[2] = this.circularLeft(tmp, 10) + tA5;
            this.state[26] = this.state[18];
            this.state[18] = this.state[10];
            this.state[10] = tA2;
            tmp = this.state[27] + (this.tmpState[11]) + (((this.state[11]
                ^ this.state[19]) & this.state[3]) ^ this.state[19]);
            this.state[3] = this.circularLeft(tmp, 10) + tA4;
            this.state[27] = this.state[19];
            this.state[19] = this.state[11];
            this.state[11] = tA3;
            tmp = this.state[28] + (this.tmpState[12]) + (((this.state[12]
                ^ this.state[20]) & this.state[4]) ^ this.state[20]);
            this.state[4] = this.circularLeft(tmp, 10) + tA3;
            this.state[28] = this.state[20];
            this.state[20] = this.state[12];
            this.state[12] = tA4;
            tmp = this.state[29] + (this.tmpState[13]) + (((this.state[13]
                ^ this.state[21]) & this.state[5]) ^ this.state[21]);
            this.state[5] = this.circularLeft(tmp, 10) + tA2;
            this.state[29] = this.state[21];
            this.state[21] = this.state[13];
            this.state[13] = tA5;
            tmp = this.state[30] + (this.tmpState[14]) + (((this.state[14]
                ^ this.state[22]) & this.state[6]) ^ this.state[22]);
            this.state[6] = this.circularLeft(tmp, 10) + tA1;
            this.state[30] = this.state[22];
            this.state[22] = this.state[14];
            this.state[14] = tA6;
            tmp = this.state[31] + (this.tmpState[15]) + (((this.state[15]
                ^ this.state[23]) & this.state[7]) ^ this.state[23]);
            this.state[7] = this.circularLeft(tmp, 10) + tA0;
            this.state[31] = this.state[23];
            this.state[23] = this.state[15];
            this.state[15] = tA7;
        }
        {
            var tA0 = this.circularLeft(this.state[0], 10);
            var tA1 = this.circularLeft(this.state[1], 10);
            var tA2 = this.circularLeft(this.state[2], 10);
            var tA3 = this.circularLeft(this.state[3], 10);
            var tA4 = this.circularLeft(this.state[4], 10);
            var tA5 = this.circularLeft(this.state[5], 10);
            var tA6 = this.circularLeft(this.state[6], 10);
            var tA7 = this.circularLeft(this.state[7], 10);
            tmp = this.state[24] + (this.tmpState[16]) + (((this.state[8]
                ^ this.state[16]) & this.state[0]) ^ this.state[16]);
            this.state[0] = this.circularLeft(tmp, 25) + tA4;
            this.state[24] = this.state[16];
            this.state[16] = this.state[8];
            this.state[8] = tA0;
            tmp = this.state[25] + (this.tmpState[17]) + (((this.state[9]
                ^ this.state[17]) & this.state[1]) ^ this.state[17]);
            this.state[1] = this.circularLeft(tmp, 25) + tA5;
            this.state[25] = this.state[17];
            this.state[17] = this.state[9];
            this.state[9] = tA1;
            tmp = this.state[26] + (this.tmpState[18]) + (((this.state[10]
                ^ this.state[18]) & this.state[2]) ^ this.state[18]);
            this.state[2] = this.circularLeft(tmp, 25) + tA6;
            this.state[26] = this.state[18];
            this.state[18] = this.state[10];
            this.state[10] = tA2;
            tmp = this.state[27] + (this.tmpState[19]) + (((this.state[11]
                ^ this.state[19]) & this.state[3]) ^ this.state[19]);
            this.state[3] = this.circularLeft(tmp, 25) + tA7;
            this.state[27] = this.state[19];
            this.state[19] = this.state[11];
            this.state[11] = tA3;
            tmp = this.state[28] + (this.tmpState[20]) + (((this.state[12]
                ^ this.state[20]) & this.state[4]) ^ this.state[20]);
            this.state[4] = this.circularLeft(tmp, 25) + tA0;
            this.state[28] = this.state[20];
            this.state[20] = this.state[12];
            this.state[12] = tA4;
            tmp = this.state[29] + (this.tmpState[21]) + (((this.state[13]
                ^ this.state[21]) & this.state[5]) ^ this.state[21]);
            this.state[5] = this.circularLeft(tmp, 25) + tA1;
            this.state[29] = this.state[21];
            this.state[21] = this.state[13];
            this.state[13] = tA5;
            tmp = this.state[30] + (this.tmpState[22]) + (((this.state[14]
                ^ this.state[22]) & this.state[6]) ^ this.state[22]);
            this.state[6] = this.circularLeft(tmp, 25) + tA2;
            this.state[30] = this.state[22];
            this.state[22] = this.state[14];
            this.state[14] = tA6;
            tmp = this.state[31] + (this.tmpState[23]) + (((this.state[15]
                ^ this.state[23]) & this.state[7]) ^ this.state[23]);
            this.state[7] = this.circularLeft(tmp, 25) + tA3;
            this.state[31] = this.state[23];
            this.state[23] = this.state[15];
            this.state[15] = tA7;
        }
        {
            var tA0 = this.circularLeft(this.state[0], 25);
            var tA1 = this.circularLeft(this.state[1], 25);
            var tA2 = this.circularLeft(this.state[2], 25);
            var tA3 = this.circularLeft(this.state[3], 25);
            var tA4 = this.circularLeft(this.state[4], 25);
            var tA5 = this.circularLeft(this.state[5], 25);
            var tA6 = this.circularLeft(this.state[6], 25);
            var tA7 = this.circularLeft(this.state[7], 25);
            tmp = this.state[24] + (this.tmpState[24]) + (((this.state[8]
                ^ this.state[16]) & this.state[0]) ^ this.state[16]);
            this.state[0] = this.circularLeft(tmp, 4) + tA1;
            this.state[24] = this.state[16];
            this.state[16] = this.state[8];
            this.state[8] = tA0;
            tmp = this.state[25] + (this.tmpState[25]) + (((this.state[9]
                ^ this.state[17]) & this.state[1]) ^ this.state[17]);
            this.state[1] = this.circularLeft(tmp, 4) + tA0;
            this.state[25] = this.state[17];
            this.state[17] = this.state[9];
            this.state[9] = tA1;
            tmp = this.state[26] + (this.tmpState[26]) + (((this.state[10]
                ^ this.state[18]) & this.state[2]) ^ this.state[18]);
            this.state[2] = this.circularLeft(tmp, 4) + tA3;
            this.state[26] = this.state[18];
            this.state[18] = this.state[10];
            this.state[10] = tA2;
            tmp = this.state[27] + (this.tmpState[27]) + (((this.state[11]
                ^ this.state[19]) & this.state[3]) ^ this.state[19]);
            this.state[3] = this.circularLeft(tmp, 4) + tA2;
            this.state[27] = this.state[19];
            this.state[19] = this.state[11];
            this.state[11] = tA3;
            tmp = this.state[28] + (this.tmpState[28]) + (((this.state[12]
                ^ this.state[20]) & this.state[4]) ^ this.state[20]);
            this.state[4] = this.circularLeft(tmp, 4) + tA5;
            this.state[28] = this.state[20];
            this.state[20] = this.state[12];
            this.state[12] = tA4;
            tmp = this.state[29] + (this.tmpState[29]) + (((this.state[13]
                ^ this.state[21]) & this.state[5]) ^ this.state[21]);
            this.state[5] = this.circularLeft(tmp, 4) + tA4;
            this.state[29] = this.state[21];
            this.state[21] = this.state[13];
            this.state[13] = tA5;
            tmp = this.state[30] + (this.tmpState[30]) + (((this.state[14]
                ^ this.state[22]) & this.state[6]) ^ this.state[22]);
            this.state[6] = this.circularLeft(tmp, 4) + tA7;
            this.state[30] = this.state[22];
            this.state[22] = this.state[14];
            this.state[14] = tA6;
            tmp = this.state[31] + (this.tmpState[31]) + (((this.state[15]
                ^ this.state[23]) & this.state[7]) ^ this.state[23]);
            this.state[7] = this.circularLeft(tmp, 4) + tA6;
            this.state[31] = this.state[23];
            this.state[23] = this.state[15];
            this.state[15] = tA7;
        }
    }
    /** @see Digest */
    toString() {
        return "SIMD-" + (this.getDigestLength() << 3);
    }
}
SIMDBigCore.alphaTab = new Int32Array([
    1, 41, 139, 45, 46, 87, 226, 14, 60, 147, 116, 130,
    190, 80, 196, 69, 2, 82, 21, 90, 92, 174, 195, 28,
    120, 37, 232, 3, 123, 160, 135, 138, 4, 164, 42, 180,
    184, 91, 133, 56, 240, 74, 207, 6, 246, 63, 13, 19,
    8, 71, 84, 103, 111, 182, 9, 112, 223, 148, 157, 12,
    235, 126, 26, 38, 16, 142, 168, 206, 222, 107, 18, 224,
    189, 39, 57, 24, 213, 252, 52, 76, 32, 27, 79, 155,
    187, 214, 36, 191, 121, 78, 114, 48, 169, 247, 104, 152,
    64, 54, 158, 53, 117, 171, 72, 125, 242, 156, 228, 96,
    81, 237, 208, 47, 128, 108, 59, 106, 234, 85, 144, 250,
    227, 55, 199, 192, 162, 217, 159, 94, 256, 216, 118, 212,
    211, 170, 31, 243, 197, 110, 141, 127, 67, 177, 61, 188,
    255, 175, 236, 167, 165, 83, 62, 229, 137, 220, 25, 254,
    134, 97, 122, 119, 253, 93, 215, 77, 73, 166, 124, 201,
    17, 183, 50, 251, 11, 194, 244, 238, 249, 186, 173, 154,
    146, 75, 248, 145, 34, 109, 100, 245, 22, 131, 231, 219,
    241, 115, 89, 51, 35, 150, 239, 33, 68, 218, 200, 233,
    44, 5, 205, 181, 225, 230, 178, 102, 70, 43, 221, 66,
    136, 179, 143, 209, 88, 10, 153, 105, 193, 203, 99, 204,
    140, 86, 185, 132, 15, 101, 29, 161, 176, 20, 49, 210,
    129, 149, 198, 151, 23, 172, 113, 7, 30, 202, 58, 65,
    95, 40, 98, 163
]);
SIMDBigCore.yoffN = new Int32Array([
    1, 163, 98, 40, 95, 65, 58, 202, 30, 7, 113, 172,
    23, 151, 198, 149, 129, 210, 49, 20, 176, 161, 29, 101,
    15, 132, 185, 86, 140, 204, 99, 203, 193, 105, 153, 10,
    88, 209, 143, 179, 136, 66, 221, 43, 70, 102, 178, 230,
    225, 181, 205, 5, 44, 233, 200, 218, 68, 33, 239, 150,
    35, 51, 89, 115, 241, 219, 231, 131, 22, 245, 100, 109,
    34, 145, 248, 75, 146, 154, 173, 186, 249, 238, 244, 194,
    11, 251, 50, 183, 17, 201, 124, 166, 73, 77, 215, 93,
    253, 119, 122, 97, 134, 254, 25, 220, 137, 229, 62, 83,
    165, 167, 236, 175, 255, 188, 61, 177, 67, 127, 141, 110,
    197, 243, 31, 170, 211, 212, 118, 216, 256, 94, 159, 217,
    162, 192, 199, 55, 227, 250, 144, 85, 234, 106, 59, 108,
    128, 47, 208, 237, 81, 96, 228, 156, 242, 125, 72, 171,
    117, 53, 158, 54, 64, 152, 104, 247, 169, 48, 114, 78,
    121, 191, 36, 214, 187, 155, 79, 27, 32, 76, 52, 252,
    213, 24, 57, 39, 189, 224, 18, 107, 222, 206, 168, 142,
    16, 38, 26, 126, 235, 12, 157, 148, 223, 112, 9, 182,
    111, 103, 84, 71, 8, 19, 13, 63, 246, 6, 207, 74,
    240, 56, 133, 91, 184, 180, 42, 164, 4, 138, 135, 160,
    123, 3, 232, 37, 120, 28, 195, 174, 92, 90, 21, 82,
    2, 69, 196, 80, 190, 130, 116, 147, 60, 14, 226, 87,
    46, 45, 139, 41
]);
SIMDBigCore.yoffF = new Int32Array([
    2, 203, 156, 47, 118, 214, 107, 106, 45, 93, 212, 20,
    111, 73, 162, 251, 97, 215, 249, 53, 211, 19, 3, 89,
    49, 207, 101, 67, 151, 130, 223, 23, 189, 202, 178, 239,
    253, 127, 204, 49, 76, 236, 82, 137, 232, 157, 65, 79,
    96, 161, 176, 130, 161, 30, 47, 9, 189, 247, 61, 226,
    248, 90, 107, 64, 0, 88, 131, 243, 133, 59, 113, 115,
    17, 236, 33, 213, 12, 191, 111, 19, 251, 61, 103, 208,
    57, 35, 148, 248, 47, 116, 65, 119, 249, 178, 143, 40,
    189, 129, 8, 163, 204, 227, 230, 196, 205, 122, 151, 45,
    187, 19, 227, 72, 247, 125, 111, 121, 140, 220, 6, 107,
    77, 69, 10, 101, 21, 65, 149, 171, 255, 54, 101, 210,
    139, 43, 150, 151, 212, 164, 45, 237, 146, 184, 95, 6,
    160, 42, 8, 204, 46, 238, 254, 168, 208, 50, 156, 190,
    106, 127, 34, 234, 68, 55, 79, 18, 4, 130, 53, 208,
    181, 21, 175, 120, 25, 100, 192, 178, 161, 96, 81, 127,
    96, 227, 210, 248, 68, 10, 196, 31, 9, 167, 150, 193,
    0, 169, 126, 14, 124, 198, 144, 142, 240, 21, 224, 44,
    245, 66, 146, 238, 6, 196, 154, 49, 200, 222, 109, 9,
    210, 141, 192, 138, 8, 79, 114, 217, 68, 128, 249, 94,
    53, 30, 27, 61, 52, 135, 106, 212, 70, 238, 30, 185,
    10, 132, 146, 136, 117, 37, 251, 150, 180, 188, 247, 156,
    236, 192, 108, 86
]);
SIMDBigCore.pp8k = new Int32Array([
    1, 6, 2, 3, 5, 7, 4, 1, 6, 2, 3
]);
SIMDBigCore.wbp = new Int32Array([
    64, 96, 0, 32,
    112, 80, 48, 16,
    240, 176, 192, 128,
    144, 208, 160, 224,
    272, 288, 368, 320,
    352, 336, 256, 304,
    480, 384, 400, 496,
    432, 464, 448, 416
]);
/**
 * <p>This class implements the SIMD-224 digest algorithm under the
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
class Simd224 extends SIMDSmallCore {
    /**
     * Create the engine.
     */
    constructor() {
        super();
    }
    /** @see SIMDSmallCore */
    getInitVal() {
        return Simd224.initVal;
    }
    /** @see Digest */
    getDigestLength() {
        return 28;
    }
    /** @see Digest */
    copy() {
        return this.copyState(new Simd224());
    }
}
exports.Simd224 = Simd224;
/** The initial value for SIMD-224. */
Simd224.initVal = new Int32Array([
    0x33586E9F, 0x12FFF033, 0xB2D9F64D, 0x6F8FEA53,
    0xDE943106, 0x2742E439, 0x4FBAB5AC, 0x62B9FF96,
    0x22E7B0AF, 0xC862B3A8, 0x33E00CDC, 0x236B86A6,
    0xF64AE77C, 0xFA373B76, 0x7DC1EE5B, 0x7FB29CE8
]);
/**
 * <p>This class implements the SIMD-256 digest algorithm under the
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
class Simd256 extends SIMDSmallCore {
    /**
     * Create the engine.
     */
    constructor() {
        super();
    }
    /** @see SIMDSmallCore */
    getInitVal() {
        return Simd256.initVal;
    }
    /** @see Digest */
    getDigestLength() {
        return 32;
    }
    /** @see Digest */
    copy() {
        return this.copyState(new Simd256());
    }
}
exports.Simd256 = Simd256;
/** The initial value for SIMD-256. */
Simd256.initVal = new Int32Array([
    0x4D567983, 0x07190BA9, 0x8474577B, 0x39D726E9,
    0xAAF3D925, 0x3EE20B03, 0xAFD5E751, 0xC96006D3,
    0xC2C2BA14, 0x49B3BCB4, 0xF67CAF46, 0x668626C9,
    0xE2EAA8D2, 0x1FF47833, 0xD0C661A5, 0x55693DE1
]);
/**
 * <p>This class implements the SIMD-384 digest algorithm under the
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
class Simd384 extends SIMDBigCore {
    /**
     * Create the engine.
     */
    constructor() {
        super();
    }
    /** @see SIMDSmallCore */
    getInitVal() {
        return Simd384.initVal;
    }
    /** @see Digest */
    getDigestLength() {
        return 48;
    }
    /** @see Digest */
    copy() {
        return this.copyState(new Simd384());
    }
}
exports.Simd384 = Simd384;
/** The initial value for SIMD-384. */
Simd384.initVal = new Int32Array([
    0x8A36EEBC, 0x94A3BD90, 0xD1537B83, 0xB25B070B,
    0xF463F1B5, 0xB6F81E20, 0x0055C339, 0xB4D144D1,
    0x7360CA61, 0x18361A03, 0x17DCB4B9, 0x3414C45A,
    0xA699A9D2, 0xE39E9664, 0x468BFE77, 0x51D062F8,
    0xB9E3BFE8, 0x63BECE2A, 0x8FE506B9, 0xF8CC4AC2,
    0x7AE11542, 0xB1AADDA1, 0x64B06794, 0x28D2F462,
    0xE64071EC, 0x1DEB91A8, 0x8AC8DB23, 0x3F782AB5,
    0x039B5CB8, 0x71DDD962, 0xFADE2CEA, 0x1416DF71
]);
/**
 * <p>This class implements the SIMD-512 digest algorithm under the
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
class Simd512 extends SIMDBigCore {
    /**
     * Create the engine.
     */
    constructor() {
        super();
    }
    /** @see SIMDSmallCore */
    getInitVal() {
        return Simd512.initVal;
    }
    /** @see Digest */
    getDigestLength() {
        return 64;
    }
    /** @see Digest */
    copy() {
        return this.copyState(new Simd512());
    }
}
exports.Simd512 = Simd512;
/** The initial value for SIMD-512. */
Simd512.initVal = new Int32Array([
    0x0BA16B95, 0x72F999AD, 0x9FECC2AE, 0xBA3264FC,
    0x5E894929, 0x8E9F30E5, 0x2F1DAA37, 0xF0F2C558,
    0xAC506643, 0xA90635A5, 0xE25B878B, 0xAAB7878F,
    0x88817F7A, 0x0A02892B, 0x559A7550, 0x598F657E,
    0x7EEF60A1, 0x6B70E3E8, 0x9C1714D1, 0xB958E2A8,
    0xAB02675E, 0xED1C014F, 0xCD8D65BB, 0xFDB7A257,
    0x09254899, 0xD699C7BC, 0x9019B6DC, 0x2B9022E4,
    0x8FA14956, 0x21BF9BD3, 0xB94D0943, 0x6FFDDC22
]);
function toHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
;
function strToUint8Array(str) {
    // Check if the browser supports TextDecoder API
    try {
        const encoder = new TextEncoder();
        // Encode the string and return as a Uint8Array
        return encoder.encode(str);
    }
    catch (e) { }
    // Fallback for older systems without TextDecoder support
    let result = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
        const codePoint = str.charCodeAt(i);
        if (codePoint <= 255) {
            result[i] = codePoint;
        }
        else {
            result.set([codePoint >> 8, codePoint & 0xFF], i * 2);
        }
    }
    return result;
}
function formatMessage(message) {
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
        return message;
    }
    throw new Error('input is invalid type');
}
/**
 * Creates a vary byte length SIMD hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {224 | 256 | 384 | 512} bitLen - length of hash (default 512 bits AKA 64 bytes)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function _SIMD(message, bitLen = 256, format = arrayType()) {
    var hash;
    switch (bitLen) {
        case 224:
            hash = new Simd224();
            break;
        case 256:
            hash = new Simd256();
            break;
        case 384:
            hash = new Simd384();
            break;
        case 512:
            hash = new Simd512();
            break;
        default:
            hash = new Simd512();
            break;
    }
    hash.update(formatMessage(message));
    const digestbytes = hash.digest();
    if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    else if (format == "hex") {
        return toHex(digestbytes);
    }
    return digestbytes;
}
exports._SIMD = _SIMD;
;
/**
 * Creates a vary byte length keyed SIMD hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {224 | 256 | 384 | 512} bitLen - length of hash (default 512 bits AKA 64 bytes)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function SIMD_HMAC(message, key, bitLen = 256, format = arrayType()) {
    var hash;
    switch (bitLen) {
        case 224:
            hash = new Simd224();
            break;
        case 256:
            hash = new Simd256();
            break;
        case 384:
            hash = new Simd384();
            break;
        case 512:
            hash = new Simd512();
            break;
        default:
            hash = new Simd512();
            break;
    }
    const mac = new HMAC(hash, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    }
    else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
}
exports.SIMD_HMAC = SIMD_HMAC;
;
/**
 * Creates a 28 byte SIMD hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function SIMD224(message, format = arrayType()) {
    const hash = new Simd224();
    hash.update(formatMessage(message));
    const digestbytes = hash.digest();
    if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    else if (format == "hex") {
        return toHex(digestbytes);
    }
    return digestbytes;
}
exports.SIMD224 = SIMD224;
;
/**
 * Creates a 28 byte keyed SIMD hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function SIMD224_HMAC(message, key, format = arrayType()) {
    const hash = new Simd224();
    const mac = new HMAC(hash, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    }
    else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
}
exports.SIMD224_HMAC = SIMD224_HMAC;
;
/**
 * Creates a 32 byte SIMD hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function SIMD256(message, format = arrayType()) {
    const hash = new Simd256();
    hash.update(formatMessage(message));
    const digestbytes = hash.digest();
    if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    else if (format == "hex") {
        return toHex(digestbytes);
    }
    return digestbytes;
}
exports.SIMD256 = SIMD256;
;
/**
 * Creates a 32 byte keyed SIMD hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function SIMD256_HMAC(message, key, format = arrayType()) {
    const hash = new Simd256();
    const mac = new HMAC(hash, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    }
    else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
}
exports.SIMD256_HMAC = SIMD256_HMAC;
;
/**
 * Creates a 48 byte SIMD hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function SIMD384(message, format = arrayType()) {
    const hash = new Simd384();
    hash.update(formatMessage(message));
    const digestbytes = hash.digest();
    if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    else if (format == "hex") {
        return toHex(digestbytes);
    }
    return digestbytes;
}
exports.SIMD384 = SIMD384;
;
/**
 * Creates a 48 byte keyed SIMD hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function SIMD384_HMAC(message, key, format = arrayType()) {
    const hash = new Simd384();
    const mac = new HMAC(hash, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    }
    else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
}
exports.SIMD384_HMAC = SIMD384_HMAC;
;
/**
 * Creates a 64 byte SIMD hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function SIMD512(message, format = arrayType()) {
    const hash = new Simd512();
    hash.update(formatMessage(message));
    const digestbytes = hash.digest();
    if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    else if (format == "hex") {
        return toHex(digestbytes);
    }
    return digestbytes;
}
exports.SIMD512 = SIMD512;
;
console.log(SIMD512(""));
/**
 * Creates a 64 byte keyed SIMD hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function SIMD512_HMAC(message, key, format = arrayType()) {
    const hash = new Simd512();
    const mac = new HMAC(hash, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    }
    else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
}
exports.SIMD512_HMAC = SIMD512_HMAC;
;
/**
 * Static class of all Single Instruction, Multiple Data (SIMD) functions and classes
 */
class SIMD {
    /**
     * List of all hashes in class
     */
    static get FUNCTION_LIST() {
        return [
            "SIMD",
            "SIMD224",
            "SIMD224_HMAC",
            "SIMD256",
            "SIMD256_HMAC",
            "SIMD384",
            "SIMD384_HMAC",
            "SIMD512",
            "SIMD512_HMAC",
            "SIMD_HMAC"
        ];
    }
}
exports.SIMD = SIMD;
SIMD.SIMD = _SIMD;
SIMD.Simd224 = Simd224;
SIMD.SIMD224 = SIMD224;
SIMD.SIMD224_HMAC = SIMD224_HMAC;
SIMD.Simd256 = Simd256;
SIMD.SIMD256 = SIMD256;
SIMD.SIMD256_HMAC = SIMD256_HMAC;
SIMD.Simd384 = Simd384;
SIMD.SIMD384 = SIMD384;
SIMD.SIMD384_HMAC = SIMD384_HMAC;
SIMD.Simd512 = Simd512;
SIMD.SIMD512 = SIMD512;
SIMD.SIMD512_HMAC = SIMD512_HMAC;
SIMD.SIMD_HMAC = SIMD_HMAC;
//# sourceMappingURL=SIMD.js.map