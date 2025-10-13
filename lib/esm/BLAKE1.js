"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BLAKE_HMAC = exports.BLAKE512_HMAC = exports.BLAKE512 = exports.BLAKE384_HMAC = exports.BLAKE384 = exports.BLAKE256_HMAC = exports.BLAKE256 = exports.BLAKE224_HMAC = exports.BLAKE224 = exports.BLAKE = exports.Blake = exports.Blake224 = void 0;
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
        arraycopy(this.inputBuf, 0, dest.inputBuf, 0, this.inputBuf.byteLength);
        this.adjustDigestLen();
        dest.adjustDigestLen();
        arraycopy(this.outputBuf, 0, dest.outputBuf, 0, this.outputBuf.byteLength);
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
 * This class implements BLAKE-224 and BLAKE-256, which differ only by
 * the IV, output length, and one bit in the padding.
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
 * @version   $Revision: 252 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
class BLAKESmallCore extends DigestEngine {
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
        dst.h = this.h;
        dst.s = this.s;
        dst.t = this.t;
        return super.copyState(dst);
    }
    /** @see DigestEngine */
    engineReset() {
        const iv = this.getInitVal();
        for (let i = 0; i < this.h.length; i++) {
            this.h[i] = iv[i];
        }
        this.s = new Int32Array(4);
        this.t = new Int32Array(2);
    }
    /** @see DigestEngine */
    doPadding(output, outputOffset) {
        var ptr = this.flush();
        var bitLen = ptr << 3;
        const h = 1;
        const l = 0;
        const t = new Int32Array(2);
        t[h] = this.t[1];
        t[l] = this.t[0] + bitLen;
        this.tmpBuf[ptr] = 0x80;
        if (ptr == 0) {
            this.t[0] = 0xFFFFFE00;
            this.t[1] = 0xFFFFFFFF;
        }
        else if (this.t[0] == 0) {
            this.t[0] = 0xFFFFFE00 + bitLen;
            this.t[1]--;
        }
        else {
            this.t[0] -= 512 - bitLen;
        }
        if (ptr < 56) {
            for (let i = ptr + 1; i < 56; i++) {
                this.tmpBuf[i] = 0x00;
            }
            if (this.getDigestLength() == 32) {
                this.tmpBuf[55] |= 0x01;
            }
            this.encodeBEInt(t[h], this.tmpBuf, 56);
            this.encodeBEInt(t[l], this.tmpBuf, 60);
            this.update(this.tmpBuf, ptr, 64 - ptr);
        }
        else {
            for (let i = ptr + 1; i < 64; i++) {
                this.tmpBuf[i] = 0;
            }
            this.update(this.tmpBuf, ptr, 64 - ptr);
            this.t[0] = 0xFFFFFE00;
            this.t[1] = 0xFFFFFFFF;
            for (let i = 0; i < 56; i++) {
                this.tmpBuf[i] = 0x00;
            }
            if (this.getDigestLength() == 32) {
                this.tmpBuf[55] = 0x01;
            }
            this.encodeBEInt(t[h], this.tmpBuf, 56);
            this.encodeBEInt(t[l], this.tmpBuf, 60);
            this.update(this.tmpBuf, 0, 64);
        }
        this.encodeBEInt(this.h[0], output, outputOffset + 0);
        this.encodeBEInt(this.h[1], output, outputOffset + 4);
        this.encodeBEInt(this.h[2], output, outputOffset + 8);
        this.encodeBEInt(this.h[3], output, outputOffset + 12);
        this.encodeBEInt(this.h[4], output, outputOffset + 16);
        this.encodeBEInt(this.h[5], output, outputOffset + 20);
        this.encodeBEInt(this.h[6], output, outputOffset + 24);
        if (this.getDigestLength() == 32) {
            this.encodeBEInt(this.h[7], output, outputOffset + 28);
        }
    }
    /** @see DigestEngine */
    doInit() {
        this.tmpM = new Int32Array(16);
        this.tmpBuf = new Uint8Array(64);
        this.h = new Int32Array(8);
        this.s = new Int32Array(4);
        this.t = new Int32Array(2);
        this.engineReset();
    }
    /**
     * Encode the 32-bit word {@code val} into the array
     * {@code buf} at offset {@code off}, in big-endian
     * convention (most significant byte first).
     *
     * @param val   the value to encode
     * @param buf   the destination buffer
     * @param off   the destination offset
     */
    encodeBEInt(val, buf, off) {
        buf[off + 0] = (val >> 24);
        buf[off + 1] = (val >> 16);
        buf[off + 2] = (val >> 8);
        buf[off + 3] = val;
    }
    /**
     * Decode a 32-bit big-endian word from the array {@code buf}
     * at offset {@code off}.
     *
     * @param buf   the source buffer
     * @param off   the source offset
     * @return  the decoded value
     */
    decodeBEInt(buf, off) {
        return ((buf[off] & 0xFF) << 24)
            | ((buf[off + 1] & 0xFF) << 16)
            | ((buf[off + 2] & 0xFF) << 8)
            | (buf[off + 3] & 0xFF);
    }
    /**
     * Perform a circular rotation by {@code n} to the right
     * of the 32-bit word {@code x}. The {@code n} parameter
     * must lie between 1 and 31 (inclusive).
     *
     * @param x   the value to rotate
     * @param n   the rotation count (between 1 and 31)
     * @return  the rotated value
    */
    circularRight(x, n) {
        const value = (x >>> n) | (x << (32 - n));
        return value;
    }
    /** @see DigestEngine */
    processBlock(data) {
        this.t[0] += 512;
        if ((this.t[0] & ~0x1FF) == 0) {
            this.t[1]++;
        }
        const v = new Int32Array(16);
        const A = 10;
        const B = 11;
        const C = 12;
        const D = 13;
        const E = 14;
        const F = 15;
        v[0] = this.h[0];
        v[1] = this.h[1];
        v[2] = this.h[2];
        v[3] = this.h[3];
        v[4] = this.h[4];
        v[5] = this.h[5];
        v[6] = this.h[6];
        v[7] = this.h[7];
        v[8] = this.s[0] ^ 0x243F6A88;
        v[9] = this.s[1] ^ 0x85A308D3;
        v[A] = this.s[2] ^ 0x13198A2E;
        v[B] = this.s[3] ^ 0x03707344;
        v[C] = this.t[0] ^ 0xA4093822;
        v[D] = this.t[0] ^ 0x299F31D0;
        v[E] = this.t[1] ^ 0x082EFA98;
        v[F] = this.t[1] ^ 0xEC4E6C89;
        const m = this.tmpM;
        for (let i = 0; i < 16; i++) {
            m[i] = this.decodeBEInt(data, 4 * i);
        }
        for (let r = 0; r < 14; r++) {
            let o0 = BLAKESmallCore.SIGMA[(r << 4) + 0x0];
            let o1 = BLAKESmallCore.SIGMA[(r << 4) + 0x1];
            v[0] += v[4] + (m[o0] ^ BLAKESmallCore.CS[o1]);
            v[C] = this.circularRight(v[C] ^ v[0], 16);
            v[8] += v[C];
            v[4] = this.circularRight(v[4] ^ v[8], 12);
            v[0] += v[4] + (m[o1] ^ BLAKESmallCore.CS[o0]);
            v[C] = this.circularRight(v[C] ^ v[0], 8);
            v[8] += v[C];
            v[4] = this.circularRight(v[4] ^ v[8], 7);
            o0 = BLAKESmallCore.SIGMA[(r << 4) + 0x2];
            o1 = BLAKESmallCore.SIGMA[(r << 4) + 0x3];
            v[1] += v[5] + (m[o0] ^ BLAKESmallCore.CS[o1]);
            v[D] = this.circularRight(v[D] ^ v[1], 16);
            v[9] += v[D];
            v[5] = this.circularRight(v[5] ^ v[9], 12);
            v[1] += v[5] + (m[o1] ^ BLAKESmallCore.CS[o0]);
            v[D] = this.circularRight(v[D] ^ v[1], 8);
            v[9] += v[D];
            v[5] = this.circularRight(v[5] ^ v[9], 7);
            o0 = BLAKESmallCore.SIGMA[(r << 4) + 0x4];
            o1 = BLAKESmallCore.SIGMA[(r << 4) + 0x5];
            v[2] += v[6] + (m[o0] ^ BLAKESmallCore.CS[o1]);
            v[E] = this.circularRight(v[E] ^ v[2], 16);
            v[A] += v[E];
            v[6] = this.circularRight(v[6] ^ v[A], 12);
            v[2] += v[6] + (m[o1] ^ BLAKESmallCore.CS[o0]);
            v[E] = this.circularRight(v[E] ^ v[2], 8);
            v[A] += v[E];
            v[6] = this.circularRight(v[6] ^ v[A], 7);
            o0 = BLAKESmallCore.SIGMA[(r << 4) + 0x6];
            o1 = BLAKESmallCore.SIGMA[(r << 4) + 0x7];
            v[3] += v[7] + (m[o0] ^ BLAKESmallCore.CS[o1]);
            v[F] = this.circularRight(v[F] ^ v[3], 16);
            v[B] += v[F];
            v[7] = this.circularRight(v[7] ^ v[B], 12);
            v[3] += v[7] + (m[o1] ^ BLAKESmallCore.CS[o0]);
            v[F] = this.circularRight(v[F] ^ v[3], 8);
            v[B] += v[F];
            v[7] = this.circularRight(v[7] ^ v[B], 7);
            o0 = BLAKESmallCore.SIGMA[(r << 4) + 0x8];
            o1 = BLAKESmallCore.SIGMA[(r << 4) + 0x9];
            v[0] += v[5] + (m[o0] ^ BLAKESmallCore.CS[o1]);
            v[F] = this.circularRight(v[F] ^ v[0], 16);
            v[A] += v[F];
            v[5] = this.circularRight(v[5] ^ v[A], 12);
            v[0] += v[5] + (m[o1] ^ BLAKESmallCore.CS[o0]);
            v[F] = this.circularRight(v[F] ^ v[0], 8);
            v[A] += v[F];
            v[5] = this.circularRight(v[5] ^ v[A], 7);
            o0 = BLAKESmallCore.SIGMA[(r << 4) + 0xA];
            o1 = BLAKESmallCore.SIGMA[(r << 4) + 0xB];
            v[1] += v[6] + (m[o0] ^ BLAKESmallCore.CS[o1]);
            v[C] = this.circularRight(v[C] ^ v[1], 16);
            v[B] += v[C];
            v[6] = this.circularRight(v[6] ^ v[B], 12);
            v[1] += v[6] + (m[o1] ^ BLAKESmallCore.CS[o0]);
            v[C] = this.circularRight(v[C] ^ v[1], 8);
            v[B] += v[C];
            v[6] = this.circularRight(v[6] ^ v[B], 7);
            o0 = BLAKESmallCore.SIGMA[(r << 4) + 0xC];
            o1 = BLAKESmallCore.SIGMA[(r << 4) + 0xD];
            v[2] += v[7] + (m[o0] ^ BLAKESmallCore.CS[o1]);
            v[D] = this.circularRight(v[D] ^ v[2], 16);
            v[8] += v[D];
            v[7] = this.circularRight(v[7] ^ v[8], 12);
            v[2] += v[7] + (m[o1] ^ BLAKESmallCore.CS[o0]);
            v[D] = this.circularRight(v[D] ^ v[2], 8);
            v[8] += v[D];
            v[7] = this.circularRight(v[7] ^ v[8], 7);
            o0 = BLAKESmallCore.SIGMA[(r << 4) + 0xE];
            o1 = BLAKESmallCore.SIGMA[(r << 4) + 0xF];
            v[3] += v[4] + (m[o0] ^ BLAKESmallCore.CS[o1]);
            v[E] = this.circularRight(v[E] ^ v[3], 16);
            v[9] += v[E];
            v[4] = this.circularRight(v[4] ^ v[9], 12);
            v[3] += v[4] + (m[o1] ^ BLAKESmallCore.CS[o0]);
            v[E] = this.circularRight(v[E] ^ v[3], 8);
            v[9] += v[E];
            v[4] = this.circularRight(v[4] ^ v[9], 7);
        }
        this.h[0] ^= this.s[0] ^ v[0] ^ v[8];
        this.h[1] ^= this.s[1] ^ v[1] ^ v[9];
        this.h[2] ^= this.s[2] ^ v[2] ^ v[A];
        this.h[3] ^= this.s[3] ^ v[3] ^ v[B];
        this.h[4] ^= this.s[0] ^ v[4] ^ v[C];
        this.h[5] ^= this.s[1] ^ v[5] ^ v[D];
        this.h[6] ^= this.s[2] ^ v[6] ^ v[E];
        this.h[7] ^= this.s[3] ^ v[7] ^ v[F];
    }
    /** @see Digest */
    toString() {
        return "BLAKE-" + (this.getDigestLength() << 3);
    }
}
BLAKESmallCore.SIGMA = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
    11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
    7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
    9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
    2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
    12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
    13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
    6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
    10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
    11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
    7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8
];
BLAKESmallCore.CS = new Int32Array([
    0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
    0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
    0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
    0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917
]);
;
/**
 * <p>This class implements the BLAKE-256 digest algorithm under the
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
 * @version   $Revision: 252 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
class Blake256 extends BLAKESmallCore {
    /**
     * Create the engine.
     */
    constructor() {
        super();
    }
    /** @see BLAKESmallCore */
    getInitVal() {
        return Blake256.initVal;
    }
    /** @see Digest */
    getDigestLength() {
        return 32;
    }
    /** @see Digest */
    copy() {
        return this.copyState(new Blake256());
    }
}
/** The initial value for BLAKE-256. */
Blake256.initVal = new Int32Array([
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
]);
/**
 * <p>This class implements the BLAKE-224 digest algorithm under the
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
 * @version   $Revision: 252 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
class Blake224 extends BLAKESmallCore {
    /**
     * Create the engine.
     */
    constructor() {
        super();
    }
    /** @see BLAKESmallCore */
    getInitVal() {
        return Blake224.initVal;
    }
    /** @see Digest */
    getDigestLength() {
        return 28;
    }
    /** @see Digest */
    copy() {
        return this.copyState(new Blake224());
    }
}
exports.Blake224 = Blake224;
/** The initial value for BLAKE-224. */
Blake224.initVal = new Int32Array([
    0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
    0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4
]);
;
/**
 * This class implements BLAKE-384 and BLAKE-512, which differ only by
 * the IV, output length, and one bit in the padding.
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
 * @version   $Revision: 252 $
 * @author    Thomas Pornin <thomas.pornin@cryptolog.com>
 */
class BLAKEBigCore extends DigestEngine {
    constructor() {
        super();
    }
    getBlockLength() {
        return 128;
    }
    copyState(dst) {
        dst.h = this.h;
        dst.s = this.s;
        dst.t = this.t;
        return super.copyState(dst);
    }
    engineReset() {
        const iv = this.getInitVal();
        for (let i = 0; i < this.h.length; i++) {
            this.h[i] = iv[i];
        }
        this.s = new BigInt64Array(4);
        this.t = new BigInt64Array(2);
    }
    doPadding(output, outputOffset) {
        var ptr = this.flush();
        var bitLen = ptr << 3;
        const h = 1;
        const l = 0;
        const t = new BigInt64Array(2);
        t[h] = this.t[1];
        t[l] = this.t[0] + BigInt(bitLen);
        this.tmpBuf[ptr] = 0x80;
        if (ptr == 0) {
            this.t[0] = BigInt(-1024);
            this.t[1] = BigInt(-1);
        }
        else if (this.t[0] == BigInt(0)) {
            this.t[0] = BigInt(-1024) + BigInt(bitLen);
            this.t[1]--;
        }
        else {
            this.t[0] -= BigInt(1024) - BigInt(bitLen);
        }
        if (ptr < 112) {
            for (let i = ptr + 1; i < 112; i++) {
                this.tmpBuf[i] = 0x00;
            }
            if (this.getDigestLength() == 64) {
                this.tmpBuf[111] |= 0x01;
            }
            this.encodeBELong(t[h], this.tmpBuf, 112);
            this.encodeBELong(t[l], this.tmpBuf, 120);
            this.update(this.tmpBuf, ptr, 128 - ptr);
        }
        else {
            for (let i = ptr + 1; i < 128; i++) {
                this.tmpBuf[i] = 0;
            }
            this.update(this.tmpBuf, ptr, 128 - ptr);
            this.t[0] = BigInt(-1024);
            this.t[1] = BigInt(-1);
            for (let i = 0; i < 112; i++) {
                this.tmpBuf[i] = 0x00;
            }
            if (this.getDigestLength() == 64) {
                this.tmpBuf[111] = 0x01;
            }
            this.encodeBELong(t[h], this.tmpBuf, 112);
            this.encodeBELong(t[l], this.tmpBuf, 120);
            this.update(this.tmpBuf, 0, 128);
        }
        this.encodeBELong(this.h[0], output, outputOffset + 0);
        this.encodeBELong(this.h[1], output, outputOffset + 8);
        this.encodeBELong(this.h[2], output, outputOffset + 16);
        this.encodeBELong(this.h[3], output, outputOffset + 24);
        this.encodeBELong(this.h[4], output, outputOffset + 32);
        this.encodeBELong(this.h[5], output, outputOffset + 40);
        if (this.getDigestLength() == 64) {
            this.encodeBELong(this.h[6], output, outputOffset + 48);
            this.encodeBELong(this.h[7], output, outputOffset + 56);
        }
    }
    doInit() {
        this.tmpM = new BigInt64Array(16);
        this.tmpBuf = new Uint8Array(128);
        this.h = new BigInt64Array(8);
        this.s = new BigInt64Array(4);
        this.t = new BigInt64Array(2);
        this.engineReset();
    }
    /**
     * Encode the 64-bit word {@code val} into the array
     * {@code buf} at offset {@code off}, in big-endian
     * convention (most significant byte first).
     *
     * @param val   the value to encode
     * @param buf   the destination buffer
     * @param off   the destination offset
     */
    encodeBELong(val, buf, off) {
        let endian = "big";
        let unsigned = false;
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
                }
                else {
                    buf[off + i * 4 + 0] = int32Array[i] & 0xFF;
                    buf[off + i * 4 + 1] = (int32Array[i] >> 8) & 0xFF;
                    buf[off + i * 4 + 2] = (int32Array[i] >> 16) & 0xFF;
                    buf[off + i * 4 + 3] = (int32Array[i] >> 24) & 0xFF;
                }
            }
            else {
                if (unsigned == undefined || unsigned == false) {
                    buf[off + (1 - i) * 4 + 3] = int32Array[i];
                    buf[off + (1 - i) * 4 + 2] = (int32Array[i] >> 8);
                    buf[off + (1 - i) * 4 + 1] = (int32Array[i] >> 16);
                    buf[off + (1 - i) * 4 + 0] = (int32Array[i] >> 24);
                }
                else {
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
    decodeBELong(buf, off) {
        let value = BigInt(0);
        let endian = "big";
        let unsigned = false;
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
     * Perform a circular rotation by {@code n} to the right
     * of the 64-bit word {@code x}. The {@code n} parameter
     * must lie between 1 and 63 (inclusive).
     *
     * @param x   the value to rotate
     * @param n   the rotation count (between 1 and 63)
     * @return  the rotated value
    */
    circularRight(x, n) {
        const s = BigInt(n & 63); // normalize rotation count to 0..63
        const ux = BigInt.asUintN(64, x); // treat x as unsigned 64-bit
        const rotated = BigInt.asUintN(64, (ux >> s) | (ux << (BigInt(64) - s))); // rotate unsigned
        const value = BigInt.asIntN(64, rotated); // return as signed 64-bit
        return value;
    }
    processBlock(data) {
        this.t[0] += BigInt(1024);
        if ((this.t[0] & BigInt(~0x3FF)) == BigInt(0)) {
            this.t[1]++;
        }
        const v = new BigInt64Array(16);
        const A = 10;
        const B = 11;
        const C = 12;
        const D = 13;
        const E = 14;
        const F = 15;
        v[0] = this.h[0];
        v[1] = this.h[1];
        v[2] = this.h[2];
        v[3] = this.h[3];
        v[4] = this.h[4];
        v[5] = this.h[5];
        v[6] = this.h[6];
        v[7] = this.h[7];
        v[8] = this.s[0] ^ BigInt("0x243F6A8885A308D3");
        v[9] = this.s[1] ^ BigInt("0x13198A2E03707344");
        v[A] = this.s[2] ^ BigInt("0xA4093822299F31D0");
        v[B] = this.s[3] ^ BigInt("0x082EFA98EC4E6C89");
        v[C] = this.t[0] ^ BigInt("0x452821E638D01377");
        v[D] = this.t[0] ^ BigInt("0xBE5466CF34E90C6C");
        v[E] = this.t[1] ^ BigInt("0xC0AC29B7C97C50DD");
        v[F] = this.t[1] ^ BigInt("0x3F84D5B5B5470917");
        const m = this.tmpM;
        for (let i = 0; i < 16; i++) {
            m[i] = this.decodeBELong(data, 8 * i);
        }
        for (let r = 0; r < 16; r++) {
            let o0 = BLAKEBigCore.SIGMA[(r << 4) + 0x0];
            let o1 = BLAKEBigCore.SIGMA[(r << 4) + 0x1];
            v[0] += v[4] + (m[o0] ^ BLAKEBigCore.CB[o1]);
            v[C] = this.circularRight(v[C] ^ v[0], 32);
            v[8] += v[C];
            v[4] = this.circularRight(v[4] ^ v[8], 25);
            v[0] += v[4] + (m[o1] ^ BLAKEBigCore.CB[o0]);
            v[C] = this.circularRight(v[C] ^ v[0], 16);
            v[8] += v[C];
            v[4] = this.circularRight(v[4] ^ v[8], 11);
            o0 = BLAKEBigCore.SIGMA[(r << 4) + 0x2];
            o1 = BLAKEBigCore.SIGMA[(r << 4) + 0x3];
            v[1] += v[5] + (m[o0] ^ BLAKEBigCore.CB[o1]);
            v[D] = this.circularRight(v[D] ^ v[1], 32);
            v[9] += v[D];
            v[5] = this.circularRight(v[5] ^ v[9], 25);
            v[1] += v[5] + (m[o1] ^ BLAKEBigCore.CB[o0]);
            v[D] = this.circularRight(v[D] ^ v[1], 16);
            v[9] += v[D];
            v[5] = this.circularRight(v[5] ^ v[9], 11);
            o0 = BLAKEBigCore.SIGMA[(r << 4) + 0x4];
            o1 = BLAKEBigCore.SIGMA[(r << 4) + 0x5];
            v[2] += v[6] + (m[o0] ^ BLAKEBigCore.CB[o1]);
            v[E] = this.circularRight(v[E] ^ v[2], 32);
            v[A] += v[E];
            v[6] = this.circularRight(v[6] ^ v[A], 25);
            v[2] += v[6] + (m[o1] ^ BLAKEBigCore.CB[o0]);
            v[E] = this.circularRight(v[E] ^ v[2], 16);
            v[A] += v[E];
            v[6] = this.circularRight(v[6] ^ v[A], 11);
            o0 = BLAKEBigCore.SIGMA[(r << 4) + 0x6];
            o1 = BLAKEBigCore.SIGMA[(r << 4) + 0x7];
            v[3] += v[7] + (m[o0] ^ BLAKEBigCore.CB[o1]);
            v[F] = this.circularRight(v[F] ^ v[3], 32);
            v[B] += v[F];
            v[7] = this.circularRight(v[7] ^ v[B], 25);
            v[3] += v[7] + (m[o1] ^ BLAKEBigCore.CB[o0]);
            v[F] = this.circularRight(v[F] ^ v[3], 16);
            v[B] += v[F];
            v[7] = this.circularRight(v[7] ^ v[B], 11);
            o0 = BLAKEBigCore.SIGMA[(r << 4) + 0x8];
            o1 = BLAKEBigCore.SIGMA[(r << 4) + 0x9];
            v[0] += v[5] + (m[o0] ^ BLAKEBigCore.CB[o1]);
            v[F] = this.circularRight(v[F] ^ v[0], 32);
            v[A] += v[F];
            v[5] = this.circularRight(v[5] ^ v[A], 25);
            v[0] += v[5] + (m[o1] ^ BLAKEBigCore.CB[o0]);
            v[F] = this.circularRight(v[F] ^ v[0], 16);
            v[A] += v[F];
            v[5] = this.circularRight(v[5] ^ v[A], 11);
            o0 = BLAKEBigCore.SIGMA[(r << 4) + 0xA];
            o1 = BLAKEBigCore.SIGMA[(r << 4) + 0xB];
            v[1] += v[6] + (m[o0] ^ BLAKEBigCore.CB[o1]);
            v[C] = this.circularRight(v[C] ^ v[1], 32);
            v[B] += v[C];
            v[6] = this.circularRight(v[6] ^ v[B], 25);
            v[1] += v[6] + (m[o1] ^ BLAKEBigCore.CB[o0]);
            v[C] = this.circularRight(v[C] ^ v[1], 16);
            v[B] += v[C];
            v[6] = this.circularRight(v[6] ^ v[B], 11);
            o0 = BLAKEBigCore.SIGMA[(r << 4) + 0xC];
            o1 = BLAKEBigCore.SIGMA[(r << 4) + 0xD];
            v[2] += v[7] + (m[o0] ^ BLAKEBigCore.CB[o1]);
            v[D] = this.circularRight(v[D] ^ v[2], 32);
            v[8] += v[D];
            v[7] = this.circularRight(v[7] ^ v[8], 25);
            v[2] += v[7] + (m[o1] ^ BLAKEBigCore.CB[o0]);
            v[D] = this.circularRight(v[D] ^ v[2], 16);
            v[8] += v[D];
            v[7] = this.circularRight(v[7] ^ v[8], 11);
            o0 = BLAKEBigCore.SIGMA[(r << 4) + 0xE];
            o1 = BLAKEBigCore.SIGMA[(r << 4) + 0xF];
            v[3] += v[4] + (m[o0] ^ BLAKEBigCore.CB[o1]);
            v[E] = this.circularRight(v[E] ^ v[3], 32);
            v[9] += v[E];
            v[4] = this.circularRight(v[4] ^ v[9], 25);
            v[3] += v[4] + (m[o1] ^ BLAKEBigCore.CB[o0]);
            v[E] = this.circularRight(v[E] ^ v[3], 16);
            v[9] += v[E];
            v[4] = this.circularRight(v[4] ^ v[9], 11);
        }
        this.h[0] ^= this.s[0] ^ v[0] ^ v[8];
        this.h[1] ^= this.s[1] ^ v[1] ^ v[9];
        this.h[2] ^= this.s[2] ^ v[2] ^ v[A];
        this.h[3] ^= this.s[3] ^ v[3] ^ v[B];
        this.h[4] ^= this.s[0] ^ v[4] ^ v[C];
        this.h[5] ^= this.s[1] ^ v[5] ^ v[D];
        this.h[6] ^= this.s[2] ^ v[6] ^ v[E];
        this.h[7] ^= this.s[3] ^ v[7] ^ v[F];
    }
    toString() {
        return `BLAKE-${this.getDigestLength() * 8}`;
    }
}
BLAKEBigCore.SIGMA = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
    11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
    7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
    9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
    2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
    12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
    13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
    6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
    10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
    11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
    7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
    9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
    2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9
];
BLAKEBigCore.CB = new BigInt64Array([
    BigInt("0x243F6A8885A308D3"), BigInt("0x13198A2E03707344"),
    BigInt("0xA4093822299F31D0"), BigInt("0x082EFA98EC4E6C89"),
    BigInt("0x452821E638D01377"), BigInt("0xBE5466CF34E90C6C"),
    BigInt("0xC0AC29B7C97C50DD"), BigInt("0x3F84D5B5B5470917"),
    BigInt("0x9216D5D98979FB1B"), BigInt("0xD1310BA698DFB5AC"),
    BigInt("0x2FFD72DBD01ADFB7"), BigInt("0xB8E1AFED6A267E96"),
    BigInt("0xBA7C9045F12C7F99"), BigInt("0x24A19947B3916CF7"),
    BigInt("0x0801F2E2858EFC16"), BigInt("0x636920D871574E69")
]);
;
/**
 * This class implements the BLAKE-512 digest algorithm under the
 * {@link Digest} API.
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
 * @version   $Revision: 252 $
 * @author    Thomas Pornin <thomas.pornin@cryptolog.com>
 */
class Blake512 extends BLAKEBigCore {
    constructor() {
        super();
    }
    getInitVal() {
        return Blake512.initVal;
    }
    getDigestLength() {
        return 64;
    }
    copy() {
        return this.copyState(new Blake512());
    }
}
Blake512.initVal = new BigInt64Array([
    BigInt("0x6A09E667F3BCC908"), BigInt("0xBB67AE8584CAA73B"),
    BigInt("0x3C6EF372FE94F82B"), BigInt("0xA54FF53A5F1D36F1"),
    BigInt("0x510E527FADE682D1"), BigInt("0x9B05688C2B3E6C1F"),
    BigInt("0x1F83D9ABFB41BD6B"), BigInt("0x5BE0CD19137E2179")
]);
;
/**
 * <p>This class implements the BLAKE-384 digest algorithm under the
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
 * @version   $Revision: 252 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
class Blake384 extends BLAKEBigCore {
    /**
     * Create the engine.
     */
    constructor() {
        super();
    }
    /** @see BLAKESmallCore */
    getInitVal() {
        return Blake384.initVal;
    }
    /** @see Digest */
    getDigestLength() {
        return 48;
    }
    /** @see Digest */
    copy() {
        return this.copyState(new Blake384());
    }
}
/** The initial value for BLAKE-384. */
Blake384.initVal = new BigInt64Array([
    BigInt("0xCBBB9D5DC1059ED8"), BigInt("0x629A292A367CD507"),
    BigInt("0x9159015A3070DD17"), BigInt("0x152FECD8F70E5939"),
    BigInt("0x67332667FFC00B31"), BigInt("0x8EB44A8768581511"),
    BigInt("0xDB0C2E0D64F98FA7"), BigInt("0x47B5481DBEFA4FA4")
]);
;
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
class Blake {
    constructor(bitLength) {
        switch (bitLength) {
            case 224:
                this.class = new Blake224();
                break;
            case 256:
                this.class = new Blake256();
                break;
            case 384:
                this.class = new Blake384();
                break;
            case 512:
                this.class = new Blake512();
                break;
            default:
                this.class = new Blake512();
                break;
        }
    }
    update(message) {
        message = formatMessage(message);
        this.class.update(message);
    }
    digest(format) {
        if (format == "hex") {
            return toHex(this.class.digest());
        }
        else if (format == "buffer") {
            return Buffer.from(this.class.digest());
        }
        return this.class.digest();
    }
}
exports.Blake = Blake;
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
 * Creates a vary byte length BLAKE of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {224 | 256 | 384 | 512} bitLen - length of hash (default 512 bits AKA 64 bytes)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function BLAKE(message, bitLen = 512, format = arrayType()) {
    const hash = new Blake(bitLen || 512);
    hash.update(message);
    return hash.digest(format);
}
exports.BLAKE = BLAKE;
;
/**
 * Creates a 28 byte BLAKE of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function BLAKE224(message, format = arrayType()) {
    const hash = new Blake(224);
    hash.update(message);
    return hash.digest(format);
}
exports.BLAKE224 = BLAKE224;
;
/**
 * Creates a 28 byte keyed BLAKE of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function BLAKE224_HMAC(message, key, format = arrayType()) {
    const hash = new Blake(224);
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    }
    else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
}
exports.BLAKE224_HMAC = BLAKE224_HMAC;
;
/**
 * Creates a 32 byte BLAKE of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function BLAKE256(message, format = arrayType()) {
    const hash = new Blake(256);
    hash.update(message);
    return hash.digest(format);
}
exports.BLAKE256 = BLAKE256;
;
/**
 * Creates a 32 byte keyed BLAKE of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function BLAKE256_HMAC(message, key, format = arrayType()) {
    const hash = new Blake(256);
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    }
    else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
}
exports.BLAKE256_HMAC = BLAKE256_HMAC;
;
/**
 * Creates a 48 byte BLAKE of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function BLAKE384(message, format = arrayType()) {
    const hash = new Blake(384);
    hash.update(message);
    return hash.digest(format);
}
exports.BLAKE384 = BLAKE384;
;
/**
 * Creates a 48 byte keyed BLAKE of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function BLAKE384_HMAC(message, key, format = arrayType()) {
    const hash = new Blake(384);
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    }
    else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
}
exports.BLAKE384_HMAC = BLAKE384_HMAC;
;
/**
 * Creates a 64 byte BLAKE of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function BLAKE512(message, format = arrayType()) {
    const hash = new Blake(512);
    hash.update(message);
    return hash.digest(format);
}
exports.BLAKE512 = BLAKE512;
;
/**
 * Creates a 64 byte keyed BLAKE of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function BLAKE512_HMAC(message, key, format = arrayType()) {
    const hash = new Blake(512);
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    }
    else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
}
exports.BLAKE512_HMAC = BLAKE512_HMAC;
;
/**
 * Creates a keyed BLAKE of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - key for hash
 * @param {224| 256 | 384 | 512} bitLen - length of hash (default 512 bits AKA 64 bytes)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function BLAKE_HMAC(message, key, bitLen = 512, format = arrayType()) {
    const hash = new Blake(bitLen || 512);
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    }
    else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
}
exports.BLAKE_HMAC = BLAKE_HMAC;
//# sourceMappingURL=BLAKE1.js.map