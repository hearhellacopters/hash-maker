"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SKEIN = exports.SKEIN512_HMAC = exports.SKEIN512 = exports.SKEIN384_HMAC = exports.SKEIN384 = exports.SKEIN256_HMAC = exports.SKEIN256 = exports.SKEIN224_HMAC = exports.SKEIN224 = exports.SKEIN_HMAC = exports._SKEIN = exports.Skein512 = exports.Skein384 = exports.Skein256 = exports.Skein224 = void 0;
function arrayType() {
    if (typeof window !== 'undefined') {
        return "array";
    }
    else {
        return "buffer";
    }
}
;
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
function lshr(x, n) {
    return (x >> BigInt(n)) & ((BigInt(1) << (BigInt(64) - BigInt(n))) - BigInt(1));
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
/**
 * This class implements the Skein core function when used with a
 * 256-bit internal state ("Skein-256" in the Skein specification
 * terminology). This class is not currently used, since the recommended
 * parameters for the SHA-3 competition call for a 512-bit internal
 * state ("Skein-512") for all output sizes (224, 256, 384 and 512
 * bits).
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
 * @version   $Revision: 253 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
class SkeinSmallCore {
    /**
     * Create the object.
     */
    constructor() {
        this.BLOCK_LEN = 32;
        this.h = new BigInt64Array(4);
        this.buf = new Uint8Array(this.BLOCK_LEN);
        this.tmpOut = new Uint8Array(this.BLOCK_LEN);
        this.reset();
    }
    /** @see Digest */
    update(inbuf, off, len) {
        if (typeof inbuf == "number") {
            if (this.ptr == this.BLOCK_LEN) {
                var etype = (this.bcount == BigInt(0)) ? 224 : 96;
                this.bcount++;
                this.ubi(etype, 0);
                this.buf[0] = inbuf;
                this.ptr = 1;
            }
            else {
                this.buf[this.ptr++] = inbuf;
            }
        }
        else if (off == undefined || len == undefined) {
            this.update(inbuf, 0, inbuf.length);
        }
        else {
            if (len <= 0) {
                return;
            }
            var clen = this.BLOCK_LEN - this.ptr;
            if (len <= clen) {
                arraycopy(inbuf, off, this.buf, this.ptr, len);
                this.ptr += len;
                return;
            }
            if (clen != 0) {
                arraycopy(inbuf, off, this.buf, this.ptr, clen);
                off += clen;
                len -= clen;
            }
            for (;;) {
                var etype = (this.bcount == BigInt(0)) ? 224 : 96;
                this.bcount++;
                this.ubi(etype, 0);
                if (len <= this.BLOCK_LEN) {
                    break;
                }
                arraycopy(inbuf, off, this.buf, 0, this.BLOCK_LEN);
                off += this.BLOCK_LEN;
                len -= this.BLOCK_LEN;
            }
            arraycopy(inbuf, off, this.buf, 0, len);
            this.ptr = len;
        }
    }
    digest(outbuf, off, len) {
        if (outbuf == undefined) {
            var len2 = this.getDigestLength();
            const out = new Uint8Array(len2);
            this.digest(out, 0, len2);
            return out;
        }
        else if (off == undefined || len == undefined) {
            this.update(outbuf, 0, outbuf.length);
            return this.digest();
        }
        else {
            for (let i = this.ptr; i < this.BLOCK_LEN; i++) {
                this.buf[i] = 0x00;
            }
            this.ubi((this.bcount == BigInt(0)) ? 480 : 352, this.ptr);
            for (let i = 0; i < this.BLOCK_LEN; i++) {
                this.buf[i] = 0x00;
            }
            this.bcount = BigInt(0);
            this.ubi(510, 8);
            this.encodeLELong(this.h[0], this.tmpOut, 0);
            this.encodeLELong(this.h[1], this.tmpOut, 8);
            this.encodeLELong(this.h[2], this.tmpOut, 16);
            this.encodeLELong(this.h[3], this.tmpOut, 24);
            var dlen = this.getDigestLength();
            if (len > dlen) {
                len = dlen;
            }
            arraycopy(this.tmpOut, 0, outbuf, off, len);
            this.reset();
            return len;
        }
    }
    /** @see Digest */
    reset() {
        this.ptr = 0;
        const iv = this.getInitVal();
        this.h[0] = iv[0];
        this.h[1] = iv[1];
        this.h[2] = iv[2];
        this.h[3] = iv[3];
        this.bcount = BigInt(0);
    }
    /** @see Digest */
    copy() {
        const dst = this.dup();
        arraycopy(this.buf, 0, dst.buf, 0, this.ptr);
        dst.ptr = this.ptr;
        dst.h[0] = this.h[0];
        dst.h[1] = this.h[1];
        dst.h[2] = this.h[2];
        dst.h[3] = this.h[3];
        dst.bcount = this.bcount;
        return dst;
    }
    /** @see Digest */
    getBlockLength() {
        return this.BLOCK_LEN;
    }
    encodeLELong(val, buf, off) {
        let endian = "little";
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
    decodeLELong(buf, off) {
        let value = BigInt(0);
        let endian = "little";
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
    ubi(etype, extra) {
        const m = new BigInt64Array(4);
        const p = new BigInt64Array(4);
        const t = new BigInt64Array(4);
        m[0] = this.decodeLELong(this.buf, 0);
        m[1] = this.decodeLELong(this.buf, 8);
        m[2] = this.decodeLELong(this.buf, 16);
        m[3] = this.decodeLELong(this.buf, 24);
        p[0] = m[0];
        p[1] = m[1];
        p[2] = m[2];
        p[3] = m[3];
        this.h[4] = (this.h[0] ^ this.h[1]) ^ (this.h[2] ^ this.h[3]) ^ BigInt("0x1BD11BDAA9FC1A22");
        t[0] = (this.bcount << BigInt(5)) + BigInt(extra);
        t[1] = (lshr(this.bcount, 59)) + (BigInt(etype) << BigInt(55));
        t[2] = t[0] ^ t[1];
        p[0] += this.h[0];
        p[1] += this.h[1] + t[0];
        p[2] += this.h[2] + t[1];
        p[3] += this.h[3] + BigInt(0);
        p[0] += p[1];
        p[1] = (p[1] << BigInt(14)) ^ (lshr(p[1], (64 - 14))) ^ p[0];
        p[2] += p[3];
        p[3] = (p[3] << BigInt(16)) ^ (lshr(p[3], (64 - 16))) ^ p[2];
        p[0] += p[3];
        p[3] = (p[3] << BigInt(52)) ^ (lshr(p[3], (64 - 52))) ^ p[0];
        p[2] += p[1];
        p[1] = (p[1] << BigInt(57)) ^ (lshr(p[1], (64 - 57))) ^ p[2];
        p[0] += p[1];
        p[1] = (p[1] << BigInt(23)) ^ (lshr(p[1], (64 - 23))) ^ p[0];
        p[2] += p[3];
        p[3] = (p[3] << BigInt(40)) ^ (lshr(p[3], (64 - 40))) ^ p[2];
        p[0] += p[3];
        p[3] = (p[3] << BigInt(5)) ^ (lshr(p[3], (64 - 5))) ^ p[0];
        p[2] += p[1];
        p[1] = (p[1] << BigInt(37)) ^ (lshr(p[1], (64 - 37))) ^ p[2];
        p[0] += this.h[1];
        p[1] += this.h[2] + t[1];
        p[2] += this.h[3] + t[2];
        p[3] += this.h[4] + BigInt(1);
        p[0] += p[1];
        p[1] = (p[1] << BigInt(25)) ^ (lshr(p[1], (64 - 25))) ^ p[0];
        p[2] += p[3];
        p[3] = (p[3] << BigInt(33)) ^ (lshr(p[3], (64 - 33))) ^ p[2];
        p[0] += p[3];
        p[3] = (p[3] << BigInt(46)) ^ (lshr(p[3], (64 - 46))) ^ p[0];
        p[2] += p[1];
        p[1] = (p[1] << BigInt(12)) ^ (lshr(p[1], (64 - 12))) ^ p[2];
        p[0] += p[1];
        p[1] = (p[1] << BigInt(58)) ^ (lshr(p[1], (64 - 58))) ^ p[0];
        p[2] += p[3];
        p[3] = (p[3] << BigInt(22)) ^ (lshr(p[3], (64 - 22))) ^ p[2];
        p[0] += p[3];
        p[3] = (p[3] << BigInt(32)) ^ (lshr(p[3], (64 - 32))) ^ p[0];
        p[2] += p[1];
        p[1] = (p[1] << BigInt(32)) ^ (lshr(p[1], (64 - 32))) ^ p[2];
        p[0] += this.h[2];
        p[1] += this.h[3] + t[2];
        p[2] += this.h[4] + t[0];
        p[3] += this.h[0] + BigInt(2);
        p[0] += p[1];
        p[1] = (p[1] << BigInt(14)) ^ (lshr(p[1], (64 - 14))) ^ p[0];
        p[2] += p[3];
        p[3] = (p[3] << BigInt(16)) ^ (lshr(p[3], (64 - 16))) ^ p[2];
        p[0] += p[3];
        p[3] = (p[3] << BigInt(52)) ^ (lshr(p[3], (64 - 52))) ^ p[0];
        p[2] += p[1];
        p[1] = (p[1] << BigInt(57)) ^ (lshr(p[1], (64 - 57))) ^ p[2];
        p[0] += p[1];
        p[1] = (p[1] << BigInt(23)) ^ (lshr(p[1], (64 - 23))) ^ p[0];
        p[2] += p[3];
        p[3] = (p[3] << BigInt(40)) ^ (lshr(p[3], (64 - 40))) ^ p[2];
        p[0] += p[3];
        p[3] = (p[3] << BigInt(5)) ^ (lshr(p[3], (64 - 5))) ^ p[0];
        p[2] += p[1];
        p[1] = (p[1] << BigInt(37)) ^ (lshr(p[1], (64 - 37))) ^ p[2];
        p[0] += this.h[3];
        p[1] += this.h[4] + t[0];
        p[2] += this.h[0] + t[1];
        p[3] += this.h[1] + BigInt(3);
        p[0] += p[1];
        p[1] = (p[1] << BigInt(25)) ^ (lshr(p[1], (64 - 25))) ^ p[0];
        p[2] += p[3];
        p[3] = (p[3] << BigInt(33)) ^ (lshr(p[3], (64 - 33))) ^ p[2];
        p[0] += p[3];
        p[3] = (p[3] << BigInt(46)) ^ (lshr(p[3], (64 - 46))) ^ p[0];
        p[2] += p[1];
        p[1] = (p[1] << BigInt(12)) ^ (lshr(p[1], (64 - 12))) ^ p[2];
        p[0] += p[1];
        p[1] = (p[1] << BigInt(58)) ^ (lshr(p[1], (64 - 58))) ^ p[0];
        p[2] += p[3];
        p[3] = (p[3] << BigInt(22)) ^ (lshr(p[3], (64 - 22))) ^ p[2];
        p[0] += p[3];
        p[3] = (p[3] << BigInt(32)) ^ (lshr(p[3], (64 - 32))) ^ p[0];
        p[2] += p[1];
        p[1] = (p[1] << BigInt(32)) ^ (lshr(p[1], (64 - 32))) ^ p[2];
        p[0] += this.h[4];
        p[1] += this.h[0] + t[1];
        p[2] += this.h[1] + t[2];
        p[3] += this.h[2] + BigInt(4);
        p[0] += p[1];
        p[1] = (p[1] << BigInt(14)) ^ (lshr(p[1], (64 - 14))) ^ p[0];
        p[2] += p[3];
        p[3] = (p[3] << BigInt(16)) ^ (lshr(p[3], (64 - 16))) ^ p[2];
        p[0] += p[3];
        p[3] = (p[3] << BigInt(52)) ^ (lshr(p[3], (64 - 52))) ^ p[0];
        p[2] += p[1];
        p[1] = (p[1] << BigInt(57)) ^ (lshr(p[1], (64 - 57))) ^ p[2];
        p[0] += p[1];
        p[1] = (p[1] << BigInt(23)) ^ (lshr(p[1], (64 - 23))) ^ p[0];
        p[2] += p[3];
        p[3] = (p[3] << BigInt(40)) ^ (lshr(p[3], (64 - 40))) ^ p[2];
        p[0] += p[3];
        p[3] = (p[3] << BigInt(5)) ^ (lshr(p[3], (64 - 5))) ^ p[0];
        p[2] += p[1];
        p[1] = (p[1] << BigInt(37)) ^ (lshr(p[1], (64 - 37))) ^ p[2];
        p[0] += this.h[0];
        p[1] += this.h[1] + t[2];
        p[2] += this.h[2] + t[0];
        p[3] += this.h[3] + BigInt(5);
        p[0] += p[1];
        p[1] = (p[1] << BigInt(25)) ^ (lshr(p[1], (64 - 25))) ^ p[0];
        p[2] += p[3];
        p[3] = (p[3] << BigInt(33)) ^ (lshr(p[3], (64 - 33))) ^ p[2];
        p[0] += p[3];
        p[3] = (p[3] << BigInt(46)) ^ (lshr(p[3], (64 - 46))) ^ p[0];
        p[2] += p[1];
        p[1] = (p[1] << BigInt(12)) ^ (lshr(p[1], (64 - 12))) ^ p[2];
        p[0] += p[1];
        p[1] = (p[1] << BigInt(58)) ^ (lshr(p[1], (64 - 58))) ^ p[0];
        p[2] += p[3];
        p[3] = (p[3] << BigInt(22)) ^ (lshr(p[3], (64 - 22))) ^ p[2];
        p[0] += p[3];
        p[3] = (p[3] << BigInt(32)) ^ (lshr(p[3], (64 - 32))) ^ p[0];
        p[2] += p[1];
        p[1] = (p[1] << BigInt(32)) ^ (lshr(p[1], (64 - 32))) ^ p[2];
        p[0] += this.h[1];
        p[1] += this.h[2] + t[0];
        p[2] += this.h[3] + t[1];
        p[3] += this.h[4] + BigInt(6);
        p[0] += p[1];
        p[1] = (p[1] << BigInt(14)) ^ (lshr(p[1], (64 - 14))) ^ p[0];
        p[2] += p[3];
        p[3] = (p[3] << BigInt(16)) ^ (lshr(p[3], (64 - 16))) ^ p[2];
        p[0] += p[3];
        p[3] = (p[3] << BigInt(52)) ^ (lshr(p[3], (64 - 52))) ^ p[0];
        p[2] += p[1];
        p[1] = (p[1] << BigInt(57)) ^ (lshr(p[1], (64 - 57))) ^ p[2];
        p[0] += p[1];
        p[1] = (p[1] << BigInt(23)) ^ (lshr(p[1], (64 - 23))) ^ p[0];
        p[2] += p[3];
        p[3] = (p[3] << BigInt(40)) ^ (lshr(p[3], (64 - 40))) ^ p[2];
        p[0] += p[3];
        p[3] = (p[3] << BigInt(5)) ^ (lshr(p[3], (64 - 5))) ^ p[0];
        p[2] += p[1];
        p[1] = (p[1] << BigInt(37)) ^ (lshr(p[1], (64 - 37))) ^ p[2];
        p[0] += this.h[2];
        p[1] += this.h[3] + t[1];
        p[2] += this.h[4] + t[2];
        p[3] += this.h[0] + BigInt(7);
        p[0] += p[1];
        p[1] = (p[1] << BigInt(25)) ^ (lshr(p[1], (64 - 25))) ^ p[0];
        p[2] += p[3];
        p[3] = (p[3] << BigInt(33)) ^ (lshr(p[3], (64 - 33))) ^ p[2];
        p[0] += p[3];
        p[3] = (p[3] << BigInt(46)) ^ (lshr(p[3], (64 - 46))) ^ p[0];
        p[2] += p[1];
        p[1] = (p[1] << BigInt(12)) ^ (lshr(p[1], (64 - 12))) ^ p[2];
        p[0] += p[1];
        p[1] = (p[1] << BigInt(58)) ^ (lshr(p[1], (64 - 58))) ^ p[0];
        p[2] += p[3];
        p[3] = (p[3] << BigInt(22)) ^ (lshr(p[3], (64 - 22))) ^ p[2];
        p[0] += p[3];
        p[3] = (p[3] << BigInt(32)) ^ (lshr(p[3], (64 - 32))) ^ p[0];
        p[2] += p[1];
        p[1] = (p[1] << BigInt(32)) ^ (lshr(p[1], (64 - 32))) ^ p[2];
        p[0] += this.h[3];
        p[1] += this.h[4] + t[2];
        p[2] += this.h[0] + t[0];
        p[3] += this.h[1] + BigInt(8);
        p[0] += p[1];
        p[1] = (p[1] << BigInt(14)) ^ (lshr(p[1], (64 - 14))) ^ p[0];
        p[2] += p[3];
        p[3] = (p[3] << BigInt(16)) ^ (lshr(p[3], (64 - 16))) ^ p[2];
        p[0] += p[3];
        p[3] = (p[3] << BigInt(52)) ^ (lshr(p[3], (64 - 52))) ^ p[0];
        p[2] += p[1];
        p[1] = (p[1] << BigInt(57)) ^ (lshr(p[1], (64 - 57))) ^ p[2];
        p[0] += p[1];
        p[1] = (p[1] << BigInt(23)) ^ (lshr(p[1], (64 - 23))) ^ p[0];
        p[2] += p[3];
        p[3] = (p[3] << BigInt(40)) ^ (lshr(p[3], (64 - 40))) ^ p[2];
        p[0] += p[3];
        p[3] = (p[3] << BigInt(5)) ^ (lshr(p[3], (64 - 5))) ^ p[0];
        p[2] += p[1];
        p[1] = (p[1] << BigInt(37)) ^ (lshr(p[1], (64 - 37))) ^ p[2];
        p[0] += this.h[4];
        p[1] += this.h[0] + t[0];
        p[2] += this.h[1] + t[1];
        p[3] += this.h[2] + BigInt(9);
        p[0] += p[1];
        p[1] = (p[1] << BigInt(25)) ^ (lshr(p[1], (64 - 25))) ^ p[0];
        p[2] += p[3];
        p[3] = (p[3] << BigInt(33)) ^ (lshr(p[3], (64 - 33))) ^ p[2];
        p[0] += p[3];
        p[3] = (p[3] << BigInt(46)) ^ (lshr(p[3], (64 - 46))) ^ p[0];
        p[2] += p[1];
        p[1] = (p[1] << BigInt(12)) ^ (lshr(p[1], (64 - 12))) ^ p[2];
        p[0] += p[1];
        p[1] = (p[1] << BigInt(58)) ^ (lshr(p[1], (64 - 58))) ^ p[0];
        p[2] += p[3];
        p[3] = (p[3] << BigInt(22)) ^ (lshr(p[3], (64 - 22))) ^ p[2];
        p[0] += p[3];
        p[3] = (p[3] << BigInt(32)) ^ (lshr(p[3], (64 - 32))) ^ p[0];
        p[2] += p[1];
        p[1] = (p[1] << BigInt(32)) ^ (lshr(p[1], (64 - 32))) ^ p[2];
        p[0] += this.h[0];
        p[1] += this.h[1] + t[1];
        p[2] += this.h[2] + t[2];
        p[3] += this.h[3] + BigInt(10);
        p[0] += p[1];
        p[1] = (p[1] << BigInt(14)) ^ (lshr(p[1], (64 - 14))) ^ p[0];
        p[2] += p[3];
        p[3] = (p[3] << BigInt(16)) ^ (lshr(p[3], (64 - 16))) ^ p[2];
        p[0] += p[3];
        p[3] = (p[3] << BigInt(52)) ^ (lshr(p[3], (64 - 52))) ^ p[0];
        p[2] += p[1];
        p[1] = (p[1] << BigInt(57)) ^ (lshr(p[1], (64 - 57))) ^ p[2];
        p[0] += p[1];
        p[1] = (p[1] << BigInt(23)) ^ (lshr(p[1], (64 - 23))) ^ p[0];
        p[2] += p[3];
        p[3] = (p[3] << BigInt(40)) ^ (lshr(p[3], (64 - 40))) ^ p[2];
        p[0] += p[3];
        p[3] = (p[3] << BigInt(5)) ^ (lshr(p[3], (64 - 5))) ^ p[0];
        p[2] += p[1];
        p[1] = (p[1] << BigInt(37)) ^ (lshr(p[1], (64 - 37))) ^ p[2];
        p[0] += this.h[1];
        p[1] += this.h[2] + t[2];
        p[2] += this.h[3] + t[0];
        p[3] += this.h[4] + BigInt(11);
        p[0] += p[1];
        p[1] = (p[1] << BigInt(25)) ^ (lshr(p[1], (64 - 25))) ^ p[0];
        p[2] += p[3];
        p[3] = (p[3] << BigInt(33)) ^ (lshr(p[3], (64 - 33))) ^ p[2];
        p[0] += p[3];
        p[3] = (p[3] << BigInt(46)) ^ (lshr(p[3], (64 - 46))) ^ p[0];
        p[2] += p[1];
        p[1] = (p[1] << BigInt(12)) ^ (lshr(p[1], (64 - 12))) ^ p[2];
        p[0] += p[1];
        p[1] = (p[1] << BigInt(58)) ^ (lshr(p[1], (64 - 58))) ^ p[0];
        p[2] += p[3];
        p[3] = (p[3] << BigInt(22)) ^ (lshr(p[3], (64 - 22))) ^ p[2];
        p[0] += p[3];
        p[3] = (p[3] << BigInt(32)) ^ (lshr(p[3], (64 - 32))) ^ p[0];
        p[2] += p[1];
        p[1] = (p[1] << BigInt(32)) ^ (lshr(p[1], (64 - 32))) ^ p[2];
        p[0] += this.h[2];
        p[1] += this.h[3] + t[0];
        p[2] += this.h[4] + t[1];
        p[3] += this.h[0] + BigInt(12);
        p[0] += p[1];
        p[1] = (p[1] << BigInt(14)) ^ (lshr(p[1], (64 - 14))) ^ p[0];
        p[2] += p[3];
        p[3] = (p[3] << BigInt(16)) ^ (lshr(p[3], (64 - 16))) ^ p[2];
        p[0] += p[3];
        p[3] = (p[3] << BigInt(52)) ^ (lshr(p[3], (64 - 52))) ^ p[0];
        p[2] += p[1];
        p[1] = (p[1] << BigInt(57)) ^ (lshr(p[1], (64 - 57))) ^ p[2];
        p[0] += p[1];
        p[1] = (p[1] << BigInt(23)) ^ (lshr(p[1], (64 - 23))) ^ p[0];
        p[2] += p[3];
        p[3] = (p[3] << BigInt(40)) ^ (lshr(p[3], (64 - 40))) ^ p[2];
        p[0] += p[3];
        p[3] = (p[3] << BigInt(5)) ^ (lshr(p[3], (64 - 5))) ^ p[0];
        p[2] += p[1];
        p[1] = (p[1] << BigInt(37)) ^ (lshr(p[1], (64 - 37))) ^ p[2];
        p[0] += this.h[3];
        p[1] += this.h[4] + t[1];
        p[2] += this.h[0] + t[2];
        p[3] += this.h[1] + BigInt(13);
        p[0] += p[1];
        p[1] = (p[1] << BigInt(25)) ^ (lshr(p[1], (64 - 25))) ^ p[0];
        p[2] += p[3];
        p[3] = (p[3] << BigInt(33)) ^ (lshr(p[3], (64 - 33))) ^ p[2];
        p[0] += p[3];
        p[3] = (p[3] << BigInt(46)) ^ (lshr(p[3], (64 - 46))) ^ p[0];
        p[2] += p[1];
        p[1] = (p[1] << BigInt(12)) ^ (lshr(p[1], (64 - 12))) ^ p[2];
        p[0] += p[1];
        p[1] = (p[1] << BigInt(58)) ^ (lshr(p[1], (64 - 58))) ^ p[0];
        p[2] += p[3];
        p[3] = (p[3] << BigInt(22)) ^ (lshr(p[3], (64 - 22))) ^ p[2];
        p[0] += p[3];
        p[3] = (p[3] << BigInt(32)) ^ (lshr(p[3], (64 - 32))) ^ p[0];
        p[2] += p[1];
        p[1] = (p[1] << BigInt(32)) ^ (lshr(p[1], (64 - 32))) ^ p[2];
        p[0] += this.h[4];
        p[1] += this.h[0] + t[2];
        p[2] += this.h[1] + t[0];
        p[3] += this.h[2] + BigInt(14);
        p[0] += p[1];
        p[1] = (p[1] << BigInt(14)) ^ (lshr(p[1], (64 - 14))) ^ p[0];
        p[2] += p[3];
        p[3] = (p[3] << BigInt(16)) ^ (lshr(p[3], (64 - 16))) ^ p[2];
        p[0] += p[3];
        p[3] = (p[3] << BigInt(52)) ^ (lshr(p[3], (64 - 52))) ^ p[0];
        p[2] += p[1];
        p[1] = (p[1] << BigInt(57)) ^ (lshr(p[1], (64 - 57))) ^ p[2];
        p[0] += p[1];
        p[1] = (p[1] << BigInt(23)) ^ (lshr(p[1], (64 - 23))) ^ p[0];
        p[2] += p[3];
        p[3] = (p[3] << BigInt(40)) ^ (lshr(p[3], (64 - 40))) ^ p[2];
        p[0] += p[3];
        p[3] = (p[3] << BigInt(5)) ^ (lshr(p[3], (64 - 5))) ^ p[0];
        p[2] += p[1];
        p[1] = (p[1] << BigInt(37)) ^ (lshr(p[1], (64 - 37))) ^ p[2];
        p[0] += this.h[0];
        p[1] += this.h[1] + t[0];
        p[2] += this.h[2] + t[1];
        p[3] += this.h[3] + BigInt(15);
        p[0] += p[1];
        p[1] = (p[1] << BigInt(25)) ^ (lshr(p[1], (64 - 25))) ^ p[0];
        p[2] += p[3];
        p[3] = (p[3] << BigInt(33)) ^ (lshr(p[3], (64 - 33))) ^ p[2];
        p[0] += p[3];
        p[3] = (p[3] << BigInt(46)) ^ (lshr(p[3], (64 - 46))) ^ p[0];
        p[2] += p[1];
        p[1] = (p[1] << BigInt(12)) ^ (lshr(p[1], (64 - 12))) ^ p[2];
        p[0] += p[1];
        p[1] = (p[1] << BigInt(58)) ^ (lshr(p[1], (64 - 58))) ^ p[0];
        p[2] += p[3];
        p[3] = (p[3] << BigInt(22)) ^ (lshr(p[3], (64 - 22))) ^ p[2];
        p[0] += p[3];
        p[3] = (p[3] << BigInt(32)) ^ (lshr(p[3], (64 - 32))) ^ p[0];
        p[2] += p[1];
        p[1] = (p[1] << BigInt(32)) ^ (lshr(p[1], (64 - 32))) ^ p[2];
        p[0] += this.h[1];
        p[1] += this.h[2] + t[1];
        p[2] += this.h[3] + t[2];
        p[3] += this.h[4] + BigInt(16);
        p[0] += p[1];
        p[1] = (p[1] << BigInt(14)) ^ (lshr(p[1], (64 - 14))) ^ p[0];
        p[2] += p[3];
        p[3] = (p[3] << BigInt(16)) ^ (lshr(p[3], (64 - 16))) ^ p[2];
        p[0] += p[3];
        p[3] = (p[3] << BigInt(52)) ^ (lshr(p[3], (64 - 52))) ^ p[0];
        p[2] += p[1];
        p[1] = (p[1] << BigInt(57)) ^ (lshr(p[1], (64 - 57))) ^ p[2];
        p[0] += p[1];
        p[1] = (p[1] << BigInt(23)) ^ (lshr(p[1], (64 - 23))) ^ p[0];
        p[2] += p[3];
        p[3] = (p[3] << BigInt(40)) ^ (lshr(p[3], (64 - 40))) ^ p[2];
        p[0] += p[3];
        p[3] = (p[3] << BigInt(5)) ^ (lshr(p[3], (64 - 5))) ^ p[0];
        p[2] += p[1];
        p[1] = (p[1] << BigInt(37)) ^ (lshr(p[1], (64 - 37))) ^ p[2];
        p[0] += this.h[2];
        p[1] += this.h[3] + t[2];
        p[2] += this.h[4] + t[0];
        p[3] += this.h[0] + BigInt(17);
        p[0] += p[1];
        p[1] = (p[1] << BigInt(25)) ^ (lshr(p[1], (64 - 25))) ^ p[0];
        p[2] += p[3];
        p[3] = (p[3] << BigInt(33)) ^ (lshr(p[3], (64 - 33))) ^ p[2];
        p[0] += p[3];
        p[3] = (p[3] << BigInt(46)) ^ (lshr(p[3], (64 - 46))) ^ p[0];
        p[2] += p[1];
        p[1] = (p[1] << BigInt(12)) ^ (lshr(p[1], (64 - 12))) ^ p[2];
        p[0] += p[1];
        p[1] = (p[1] << BigInt(58)) ^ (lshr(p[1], (64 - 58))) ^ p[0];
        p[2] += p[3];
        p[3] = (p[3] << BigInt(22)) ^ (lshr(p[3], (64 - 22))) ^ p[2];
        p[0] += p[3];
        p[3] = (p[3] << BigInt(32)) ^ (lshr(p[3], (64 - 32))) ^ p[0];
        p[2] += p[1];
        p[1] = (p[1] << BigInt(32)) ^ (lshr(p[1], (64 - 32))) ^ p[2];
        p[0] += this.h[3];
        p[1] += this.h[4] + t[0];
        p[2] += this.h[0] + t[1];
        p[3] += this.h[1] + BigInt(18);
        this.h[0] = m[0] ^ p[0];
        this.h[1] = m[1] ^ p[1];
        this.h[2] = m[2] ^ p[2];
        this.h[3] = m[3] ^ p[3];
    }
    /** @see Digest */
    toString() {
        return "Skein-" + (this.getDigestLength() << 3);
    }
}
/**
 * This class implements the Skein core with a 512-bit internal state
 * ("Skein-512" in the Skein specification terminology). This is used
 * for Skein-224, Skein-256, Skein-384 and Skein-512 (the SHA-3
 * candidates).
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
 * @version   $Revision: 253 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
class SkeinBigCore {
    /**
     * Create the object.
     */
    constructor() {
        this.BLOCK_LEN = 64;
        this.h = new BigInt64Array(27);
        this.buf = new Uint8Array(this.BLOCK_LEN);
        this.tmpOut = new Uint8Array(this.BLOCK_LEN);
        this.h = new BigInt64Array(27);
        this.reset();
    }
    /** @see Digest */
    update(inbuf, off, len) {
        if (typeof inbuf == "number") {
            if (this.ptr == this.BLOCK_LEN) {
                var etype = (this.bcount == BigInt(0)) ? 224 : 96;
                this.bcount++;
                this.ubi(etype, 0);
                this.buf[0] = inbuf;
                this.ptr = 1;
            }
            else {
                this.buf[this.ptr++] = inbuf;
            }
        }
        else if (off == undefined || len == undefined) {
            this.update(inbuf, 0, inbuf.length);
        }
        else {
            if (len <= 0) {
                return;
            }
            var clen = this.BLOCK_LEN - this.ptr;
            if (len <= clen) {
                arraycopy(inbuf, off, this.buf, this.ptr, len);
                this.ptr += len;
                return;
            }
            if (clen != 0) {
                arraycopy(inbuf, off, this.buf, this.ptr, clen);
                off += clen;
                len -= clen;
            }
            for (;;) {
                var etype = (this.bcount == BigInt(0)) ? 224 : 96;
                this.bcount++;
                this.ubi(etype, 0);
                if (len <= this.BLOCK_LEN) {
                    break;
                }
                arraycopy(inbuf, off, this.buf, 0, this.BLOCK_LEN);
                off += this.BLOCK_LEN;
                len -= this.BLOCK_LEN;
            }
            arraycopy(inbuf, off, this.buf, 0, len);
            this.ptr = len;
        }
    }
    digest(outbuf, off, len) {
        if (outbuf == undefined) {
            var len2 = this.getDigestLength();
            const out = new Uint8Array(len2);
            this.digest(out, 0, len2);
            return out;
        }
        else if (off == undefined || len == undefined) {
            this.update(outbuf, 0, outbuf.length);
            return this.digest();
        }
        else {
            for (let i = this.ptr; i < this.BLOCK_LEN; i++) {
                this.buf[i] = 0x00;
            }
            this.ubi((this.bcount == BigInt(0)) ? 480 : 352, this.ptr);
            for (let i = 0; i < this.BLOCK_LEN; i++) {
                this.buf[i] = 0x00;
            }
            this.bcount = BigInt(0);
            this.ubi(510, 8);
            for (let i = 0; i < 8; i++) {
                this.encodeLELong(this.h[i], this.tmpOut, i << 3);
            }
            var dlen = this.getDigestLength();
            if (len > dlen)
                len = dlen;
            arraycopy(this.tmpOut, 0, outbuf, off, len);
            this.reset();
            return len;
        }
    }
    /** @see Digest */
    reset() {
        this.ptr = 0;
        const iv = this.getInitVal();
        arraycopy(iv, 0, this.h, 0, 8);
        this.bcount = BigInt(0);
    }
    /** @see Digest */
    copy() {
        const dst = this.dup();
        arraycopy(this.buf, 0, dst.buf, 0, this.ptr);
        dst.ptr = this.ptr;
        arraycopy(this.h, 0, dst.h, 0, 8);
        dst.bcount = this.bcount;
        return dst;
    }
    /** @see Digest */
    getBlockLength() {
        return this.BLOCK_LEN;
    }
    encodeLELong(val, buf, off) {
        let endian = "little";
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
    decodeLELong(buf, off) {
        let value = BigInt(0);
        let endian = "little";
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
    ubi(etype, extra) {
        const m = new BigInt64Array(8);
        const p = new BigInt64Array(8);
        const t = new BigInt64Array(4);
        m[0] = this.decodeLELong(this.buf, 0);
        m[1] = this.decodeLELong(this.buf, 8);
        m[2] = this.decodeLELong(this.buf, 16);
        m[3] = this.decodeLELong(this.buf, 24);
        m[4] = this.decodeLELong(this.buf, 32);
        m[5] = this.decodeLELong(this.buf, 40);
        m[6] = this.decodeLELong(this.buf, 48);
        m[7] = this.decodeLELong(this.buf, 56);
        p[0] = m[0];
        p[1] = m[1];
        p[2] = m[2];
        p[3] = m[3];
        p[4] = m[4];
        p[5] = m[5];
        p[6] = m[6];
        p[7] = m[7];
        this.h[8] = ((this.h[0] ^ this.h[1]) ^ (this.h[2] ^ this.h[3]))
            ^ ((this.h[4] ^ this.h[5]) ^ (this.h[6] ^ this.h[7])) ^ BigInt("0x1BD11BDAA9FC1A22");
        t[0] = (this.bcount << BigInt(6)) + BigInt(extra);
        t[1] = (lshr(this.bcount, 58)) + (BigInt(etype) << BigInt(55));
        t[2] = t[0] ^ t[1];
        for (let u = 0; u <= 15; u += 3) {
            this.h[u + 9] = this.h[u + 0];
            this.h[u + 10] = this.h[u + 1];
            this.h[u + 11] = this.h[u + 2];
        }
        for (let u = 0; u < 9; u++) {
            var s = u << 1;
            p[0] += this.h[s + 0];
            p[1] += this.h[s + 1];
            p[2] += this.h[s + 2];
            p[3] += this.h[s + 3];
            p[4] += this.h[s + 4];
            p[5] += this.h[s + 5] + t[0];
            p[6] += this.h[s + 6] + t[1];
            p[7] += this.h[s + 7] + BigInt(s);
            p[0] += p[1];
            p[1] = (p[1] << BigInt(46)) ^ (lshr(p[1], (64 - 46))) ^ p[0];
            p[2] += p[3];
            p[3] = (p[3] << BigInt(36)) ^ (lshr(p[3], (64 - 36))) ^ p[2];
            p[4] += p[5];
            p[5] = (p[5] << BigInt(19)) ^ (lshr(p[5], (64 - 19))) ^ p[4];
            p[6] += p[7];
            p[7] = (p[7] << BigInt(37)) ^ (lshr(p[7], (64 - 37))) ^ p[6];
            p[2] += p[1];
            p[1] = (p[1] << BigInt(33)) ^ (lshr(p[1], (64 - 33))) ^ p[2];
            p[4] += p[7];
            p[7] = (p[7] << BigInt(27)) ^ (lshr(p[7], (64 - 27))) ^ p[4];
            p[6] += p[5];
            p[5] = (p[5] << BigInt(14)) ^ (lshr(p[5], (64 - 14))) ^ p[6];
            p[0] += p[3];
            p[3] = (p[3] << BigInt(42)) ^ (lshr(p[3], (64 - 42))) ^ p[0];
            p[4] += p[1];
            p[1] = (p[1] << BigInt(17)) ^ (lshr(p[1], (64 - 17))) ^ p[4];
            p[6] += p[3];
            p[3] = (p[3] << BigInt(49)) ^ (lshr(p[3], (64 - 49))) ^ p[6];
            p[0] += p[5];
            p[5] = (p[5] << BigInt(36)) ^ (lshr(p[5], (64 - 36))) ^ p[0];
            p[2] += p[7];
            p[7] = (p[7] << BigInt(39)) ^ (lshr(p[7], (64 - 39))) ^ p[2];
            p[6] += p[1];
            p[1] = (p[1] << BigInt(44)) ^ (lshr(p[1], (64 - 44))) ^ p[6];
            p[0] += p[7];
            p[7] = (p[7] << BigInt(9)) ^ (lshr(p[7], (64 - 9))) ^ p[0];
            p[2] += p[5];
            p[5] = (p[5] << BigInt(54)) ^ (lshr(p[5], (64 - 54))) ^ p[2];
            p[4] += p[3];
            p[3] = (p[3] << BigInt(56)) ^ (lshr(p[3], (64 - 56))) ^ p[4];
            p[0] += this.h[s + 1 + 0];
            p[1] += this.h[s + 1 + 1];
            p[2] += this.h[s + 1 + 2];
            p[3] += this.h[s + 1 + 3];
            p[4] += this.h[s + 1 + 4];
            p[5] += this.h[s + 1 + 5] + t[1];
            p[6] += this.h[s + 1 + 6] + t[2];
            p[7] += this.h[s + 1 + 7] + BigInt(s) + BigInt(1);
            p[0] += p[1];
            p[1] = (p[1] << BigInt(39)) ^ (lshr(p[1], (64 - 39))) ^ p[0];
            p[2] += p[3];
            p[3] = (p[3] << BigInt(30)) ^ (lshr(p[3], (64 - 30))) ^ p[2];
            p[4] += p[5];
            p[5] = (p[5] << BigInt(34)) ^ (lshr(p[5], (64 - 34))) ^ p[4];
            p[6] += p[7];
            p[7] = (p[7] << BigInt(24)) ^ (lshr(p[7], (64 - 24))) ^ p[6];
            p[2] += p[1];
            p[1] = (p[1] << BigInt(13)) ^ (lshr(p[1], (64 - 13))) ^ p[2];
            p[4] += p[7];
            p[7] = (p[7] << BigInt(50)) ^ (lshr(p[7], (64 - 50))) ^ p[4];
            p[6] += p[5];
            p[5] = (p[5] << BigInt(10)) ^ (lshr(p[5], (64 - 10))) ^ p[6];
            p[0] += p[3];
            p[3] = (p[3] << BigInt(17)) ^ (lshr(p[3], (64 - 17))) ^ p[0];
            p[4] += p[1];
            p[1] = (p[1] << BigInt(25)) ^ (lshr(p[1], (64 - 25))) ^ p[4];
            p[6] += p[3];
            p[3] = (p[3] << BigInt(29)) ^ (lshr(p[3], (64 - 29))) ^ p[6];
            p[0] += p[5];
            p[5] = (p[5] << BigInt(39)) ^ (lshr(p[5], (64 - 39))) ^ p[0];
            p[2] += p[7];
            p[7] = (p[7] << BigInt(43)) ^ (lshr(p[7], (64 - 43))) ^ p[2];
            p[6] += p[1];
            p[1] = (p[1] << BigInt(8)) ^ (lshr(p[1], (64 - 8))) ^ p[6];
            p[0] += p[7];
            p[7] = (p[7] << BigInt(35)) ^ (lshr(p[7], (64 - 35))) ^ p[0];
            p[2] += p[5];
            p[5] = (p[5] << BigInt(56)) ^ (lshr(p[5], (64 - 56))) ^ p[2];
            p[4] += p[3];
            p[3] = (p[3] << BigInt(22)) ^ (lshr(p[3], (64 - 22))) ^ p[4];
            var tmp = t[2];
            t[2] = t[1];
            t[1] = t[0];
            t[0] = tmp;
        }
        p[0] += this.h[18 + 0];
        p[1] += this.h[18 + 1];
        p[2] += this.h[18 + 2];
        p[3] += this.h[18 + 3];
        p[4] += this.h[18 + 4];
        p[5] += this.h[18 + 5] + t[0];
        p[6] += this.h[18 + 6] + t[1];
        p[7] += this.h[18 + 7] + BigInt(18);
        this.h[0] = m[0] ^ p[0];
        this.h[1] = m[1] ^ p[1];
        this.h[2] = m[2] ^ p[2];
        this.h[3] = m[3] ^ p[3];
        this.h[4] = m[4] ^ p[4];
        this.h[5] = m[5] ^ p[5];
        this.h[6] = m[6] ^ p[6];
        this.h[7] = m[7] ^ p[7];
    }
    /** @see Digest */
    toString() {
        return "Skein-" + (this.getDigestLength() << 3);
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
 * <p>This class implements the Skein-224 digest algorithm under the
 * {@link Digest} API. In the Skein specification, that function is
 * called under the full name "Skein-512-224".</p>
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
 * @version   $Revision: 253 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
class Skein224 extends SkeinBigCore {
    /**
     * Create the engine.
     */
    constructor() {
        super();
    }
    /** @see SkeinBigCore */
    getInitVal() {
        return Skein224.initVal;
    }
    /** @see Digest */
    getDigestLength() {
        return 28;
    }
    /** @see SkeinBigCore */
    dup() {
        return new Skein224();
    }
}
exports.Skein224 = Skein224;
/** The initial value for Skein-224. */
Skein224.initVal = new BigInt64Array([
    BigInt("0xCCD0616248677224"), BigInt("0xCBA65CF3A92339EF"),
    BigInt("0x8CCD69D652FF4B64"), BigInt("0x398AED7B3AB890B4"),
    BigInt("0x0F59D1B1457D2BD0"), BigInt("0x6776FE6575D4EB3D"),
    BigInt("0x99FBC70E997413E9"), BigInt("0x9E2CFCCFE1C41EF7")
]);
/**
 * <p>This class implements the Skein-256 digest algorithm under the
 * {@link Digest} API. In the Skein specification, that function is
 * called under the full name "Skein-512-256".</p>
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
 * @version   $Revision: 253 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
class Skein256 extends SkeinBigCore {
    /**
     * Create the engine.
     */
    constructor() {
        super();
    }
    /** @see SkeinBigCore */
    getInitVal() {
        return Skein256.initVal;
    }
    /** @see Digest */
    getDigestLength() {
        return 32;
    }
    /** @see SkeinBigCore */
    dup() {
        return new Skein256();
    }
}
exports.Skein256 = Skein256;
/** The initial value for Skein-256. */
Skein256.initVal = new BigInt64Array([
    BigInt("0xCCD044A12FDB3E13"), BigInt("0xE83590301A79A9EB"),
    BigInt("0x55AEA0614F816E6F"), BigInt("0x2A2767A4AE9B94DB"),
    BigInt("0xEC06025E74DD7683"), BigInt("0xE7A436CDC4746251"),
    BigInt("0xC36FBAF9393AD185"), BigInt("0x3EEDBA1833EDFC13")
]);
/**
 * <p>This class implements the Skein-384 digest algorithm under the
 * {@link Digest} API. In the Skein specification, that function is
 * called under the full name "Skein-512-384".</p>
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
 * @version   $Revision: 253 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
class Skein384 extends SkeinBigCore {
    /**
     * Create the engine.
     */
    constructor() {
        super();
    }
    /** @see SkeinBigCore */
    getInitVal() {
        return Skein384.initVal;
    }
    /** @see Digest */
    getDigestLength() {
        return 48;
    }
    /** @see SkeinBigCore */
    dup() {
        return new Skein384();
    }
}
exports.Skein384 = Skein384;
/** The initial value for Skein-384. */
Skein384.initVal = new BigInt64Array([
    BigInt("0xA3F6C6BF3A75EF5F"), BigInt("0xB0FEF9CCFD84FAA4"),
    BigInt("0x9D77DD663D770CFE"), BigInt("0xD798CBF3B468FDDA"),
    BigInt("0x1BC4A6668A0E4465"), BigInt("0x7ED7D434E5807407"),
    BigInt("0x548FC1ACD4EC44D6"), BigInt("0x266E17546AA18FF8")
]);
/**
 * <p>This class implements the Skein-512 digest algorithm under the
 * {@link Digest} API. In the Skein specification, that function is
 * called under the full name "Skein-512-512".</p>
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
 * @version   $Revision: 253 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
class Skein512 extends SkeinBigCore {
    /**
     * Create the engine.
     */
    constructor() {
        super();
    }
    /** @see SkeinBigCore */
    getInitVal() {
        return Skein512.initVal;
    }
    /** @see Digest */
    getDigestLength() {
        return 64;
    }
    /** @see SkeinBigCore */
    dup() {
        return new Skein512();
    }
}
exports.Skein512 = Skein512;
/** The initial value for Skein-512. */
Skein512.initVal = new BigInt64Array([
    BigInt("0x4903ADFF749C51CE"), BigInt("0x0D95DE399746DF03"),
    BigInt("0x8FD1934127C79BCE"), BigInt("0x9A255629FF352CB1"),
    BigInt("0x5DB62599DF6CA7B0"), BigInt("0xEABE394CA9D5C3F4"),
    BigInt("0x991112C71A75B523"), BigInt("0xAE18A40B660FCC33")
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
 * Creates a vary byte length Skein hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {224 | 256 | 384 | 512} bitLen - length of hash (default 512 bits AKA 64 bytes)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function _SKEIN(message, bitLen = 256, format = arrayType()) {
    var hash;
    switch (bitLen) {
        case 224:
            hash = new Skein224();
            break;
        case 256:
            hash = new Skein256();
            break;
        case 384:
            hash = new Skein384();
            break;
        case 512:
            hash = new Skein512();
            break;
        default:
            hash = new Skein512();
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
exports._SKEIN = _SKEIN;
;
/**
 * Creates a vary byte length keyed Skein hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {224 | 256 | 384 | 512} bitLen - length of hash (default 512 bits AKA 64 bytes)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function SKEIN_HMAC(message, key, bitLen = 256, format = arrayType()) {
    var hash;
    switch (bitLen) {
        case 224:
            hash = new Skein224();
            break;
        case 256:
            hash = new Skein256();
            break;
        case 384:
            hash = new Skein384();
            break;
        case 512:
            hash = new Skein512();
            break;
        default:
            hash = new Skein512();
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
exports.SKEIN_HMAC = SKEIN_HMAC;
;
/**
 * Creates a 28 byte Skein hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function SKEIN224(message, format = arrayType()) {
    const hash = new Skein224();
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
exports.SKEIN224 = SKEIN224;
;
/**
 * Creates a 28 byte keyed Skein hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function SKEIN224_HMAC(message, key, format = arrayType()) {
    const hash = new Skein224();
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
exports.SKEIN224_HMAC = SKEIN224_HMAC;
;
/**
 * Creates a 32 byte Skein hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function SKEIN256(message, format = arrayType()) {
    const hash = new Skein256();
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
exports.SKEIN256 = SKEIN256;
;
/**
 * Creates a 32 byte keyed Skein hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function SKEIN256_HMAC(message, key, format = arrayType()) {
    const hash = new Skein256();
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
exports.SKEIN256_HMAC = SKEIN256_HMAC;
;
/**
 * Creates a 48 byte Skein hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function SKEIN384(message, format = arrayType()) {
    const hash = new Skein384();
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
exports.SKEIN384 = SKEIN384;
;
/**
 * Creates a 48 byte keyed Skein hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function SKEIN384_HMAC(message, key, format = arrayType()) {
    const hash = new Skein384();
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
exports.SKEIN384_HMAC = SKEIN384_HMAC;
;
/**
 * Creates a 64 byte Skein hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function SKEIN512(message, format = arrayType()) {
    const hash = new Skein512();
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
exports.SKEIN512 = SKEIN512;
;
/**
 * Creates a 64 byte keyed Skein hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function SKEIN512_HMAC(message, key, format = arrayType()) {
    const hash = new Skein512();
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
exports.SKEIN512_HMAC = SKEIN512_HMAC;
;
/**
 * Static class of all SKEIN functions and classes
 */
class SKEIN {
    /**
     * List of all hashes in class
     */
    static get FUNCTION_LIST() {
        return [
            "SKEIN",
            "SKEIN224",
            "SKEIN224_HMAC",
            "SKEIN256",
            "SKEIN256_HMAC",
            "SKEIN384",
            "SKEIN384_HMAC",
            "SKEIN512",
            "SKEIN512_HMAC",
            "SKEIN_HMAC"
        ];
    }
}
exports.SKEIN = SKEIN;
SKEIN.SKEIN = _SKEIN;
SKEIN.Skein224 = Skein224;
SKEIN.SKEIN224 = SKEIN224;
SKEIN.SKEIN224_HMAC = SKEIN224_HMAC;
SKEIN.Skein256 = Skein256;
SKEIN.SKEIN256 = SKEIN256;
SKEIN.SKEIN256_HMAC = SKEIN256_HMAC;
SKEIN.Skein384 = Skein384;
SKEIN.SKEIN384 = SKEIN384;
SKEIN.SKEIN384_HMAC = SKEIN384_HMAC;
SKEIN.Skein512 = Skein512;
SKEIN.SKEIN512 = SKEIN512;
SKEIN.SKEIN512_HMAC = SKEIN512_HMAC;
SKEIN.SKEIN_HMAC = SKEIN_HMAC;
//# sourceMappingURL=SKEIN.js.map