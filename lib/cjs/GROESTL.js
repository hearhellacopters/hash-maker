"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.GROESTL = exports.GROESTL512_HMAC = exports.GROESTL512 = exports.GROESTL384_HMAC = exports.GROESTL384 = exports.GROESTL256_HMAC = exports.GROESTL256 = exports.GROESTL224_HMAC = exports.GROESTL224 = exports.GROESTL_HMAC = exports._GROESTL = exports.Groestl512 = exports.Groestl384 = exports.Groestl256 = exports.Groestl224 = void 0;
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
class GroestlSmallCore extends DigestEngine {
    constructor() {
        super();
        this.T1 = new BigInt64Array(GroestlSmallCore.T0.length);
        this.T2 = new BigInt64Array(GroestlSmallCore.T0.length);
        this.T3 = new BigInt64Array(GroestlSmallCore.T0.length);
        this.T4 = new BigInt64Array(GroestlSmallCore.T0.length);
        this.T5 = new BigInt64Array(GroestlSmallCore.T0.length);
        this.T6 = new BigInt64Array(GroestlSmallCore.T0.length);
        this.T7 = new BigInt64Array(GroestlSmallCore.T0.length);
        for (let i = 0; i < GroestlSmallCore.T0.length; i++) {
            var v = GroestlSmallCore.T0[i];
            this.T1[i] = GroestlSmallCore.circularLeft(v, 56);
            this.T2[i] = GroestlSmallCore.circularLeft(v, 48);
            this.T3[i] = GroestlSmallCore.circularLeft(v, 40);
            this.T4[i] = GroestlSmallCore.circularLeft(v, 32);
            this.T5[i] = GroestlSmallCore.circularLeft(v, 24);
            this.T6[i] = GroestlSmallCore.circularLeft(v, 16);
            this.T7[i] = GroestlSmallCore.circularLeft(v, 8);
        }
    }
    getBlockLength() {
        return 64;
    }
    copyState(dst) {
        arraycopy(this.H, 0, dst.H, 0, this.H.length);
        return super.copyState(dst);
    }
    engineReset() {
        this.H.fill(BigInt(0));
        this.H[7] = BigInt(this.getDigestLength() << 3);
    }
    doPadding(output, outputOffset) {
        const buf = this.getBlockBuffer();
        var ptr = this.flush();
        buf[ptr++] = 0x80;
        var count = this.getBlockCount();
        if (ptr <= 56) {
            for (let i = ptr; i < 56; i++) {
                buf[i] = 0;
            }
            count++;
        }
        else {
            for (let i = ptr; i < 64; i++) {
                buf[i] = 0;
            }
            this.processBlock(buf);
            for (let i = 0; i < 56; i++) {
                buf[i] = 0;
            }
            count += BigInt(2);
        }
        this.encodeBELong(count, buf, 56);
        this.processBlock(buf);
        arraycopy(this.H, 0, this.G, 0, this.H.length);
        this.doPermP(this.G);
        for (let i = 0; i < 4; i++) {
            this.encodeBELong(this.H[i + 4] ^ this.G[i + 4], buf, 8 * i);
        }
        var outLen = this.getDigestLength();
        arraycopy(buf, 32 - outLen, output, outputOffset, outLen);
    }
    doInit() {
        this.H = new BigInt64Array(8);
        this.G = new BigInt64Array(8);
        this.M = new BigInt64Array(8);
        this.engineReset();
    }
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
    static circularLeft(x, n) {
        const mask = (BigInt(1) << BigInt(64)) - BigInt(1);
        const s = BigInt(n & 63);
        const ux = x & mask; // unsigned 64-bit
        const rotated = ((ux << s) | (ux >> (BigInt(64) - s))) & mask;
        const value = rotated >= (BigInt(1) << BigInt(63)) ? rotated - (BigInt(1) << BigInt(64)) : rotated;
        return value;
    }
    doPermP(x) {
        const t = new BigInt64Array(8);
        for (let r = 0; r < 10; r += 2) {
            x[0] ^= BigInt(r) << BigInt(56);
            x[1] ^= BigInt(0x10 + r) << BigInt(56);
            x[2] ^= BigInt(0x20 + r) << BigInt(56);
            x[3] ^= BigInt(0x30 + r) << BigInt(56);
            x[4] ^= BigInt(0x40 + r) << BigInt(56);
            x[5] ^= BigInt(0x50 + r) << BigInt(56);
            x[6] ^= BigInt(0x60 + r) << BigInt(56);
            x[7] ^= BigInt(0x70 + r) << BigInt(56);
            t[0] =
                GroestlSmallCore.T0[Number((x[0] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[1] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[2] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[3] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[4] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[5] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[6] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[7] & BigInt(0xFF))];
            t[1] =
                GroestlSmallCore.T0[Number((x[1] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[2] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[3] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[4] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[5] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[6] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[7] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[0] & BigInt(0xFF))];
            t[2] =
                GroestlSmallCore.T0[Number((x[2] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[3] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[4] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[5] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[6] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[7] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[0] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[1] & BigInt(0xFF))];
            t[3] =
                GroestlSmallCore.T0[Number((x[3] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[4] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[5] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[6] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[7] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[0] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[1] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[2] & BigInt(0xFF))];
            t[4] =
                GroestlSmallCore.T0[Number((x[4] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[5] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[6] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[7] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[0] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[1] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[2] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[3] & BigInt(0xFF))];
            t[5] =
                GroestlSmallCore.T0[Number((x[5] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[6] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[7] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[0] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[1] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[2] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[3] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[4] & BigInt(0xFF))];
            t[6] =
                GroestlSmallCore.T0[Number((x[6] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[7] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[0] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[1] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[2] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[3] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[4] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[5] & BigInt(0xFF))];
            t[7] =
                GroestlSmallCore.T0[Number((x[7] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[0] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[1] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[2] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[3] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[4] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[5] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[6] & BigInt(0xFF))];
            t[0] ^= BigInt(r + 1) << BigInt(56);
            t[1] ^= BigInt(0x10 + (r + 1)) << BigInt(56);
            t[2] ^= BigInt(0x20 + (r + 1)) << BigInt(56);
            t[3] ^= BigInt(0x30 + (r + 1)) << BigInt(56);
            t[4] ^= BigInt(0x40 + (r + 1)) << BigInt(56);
            t[5] ^= BigInt(0x50 + (r + 1)) << BigInt(56);
            t[6] ^= BigInt(0x60 + (r + 1)) << BigInt(56);
            t[7] ^= BigInt(0x70 + (r + 1)) << BigInt(56);
            x[0] =
                GroestlSmallCore.T0[Number((t[0] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((t[1] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((t[2] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((t[3] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((t[4] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((t[5] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((t[6] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(t[7] & BigInt(0xFF))];
            x[1] =
                GroestlSmallCore.T0[Number((t[1] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((t[2] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((t[3] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((t[4] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((t[5] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((t[6] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((t[7] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(t[0] & BigInt(0xFF))];
            x[2] =
                GroestlSmallCore.T0[Number((t[2] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((t[3] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((t[4] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((t[5] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((t[6] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((t[7] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((t[0] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(t[1] & BigInt(0xFF))];
            x[3] =
                GroestlSmallCore.T0[Number((t[3] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((t[4] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((t[5] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((t[6] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((t[7] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((t[0] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((t[1] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(t[2] & BigInt(0xFF))];
            x[4] =
                GroestlSmallCore.T0[Number((t[4] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((t[5] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((t[6] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((t[7] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((t[0] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((t[1] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((t[2] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(t[3] & BigInt(0xFF))];
            x[5] =
                GroestlSmallCore.T0[Number((t[5] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((t[6] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((t[7] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((t[0] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((t[1] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((t[2] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((t[3] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(t[4] & BigInt(0xFF))];
            x[6] =
                GroestlSmallCore.T0[Number((t[6] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((t[7] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((t[0] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((t[1] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((t[2] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((t[3] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((t[4] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(t[5] & BigInt(0xFF))];
            x[7] =
                GroestlSmallCore.T0[Number((t[7] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((t[0] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((t[1] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((t[2] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((t[3] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((t[4] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((t[5] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(t[6] & BigInt(0xFF))];
        }
    }
    doPermQ(x) {
        const t = new BigInt64Array(8);
        for (let r = 0; r < 10; r += 2) {
            x[0] ^= BigInt(r) ^ BigInt(-0x01);
            x[1] ^= BigInt(r) ^ BigInt(-0x11);
            x[2] ^= BigInt(r) ^ BigInt(-0x21);
            x[3] ^= BigInt(r) ^ BigInt(-0x31);
            x[4] ^= BigInt(r) ^ BigInt(-0x41);
            x[5] ^= BigInt(r) ^ BigInt(-0x51);
            x[6] ^= BigInt(r) ^ BigInt(-0x61);
            x[7] ^= BigInt(r) ^ BigInt(-0x71);
            t[0] =
                GroestlSmallCore.T0[Number((x[1] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[3] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[5] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[7] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[0] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[2] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[4] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[6] & BigInt(0xFF))];
            t[1] =
                GroestlSmallCore.T0[Number((x[2] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[4] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[6] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[0] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[1] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[3] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[5] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[7] & BigInt(0xFF))];
            t[2] =
                GroestlSmallCore.T0[Number((x[3] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[5] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[7] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[1] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[2] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[4] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[6] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[0] & BigInt(0xFF))];
            t[3] =
                GroestlSmallCore.T0[Number((x[4] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[6] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[0] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[2] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[3] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[5] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[7] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[1] & BigInt(0xFF))];
            t[4] =
                GroestlSmallCore.T0[Number((x[5] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[7] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[1] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[3] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[4] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[6] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[0] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[2] & BigInt(0xFF))];
            t[5] =
                GroestlSmallCore.T0[Number((x[6] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[0] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[2] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[4] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[5] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[7] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[1] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[3] & BigInt(0xFF))];
            t[6] =
                GroestlSmallCore.T0[Number((x[7] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[1] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[3] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[5] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[6] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[0] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[2] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[4] & BigInt(0xFF))];
            t[7] =
                GroestlSmallCore.T0[Number((x[0] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[2] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[4] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[6] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[7] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[1] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[3] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[5] & BigInt(0xFF))];
            t[0] ^= BigInt(r + 1) ^ BigInt(-0x01);
            t[1] ^= BigInt(r + 1) ^ BigInt(-0x11);
            t[2] ^= BigInt(r + 1) ^ BigInt(-0x21);
            t[3] ^= BigInt(r + 1) ^ BigInt(-0x31);
            t[4] ^= BigInt(r + 1) ^ BigInt(-0x41);
            t[5] ^= BigInt(r + 1) ^ BigInt(-0x51);
            t[6] ^= BigInt(r + 1) ^ BigInt(-0x61);
            t[7] ^= BigInt(r + 1) ^ BigInt(-0x71);
            x[0] =
                GroestlSmallCore.T0[Number((t[1] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((t[3] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((t[5] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((t[7] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((t[0] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((t[2] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((t[4] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(t[6] & BigInt(0xFF))];
            x[1] =
                GroestlSmallCore.T0[Number((t[2] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((t[4] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((t[6] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((t[0] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((t[1] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((t[3] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((t[5] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(t[7] & BigInt(0xFF))];
            x[2] =
                GroestlSmallCore.T0[Number((t[3] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((t[5] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((t[7] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((t[1] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((t[2] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((t[4] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((t[6] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(t[0] & BigInt(0xFF))];
            x[3] =
                GroestlSmallCore.T0[Number((t[4] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((t[6] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((t[0] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((t[2] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((t[3] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((t[5] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((t[7] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(t[1] & BigInt(0xFF))];
            x[4] =
                GroestlSmallCore.T0[Number((t[5] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((t[7] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((t[1] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((t[3] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((t[4] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((t[6] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((t[0] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(t[2] & BigInt(0xFF))];
            x[5] =
                GroestlSmallCore.T0[Number((t[6] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((t[0] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((t[2] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((t[4] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((t[5] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((t[7] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((t[1] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(t[3] & BigInt(0xFF))];
            x[6] =
                GroestlSmallCore.T0[Number((t[7] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((t[1] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((t[3] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((t[5] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((t[6] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((t[0] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((t[2] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(t[4] & BigInt(0xFF))];
            x[7] =
                GroestlSmallCore.T0[Number((t[0] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((t[2] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((t[4] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((t[6] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((t[7] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((t[1] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((t[3] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(t[5] & BigInt(0xFF))];
        }
    }
    /** @see DigestEngine */
    processBlock(data) {
        for (let i = 0; i < 8; i++) {
            this.M[i] = this.decodeBELong(data, i * 8);
            this.G[i] = this.M[i] ^ this.H[i];
        }
        this.doPermP(this.G);
        this.doPermQ(this.M);
        for (let i = 0; i < 8; i++) {
            this.H[i] ^= this.G[i] ^ this.M[i];
        }
    }
    toString() {
        return "Groestl-" + (this.getDigestLength() << 3);
    }
}
GroestlSmallCore.T0 = new BigInt64Array([
    BigInt("0xc632f4a5f497a5c6"), BigInt("0xf86f978497eb84f8"),
    BigInt("0xee5eb099b0c799ee"), BigInt("0xf67a8c8d8cf78df6"),
    BigInt("0xffe8170d17e50dff"), BigInt("0xd60adcbddcb7bdd6"),
    BigInt("0xde16c8b1c8a7b1de"), BigInt("0x916dfc54fc395491"),
    BigInt("0x6090f050f0c05060"), BigInt("0x0207050305040302"),
    BigInt("0xce2ee0a9e087a9ce"), BigInt("0x56d1877d87ac7d56"),
    BigInt("0xe7cc2b192bd519e7"), BigInt("0xb513a662a67162b5"),
    BigInt("0x4d7c31e6319ae64d"), BigInt("0xec59b59ab5c39aec"),
    BigInt("0x8f40cf45cf05458f"), BigInt("0x1fa3bc9dbc3e9d1f"),
    BigInt("0x8949c040c0094089"), BigInt("0xfa68928792ef87fa"),
    BigInt("0xefd03f153fc515ef"), BigInt("0xb29426eb267febb2"),
    BigInt("0x8ece40c94007c98e"), BigInt("0xfbe61d0b1ded0bfb"),
    BigInt("0x416e2fec2f82ec41"), BigInt("0xb31aa967a97d67b3"),
    BigInt("0x5f431cfd1cbefd5f"), BigInt("0x456025ea258aea45"),
    BigInt("0x23f9dabfda46bf23"), BigInt("0x535102f702a6f753"),
    BigInt("0xe445a196a1d396e4"), BigInt("0x9b76ed5bed2d5b9b"),
    BigInt("0x75285dc25deac275"), BigInt("0xe1c5241c24d91ce1"),
    BigInt("0x3dd4e9aee97aae3d"), BigInt("0x4cf2be6abe986a4c"),
    BigInt("0x6c82ee5aeed85a6c"), BigInt("0x7ebdc341c3fc417e"),
    BigInt("0xf5f3060206f102f5"), BigInt("0x8352d14fd11d4f83"),
    BigInt("0x688ce45ce4d05c68"), BigInt("0x515607f407a2f451"),
    BigInt("0xd18d5c345cb934d1"), BigInt("0xf9e1180818e908f9"),
    BigInt("0xe24cae93aedf93e2"), BigInt("0xab3e9573954d73ab"),
    BigInt("0x6297f553f5c45362"), BigInt("0x2a6b413f41543f2a"),
    BigInt("0x081c140c14100c08"), BigInt("0x9563f652f6315295"),
    BigInt("0x46e9af65af8c6546"), BigInt("0x9d7fe25ee2215e9d"),
    BigInt("0x3048782878602830"), BigInt("0x37cff8a1f86ea137"),
    BigInt("0x0a1b110f11140f0a"), BigInt("0x2febc4b5c45eb52f"),
    BigInt("0x0e151b091b1c090e"), BigInt("0x247e5a365a483624"),
    BigInt("0x1badb69bb6369b1b"), BigInt("0xdf98473d47a53ddf"),
    BigInt("0xcda76a266a8126cd"), BigInt("0x4ef5bb69bb9c694e"),
    BigInt("0x7f334ccd4cfecd7f"), BigInt("0xea50ba9fbacf9fea"),
    BigInt("0x123f2d1b2d241b12"), BigInt("0x1da4b99eb93a9e1d"),
    BigInt("0x58c49c749cb07458"), BigInt("0x3446722e72682e34"),
    BigInt("0x3641772d776c2d36"), BigInt("0xdc11cdb2cda3b2dc"),
    BigInt("0xb49d29ee2973eeb4"), BigInt("0x5b4d16fb16b6fb5b"),
    BigInt("0xa4a501f60153f6a4"), BigInt("0x76a1d74dd7ec4d76"),
    BigInt("0xb714a361a37561b7"), BigInt("0x7d3449ce49face7d"),
    BigInt("0x52df8d7b8da47b52"), BigInt("0xdd9f423e42a13edd"),
    BigInt("0x5ecd937193bc715e"), BigInt("0x13b1a297a2269713"),
    BigInt("0xa6a204f50457f5a6"), BigInt("0xb901b868b86968b9"),
    BigInt("0x0000000000000000"), BigInt("0xc1b5742c74992cc1"),
    BigInt("0x40e0a060a0806040"), BigInt("0xe3c2211f21dd1fe3"),
    BigInt("0x793a43c843f2c879"), BigInt("0xb69a2ced2c77edb6"),
    BigInt("0xd40dd9bed9b3bed4"), BigInt("0x8d47ca46ca01468d"),
    BigInt("0x671770d970ced967"), BigInt("0x72afdd4bdde44b72"),
    BigInt("0x94ed79de7933de94"), BigInt("0x98ff67d4672bd498"),
    BigInt("0xb09323e8237be8b0"), BigInt("0x855bde4ade114a85"),
    BigInt("0xbb06bd6bbd6d6bbb"), BigInt("0xc5bb7e2a7e912ac5"),
    BigInt("0x4f7b34e5349ee54f"), BigInt("0xedd73a163ac116ed"),
    BigInt("0x86d254c55417c586"), BigInt("0x9af862d7622fd79a"),
    BigInt("0x6699ff55ffcc5566"), BigInt("0x11b6a794a7229411"),
    BigInt("0x8ac04acf4a0fcf8a"), BigInt("0xe9d9301030c910e9"),
    BigInt("0x040e0a060a080604"), BigInt("0xfe66988198e781fe"),
    BigInt("0xa0ab0bf00b5bf0a0"), BigInt("0x78b4cc44ccf04478"),
    BigInt("0x25f0d5bad54aba25"), BigInt("0x4b753ee33e96e34b"),
    BigInt("0xa2ac0ef30e5ff3a2"), BigInt("0x5d4419fe19bafe5d"),
    BigInt("0x80db5bc05b1bc080"), BigInt("0x0580858a850a8a05"),
    BigInt("0x3fd3ecadec7ead3f"), BigInt("0x21fedfbcdf42bc21"),
    BigInt("0x70a8d848d8e04870"), BigInt("0xf1fd0c040cf904f1"),
    BigInt("0x63197adf7ac6df63"), BigInt("0x772f58c158eec177"),
    BigInt("0xaf309f759f4575af"), BigInt("0x42e7a563a5846342"),
    BigInt("0x2070503050403020"), BigInt("0xe5cb2e1a2ed11ae5"),
    BigInt("0xfdef120e12e10efd"), BigInt("0xbf08b76db7656dbf"),
    BigInt("0x8155d44cd4194c81"), BigInt("0x18243c143c301418"),
    BigInt("0x26795f355f4c3526"), BigInt("0xc3b2712f719d2fc3"),
    BigInt("0xbe8638e13867e1be"), BigInt("0x35c8fda2fd6aa235"),
    BigInt("0x88c74fcc4f0bcc88"), BigInt("0x2e654b394b5c392e"),
    BigInt("0x936af957f93d5793"), BigInt("0x55580df20daaf255"),
    BigInt("0xfc619d829de382fc"), BigInt("0x7ab3c947c9f4477a"),
    BigInt("0xc827efacef8bacc8"), BigInt("0xba8832e7326fe7ba"),
    BigInt("0x324f7d2b7d642b32"), BigInt("0xe642a495a4d795e6"),
    BigInt("0xc03bfba0fb9ba0c0"), BigInt("0x19aab398b3329819"),
    BigInt("0x9ef668d16827d19e"), BigInt("0xa322817f815d7fa3"),
    BigInt("0x44eeaa66aa886644"), BigInt("0x54d6827e82a87e54"),
    BigInt("0x3bdde6abe676ab3b"), BigInt("0x0b959e839e16830b"),
    BigInt("0x8cc945ca4503ca8c"), BigInt("0xc7bc7b297b9529c7"),
    BigInt("0x6b056ed36ed6d36b"), BigInt("0x286c443c44503c28"),
    BigInt("0xa72c8b798b5579a7"), BigInt("0xbc813de23d63e2bc"),
    BigInt("0x1631271d272c1d16"), BigInt("0xad379a769a4176ad"),
    BigInt("0xdb964d3b4dad3bdb"), BigInt("0x649efa56fac85664"),
    BigInt("0x74a6d24ed2e84e74"), BigInt("0x1436221e22281e14"),
    BigInt("0x92e476db763fdb92"), BigInt("0x0c121e0a1e180a0c"),
    BigInt("0x48fcb46cb4906c48"), BigInt("0xb88f37e4376be4b8"),
    BigInt("0x9f78e75de7255d9f"), BigInt("0xbd0fb26eb2616ebd"),
    BigInt("0x43692aef2a86ef43"), BigInt("0xc435f1a6f193a6c4"),
    BigInt("0x39dae3a8e372a839"), BigInt("0x31c6f7a4f762a431"),
    BigInt("0xd38a593759bd37d3"), BigInt("0xf274868b86ff8bf2"),
    BigInt("0xd583563256b132d5"), BigInt("0x8b4ec543c50d438b"),
    BigInt("0x6e85eb59ebdc596e"), BigInt("0xda18c2b7c2afb7da"),
    BigInt("0x018e8f8c8f028c01"), BigInt("0xb11dac64ac7964b1"),
    BigInt("0x9cf16dd26d23d29c"), BigInt("0x49723be03b92e049"),
    BigInt("0xd81fc7b4c7abb4d8"), BigInt("0xacb915fa1543faac"),
    BigInt("0xf3fa090709fd07f3"), BigInt("0xcfa06f256f8525cf"),
    BigInt("0xca20eaafea8fafca"), BigInt("0xf47d898e89f38ef4"),
    BigInt("0x476720e9208ee947"), BigInt("0x1038281828201810"),
    BigInt("0x6f0b64d564ded56f"), BigInt("0xf073838883fb88f0"),
    BigInt("0x4afbb16fb1946f4a"), BigInt("0x5cca967296b8725c"),
    BigInt("0x38546c246c702438"), BigInt("0x575f08f108aef157"),
    BigInt("0x732152c752e6c773"), BigInt("0x9764f351f3355197"),
    BigInt("0xcbae6523658d23cb"), BigInt("0xa125847c84597ca1"),
    BigInt("0xe857bf9cbfcb9ce8"), BigInt("0x3e5d6321637c213e"),
    BigInt("0x96ea7cdd7c37dd96"), BigInt("0x611e7fdc7fc2dc61"),
    BigInt("0x0d9c9186911a860d"), BigInt("0x0f9b9485941e850f"),
    BigInt("0xe04bab90abdb90e0"), BigInt("0x7cbac642c6f8427c"),
    BigInt("0x712657c457e2c471"), BigInt("0xcc29e5aae583aacc"),
    BigInt("0x90e373d8733bd890"), BigInt("0x06090f050f0c0506"),
    BigInt("0xf7f4030103f501f7"), BigInt("0x1c2a36123638121c"),
    BigInt("0xc23cfea3fe9fa3c2"), BigInt("0x6a8be15fe1d45f6a"),
    BigInt("0xaebe10f91047f9ae"), BigInt("0x69026bd06bd2d069"),
    BigInt("0x17bfa891a82e9117"), BigInt("0x9971e858e8295899"),
    BigInt("0x3a5369276974273a"), BigInt("0x27f7d0b9d04eb927"),
    BigInt("0xd991483848a938d9"), BigInt("0xebde351335cd13eb"),
    BigInt("0x2be5ceb3ce56b32b"), BigInt("0x2277553355443322"),
    BigInt("0xd204d6bbd6bfbbd2"), BigInt("0xa9399070904970a9"),
    BigInt("0x07878089800e8907"), BigInt("0x33c1f2a7f266a733"),
    BigInt("0x2decc1b6c15ab62d"), BigInt("0x3c5a66226678223c"),
    BigInt("0x15b8ad92ad2a9215"), BigInt("0xc9a96020608920c9"),
    BigInt("0x875cdb49db154987"), BigInt("0xaab01aff1a4fffaa"),
    BigInt("0x50d8887888a07850"), BigInt("0xa52b8e7a8e517aa5"),
    BigInt("0x03898a8f8a068f03"), BigInt("0x594a13f813b2f859"),
    BigInt("0x09929b809b128009"), BigInt("0x1a2339173934171a"),
    BigInt("0x651075da75cada65"), BigInt("0xd784533153b531d7"),
    BigInt("0x84d551c65113c684"), BigInt("0xd003d3b8d3bbb8d0"),
    BigInt("0x82dc5ec35e1fc382"), BigInt("0x29e2cbb0cb52b029"),
    BigInt("0x5ac3997799b4775a"), BigInt("0x1e2d3311333c111e"),
    BigInt("0x7b3d46cb46f6cb7b"), BigInt("0xa8b71ffc1f4bfca8"),
    BigInt("0x6d0c61d661dad66d"), BigInt("0x2c624e3a4e583a2c")
]);
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
class GroestlBigCore extends DigestEngine {
    /**
     * Create the object.
     */
    constructor() {
        super();
        this.T1 = new BigInt64Array(GroestlBigCore.T0.length);
        this.T2 = new BigInt64Array(GroestlBigCore.T0.length);
        this.T3 = new BigInt64Array(GroestlBigCore.T0.length);
        this.T4 = new BigInt64Array(GroestlBigCore.T0.length);
        this.T5 = new BigInt64Array(GroestlBigCore.T0.length);
        this.T6 = new BigInt64Array(GroestlBigCore.T0.length);
        this.T7 = new BigInt64Array(GroestlBigCore.T0.length);
        for (let i = 0; i < GroestlBigCore.T0.length; i++) {
            var v = GroestlBigCore.T0[i];
            this.T1[i] = GroestlBigCore.circularLeft(v, 56);
            this.T2[i] = GroestlBigCore.circularLeft(v, 48);
            this.T3[i] = GroestlBigCore.circularLeft(v, 40);
            this.T4[i] = GroestlBigCore.circularLeft(v, 32);
            this.T5[i] = GroestlBigCore.circularLeft(v, 24);
            this.T6[i] = GroestlBigCore.circularLeft(v, 16);
            this.T7[i] = GroestlBigCore.circularLeft(v, 8);
        }
    }
    /** @see Digest */
    getBlockLength() {
        return 128;
    }
    /** @see DigestEngine */
    copyState(dst) {
        arraycopy(this.H, 0, dst.H, 0, this.H.length);
        return super.copyState(dst);
    }
    /** @see DigestEngine */
    engineReset() {
        for (let i = 0; i < 15; i++) {
            this.H[i] = BigInt(0);
        }
        this.H[15] = BigInt(this.getDigestLength() << 3);
    }
    /** @see DigestEngine */
    doPadding(output, outputOffset) {
        const buf = this.getBlockBuffer();
        var ptr = this.flush();
        buf[ptr++] = 0x80;
        var count = this.getBlockCount();
        if (ptr <= 120) {
            for (let i = ptr; i < 120; i++) {
                buf[i] = 0;
            }
            count++;
        }
        else {
            for (let i = ptr; i < 128; i++) {
                buf[i] = 0;
            }
            this.processBlock(buf);
            for (let i = 0; i < 120; i++) {
                buf[i] = 0;
            }
            count += BigInt(2);
        }
        this.encodeBELong(count, buf, 120);
        this.processBlock(buf);
        arraycopy(this.H, 0, this.G, 0, this.H.length);
        this.doPermP(this.G);
        for (let i = 0; i < 8; i++) {
            this.encodeBELong(this.H[i + 8] ^ this.G[i + 8], buf, 8 * i);
        }
        const outLen = this.getDigestLength();
        arraycopy(buf, 64 - outLen, output, outputOffset, outLen);
    }
    /** @see DigestEngine */
    doInit() {
        this.H = new BigInt64Array(16);
        this.G = new BigInt64Array(16);
        this.M = new BigInt64Array(16);
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
     * Perform a circular rotation by {@code n} to the left
     * of the 64-bit word {@code x}. The {@code n} parameter
     * must lie between 1 and 63 (inclusive).
     *
     * @param x   the value to rotate
     * @param n   the rotation count (between 1 and 63)
     * @return  the rotated value
    */
    static circularLeft(x, n) {
        const mask = (BigInt(1) << BigInt(64)) - BigInt(1);
        const s = BigInt(n & 63);
        const ux = x & mask; // unsigned 64-bit
        const rotated = ((ux << s) | (ux >> (BigInt(64) - s))) & mask;
        const value = rotated >= (BigInt(1) << BigInt(63)) ? rotated - (BigInt(1) << BigInt(64)) : rotated;
        return value;
    }
    doPermP(x) {
        const t = new BigInt64Array(16);
        const A = 10;
        const B = 11;
        const C = 12;
        const D = 13;
        const E = 14;
        const F = 15;
        for (let r = 0; r < 14; r++) {
            x[0x0] ^= BigInt(r) << BigInt(56);
            x[0x1] ^= BigInt(0x10 + r) << BigInt(56);
            x[0x2] ^= BigInt(0x20 + r) << BigInt(56);
            x[0x3] ^= BigInt(0x30 + r) << BigInt(56);
            x[0x4] ^= BigInt(0x40 + r) << BigInt(56);
            x[0x5] ^= BigInt(0x50 + r) << BigInt(56);
            x[0x6] ^= BigInt(0x60 + r) << BigInt(56);
            x[0x7] ^= BigInt(0x70 + r) << BigInt(56);
            x[0x8] ^= BigInt(0x80 + r) << BigInt(56);
            x[0x9] ^= BigInt(0x90 + r) << BigInt(56);
            x[0xA] ^= BigInt(0xA0 + r) << BigInt(56);
            x[0xB] ^= BigInt(0xB0 + r) << BigInt(56);
            x[0xC] ^= BigInt(0xC0 + r) << BigInt(56);
            x[0xD] ^= BigInt(0xD0 + r) << BigInt(56);
            x[0xE] ^= BigInt(0xE0 + r) << BigInt(56);
            x[0xF] ^= BigInt(0xF0 + r) << BigInt(56);
            t[0] =
                GroestlBigCore.T0[Number((x[0x0] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[0x1] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[0x2] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[0x3] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[0x4] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[0x5] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[0x6] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[0xB] & BigInt(0xFF))];
            t[1] =
                GroestlBigCore.T0[Number((x[0x1] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[0x2] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[0x3] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[0x4] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[0x5] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[0x6] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[0x7] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[0xC] & BigInt(0xFF))];
            t[2] =
                GroestlBigCore.T0[Number((x[0x2] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[0x3] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[0x4] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[0x5] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[0x6] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[0x7] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[0x8] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[0xD] & BigInt(0xFF))];
            t[3] =
                GroestlBigCore.T0[Number((x[0x3] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[0x4] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[0x5] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[0x6] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[0x7] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[0x8] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[0x9] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[0xE] & BigInt(0xFF))];
            t[4] =
                GroestlBigCore.T0[Number((x[0x4] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[0x5] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[0x6] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[0x7] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[0x8] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[0x9] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[0xA] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[0xF] & BigInt(0xFF))];
            t[5] =
                GroestlBigCore.T0[Number((x[0x5] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[0x6] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[0x7] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[0x8] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[0x9] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[0xA] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[0xB] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[0x0] & BigInt(0xFF))];
            t[6] =
                GroestlBigCore.T0[Number((x[0x6] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[0x7] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[0x8] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[0x9] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[0xA] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[0xB] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[0xC] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[0x1] & BigInt(0xFF))];
            t[7] =
                GroestlBigCore.T0[Number((x[0x7] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[0x8] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[0x9] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[0xA] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[0xB] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[0xC] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[0xD] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[0x2] & BigInt(0xFF))];
            t[8] =
                GroestlBigCore.T0[Number((x[0x8] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[0x9] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[0xA] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[0xB] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[0xC] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[0xD] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[0xE] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[0x3] & BigInt(0xFF))];
            t[9] =
                GroestlBigCore.T0[Number((x[0x9] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[0xA] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[0xB] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[0xC] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[0xD] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[0xE] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[0xF] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[0x4] & BigInt(0xFF))];
            t[A] =
                GroestlBigCore.T0[Number((x[0xA] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[0xB] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[0xC] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[0xD] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[0xE] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[0xF] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[0x0] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[0x5] & BigInt(0xFF))];
            t[B] =
                GroestlBigCore.T0[Number((x[0xB] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[0xC] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[0xD] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[0xE] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[0xF] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[0x0] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[0x1] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[0x6] & BigInt(0xFF))];
            t[C] =
                GroestlBigCore.T0[Number((x[0xC] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[0xD] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[0xE] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[0xF] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[0x0] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[0x1] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[0x2] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[0x7] & BigInt(0xFF))];
            t[D] =
                GroestlBigCore.T0[Number((x[0xD] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[0xE] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[0xF] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[0x0] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[0x1] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[0x2] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[0x3] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[0x8] & BigInt(0xFF))];
            t[E] =
                GroestlBigCore.T0[Number((x[0xE] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[0xF] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[0x0] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[0x1] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[0x2] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[0x3] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[0x4] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[0x9] & BigInt(0xFF))];
            t[F]
                =
                    GroestlBigCore.T0[Number((x[0xF] >> BigInt(56)) & BigInt(0xFF))]
                        ^ this.T1[Number((x[0x0] >> BigInt(48)) & BigInt(0xFF))]
                        ^ this.T2[Number((x[0x1] >> BigInt(40)) & BigInt(0xFF))]
                        ^ this.T3[Number((x[0x2] >> BigInt(32)) & BigInt(0xFF))]
                        ^ this.T4[Number((x[0x3] >> BigInt(24)) & BigInt(0xFF))]
                        ^ this.T5[Number((x[0x4] >> BigInt(16)) & BigInt(0xFF))]
                        ^ this.T6[Number((x[0x5] >> BigInt(8)) & BigInt(0xFF))]
                        ^ this.T7[Number(x[0xA] & BigInt(0xFF))];
            x[0x0] = t[0];
            x[0x1] = t[1];
            x[0x2] = t[2];
            x[0x3] = t[3];
            x[0x4] = t[4];
            x[0x5] = t[5];
            x[0x6] = t[6];
            x[0x7] = t[7];
            x[0x8] = t[8];
            x[0x9] = t[9];
            x[0xA] = t[A];
            x[0xB] = t[B];
            x[0xC] = t[C];
            x[0xD] = t[D];
            x[0xE] = t[E];
            x[0xF] = t[F];
        }
    }
    doPermQ(x) {
        const t = new BigInt64Array(16);
        const A = 10;
        const B = 11;
        const C = 12;
        const D = 13;
        const E = 14;
        const F = 15;
        for (let r = 0; r < 14; r++) {
            x[0x0] ^= BigInt(r) ^ BigInt(-0x01);
            x[0x1] ^= BigInt(r) ^ BigInt(-0x11);
            x[0x2] ^= BigInt(r) ^ BigInt(-0x21);
            x[0x3] ^= BigInt(r) ^ BigInt(-0x31);
            x[0x4] ^= BigInt(r) ^ BigInt(-0x41);
            x[0x5] ^= BigInt(r) ^ BigInt(-0x51);
            x[0x6] ^= BigInt(r) ^ BigInt(-0x61);
            x[0x7] ^= BigInt(r) ^ BigInt(-0x71);
            x[0x8] ^= BigInt(r) ^ BigInt(-0x81);
            x[0x9] ^= BigInt(r) ^ BigInt(-0x91);
            x[0xA] ^= BigInt(r) ^ BigInt(-0xA1);
            x[0xB] ^= BigInt(r) ^ BigInt(-0xB1);
            x[0xC] ^= BigInt(r) ^ BigInt(-0xC1);
            x[0xD] ^= BigInt(r) ^ BigInt(-0xD1);
            x[0xE] ^= BigInt(r) ^ BigInt(-0xE1);
            x[0xF] ^= BigInt(r) ^ BigInt(-0xF1);
            t[0] =
                GroestlBigCore.T0[Number((x[0x1] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[0x3] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[0x5] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[0xB] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[0x0] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[0x2] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[0x4] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[0x6] & BigInt(0xFF))];
            t[1] =
                GroestlBigCore.T0[Number((x[0x2] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[0x4] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[0x6] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[0xC] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[0x1] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[0x3] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[0x5] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[0x7] & BigInt(0xFF))];
            t[2] =
                GroestlBigCore.T0[Number((x[0x3] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[0x5] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[0x7] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[0xD] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[0x2] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[0x4] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[0x6] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[0x8] & BigInt(0xFF))];
            t[3] =
                GroestlBigCore.T0[Number((x[0x4] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[0x6] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[0x8] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[0xE] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[0x3] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[0x5] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[0x7] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[0x9] & BigInt(0xFF))];
            t[4] =
                GroestlBigCore.T0[Number((x[0x5] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[0x7] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[0x9] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[0xF] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[0x4] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[0x6] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[0x8] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[0xA] & BigInt(0xFF))];
            t[5] =
                GroestlBigCore.T0[Number((x[0x6] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[0x8] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[0xA] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[0x0] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[0x5] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[0x7] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[0x9] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[0xB] & BigInt(0xFF))];
            t[6] =
                GroestlBigCore.T0[Number((x[0x7] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[0x9] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[0xB] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[0x1] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[0x6] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[0x8] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[0xA] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[0xC] & BigInt(0xFF))];
            t[7] =
                GroestlBigCore.T0[Number((x[0x8] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[0xA] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[0xC] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[0x2] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[0x7] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[0x9] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[0xB] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[0xD] & BigInt(0xFF))];
            t[8] =
                GroestlBigCore.T0[Number((x[0x9] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[0xB] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[0xD] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[0x3] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[0x8] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[0xA] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[0xC] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[0xE] & BigInt(0xFF))];
            t[9] =
                GroestlBigCore.T0[Number((x[0xA] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[0xC] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[0xE] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[0x4] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[0x9] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[0xB] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[0xD] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[0xF] & BigInt(0xFF))];
            t[A] =
                GroestlBigCore.T0[Number((x[0xB] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[0xD] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[0xF] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[0x5] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[0xA] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[0xC] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[0xE] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[0x0] & BigInt(0xFF))];
            t[B] =
                GroestlBigCore.T0[Number((x[0xC] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[0xE] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[0x0] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[0x6] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[0xB] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[0xD] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[0xF] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[0x1] & BigInt(0xFF))];
            t[C] =
                GroestlBigCore.T0[Number((x[0xD] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[0xF] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[0x1] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[0x7] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[0xC] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[0xE] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[0x0] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[0x2] & BigInt(0xFF))];
            t[D] =
                GroestlBigCore.T0[Number((x[0xE] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[0x0] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[0x2] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[0x8] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[0xD] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[0xF] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[0x1] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[0x3] & BigInt(0xFF))];
            t[E] =
                GroestlBigCore.T0[Number((x[0xF] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[0x1] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[0x3] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[0x9] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[0xE] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[0x0] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[0x2] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[0x4] & BigInt(0xFF))];
            t[F] =
                GroestlBigCore.T0[Number((x[0x0] >> BigInt(56)) & BigInt(0xFF))]
                    ^ this.T1[Number((x[0x2] >> BigInt(48)) & BigInt(0xFF))]
                    ^ this.T2[Number((x[0x4] >> BigInt(40)) & BigInt(0xFF))]
                    ^ this.T3[Number((x[0xA] >> BigInt(32)) & BigInt(0xFF))]
                    ^ this.T4[Number((x[0xF] >> BigInt(24)) & BigInt(0xFF))]
                    ^ this.T5[Number((x[0x1] >> BigInt(16)) & BigInt(0xFF))]
                    ^ this.T6[Number((x[0x3] >> BigInt(8)) & BigInt(0xFF))]
                    ^ this.T7[Number(x[0x5] & BigInt(0xFF))];
            x[0x0] = t[0];
            x[0x1] = t[1];
            x[0x2] = t[2];
            x[0x3] = t[3];
            x[0x4] = t[4];
            x[0x5] = t[5];
            x[0x6] = t[6];
            x[0x7] = t[7];
            x[0x8] = t[8];
            x[0x9] = t[9];
            x[0xA] = t[A];
            x[0xB] = t[B];
            x[0xC] = t[C];
            x[0xD] = t[D];
            x[0xE] = t[E];
            x[0xF] = t[F];
        }
    }
    /** @see DigestEngine */
    processBlock(data) {
        for (let i = 0; i < 16; i++) {
            this.M[i] = this.decodeBELong(data, i * 8);
            this.G[i] = this.M[i] ^ this.H[i];
        }
        this.doPermP(this.G);
        this.doPermQ(this.M);
        for (let i = 0; i < 16; i++) {
            this.H[i] ^= this.G[i] ^ this.M[i];
        }
    }
    /** @see Digest */
    toString() {
        return "Groestl-" + (this.getDigestLength() << 3);
    }
}
GroestlBigCore.T0 = new BigInt64Array([
    BigInt("0xc632f4a5f497a5c6"), BigInt("0xf86f978497eb84f8"),
    BigInt("0xee5eb099b0c799ee"), BigInt("0xf67a8c8d8cf78df6"),
    BigInt("0xffe8170d17e50dff"), BigInt("0xd60adcbddcb7bdd6"),
    BigInt("0xde16c8b1c8a7b1de"), BigInt("0x916dfc54fc395491"),
    BigInt("0x6090f050f0c05060"), BigInt("0x0207050305040302"),
    BigInt("0xce2ee0a9e087a9ce"), BigInt("0x56d1877d87ac7d56"),
    BigInt("0xe7cc2b192bd519e7"), BigInt("0xb513a662a67162b5"),
    BigInt("0x4d7c31e6319ae64d"), BigInt("0xec59b59ab5c39aec"),
    BigInt("0x8f40cf45cf05458f"), BigInt("0x1fa3bc9dbc3e9d1f"),
    BigInt("0x8949c040c0094089"), BigInt("0xfa68928792ef87fa"),
    BigInt("0xefd03f153fc515ef"), BigInt("0xb29426eb267febb2"),
    BigInt("0x8ece40c94007c98e"), BigInt("0xfbe61d0b1ded0bfb"),
    BigInt("0x416e2fec2f82ec41"), BigInt("0xb31aa967a97d67b3"),
    BigInt("0x5f431cfd1cbefd5f"), BigInt("0x456025ea258aea45"),
    BigInt("0x23f9dabfda46bf23"), BigInt("0x535102f702a6f753"),
    BigInt("0xe445a196a1d396e4"), BigInt("0x9b76ed5bed2d5b9b"),
    BigInt("0x75285dc25deac275"), BigInt("0xe1c5241c24d91ce1"),
    BigInt("0x3dd4e9aee97aae3d"), BigInt("0x4cf2be6abe986a4c"),
    BigInt("0x6c82ee5aeed85a6c"), BigInt("0x7ebdc341c3fc417e"),
    BigInt("0xf5f3060206f102f5"), BigInt("0x8352d14fd11d4f83"),
    BigInt("0x688ce45ce4d05c68"), BigInt("0x515607f407a2f451"),
    BigInt("0xd18d5c345cb934d1"), BigInt("0xf9e1180818e908f9"),
    BigInt("0xe24cae93aedf93e2"), BigInt("0xab3e9573954d73ab"),
    BigInt("0x6297f553f5c45362"), BigInt("0x2a6b413f41543f2a"),
    BigInt("0x081c140c14100c08"), BigInt("0x9563f652f6315295"),
    BigInt("0x46e9af65af8c6546"), BigInt("0x9d7fe25ee2215e9d"),
    BigInt("0x3048782878602830"), BigInt("0x37cff8a1f86ea137"),
    BigInt("0x0a1b110f11140f0a"), BigInt("0x2febc4b5c45eb52f"),
    BigInt("0x0e151b091b1c090e"), BigInt("0x247e5a365a483624"),
    BigInt("0x1badb69bb6369b1b"), BigInt("0xdf98473d47a53ddf"),
    BigInt("0xcda76a266a8126cd"), BigInt("0x4ef5bb69bb9c694e"),
    BigInt("0x7f334ccd4cfecd7f"), BigInt("0xea50ba9fbacf9fea"),
    BigInt("0x123f2d1b2d241b12"), BigInt("0x1da4b99eb93a9e1d"),
    BigInt("0x58c49c749cb07458"), BigInt("0x3446722e72682e34"),
    BigInt("0x3641772d776c2d36"), BigInt("0xdc11cdb2cda3b2dc"),
    BigInt("0xb49d29ee2973eeb4"), BigInt("0x5b4d16fb16b6fb5b"),
    BigInt("0xa4a501f60153f6a4"), BigInt("0x76a1d74dd7ec4d76"),
    BigInt("0xb714a361a37561b7"), BigInt("0x7d3449ce49face7d"),
    BigInt("0x52df8d7b8da47b52"), BigInt("0xdd9f423e42a13edd"),
    BigInt("0x5ecd937193bc715e"), BigInt("0x13b1a297a2269713"),
    BigInt("0xa6a204f50457f5a6"), BigInt("0xb901b868b86968b9"),
    BigInt("0x0000000000000000"), BigInt("0xc1b5742c74992cc1"),
    BigInt("0x40e0a060a0806040"), BigInt("0xe3c2211f21dd1fe3"),
    BigInt("0x793a43c843f2c879"), BigInt("0xb69a2ced2c77edb6"),
    BigInt("0xd40dd9bed9b3bed4"), BigInt("0x8d47ca46ca01468d"),
    BigInt("0x671770d970ced967"), BigInt("0x72afdd4bdde44b72"),
    BigInt("0x94ed79de7933de94"), BigInt("0x98ff67d4672bd498"),
    BigInt("0xb09323e8237be8b0"), BigInt("0x855bde4ade114a85"),
    BigInt("0xbb06bd6bbd6d6bbb"), BigInt("0xc5bb7e2a7e912ac5"),
    BigInt("0x4f7b34e5349ee54f"), BigInt("0xedd73a163ac116ed"),
    BigInt("0x86d254c55417c586"), BigInt("0x9af862d7622fd79a"),
    BigInt("0x6699ff55ffcc5566"), BigInt("0x11b6a794a7229411"),
    BigInt("0x8ac04acf4a0fcf8a"), BigInt("0xe9d9301030c910e9"),
    BigInt("0x040e0a060a080604"), BigInt("0xfe66988198e781fe"),
    BigInt("0xa0ab0bf00b5bf0a0"), BigInt("0x78b4cc44ccf04478"),
    BigInt("0x25f0d5bad54aba25"), BigInt("0x4b753ee33e96e34b"),
    BigInt("0xa2ac0ef30e5ff3a2"), BigInt("0x5d4419fe19bafe5d"),
    BigInt("0x80db5bc05b1bc080"), BigInt("0x0580858a850a8a05"),
    BigInt("0x3fd3ecadec7ead3f"), BigInt("0x21fedfbcdf42bc21"),
    BigInt("0x70a8d848d8e04870"), BigInt("0xf1fd0c040cf904f1"),
    BigInt("0x63197adf7ac6df63"), BigInt("0x772f58c158eec177"),
    BigInt("0xaf309f759f4575af"), BigInt("0x42e7a563a5846342"),
    BigInt("0x2070503050403020"), BigInt("0xe5cb2e1a2ed11ae5"),
    BigInt("0xfdef120e12e10efd"), BigInt("0xbf08b76db7656dbf"),
    BigInt("0x8155d44cd4194c81"), BigInt("0x18243c143c301418"),
    BigInt("0x26795f355f4c3526"), BigInt("0xc3b2712f719d2fc3"),
    BigInt("0xbe8638e13867e1be"), BigInt("0x35c8fda2fd6aa235"),
    BigInt("0x88c74fcc4f0bcc88"), BigInt("0x2e654b394b5c392e"),
    BigInt("0x936af957f93d5793"), BigInt("0x55580df20daaf255"),
    BigInt("0xfc619d829de382fc"), BigInt("0x7ab3c947c9f4477a"),
    BigInt("0xc827efacef8bacc8"), BigInt("0xba8832e7326fe7ba"),
    BigInt("0x324f7d2b7d642b32"), BigInt("0xe642a495a4d795e6"),
    BigInt("0xc03bfba0fb9ba0c0"), BigInt("0x19aab398b3329819"),
    BigInt("0x9ef668d16827d19e"), BigInt("0xa322817f815d7fa3"),
    BigInt("0x44eeaa66aa886644"), BigInt("0x54d6827e82a87e54"),
    BigInt("0x3bdde6abe676ab3b"), BigInt("0x0b959e839e16830b"),
    BigInt("0x8cc945ca4503ca8c"), BigInt("0xc7bc7b297b9529c7"),
    BigInt("0x6b056ed36ed6d36b"), BigInt("0x286c443c44503c28"),
    BigInt("0xa72c8b798b5579a7"), BigInt("0xbc813de23d63e2bc"),
    BigInt("0x1631271d272c1d16"), BigInt("0xad379a769a4176ad"),
    BigInt("0xdb964d3b4dad3bdb"), BigInt("0x649efa56fac85664"),
    BigInt("0x74a6d24ed2e84e74"), BigInt("0x1436221e22281e14"),
    BigInt("0x92e476db763fdb92"), BigInt("0x0c121e0a1e180a0c"),
    BigInt("0x48fcb46cb4906c48"), BigInt("0xb88f37e4376be4b8"),
    BigInt("0x9f78e75de7255d9f"), BigInt("0xbd0fb26eb2616ebd"),
    BigInt("0x43692aef2a86ef43"), BigInt("0xc435f1a6f193a6c4"),
    BigInt("0x39dae3a8e372a839"), BigInt("0x31c6f7a4f762a431"),
    BigInt("0xd38a593759bd37d3"), BigInt("0xf274868b86ff8bf2"),
    BigInt("0xd583563256b132d5"), BigInt("0x8b4ec543c50d438b"),
    BigInt("0x6e85eb59ebdc596e"), BigInt("0xda18c2b7c2afb7da"),
    BigInt("0x018e8f8c8f028c01"), BigInt("0xb11dac64ac7964b1"),
    BigInt("0x9cf16dd26d23d29c"), BigInt("0x49723be03b92e049"),
    BigInt("0xd81fc7b4c7abb4d8"), BigInt("0xacb915fa1543faac"),
    BigInt("0xf3fa090709fd07f3"), BigInt("0xcfa06f256f8525cf"),
    BigInt("0xca20eaafea8fafca"), BigInt("0xf47d898e89f38ef4"),
    BigInt("0x476720e9208ee947"), BigInt("0x1038281828201810"),
    BigInt("0x6f0b64d564ded56f"), BigInt("0xf073838883fb88f0"),
    BigInt("0x4afbb16fb1946f4a"), BigInt("0x5cca967296b8725c"),
    BigInt("0x38546c246c702438"), BigInt("0x575f08f108aef157"),
    BigInt("0x732152c752e6c773"), BigInt("0x9764f351f3355197"),
    BigInt("0xcbae6523658d23cb"), BigInt("0xa125847c84597ca1"),
    BigInt("0xe857bf9cbfcb9ce8"), BigInt("0x3e5d6321637c213e"),
    BigInt("0x96ea7cdd7c37dd96"), BigInt("0x611e7fdc7fc2dc61"),
    BigInt("0x0d9c9186911a860d"), BigInt("0x0f9b9485941e850f"),
    BigInt("0xe04bab90abdb90e0"), BigInt("0x7cbac642c6f8427c"),
    BigInt("0x712657c457e2c471"), BigInt("0xcc29e5aae583aacc"),
    BigInt("0x90e373d8733bd890"), BigInt("0x06090f050f0c0506"),
    BigInt("0xf7f4030103f501f7"), BigInt("0x1c2a36123638121c"),
    BigInt("0xc23cfea3fe9fa3c2"), BigInt("0x6a8be15fe1d45f6a"),
    BigInt("0xaebe10f91047f9ae"), BigInt("0x69026bd06bd2d069"),
    BigInt("0x17bfa891a82e9117"), BigInt("0x9971e858e8295899"),
    BigInt("0x3a5369276974273a"), BigInt("0x27f7d0b9d04eb927"),
    BigInt("0xd991483848a938d9"), BigInt("0xebde351335cd13eb"),
    BigInt("0x2be5ceb3ce56b32b"), BigInt("0x2277553355443322"),
    BigInt("0xd204d6bbd6bfbbd2"), BigInt("0xa9399070904970a9"),
    BigInt("0x07878089800e8907"), BigInt("0x33c1f2a7f266a733"),
    BigInt("0x2decc1b6c15ab62d"), BigInt("0x3c5a66226678223c"),
    BigInt("0x15b8ad92ad2a9215"), BigInt("0xc9a96020608920c9"),
    BigInt("0x875cdb49db154987"), BigInt("0xaab01aff1a4fffaa"),
    BigInt("0x50d8887888a07850"), BigInt("0xa52b8e7a8e517aa5"),
    BigInt("0x03898a8f8a068f03"), BigInt("0x594a13f813b2f859"),
    BigInt("0x09929b809b128009"), BigInt("0x1a2339173934171a"),
    BigInt("0x651075da75cada65"), BigInt("0xd784533153b531d7"),
    BigInt("0x84d551c65113c684"), BigInt("0xd003d3b8d3bbb8d0"),
    BigInt("0x82dc5ec35e1fc382"), BigInt("0x29e2cbb0cb52b029"),
    BigInt("0x5ac3997799b4775a"), BigInt("0x1e2d3311333c111e"),
    BigInt("0x7b3d46cb46f6cb7b"), BigInt("0xa8b71ffc1f4bfca8"),
    BigInt("0x6d0c61d661dad66d"), BigInt("0x2c624e3a4e583a2c")
]);
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
class Groestl224 extends GroestlSmallCore {
    /**
     * Create the engine.
     */
    constructor() {
        super();
    }
    /** @see Digest */
    getDigestLength() {
        return 28;
    }
    /** @see Digest */
    copy() {
        return this.copyState(new Groestl224());
    }
}
exports.Groestl224 = Groestl224;
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
class Groestl256 extends GroestlSmallCore {
    /**
     * Create the engine.
     */
    constructor() {
        super();
    }
    /** @see Digest */
    getDigestLength() {
        return 32;
    }
    /** @see Digest */
    copy() {
        return this.copyState(new Groestl256());
    }
}
exports.Groestl256 = Groestl256;
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
class Groestl384 extends GroestlBigCore {
    /**
     * Create the engine.
     */
    constructor() {
        super();
    }
    /** @see Digest */
    getDigestLength() {
        return 48;
    }
    /** @see Digest */
    copy() {
        return this.copyState(new Groestl384());
    }
}
exports.Groestl384 = Groestl384;
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
class Groestl512 extends GroestlBigCore {
    /**
     * Create the engine.
     */
    constructor() {
        super();
    }
    /** @see Digest */
    getDigestLength() {
        return 64;
    }
    /** @see Digest */
    copy() {
        return this.copyState(new Groestl512());
    }
}
exports.Groestl512 = Groestl512;
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
 * Creates a vary byte length Grøstl of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {224 | 256 | 384 | 512} bitLen - length of hash (default 512 bits AKA 64 bytes)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function _GROESTL(message, bitLen = 512, format = arrayType()) {
    var hash;
    switch (bitLen) {
        case 224:
            hash = new Groestl224();
            break;
        case 256:
            hash = new Groestl256();
            break;
        case 384:
            hash = new Groestl384();
            break;
        case 512:
            hash = new Groestl512();
            break;
        default:
            hash = new Groestl512();
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
exports._GROESTL = _GROESTL;
;
/**
 * Creates a vary byte length keyed Grøstl of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {224 | 256 | 384 | 512} bitLen - length of hash (default 512 bits AKA 64 bytes)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function GROESTL_HMAC(message, key, bitLen = 512, format = arrayType()) {
    var hash;
    switch (bitLen) {
        case 224:
            hash = new Groestl224();
            break;
        case 256:
            hash = new Groestl256();
            break;
        case 384:
            hash = new Groestl384();
            break;
        case 512:
            hash = new Groestl512();
            break;
        default:
            hash = new Groestl512();
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
exports.GROESTL_HMAC = GROESTL_HMAC;
;
/**
 * Creates a 28 byte Grøstl of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function GROESTL224(message, format = arrayType()) {
    const hash = new Groestl224();
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
exports.GROESTL224 = GROESTL224;
;
/**
 * Creates a 28 byte keyed Grøstl of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function GROESTL224_HMAC(message, key, format = arrayType()) {
    const hash = new Groestl224();
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
exports.GROESTL224_HMAC = GROESTL224_HMAC;
;
/**
 * Creates a 32 byte Grøstl of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function GROESTL256(message, format = arrayType()) {
    const hash = new Groestl256();
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
exports.GROESTL256 = GROESTL256;
;
/**
 * Creates a 32 byte keyed Grøstl of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function GROESTL256_HMAC(message, key, format = arrayType()) {
    const hash = new Groestl256();
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
exports.GROESTL256_HMAC = GROESTL256_HMAC;
;
/**
 * Creates a 48 byte Grøstl of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function GROESTL384(message, format = arrayType()) {
    const hash = new Groestl384();
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
exports.GROESTL384 = GROESTL384;
;
/**
 * Creates a 48 byte keyed Grøstl of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function GROESTL384_HMAC(message, key, format = arrayType()) {
    const hash = new Groestl384();
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
exports.GROESTL384_HMAC = GROESTL384_HMAC;
;
/**
 * Creates a 64 byte Grøstl of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function GROESTL512(message, format = arrayType()) {
    const hash = new Groestl512();
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
exports.GROESTL512 = GROESTL512;
;
/**
 * Creates a 64 byte keyed Grøstl of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function GROESTL512_HMAC(message, key, format = arrayType()) {
    const hash = new Groestl512();
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
exports.GROESTL512_HMAC = GROESTL512_HMAC;
;
/**
 * Static class of all Grøstl functions and classes
 */
class GROESTL {
    /**
     * List of all hashes in class
     */
    static get FUNCTION_LIST() {
        return [
            "GROESTL",
            "GROESTL224",
            "GROESTL224_HMAC",
            "GROESTL2256",
            "GROESTL2256_HMAC",
            "GROESTL384",
            "GROESTL384_HMAC",
            "GROESTL512",
            "GROESTL512_HMAC",
            "GROESTL_HMAC"
        ];
    }
}
exports.GROESTL = GROESTL;
GROESTL.GROESTL = _GROESTL;
GROESTL.Groestl224 = Groestl224;
GROESTL.GROESTL224 = GROESTL224;
GROESTL.GROESTL224_HMAC = GROESTL224_HMAC;
GROESTL.Groestl256 = Groestl256;
GROESTL.GROESTL256 = GROESTL256;
GROESTL.GROESTL256_HMAC = GROESTL256_HMAC;
GROESTL.Groestl384 = Groestl384;
GROESTL.GROESTL384 = GROESTL384;
GROESTL.GROESTL384_HMAC = GROESTL384_HMAC;
GROESTL.Groestl512 = Groestl512;
GROESTL.GROESTL512 = GROESTL512;
GROESTL.GROESTL512_HMAC = GROESTL512_HMAC;
GROESTL.GROESTL_HMAC = GROESTL_HMAC;
//# sourceMappingURL=GROESTL.js.map