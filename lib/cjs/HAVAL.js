"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.HAVAL256_3 = exports.HAVAL256_HMAC = exports.HAVAL256 = exports.HAVAL224_5_HMAC = exports.HAVAL224_5 = exports.HAVAL224_4_HMAC = exports.HAVAL224_4 = exports.HAVAL224_3_HMAC = exports.HAVAL224_3 = exports.HAVAL224_HMAC = exports.HAVAL224 = exports.HAVAL192_5_HMAC = exports.HAVAL192_5 = exports.HAVAL192_4_HMAC = exports.HAVAL192_4 = exports.HAVAL192_3_HMAC = exports.HAVAL192_3 = exports.HAVAL192_HMAC = exports.HAVAL192 = exports.HAVAL160_5_HMAC = exports.HAVAL160_5 = exports.HAVAL160_4_HMAC = exports.HAVAL160_4 = exports.HAVAL160_3_HMAC = exports.HAVAL160_3 = exports.HAVAL160_HMAC = exports.HAVAL160 = exports.HAVAL128_5_HMAC = exports.HAVAL128_5 = exports.HAVAL128_4_HMAC = exports.HAVAL128_4 = exports.HAVAL128_3_HMAC = exports.HAVAL128_3 = exports.HAVAL128_HMAC = exports.HAVAL128 = exports.Haval256_5 = exports.Haval256_4 = exports.Haval256_3 = exports.Haval224_5 = exports.Haval224_4 = exports.Haval224_3 = exports.Haval192_5 = exports.Haval192_4 = exports.Haval192_3 = exports.Haval160_5 = exports.Haval160_4 = exports.Haval160_3 = exports.Haval128_5 = exports.Haval128_4 = exports.Haval128_3 = void 0;
exports.HAVAL = exports.HAVAL_HMAC = exports._HAVAL = exports.HAVAL256_5_HMAC = exports.HAVAL256_5 = exports.HAVAL256_4_HMAC = exports.HAVAL256_4 = exports.HAVAL256_3_HMAC = void 0;
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
class HAVALCore extends DigestEngine {
    /**
     * Create the object.
     *
     * @param outputLength   output length (in bits)
     * @param passes         number of passes (3, 4 or 5)
     */
    constructor(outputLength, passes) {
        super();
        this.olen = outputLength >> 5;
        this.passes = passes;
    }
    /** @see DigestEngine */
    copyState(dst) {
        dst.olen = this.olen;
        dst.passes = this.passes;
        dst.s = this.s;
        return super.copyState(dst);
    }
    /** @see Digest */
    getBlockLength() {
        return 128;
    }
    /** @see DigestEngine */
    engineReset() {
        this.s = new Int32Array(8);
        this.s[0] = 0x243F6A88;
        this.s[1] = 0x85A308D3;
        this.s[2] = 0x13198A2E;
        this.s[3] = 0x03707344;
        this.s[4] = 0xA4093822;
        this.s[5] = 0x299F31D0;
        this.s[6] = 0x082EFA98;
        this.s[7] = 0xEC4E6C89;
    }
    /** @see DigestEngine */
    doPadding(output, outputOffset) {
        var dataLen = this.flush();
        var currentLength = ((this.getBlockCount() << BigInt(7)) + BigInt(dataLen)) << BigInt(3);
        this.padBuf[0] = (0x01 | (this.passes << 3));
        this.padBuf[1] = (this.olen << 3) & 0xFF;
        this.encodeLEInt(Number(currentLength), this.padBuf, 2);
        this.encodeLEInt(Number(currentLength >> BigInt(32)), this.padBuf, 6);
        var endLen = (dataLen + 138) & ~127;
        this.update(0x01);
        for (let i = dataLen + 1; i < (endLen - 10); i++) {
            this.update(0);
        }
        this.update(this.padBuf);
        /*
         * This code is used only for debugging purposes.
         *
        if (flush() != 0)
            throw new Error("panic: buffering went astray");
         *
         */
        this.writeOutput(output, outputOffset);
    }
    /** @see DigestEngine */
    doInit() {
        this.padBuf = new Uint8Array(10);
        this.inw = new Int32Array(32);
        this.engineReset();
    }
    /**
     * Encode the 32-bit word {@code val} into the array
     * {@code buf} at offset {@code buf}, in little-endian
     * convention (least significant byte first).
     *
     * @param val   the value to encode
     * @param buf   the destination buffer
     * @param off   the destination offset
     */
    encodeLEInt(val, buf, off) {
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
    decodeLEInt(buf, off) {
        return ((buf[off + 3] & 0xFF) << 24)
            | ((buf[off + 2] & 0xFF) << 16)
            | ((buf[off + 1] & 0xFF) << 8)
            | (buf[off + 0] & 0xFF);
    }
    /**
     * Circular rotation of a 32-bit word to the left. The rotation
     * count must lie between 1 and 31 (inclusive).
     *
     * @param x   the value to rotate
     * @param n   the rotation count
     * @return  the rotated value
     */
    circularLeft(x, n) {
        return (x << n) | (x >>> (32 - n));
    }
    /** @see DigestEngine */
    processBlock(data) {
        for (let i = 0; i < 32; i++) {
            this.inw[i] = this.decodeLEInt(data, 4 * i);
        }
        var save0 = this.s[0];
        var save1 = this.s[1];
        var save2 = this.s[2];
        var save3 = this.s[3];
        var save4 = this.s[4];
        var save5 = this.s[5];
        var save6 = this.s[6];
        var save7 = this.s[7];
        switch (this.passes) {
            case 3:
                this.pass31(this.inw);
                this.pass32(this.inw);
                this.pass33(this.inw);
                break;
            case 4:
                this.pass41(this.inw);
                this.pass42(this.inw);
                this.pass43(this.inw);
                this.pass44(this.inw);
                break;
            case 5:
                this.pass51(this.inw);
                this.pass52(this.inw);
                this.pass53(this.inw);
                this.pass54(this.inw);
                this.pass55(this.inw);
                break;
        }
        this.s[0] += save0;
        this.s[1] += save1;
        this.s[2] += save2;
        this.s[3] += save3;
        this.s[4] += save4;
        this.s[5] += save5;
        this.s[6] += save6;
        this.s[7] += save7;
    }
    F1(x6, x5, x4, x3, x2, x1, x0) {
        return (x1 & x4) ^ (x2 & x5) ^ (x3 & x6) ^ (x0 & x1) ^ x0;
    }
    F2(x6, x5, x4, x3, x2, x1, x0) {
        return (x2 & ((x1 & ~x3) ^ (x4 & x5) ^ x6 ^ x0))
            ^ (x4 & (x1 ^ x5)) ^ ((x3 & x5) ^ x0);
    }
    F3(x6, x5, x4, x3, x2, x1, x0) {
        return (x3 & ((x1 & x2) ^ x6 ^ x0))
            ^ (x1 & x4) ^ (x2 & x5) ^ x0;
    }
    F4(x6, x5, x4, x3, x2, x1, x0) {
        return (x3 & ((x1 & x2) ^ (x4 | x6) ^ x5))
            ^ (x4 & ((~x2 & x5) ^ x1 ^ x6 ^ x0)) ^ (x2 & x6) ^ x0;
    }
    F5(x6, x5, x4, x3, x2, x1, x0) {
        return (x0 & ~((x1 & x2 & x3) ^ x5))
            ^ (x1 & x4) ^ (x2 & x5) ^ (x3 & x6);
    }
    pass31(inw) {
        const x = new Int32Array(8);
        x[0] = this.s[0], x[1] = this.s[1], x[2] = this.s[2], x[3] = this.s[3];
        x[4] = this.s[4], x[5] = this.s[5], x[6] = this.s[6], x[7] = this.s[7];
        for (let i = 0; i < 32; i += 8) {
            x[7] = this.circularLeft(this.F1(x[1], x[0], x[3], x[5], x[6], x[2], x[4]), 25)
                + this.circularLeft(x[7], 21) + inw[i + 0];
            x[6] = this.circularLeft(this.F1(x[0], x[7], x[2], x[4], x[5], x[1], x[3]), 25)
                + this.circularLeft(x[6], 21) + inw[i + 1];
            x[5] = this.circularLeft(this.F1(x[7], x[6], x[1], x[3], x[4], x[0], x[2]), 25)
                + this.circularLeft(x[5], 21) + inw[i + 2];
            x[4] = this.circularLeft(this.F1(x[6], x[5], x[0], x[2], x[3], x[7], x[1]), 25)
                + this.circularLeft(x[4], 21) + inw[i + 3];
            x[3] = this.circularLeft(this.F1(x[5], x[4], x[7], x[1], x[2], x[6], x[0]), 25)
                + this.circularLeft(x[3], 21) + inw[i + 4];
            x[2] = this.circularLeft(this.F1(x[4], x[3], x[6], x[0], x[1], x[5], x[7]), 25)
                + this.circularLeft(x[2], 21) + inw[i + 5];
            x[1] = this.circularLeft(this.F1(x[3], x[2], x[5], x[7], x[0], x[4], x[6]), 25)
                + this.circularLeft(x[1], 21) + inw[i + 6];
            x[0] = this.circularLeft(this.F1(x[2], x[1], x[4], x[6], x[7], x[3], x[5]), 25)
                + this.circularLeft(x[0], 21) + inw[i + 7];
        }
        this.s[0] = x[0];
        this.s[1] = x[1];
        this.s[2] = x[2];
        this.s[3] = x[3];
        this.s[4] = x[4];
        this.s[5] = x[5];
        this.s[6] = x[6];
        this.s[7] = x[7];
    }
    pass32(inw) {
        const x = new Int32Array(8);
        x[0] = this.s[0], x[1] = this.s[1], x[2] = this.s[2], x[3] = this.s[3];
        x[4] = this.s[4], x[5] = this.s[5], x[6] = this.s[6], x[7] = this.s[7];
        for (let i = 0; i < 32; i += 8) {
            x[7] = this.circularLeft(this.F2(x[4], x[2], x[1], x[0], x[5], x[3], x[6]), 25)
                + this.circularLeft(x[7], 21)
                + inw[HAVALCore.wp2[i + 0]] + HAVALCore.K2[i + 0];
            x[6] = this.circularLeft(this.F2(x[3], x[1], x[0], x[7], x[4], x[2], x[5]), 25)
                + this.circularLeft(x[6], 21)
                + inw[HAVALCore.wp2[i + 1]] + HAVALCore.K2[i + 1];
            x[5] = this.circularLeft(this.F2(x[2], x[0], x[7], x[6], x[3], x[1], x[4]), 25)
                + this.circularLeft(x[5], 21)
                + inw[HAVALCore.wp2[i + 2]] + HAVALCore.K2[i + 2];
            x[4] = this.circularLeft(this.F2(x[1], x[7], x[6], x[5], x[2], x[0], x[3]), 25)
                + this.circularLeft(x[4], 21)
                + inw[HAVALCore.wp2[i + 3]] + HAVALCore.K2[i + 3];
            x[3] = this.circularLeft(this.F2(x[0], x[6], x[5], x[4], x[1], x[7], x[2]), 25)
                + this.circularLeft(x[3], 21)
                + inw[HAVALCore.wp2[i + 4]] + HAVALCore.K2[i + 4];
            x[2] = this.circularLeft(this.F2(x[7], x[5], x[4], x[3], x[0], x[6], x[1]), 25)
                + this.circularLeft(x[2], 21)
                + inw[HAVALCore.wp2[i + 5]] + HAVALCore.K2[i + 5];
            x[1] = this.circularLeft(this.F2(x[6], x[4], x[3], x[2], x[7], x[5], x[0]), 25)
                + this.circularLeft(x[1], 21)
                + inw[HAVALCore.wp2[i + 6]] + HAVALCore.K2[i + 6];
            x[0] = this.circularLeft(this.F2(x[5], x[3], x[2], x[1], x[6], x[4], x[7]), 25)
                + this.circularLeft(x[0], 21)
                + inw[HAVALCore.wp2[i + 7]] + HAVALCore.K2[i + 7];
        }
        this.s[0] = x[0];
        this.s[1] = x[1];
        this.s[2] = x[2];
        this.s[3] = x[3];
        this.s[4] = x[4];
        this.s[5] = x[5];
        this.s[6] = x[6];
        this.s[7] = x[7];
    }
    pass33(inw) {
        const x = new Int32Array(8);
        x[0] = this.s[0], x[1] = this.s[1], x[2] = this.s[2], x[3] = this.s[3];
        x[4] = this.s[4], x[5] = this.s[5], x[6] = this.s[6], x[7] = this.s[7];
        for (let i = 0; i < 32; i += 8) {
            x[7] = this.circularLeft(this.F3(x[6], x[1], x[2], x[3], x[4], x[5], x[0]), 25)
                + this.circularLeft(x[7], 21)
                + inw[HAVALCore.wp3[i + 0]] + HAVALCore.K3[i + 0];
            x[6] = this.circularLeft(this.F3(x[5], x[0], x[1], x[2], x[3], x[4], x[7]), 25)
                + this.circularLeft(x[6], 21)
                + inw[HAVALCore.wp3[i + 1]] + HAVALCore.K3[i + 1];
            x[5] = this.circularLeft(this.F3(x[4], x[7], x[0], x[1], x[2], x[3], x[6]), 25)
                + this.circularLeft(x[5], 21)
                + inw[HAVALCore.wp3[i + 2]] + HAVALCore.K3[i + 2];
            x[4] = this.circularLeft(this.F3(x[3], x[6], x[7], x[0], x[1], x[2], x[5]), 25)
                + this.circularLeft(x[4], 21)
                + inw[HAVALCore.wp3[i + 3]] + HAVALCore.K3[i + 3];
            x[3] = this.circularLeft(this.F3(x[2], x[5], x[6], x[7], x[0], x[1], x[4]), 25)
                + this.circularLeft(x[3], 21)
                + inw[HAVALCore.wp3[i + 4]] + HAVALCore.K3[i + 4];
            x[2] = this.circularLeft(this.F3(x[1], x[4], x[5], x[6], x[7], x[0], x[3]), 25)
                + this.circularLeft(x[2], 21)
                + inw[HAVALCore.wp3[i + 5]] + HAVALCore.K3[i + 5];
            x[1] = this.circularLeft(this.F3(x[0], x[3], x[4], x[5], x[6], x[7], x[2]), 25)
                + this.circularLeft(x[1], 21)
                + inw[HAVALCore.wp3[i + 6]] + HAVALCore.K3[i + 6];
            x[0] = this.circularLeft(this.F3(x[7], x[2], x[3], x[4], x[5], x[6], x[1]), 25)
                + this.circularLeft(x[0], 21)
                + inw[HAVALCore.wp3[i + 7]] + HAVALCore.K3[i + 7];
        }
        this.s[0] = x[0];
        this.s[1] = x[1];
        this.s[2] = x[2];
        this.s[3] = x[3];
        this.s[4] = x[4];
        this.s[5] = x[5];
        this.s[6] = x[6];
        this.s[7] = x[7];
    }
    pass41(inw) {
        const x = new Int32Array(8);
        x[0] = this.s[0], x[1] = this.s[1], x[2] = this.s[2], x[3] = this.s[3];
        x[4] = this.s[4], x[5] = this.s[5], x[6] = this.s[6], x[7] = this.s[7];
        for (let i = 0; i < 32; i += 8) {
            x[7] = this.circularLeft(this.F1(x[2], x[6], x[1], x[4], x[5], x[3], x[0]), 25)
                + this.circularLeft(x[7], 21) + inw[i + 0];
            x[6] = this.circularLeft(this.F1(x[1], x[5], x[0], x[3], x[4], x[2], x[7]), 25)
                + this.circularLeft(x[6], 21) + inw[i + 1];
            x[5] = this.circularLeft(this.F1(x[0], x[4], x[7], x[2], x[3], x[1], x[6]), 25)
                + this.circularLeft(x[5], 21) + inw[i + 2];
            x[4] = this.circularLeft(this.F1(x[7], x[3], x[6], x[1], x[2], x[0], x[5]), 25)
                + this.circularLeft(x[4], 21) + inw[i + 3];
            x[3] = this.circularLeft(this.F1(x[6], x[2], x[5], x[0], x[1], x[7], x[4]), 25)
                + this.circularLeft(x[3], 21) + inw[i + 4];
            x[2] = this.circularLeft(this.F1(x[5], x[1], x[4], x[7], x[0], x[6], x[3]), 25)
                + this.circularLeft(x[2], 21) + inw[i + 5];
            x[1] = this.circularLeft(this.F1(x[4], x[0], x[3], x[6], x[7], x[5], x[2]), 25)
                + this.circularLeft(x[1], 21) + inw[i + 6];
            x[0] = this.circularLeft(this.F1(x[3], x[7], x[2], x[5], x[6], x[4], x[1]), 25)
                + this.circularLeft(x[0], 21) + inw[i + 7];
        }
        this.s[0] = x[0];
        this.s[1] = x[1];
        this.s[2] = x[2];
        this.s[3] = x[3];
        this.s[4] = x[4];
        this.s[5] = x[5];
        this.s[6] = x[6];
        this.s[7] = x[7];
    }
    pass42(inw) {
        const x = new Int32Array(8);
        x[0] = this.s[0], x[1] = this.s[1], x[2] = this.s[2], x[3] = this.s[3];
        x[4] = this.s[4], x[5] = this.s[5], x[6] = this.s[6], x[7] = this.s[7];
        for (let i = 0; i < 32; i += 8) {
            x[7] = this.circularLeft(this.F2(x[3], x[5], x[2], x[0], x[1], x[6], x[4]), 25)
                + this.circularLeft(x[7], 21)
                + inw[HAVALCore.wp2[i + 0]] + HAVALCore.K2[i + 0];
            x[6] = this.circularLeft(this.F2(x[2], x[4], x[1], x[7], x[0], x[5], x[3]), 25)
                + this.circularLeft(x[6], 21)
                + inw[HAVALCore.wp2[i + 1]] + HAVALCore.K2[i + 1];
            x[5] = this.circularLeft(this.F2(x[1], x[3], x[0], x[6], x[7], x[4], x[2]), 25)
                + this.circularLeft(x[5], 21)
                + inw[HAVALCore.wp2[i + 2]] + HAVALCore.K2[i + 2];
            x[4] = this.circularLeft(this.F2(x[0], x[2], x[7], x[5], x[6], x[3], x[1]), 25)
                + this.circularLeft(x[4], 21)
                + inw[HAVALCore.wp2[i + 3]] + HAVALCore.K2[i + 3];
            x[3] = this.circularLeft(this.F2(x[7], x[1], x[6], x[4], x[5], x[2], x[0]), 25)
                + this.circularLeft(x[3], 21)
                + inw[HAVALCore.wp2[i + 4]] + HAVALCore.K2[i + 4];
            x[2] = this.circularLeft(this.F2(x[6], x[0], x[5], x[3], x[4], x[1], x[7]), 25)
                + this.circularLeft(x[2], 21)
                + inw[HAVALCore.wp2[i + 5]] + HAVALCore.K2[i + 5];
            x[1] = this.circularLeft(this.F2(x[5], x[7], x[4], x[2], x[3], x[0], x[6]), 25)
                + this.circularLeft(x[1], 21)
                + inw[HAVALCore.wp2[i + 6]] + HAVALCore.K2[i + 6];
            x[0] = this.circularLeft(this.F2(x[4], x[6], x[3], x[1], x[2], x[7], x[5]), 25)
                + this.circularLeft(x[0], 21)
                + inw[HAVALCore.wp2[i + 7]] + HAVALCore.K2[i + 7];
        }
        this.s[0] = x[0];
        this.s[1] = x[1];
        this.s[2] = x[2];
        this.s[3] = x[3];
        this.s[4] = x[4];
        this.s[5] = x[5];
        this.s[6] = x[6];
        this.s[7] = x[7];
    }
    pass43(inw) {
        const x = new Int32Array(8);
        x[0] = this.s[0], x[1] = this.s[1], x[2] = this.s[2], x[3] = this.s[3];
        x[4] = this.s[4], x[5] = this.s[5], x[6] = this.s[6], x[7] = this.s[7];
        for (let i = 0; i < 32; i += 8) {
            x[7] = this.circularLeft(this.F3(x[1], x[4], x[3], x[6], x[0], x[2], x[5]), 25)
                + this.circularLeft(x[7], 21)
                + inw[HAVALCore.wp3[i + 0]] + HAVALCore.K3[i + 0];
            x[6] = this.circularLeft(this.F3(x[0], x[3], x[2], x[5], x[7], x[1], x[4]), 25)
                + this.circularLeft(x[6], 21)
                + inw[HAVALCore.wp3[i + 1]] + HAVALCore.K3[i + 1];
            x[5] = this.circularLeft(this.F3(x[7], x[2], x[1], x[4], x[6], x[0], x[3]), 25)
                + this.circularLeft(x[5], 21)
                + inw[HAVALCore.wp3[i + 2]] + HAVALCore.K3[i + 2];
            x[4] = this.circularLeft(this.F3(x[6], x[1], x[0], x[3], x[5], x[7], x[2]), 25)
                + this.circularLeft(x[4], 21)
                + inw[HAVALCore.wp3[i + 3]] + HAVALCore.K3[i + 3];
            x[3] = this.circularLeft(this.F3(x[5], x[0], x[7], x[2], x[4], x[6], x[1]), 25)
                + this.circularLeft(x[3], 21)
                + inw[HAVALCore.wp3[i + 4]] + HAVALCore.K3[i + 4];
            x[2] = this.circularLeft(this.F3(x[4], x[7], x[6], x[1], x[3], x[5], x[0]), 25)
                + this.circularLeft(x[2], 21)
                + inw[HAVALCore.wp3[i + 5]] + HAVALCore.K3[i + 5];
            x[1] = this.circularLeft(this.F3(x[3], x[6], x[5], x[0], x[2], x[4], x[7]), 25)
                + this.circularLeft(x[1], 21)
                + inw[HAVALCore.wp3[i + 6]] + HAVALCore.K3[i + 6];
            x[0] = this.circularLeft(this.F3(x[2], x[5], x[4], x[7], x[1], x[3], x[6]), 25)
                + this.circularLeft(x[0], 21)
                + inw[HAVALCore.wp3[i + 7]] + HAVALCore.K3[i + 7];
        }
        this.s[0] = x[0];
        this.s[1] = x[1];
        this.s[2] = x[2];
        this.s[3] = x[3];
        this.s[4] = x[4];
        this.s[5] = x[5];
        this.s[6] = x[6];
        this.s[7] = x[7];
    }
    pass44(inw) {
        const x = new Int32Array(8);
        x[0] = this.s[0], x[1] = this.s[1], x[2] = this.s[2], x[3] = this.s[3];
        x[4] = this.s[4], x[5] = this.s[5], x[6] = this.s[6], x[7] = this.s[7];
        for (let i = 0; i < 32; i += 8) {
            x[7] = this.circularLeft(this.F4(x[6], x[4], x[0], x[5], x[2], x[1], x[3]), 25)
                + this.circularLeft(x[7], 21)
                + inw[HAVALCore.wp4[i + 0]] + HAVALCore.K4[i + 0];
            x[6] = this.circularLeft(this.F4(x[5], x[3], x[7], x[4], x[1], x[0], x[2]), 25)
                + this.circularLeft(x[6], 21)
                + inw[HAVALCore.wp4[i + 1]] + HAVALCore.K4[i + 1];
            x[5] = this.circularLeft(this.F4(x[4], x[2], x[6], x[3], x[0], x[7], x[1]), 25)
                + this.circularLeft(x[5], 21)
                + inw[HAVALCore.wp4[i + 2]] + HAVALCore.K4[i + 2];
            x[4] = this.circularLeft(this.F4(x[3], x[1], x[5], x[2], x[7], x[6], x[0]), 25)
                + this.circularLeft(x[4], 21)
                + inw[HAVALCore.wp4[i + 3]] + HAVALCore.K4[i + 3];
            x[3] = this.circularLeft(this.F4(x[2], x[0], x[4], x[1], x[6], x[5], x[7]), 25)
                + this.circularLeft(x[3], 21)
                + inw[HAVALCore.wp4[i + 4]] + HAVALCore.K4[i + 4];
            x[2] = this.circularLeft(this.F4(x[1], x[7], x[3], x[0], x[5], x[4], x[6]), 25)
                + this.circularLeft(x[2], 21)
                + inw[HAVALCore.wp4[i + 5]] + HAVALCore.K4[i + 5];
            x[1] = this.circularLeft(this.F4(x[0], x[6], x[2], x[7], x[4], x[3], x[5]), 25)
                + this.circularLeft(x[1], 21)
                + inw[HAVALCore.wp4[i + 6]] + HAVALCore.K4[i + 6];
            x[0] = this.circularLeft(this.F4(x[7], x[5], x[1], x[6], x[3], x[2], x[4]), 25)
                + this.circularLeft(x[0], 21)
                + inw[HAVALCore.wp4[i + 7]] + HAVALCore.K4[i + 7];
        }
        this.s[0] = x[0];
        this.s[1] = x[1];
        this.s[2] = x[2];
        this.s[3] = x[3];
        this.s[4] = x[4];
        this.s[5] = x[5];
        this.s[6] = x[6];
        this.s[7] = x[7];
    }
    pass51(inw) {
        const x = new Int32Array(8);
        x[0] = this.s[0], x[1] = this.s[1], x[2] = this.s[2], x[3] = this.s[3];
        x[4] = this.s[4], x[5] = this.s[5], x[6] = this.s[6], x[7] = this.s[7];
        for (let i = 0; i < 32; i += 8) {
            x[7] = this.circularLeft(this.F1(x[3], x[4], x[1], x[0], x[5], x[2], x[6]), 25)
                + this.circularLeft(x[7], 21) + inw[i + 0];
            x[6] = this.circularLeft(this.F1(x[2], x[3], x[0], x[7], x[4], x[1], x[5]), 25)
                + this.circularLeft(x[6], 21) + inw[i + 1];
            x[5] = this.circularLeft(this.F1(x[1], x[2], x[7], x[6], x[3], x[0], x[4]), 25)
                + this.circularLeft(x[5], 21) + inw[i + 2];
            x[4] = this.circularLeft(this.F1(x[0], x[1], x[6], x[5], x[2], x[7], x[3]), 25)
                + this.circularLeft(x[4], 21) + inw[i + 3];
            x[3] = this.circularLeft(this.F1(x[7], x[0], x[5], x[4], x[1], x[6], x[2]), 25)
                + this.circularLeft(x[3], 21) + inw[i + 4];
            x[2] = this.circularLeft(this.F1(x[6], x[7], x[4], x[3], x[0], x[5], x[1]), 25)
                + this.circularLeft(x[2], 21) + inw[i + 5];
            x[1] = this.circularLeft(this.F1(x[5], x[6], x[3], x[2], x[7], x[4], x[0]), 25)
                + this.circularLeft(x[1], 21) + inw[i + 6];
            x[0] = this.circularLeft(this.F1(x[4], x[5], x[2], x[1], x[6], x[3], x[7]), 25)
                + this.circularLeft(x[0], 21) + inw[i + 7];
        }
        this.s[0] = x[0];
        this.s[1] = x[1];
        this.s[2] = x[2];
        this.s[3] = x[3];
        this.s[4] = x[4];
        this.s[5] = x[5];
        this.s[6] = x[6];
        this.s[7] = x[7];
    }
    pass52(inw) {
        const x = new Int32Array(8);
        x[0] = this.s[0], x[1] = this.s[1], x[2] = this.s[2], x[3] = this.s[3];
        x[4] = this.s[4], x[5] = this.s[5], x[6] = this.s[6], x[7] = this.s[7];
        for (let i = 0; i < 32; i += 8) {
            x[7] = this.circularLeft(this.F2(x[6], x[2], x[1], x[0], x[3], x[4], x[5]), 25)
                + this.circularLeft(x[7], 21)
                + inw[HAVALCore.wp2[i + 0]] + HAVALCore.K2[i + 0];
            x[6] = this.circularLeft(this.F2(x[5], x[1], x[0], x[7], x[2], x[3], x[4]), 25)
                + this.circularLeft(x[6], 21)
                + inw[HAVALCore.wp2[i + 1]] + HAVALCore.K2[i + 1];
            x[5] = this.circularLeft(this.F2(x[4], x[0], x[7], x[6], x[1], x[2], x[3]), 25)
                + this.circularLeft(x[5], 21)
                + inw[HAVALCore.wp2[i + 2]] + HAVALCore.K2[i + 2];
            x[4] = this.circularLeft(this.F2(x[3], x[7], x[6], x[5], x[0], x[1], x[2]), 25)
                + this.circularLeft(x[4], 21)
                + inw[HAVALCore.wp2[i + 3]] + HAVALCore.K2[i + 3];
            x[3] = this.circularLeft(this.F2(x[2], x[6], x[5], x[4], x[7], x[0], x[1]), 25)
                + this.circularLeft(x[3], 21)
                + inw[HAVALCore.wp2[i + 4]] + HAVALCore.K2[i + 4];
            x[2] = this.circularLeft(this.F2(x[1], x[5], x[4], x[3], x[6], x[7], x[0]), 25)
                + this.circularLeft(x[2], 21)
                + inw[HAVALCore.wp2[i + 5]] + HAVALCore.K2[i + 5];
            x[1] = this.circularLeft(this.F2(x[0], x[4], x[3], x[2], x[5], x[6], x[7]), 25)
                + this.circularLeft(x[1], 21)
                + inw[HAVALCore.wp2[i + 6]] + HAVALCore.K2[i + 6];
            x[0] = this.circularLeft(this.F2(x[7], x[3], x[2], x[1], x[4], x[5], x[6]), 25)
                + this.circularLeft(x[0], 21)
                + inw[HAVALCore.wp2[i + 7]] + HAVALCore.K2[i + 7];
        }
        this.s[0] = x[0];
        this.s[1] = x[1];
        this.s[2] = x[2];
        this.s[3] = x[3];
        this.s[4] = x[4];
        this.s[5] = x[5];
        this.s[6] = x[6];
        this.s[7] = x[7];
    }
    pass53(inw) {
        const x = new Int32Array(8);
        x[0] = this.s[0], x[1] = this.s[1], x[2] = this.s[2], x[3] = this.s[3];
        x[4] = this.s[4], x[5] = this.s[5], x[6] = this.s[6], x[7] = this.s[7];
        for (let i = 0; i < 32; i += 8) {
            x[7] = this.circularLeft(this.F3(x[2], x[6], x[0], x[4], x[3], x[1], x[5]), 25)
                + this.circularLeft(x[7], 21)
                + inw[HAVALCore.wp3[i + 0]] + HAVALCore.K3[i + 0];
            x[6] = this.circularLeft(this.F3(x[1], x[5], x[7], x[3], x[2], x[0], x[4]), 25)
                + this.circularLeft(x[6], 21)
                + inw[HAVALCore.wp3[i + 1]] + HAVALCore.K3[i + 1];
            x[5] = this.circularLeft(this.F3(x[0], x[4], x[6], x[2], x[1], x[7], x[3]), 25)
                + this.circularLeft(x[5], 21)
                + inw[HAVALCore.wp3[i + 2]] + HAVALCore.K3[i + 2];
            x[4] = this.circularLeft(this.F3(x[7], x[3], x[5], x[1], x[0], x[6], x[2]), 25)
                + this.circularLeft(x[4], 21)
                + inw[HAVALCore.wp3[i + 3]] + HAVALCore.K3[i + 3];
            x[3] = this.circularLeft(this.F3(x[6], x[2], x[4], x[0], x[7], x[5], x[1]), 25)
                + this.circularLeft(x[3], 21)
                + inw[HAVALCore.wp3[i + 4]] + HAVALCore.K3[i + 4];
            x[2] = this.circularLeft(this.F3(x[5], x[1], x[3], x[7], x[6], x[4], x[0]), 25)
                + this.circularLeft(x[2], 21)
                + inw[HAVALCore.wp3[i + 5]] + HAVALCore.K3[i + 5];
            x[1] = this.circularLeft(this.F3(x[4], x[0], x[2], x[6], x[5], x[3], x[7]), 25)
                + this.circularLeft(x[1], 21)
                + inw[HAVALCore.wp3[i + 6]] + HAVALCore.K3[i + 6];
            x[0] = this.circularLeft(this.F3(x[3], x[7], x[1], x[5], x[4], x[2], x[6]), 25)
                + this.circularLeft(x[0], 21)
                + inw[HAVALCore.wp3[i + 7]] + HAVALCore.K3[i + 7];
        }
        this.s[0] = x[0];
        this.s[1] = x[1];
        this.s[2] = x[2];
        this.s[3] = x[3];
        this.s[4] = x[4];
        this.s[5] = x[5];
        this.s[6] = x[6];
        this.s[7] = x[7];
    }
    pass54(inw) {
        const x = new Int32Array(8);
        x[0] = this.s[0], x[1] = this.s[1], x[2] = this.s[2], x[3] = this.s[3];
        x[4] = this.s[4], x[5] = this.s[5], x[6] = this.s[6], x[7] = this.s[7];
        for (let i = 0; i < 32; i += 8) {
            x[7] = this.circularLeft(this.F4(x[1], x[5], x[3], x[2], x[0], x[4], x[6]), 25)
                + this.circularLeft(x[7], 21)
                + inw[HAVALCore.wp4[i + 0]] + HAVALCore.K4[i + 0];
            x[6] = this.circularLeft(this.F4(x[0], x[4], x[2], x[1], x[7], x[3], x[5]), 25)
                + this.circularLeft(x[6], 21)
                + inw[HAVALCore.wp4[i + 1]] + HAVALCore.K4[i + 1];
            x[5] = this.circularLeft(this.F4(x[7], x[3], x[1], x[0], x[6], x[2], x[4]), 25)
                + this.circularLeft(x[5], 21)
                + inw[HAVALCore.wp4[i + 2]] + HAVALCore.K4[i + 2];
            x[4] = this.circularLeft(this.F4(x[6], x[2], x[0], x[7], x[5], x[1], x[3]), 25)
                + this.circularLeft(x[4], 21)
                + inw[HAVALCore.wp4[i + 3]] + HAVALCore.K4[i + 3];
            x[3] = this.circularLeft(this.F4(x[5], x[1], x[7], x[6], x[4], x[0], x[2]), 25)
                + this.circularLeft(x[3], 21)
                + inw[HAVALCore.wp4[i + 4]] + HAVALCore.K4[i + 4];
            x[2] = this.circularLeft(this.F4(x[4], x[0], x[6], x[5], x[3], x[7], x[1]), 25)
                + this.circularLeft(x[2], 21)
                + inw[HAVALCore.wp4[i + 5]] + HAVALCore.K4[i + 5];
            x[1] = this.circularLeft(this.F4(x[3], x[7], x[5], x[4], x[2], x[6], x[0]), 25)
                + this.circularLeft(x[1], 21)
                + inw[HAVALCore.wp4[i + 6]] + HAVALCore.K4[i + 6];
            x[0] = this.circularLeft(this.F4(x[2], x[6], x[4], x[3], x[1], x[5], x[7]), 25)
                + this.circularLeft(x[0], 21)
                + inw[HAVALCore.wp4[i + 7]] + HAVALCore.K4[i + 7];
        }
        this.s[0] = x[0];
        this.s[1] = x[1];
        this.s[2] = x[2];
        this.s[3] = x[3];
        this.s[4] = x[4];
        this.s[5] = x[5];
        this.s[6] = x[6];
        this.s[7] = x[7];
    }
    pass55(inw) {
        const x = new Int32Array(8);
        x[0] = this.s[0], x[1] = this.s[1], x[2] = this.s[2], x[3] = this.s[3];
        x[4] = this.s[4], x[5] = this.s[5], x[6] = this.s[6], x[7] = this.s[7];
        for (let i = 0; i < 32; i += 8) {
            x[7] = this.circularLeft(this.F5(x[2], x[5], x[0], x[6], x[4], x[3], x[1]), 25)
                + this.circularLeft(x[7], 21)
                + inw[HAVALCore.wp5[i + 0]] + HAVALCore.K5[i + 0];
            x[6] = this.circularLeft(this.F5(x[1], x[4], x[7], x[5], x[3], x[2], x[0]), 25)
                + this.circularLeft(x[6], 21)
                + inw[HAVALCore.wp5[i + 1]] + HAVALCore.K5[i + 1];
            x[5] = this.circularLeft(this.F5(x[0], x[3], x[6], x[4], x[2], x[1], x[7]), 25)
                + this.circularLeft(x[5], 21)
                + inw[HAVALCore.wp5[i + 2]] + HAVALCore.K5[i + 2];
            x[4] = this.circularLeft(this.F5(x[7], x[2], x[5], x[3], x[1], x[0], x[6]), 25)
                + this.circularLeft(x[4], 21)
                + inw[HAVALCore.wp5[i + 3]] + HAVALCore.K5[i + 3];
            x[3] = this.circularLeft(this.F5(x[6], x[1], x[4], x[2], x[0], x[7], x[5]), 25)
                + this.circularLeft(x[3], 21)
                + inw[HAVALCore.wp5[i + 4]] + HAVALCore.K5[i + 4];
            x[2] = this.circularLeft(this.F5(x[5], x[0], x[3], x[1], x[7], x[6], x[4]), 25)
                + this.circularLeft(x[2], 21)
                + inw[HAVALCore.wp5[i + 5]] + HAVALCore.K5[i + 5];
            x[1] = this.circularLeft(this.F5(x[4], x[7], x[2], x[0], x[6], x[5], x[3]), 25)
                + this.circularLeft(x[1], 21)
                + inw[HAVALCore.wp5[i + 6]] + HAVALCore.K5[i + 6];
            x[0] = this.circularLeft(this.F5(x[3], x[6], x[1], x[7], x[5], x[4], x[2]), 25)
                + this.circularLeft(x[0], 21)
                + inw[HAVALCore.wp5[i + 7]] + HAVALCore.K5[i + 7];
        }
        this.s[0] = x[0];
        this.s[1] = x[1];
        this.s[2] = x[2];
        this.s[3] = x[3];
        this.s[4] = x[4];
        this.s[5] = x[5];
        this.s[6] = x[6];
        this.s[7] = x[7];
    }
    mix128(a0, a1, a2, a3, n) {
        var tmp = (a0 & 0x000000FF)
            | (a1 & 0x0000FF00)
            | (a2 & 0x00FF0000)
            | (a3 & 0xFF000000);
        if (n > 0) {
            tmp = this.circularLeft(tmp, n);
        }
        return tmp;
    }
    mix160_0(x5, x6, x7) {
        return this.circularLeft((x5 & 0x01F80000)
            | (x6 & 0xFE000000) | (x7 & 0x0000003F), 13);
    }
    mix160_1(x5, x6, x7) {
        return this.circularLeft((x5 & 0xFE000000)
            | (x6 & 0x0000003F) | (x7 & 0x00000FC0), 7);
    }
    mix160_2(x5, x6, x7) {
        return (x5 & 0x0000003F)
            | (x6 & 0x00000FC0)
            | (x7 & 0x0007F000);
    }
    mix160_3(x5, x6, x7) {
        return ((x5 & 0x00000FC0)
            | (x6 & 0x0007F000)
            | (x7 & 0x01F80000)) >>> 6;
    }
    mix160_4(x5, x6, x7) {
        return ((x5 & 0x0007F000)
            | (x6 & 0x01F80000)
            | (x7 & 0xFE000000)) >>> 12;
    }
    mix192_0(x6, x7) {
        return this.circularLeft((x6 & 0xFC000000) | (x7 & 0x0000001F), 6);
    }
    mix192_1(x6, x7) {
        return (x6 & 0x0000001F) | (x7 & 0x000003E0);
    }
    mix192_2(x6, x7) {
        return ((x6 & 0x000003E0) | (x7 & 0x0000FC00)) >>> 5;
    }
    mix192_3(x6, x7) {
        return ((x6 & 0x0000FC00) | (x7 & 0x001F0000)) >>> 10;
    }
    mix192_4(x6, x7) {
        return ((x6 & 0x001F0000) | (x7 & 0x03E00000)) >>> 16;
    }
    mix192_5(x6, x7) {
        return ((x6 & 0x03E00000) | (x7 & 0xFC000000)) >>> 21;
    }
    write128(out, off) {
        this.encodeLEInt(this.s[0] + this.mix128(this.s[7], this.s[4], this.s[5], this.s[6], 24), out, off);
        this.encodeLEInt(this.s[1] + this.mix128(this.s[6], this.s[7], this.s[4], this.s[5], 16), out, off + 4);
        this.encodeLEInt(this.s[2] + this.mix128(this.s[5], this.s[6], this.s[7], this.s[4], 8), out, off + 8);
        this.encodeLEInt(this.s[3] + this.mix128(this.s[4], this.s[5], this.s[6], this.s[7], 0), out, off + 12);
    }
    write160(out, off) {
        this.encodeLEInt(this.s[0] + this.mix160_0(this.s[5], this.s[6], this.s[7]), out, off);
        this.encodeLEInt(this.s[1] + this.mix160_1(this.s[5], this.s[6], this.s[7]), out, off + 4);
        this.encodeLEInt(this.s[2] + this.mix160_2(this.s[5], this.s[6], this.s[7]), out, off + 8);
        this.encodeLEInt(this.s[3] + this.mix160_3(this.s[5], this.s[6], this.s[7]), out, off + 12);
        this.encodeLEInt(this.s[4] + this.mix160_4(this.s[5], this.s[6], this.s[7]), out, off + 16);
    }
    write192(out, off) {
        this.encodeLEInt(this.s[0] + this.mix192_0(this.s[6], this.s[7]), out, off);
        this.encodeLEInt(this.s[1] + this.mix192_1(this.s[6], this.s[7]), out, off + 4);
        this.encodeLEInt(this.s[2] + this.mix192_2(this.s[6], this.s[7]), out, off + 8);
        this.encodeLEInt(this.s[3] + this.mix192_3(this.s[6], this.s[7]), out, off + 12);
        this.encodeLEInt(this.s[4] + this.mix192_4(this.s[6], this.s[7]), out, off + 16);
        this.encodeLEInt(this.s[5] + this.mix192_5(this.s[6], this.s[7]), out, off + 20);
    }
    write224(out, off) {
        this.encodeLEInt(this.s[0] + ((this.s[7] >>> 27) & 0x1F), out, off);
        this.encodeLEInt(this.s[1] + ((this.s[7] >>> 22) & 0x1F), out, off + 4);
        this.encodeLEInt(this.s[2] + ((this.s[7] >>> 18) & 0x0F), out, off + 8);
        this.encodeLEInt(this.s[3] + ((this.s[7] >>> 13) & 0x1F), out, off + 12);
        this.encodeLEInt(this.s[4] + ((this.s[7] >>> 9) & 0x0F), out, off + 16);
        this.encodeLEInt(this.s[5] + ((this.s[7] >>> 4) & 0x1F), out, off + 20);
        this.encodeLEInt(this.s[6] + ((this.s[7]) & 0x0F), out, off + 24);
    }
    write256(out, off) {
        this.encodeLEInt(this.s[0], out, off);
        this.encodeLEInt(this.s[1], out, off + 4);
        this.encodeLEInt(this.s[2], out, off + 8);
        this.encodeLEInt(this.s[3], out, off + 12);
        this.encodeLEInt(this.s[4], out, off + 16);
        this.encodeLEInt(this.s[5], out, off + 20);
        this.encodeLEInt(this.s[6], out, off + 24);
        this.encodeLEInt(this.s[7], out, off + 28);
    }
    writeOutput(out, off) {
        switch (this.olen) {
            case 4:
                this.write128(out, off);
                break;
            case 5:
                this.write160(out, off);
                break;
            case 6:
                this.write192(out, off);
                break;
            case 7:
                this.write224(out, off);
                break;
            case 8:
                this.write256(out, off);
                break;
        }
    }
    /** @see Digest */
    toString() {
        return "HAVAL-" + this.passes + "-" + (this.olen << 5);
    }
}
HAVALCore.K2 = new Int32Array([
    0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
    0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917,
    0x9216D5D9, 0x8979FB1B, 0xD1310BA6, 0x98DFB5AC,
    0x2FFD72DB, 0xD01ADFB7, 0xB8E1AFED, 0x6A267E96,
    0xBA7C9045, 0xF12C7F99, 0x24A19947, 0xB3916CF7,
    0x0801F2E2, 0x858EFC16, 0x636920D8, 0x71574E69,
    0xA458FEA3, 0xF4933D7E, 0x0D95748F, 0x728EB658,
    0x718BCD58, 0x82154AEE, 0x7B54A41D, 0xC25A59B5
]);
HAVALCore.K3 = new Int32Array([
    0x9C30D539, 0x2AF26013, 0xC5D1B023, 0x286085F0,
    0xCA417918, 0xB8DB38EF, 0x8E79DCB0, 0x603A180E,
    0x6C9E0E8B, 0xB01E8A3E, 0xD71577C1, 0xBD314B27,
    0x78AF2FDA, 0x55605C60, 0xE65525F3, 0xAA55AB94,
    0x57489862, 0x63E81440, 0x55CA396A, 0x2AAB10B6,
    0xB4CC5C34, 0x1141E8CE, 0xA15486AF, 0x7C72E993,
    0xB3EE1411, 0x636FBC2A, 0x2BA9C55D, 0x741831F6,
    0xCE5C3E16, 0x9B87931E, 0xAFD6BA33, 0x6C24CF5C
]);
HAVALCore.K4 = new Int32Array([
    0x7A325381, 0x28958677, 0x3B8F4898, 0x6B4BB9AF,
    0xC4BFE81B, 0x66282193, 0x61D809CC, 0xFB21A991,
    0x487CAC60, 0x5DEC8032, 0xEF845D5D, 0xE98575B1,
    0xDC262302, 0xEB651B88, 0x23893E81, 0xD396ACC5,
    0x0F6D6FF3, 0x83F44239, 0x2E0B4482, 0xA4842004,
    0x69C8F04A, 0x9E1F9B5E, 0x21C66842, 0xF6E96C9A,
    0x670C9C61, 0xABD388F0, 0x6A51A0D2, 0xD8542F68,
    0x960FA728, 0xAB5133A3, 0x6EEF0B6C, 0x137A3BE4
]);
HAVALCore.K5 = new Int32Array([
    0xBA3BF050, 0x7EFB2A98, 0xA1F1651D, 0x39AF0176,
    0x66CA593E, 0x82430E88, 0x8CEE8619, 0x456F9FB4,
    0x7D84A5C3, 0x3B8B5EBE, 0xE06F75D8, 0x85C12073,
    0x401A449F, 0x56C16AA6, 0x4ED3AA62, 0x363F7706,
    0x1BFEDF72, 0x429B023D, 0x37D0D724, 0xD00A1248,
    0xDB0FEAD3, 0x49F1C09B, 0x075372C9, 0x80991B7B,
    0x25D479D8, 0xF6E8DEF7, 0xE3FE501A, 0xB6794C3B,
    0x976CE0BD, 0x04C006BA, 0xC1A94FB6, 0x409F60C4
]);
HAVALCore.wp2 = new Int32Array([
    5, 14, 26, 18, 11, 28, 7, 16, 0, 23, 20, 22, 1, 10, 4, 8,
    30, 3, 21, 9, 17, 24, 29, 6, 19, 12, 15, 13, 2, 25, 31, 27
]);
HAVALCore.wp3 = new Int32Array([
    19, 9, 4, 20, 28, 17, 8, 22, 29, 14, 25, 12, 24, 30, 16, 26,
    31, 15, 7, 3, 1, 0, 18, 27, 13, 6, 21, 10, 23, 11, 5, 2
]);
HAVALCore.wp4 = new Int32Array([
    24, 4, 0, 14, 2, 7, 28, 23, 26, 6, 30, 20, 18, 25, 19, 3,
    22, 11, 31, 21, 8, 27, 12, 9, 1, 29, 5, 15, 17, 10, 16, 13
]);
HAVALCore.wp5 = new Int32Array([
    27, 3, 21, 26, 17, 11, 20, 29, 19, 0, 12, 7, 13, 8, 31, 10,
    5, 9, 14, 30, 18, 6, 28, 24, 2, 23, 16, 22, 4, 1, 25, 15
]);
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
class Haval128_3 extends HAVALCore {
    /**
     * Create the object.
     */
    constructor() {
        super(128, 3);
    }
    /** @see Digest */
    getDigestLength() {
        return 16;
    }
    /** @see Digest */
    copy() {
        return this.copyState(new Haval128_3());
    }
}
exports.Haval128_3 = Haval128_3;
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
class Haval128_4 extends HAVALCore {
    /**
     * Create the object.
     */
    constructor() {
        super(128, 4);
    }
    /** @see Digest */
    getDigestLength() {
        return 16;
    }
    /** @see Digest */
    copy() {
        return this.copyState(new Haval128_4());
    }
}
exports.Haval128_4 = Haval128_4;
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
class Haval128_5 extends HAVALCore {
    /**
     * Create the object.
     */
    constructor() {
        super(128, 5);
    }
    /** @see Digest */
    getDigestLength() {
        return 16;
    }
    /** @see Digest */
    copy() {
        return this.copyState(new Haval128_5());
    }
}
exports.Haval128_5 = Haval128_5;
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
class Haval160_3 extends HAVALCore {
    /**
     * Create the object.
     */
    constructor() {
        super(160, 3);
    }
    /** @see Digest */
    getDigestLength() {
        return 20;
    }
    /** @see Digest */
    copy() {
        return this.copyState(new Haval160_3());
    }
}
exports.Haval160_3 = Haval160_3;
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
class Haval160_4 extends HAVALCore {
    /**
     * Create the object.
     */
    constructor() {
        super(160, 4);
    }
    /** @see Digest */
    getDigestLength() {
        return 20;
    }
    /** @see Digest */
    copy() {
        return this.copyState(new Haval160_4());
    }
}
exports.Haval160_4 = Haval160_4;
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
class Haval160_5 extends HAVALCore {
    /**
     * Create the object.
     */
    constructor() {
        super(160, 5);
    }
    /** @see Digest */
    getDigestLength() {
        return 20;
    }
    /** @see Digest */
    copy() {
        return this.copyState(new Haval160_5());
    }
}
exports.Haval160_5 = Haval160_5;
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
class Haval192_3 extends HAVALCore {
    /**
     * Create the object.
     */
    constructor() {
        super(192, 3);
    }
    /** @see Digest */
    getDigestLength() {
        return 24;
    }
    /** @see Digest */
    copy() {
        return this.copyState(new Haval192_3());
    }
}
exports.Haval192_3 = Haval192_3;
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
class Haval192_4 extends HAVALCore {
    /**
     * Create the object.
     */
    constructor() {
        super(192, 4);
    }
    /** @see Digest */
    getDigestLength() {
        return 24;
    }
    /** @see Digest */
    copy() {
        return this.copyState(new Haval192_4());
    }
}
exports.Haval192_4 = Haval192_4;
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
class Haval192_5 extends HAVALCore {
    /**
     * Create the object.
     */
    constructor() {
        super(192, 5);
    }
    /** @see Digest */
    getDigestLength() {
        return 24;
    }
    /** @see Digest */
    copy() {
        return this.copyState(new Haval192_5());
    }
}
exports.Haval192_5 = Haval192_5;
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
class Haval224_3 extends HAVALCore {
    /**
     * Create the object.
     */
    constructor() {
        super(224, 3);
    }
    /** @see Digest */
    getDigestLength() {
        return 28;
    }
    /** @see Digest */
    copy() {
        return this.copyState(new Haval224_3());
    }
}
exports.Haval224_3 = Haval224_3;
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
class Haval224_4 extends HAVALCore {
    /**
     * Create the object.
     */
    constructor() {
        super(224, 4);
    }
    /** @see Digest */
    getDigestLength() {
        return 28;
    }
    /** @see Digest */
    copy() {
        return this.copyState(new Haval224_4());
    }
}
exports.Haval224_4 = Haval224_4;
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
class Haval224_5 extends HAVALCore {
    /**
     * Create the object.
     */
    constructor() {
        super(224, 5);
    }
    /** @see Digest */
    getDigestLength() {
        return 28;
    }
    /** @see Digest */
    copy() {
        return this.copyState(new Haval224_5());
    }
}
exports.Haval224_5 = Haval224_5;
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
class Haval256_3 extends HAVALCore {
    /**
     * Create the object.
     */
    constructor() {
        super(256, 3);
    }
    /** @see Digest */
    getDigestLength() {
        return 32;
    }
    /** @see Digest */
    copy() {
        return this.copyState(new Haval256_3());
    }
}
exports.Haval256_3 = Haval256_3;
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
class Haval256_4 extends HAVALCore {
    /**
     * Create the object.
     */
    constructor() {
        super(256, 4);
    }
    /** @see Digest */
    getDigestLength() {
        return 32;
    }
    /** @see Digest */
    copy() {
        return this.copyState(new Haval256_4());
    }
}
exports.Haval256_4 = Haval256_4;
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
class Haval256_5 extends HAVALCore {
    /**
     * Create the object.
     */
    constructor() {
        super(256, 5);
    }
    /** @see Digest */
    getDigestLength() {
        return 32;
    }
    /** @see Digest */
    copy() {
        return this.copyState(new Haval256_5());
    }
}
exports.Haval256_5 = Haval256_5;
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
 * Creates a 16 byte vary rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {3|4|5} rounds - hash rounds
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HAVAL128(message, rounds = 3, format = arrayType()) {
    var hash;
    switch (rounds) {
        case 3:
            hash = new Haval128_3();
            break;
        case 4:
            hash = new Haval128_4();
            break;
        case 5:
            hash = new Haval128_5();
            break;
        default:
            hash = new Haval128_3();
            break;
    }
    hash.update(formatMessage(message));
    var digestbytes = hash.digest();
    if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    else if (format == "hex") {
        return toHex(digestbytes);
    }
    return digestbytes;
}
exports.HAVAL128 = HAVAL128;
/**
 * Creates a 16 byte vary rounds keyed Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {3|4|5} rounds - hash rounds
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HAVAL128_HMAC(message, key, rounds = 3, format = arrayType()) {
    var hash;
    switch (rounds) {
        case 3:
            hash = new Haval128_3();
            break;
        case 4:
            hash = new Haval128_4();
            break;
        case 5:
            hash = new Haval128_5();
            break;
        default:
            hash = new Haval128_3();
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
exports.HAVAL128_HMAC = HAVAL128_HMAC;
/**
 * Creates a 16 byte 3 rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HAVAL128_3(message, format = arrayType()) {
    const hash = new Haval128_3();
    hash.update(formatMessage(message));
    var digestbytes = hash.digest();
    if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    else if (format == "hex") {
        return toHex(digestbytes);
    }
    return digestbytes;
}
exports.HAVAL128_3 = HAVAL128_3;
/**
 * Creates a 16 byte 3 rounds keyed Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HAVAL128_3_HMAC(message, key, format = arrayType()) {
    const hash = new Haval128_3();
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
exports.HAVAL128_3_HMAC = HAVAL128_3_HMAC;
/**
 * Creates a 16 byte 4 rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HAVAL128_4(message, format = arrayType()) {
    const hash = new Haval128_4();
    hash.update(formatMessage(message));
    var digestbytes = hash.digest();
    if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    else if (format == "hex") {
        return toHex(digestbytes);
    }
    return digestbytes;
}
exports.HAVAL128_4 = HAVAL128_4;
/**
 * Creates a 16 byte 4 rounds keyed Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HAVAL128_4_HMAC(message, key, format = arrayType()) {
    const hash = new Haval128_4();
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
exports.HAVAL128_4_HMAC = HAVAL128_4_HMAC;
/**
 * Creates a 16 byte 5 rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HAVAL128_5(message, format = arrayType()) {
    const hash = new Haval128_5();
    hash.update(formatMessage(message));
    var digestbytes = hash.digest();
    if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    else if (format == "hex") {
        return toHex(digestbytes);
    }
    return digestbytes;
}
exports.HAVAL128_5 = HAVAL128_5;
/**
 * Creates a 16 byte 5 rounds keyed Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HAVAL128_5_HMAC(message, key, format = arrayType()) {
    const hash = new Haval128_5();
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
exports.HAVAL128_5_HMAC = HAVAL128_5_HMAC;
/**
 * Creates a 20 byte vary rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {3|4|5} rounds - hash rounds
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HAVAL160(message, rounds = 3, format = arrayType()) {
    var hash;
    switch (rounds) {
        case 3:
            hash = new Haval160_3();
            break;
        case 4:
            hash = new Haval160_4();
            break;
        case 5:
            hash = new Haval160_5();
            break;
        default:
            hash = new Haval160_3();
            break;
    }
    hash.update(formatMessage(message));
    var digestbytes = hash.digest();
    if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    else if (format == "hex") {
        return toHex(digestbytes);
    }
    return digestbytes;
}
exports.HAVAL160 = HAVAL160;
/**
 * Creates a 20 byte vary rounds keyed Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {3|4|5} rounds - hash rounds
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HAVAL160_HMAC(message, key, rounds = 3, format = arrayType()) {
    var hash;
    switch (rounds) {
        case 3:
            hash = new Haval160_3();
            break;
        case 4:
            hash = new Haval160_4();
            break;
        case 5:
            hash = new Haval160_5();
            break;
        default:
            hash = new Haval160_3();
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
exports.HAVAL160_HMAC = HAVAL160_HMAC;
/**
 * Creates a 20 byte 3 rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HAVAL160_3(message, format = arrayType()) {
    const hash = new Haval160_3();
    hash.update(formatMessage(message));
    var digestbytes = hash.digest();
    if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    else if (format == "hex") {
        return toHex(digestbytes);
    }
    return digestbytes;
}
exports.HAVAL160_3 = HAVAL160_3;
/**
 * Creates a 20 byte 3 rounds keyed Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HAVAL160_3_HMAC(message, key, format = arrayType()) {
    const hash = new Haval160_3();
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
exports.HAVAL160_3_HMAC = HAVAL160_3_HMAC;
/**
 * Creates a 20 byte 4 rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HAVAL160_4(message, format = arrayType()) {
    const hash = new Haval160_4();
    hash.update(formatMessage(message));
    var digestbytes = hash.digest();
    if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    else if (format == "hex") {
        return toHex(digestbytes);
    }
    return digestbytes;
}
exports.HAVAL160_4 = HAVAL160_4;
/**
 * Creates a 20 byte 4 rounds keyed Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HAVAL160_4_HMAC(message, key, format = arrayType()) {
    const hash = new Haval160_4();
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
exports.HAVAL160_4_HMAC = HAVAL160_4_HMAC;
/**
 * Creates a 20 byte 5 rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HAVAL160_5(message, format = arrayType()) {
    const hash = new Haval160_5();
    hash.update(formatMessage(message));
    var digestbytes = hash.digest();
    if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    else if (format == "hex") {
        return toHex(digestbytes);
    }
    return digestbytes;
}
exports.HAVAL160_5 = HAVAL160_5;
/**
 * Creates a 20 byte 5 rounds keyed Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HAVAL160_5_HMAC(message, key, format = arrayType()) {
    const hash = new Haval160_5();
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
exports.HAVAL160_5_HMAC = HAVAL160_5_HMAC;
/**
 * Creates a 24 byte vary rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {3|4|5} rounds - hash rounds
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HAVAL192(message, rounds = 3, format = arrayType()) {
    var hash;
    switch (rounds) {
        case 3:
            hash = new Haval192_3();
            break;
        case 4:
            hash = new Haval192_4();
            break;
        case 5:
            hash = new Haval192_5();
            break;
        default:
            hash = new Haval192_3();
            break;
    }
    hash.update(formatMessage(message));
    var digestbytes = hash.digest();
    if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    else if (format == "hex") {
        return toHex(digestbytes);
    }
    return digestbytes;
}
exports.HAVAL192 = HAVAL192;
/**
 * Creates a 24 byte vary rounds keyed Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {3|4|5} rounds - hash rounds
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HAVAL192_HMAC(message, key, rounds = 3, format = arrayType()) {
    var hash;
    switch (rounds) {
        case 3:
            hash = new Haval192_3();
            break;
        case 4:
            hash = new Haval192_4();
            break;
        case 5:
            hash = new Haval192_5();
            break;
        default:
            hash = new Haval192_3();
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
exports.HAVAL192_HMAC = HAVAL192_HMAC;
/**
 * Creates a 24 byte 3 rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HAVAL192_3(message, format = arrayType()) {
    const hash = new Haval192_3();
    hash.update(formatMessage(message));
    var digestbytes = hash.digest();
    if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    else if (format == "hex") {
        return toHex(digestbytes);
    }
    return digestbytes;
}
exports.HAVAL192_3 = HAVAL192_3;
/**
 * Creates a 24 byte 3 rounds keyed Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HAVAL192_3_HMAC(message, key, format = arrayType()) {
    const hash = new Haval192_3();
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
exports.HAVAL192_3_HMAC = HAVAL192_3_HMAC;
/**
 * Creates a 24 byte 4 rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HAVAL192_4(message, format = arrayType()) {
    const hash = new Haval192_4();
    hash.update(formatMessage(message));
    var digestbytes = hash.digest();
    if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    else if (format == "hex") {
        return toHex(digestbytes);
    }
    return digestbytes;
}
exports.HAVAL192_4 = HAVAL192_4;
/**
 * Creates a 24 byte 4 rounds keyed Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HAVAL192_4_HMAC(message, key, format = arrayType()) {
    const hash = new Haval192_4();
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
exports.HAVAL192_4_HMAC = HAVAL192_4_HMAC;
/**
 * Creates a 24 byte 5 rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HAVAL192_5(message, format = arrayType()) {
    const hash = new Haval192_5();
    hash.update(formatMessage(message));
    var digestbytes = hash.digest();
    if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    else if (format == "hex") {
        return toHex(digestbytes);
    }
    return digestbytes;
}
exports.HAVAL192_5 = HAVAL192_5;
/**
 * Creates a 24 byte 5 rounds keyed Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HAVAL192_5_HMAC(message, key, format = arrayType()) {
    const hash = new Haval192_5();
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
exports.HAVAL192_5_HMAC = HAVAL192_5_HMAC;
/**
 * Creates a 28 byte vary rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {3|4|5} rounds - hash rounds
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HAVAL224(message, rounds = 3, format = arrayType()) {
    var hash;
    switch (rounds) {
        case 3:
            hash = new Haval224_3();
            break;
        case 4:
            hash = new Haval224_4();
            break;
        case 5:
            hash = new Haval224_5();
            break;
        default:
            hash = new Haval224_3();
            break;
    }
    hash.update(formatMessage(message));
    var digestbytes = hash.digest();
    if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    else if (format == "hex") {
        return toHex(digestbytes);
    }
    return digestbytes;
}
exports.HAVAL224 = HAVAL224;
/**
 * Creates a 28 byte vary rounds keyed Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {3|4|5} rounds - hash rounds
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HAVAL224_HMAC(message, key, rounds = 3, format = arrayType()) {
    var hash;
    switch (rounds) {
        case 3:
            hash = new Haval224_3();
            break;
        case 4:
            hash = new Haval224_4();
            break;
        case 5:
            hash = new Haval224_5();
            break;
        default:
            hash = new Haval224_3();
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
exports.HAVAL224_HMAC = HAVAL224_HMAC;
/**
 * Creates a 28 byte 3 rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HAVAL224_3(message, format = arrayType()) {
    const hash = new Haval224_3();
    hash.update(formatMessage(message));
    var digestbytes = hash.digest();
    if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    else if (format == "hex") {
        return toHex(digestbytes);
    }
    return digestbytes;
}
exports.HAVAL224_3 = HAVAL224_3;
/**
 * Creates a 28 byte 3 rounds keyed Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HAVAL224_3_HMAC(message, key, format = arrayType()) {
    const hash = new Haval192_3();
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
exports.HAVAL224_3_HMAC = HAVAL224_3_HMAC;
/**
 * Creates a 28 byte 4 rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HAVAL224_4(message, format = arrayType()) {
    const hash = new Haval224_4();
    hash.update(formatMessage(message));
    var digestbytes = hash.digest();
    if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    else if (format == "hex") {
        return toHex(digestbytes);
    }
    return digestbytes;
}
exports.HAVAL224_4 = HAVAL224_4;
/**
 * Creates a 28 byte 4 rounds keyed Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HAVAL224_4_HMAC(message, key, format = arrayType()) {
    const hash = new Haval192_4();
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
exports.HAVAL224_4_HMAC = HAVAL224_4_HMAC;
/**
 * Creates a 28 byte 5 rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HAVAL224_5(message, format = arrayType()) {
    const hash = new Haval224_5();
    hash.update(formatMessage(message));
    var digestbytes = hash.digest();
    if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    else if (format == "hex") {
        return toHex(digestbytes);
    }
    return digestbytes;
}
exports.HAVAL224_5 = HAVAL224_5;
/**
 * Creates a 28 byte 5 rounds keyed Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HAVAL224_5_HMAC(message, key, format = arrayType()) {
    const hash = new Haval192_5();
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
exports.HAVAL224_5_HMAC = HAVAL224_5_HMAC;
/**
 * Creates a 32 byte vary rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {3|4|5} rounds - hash rounds
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HAVAL256(message, rounds = 3, format = arrayType()) {
    var hash;
    switch (rounds) {
        case 3:
            hash = new Haval256_3();
            break;
        case 4:
            hash = new Haval256_4();
            break;
        case 5:
            hash = new Haval256_5();
            break;
        default:
            hash = new Haval256_3();
            break;
    }
    hash.update(formatMessage(message));
    var digestbytes = hash.digest();
    if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    else if (format == "hex") {
        return toHex(digestbytes);
    }
    return digestbytes;
}
exports.HAVAL256 = HAVAL256;
/**
 * Creates a 32 byte vary rounds keyed Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {3|4|5} rounds - hash rounds
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HAVAL256_HMAC(message, key, rounds = 3, format = arrayType()) {
    var hash;
    switch (rounds) {
        case 3:
            hash = new Haval256_3();
            break;
        case 4:
            hash = new Haval256_4();
            break;
        case 5:
            hash = new Haval256_5();
            break;
        default:
            hash = new Haval256_3();
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
exports.HAVAL256_HMAC = HAVAL256_HMAC;
/**
 * Creates a 32 byte 3 rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HAVAL256_3(message, format = arrayType()) {
    const hash = new Haval256_3();
    hash.update(formatMessage(message));
    var digestbytes = hash.digest();
    if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    else if (format == "hex") {
        return toHex(digestbytes);
    }
    return digestbytes;
}
exports.HAVAL256_3 = HAVAL256_3;
/**
 * Creates a 32 byte 3 rounds keyed Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HAVAL256_3_HMAC(message, key, format = arrayType()) {
    const hash = new Haval256_3();
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
exports.HAVAL256_3_HMAC = HAVAL256_3_HMAC;
/**
 * Creates a 32 byte 4 rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HAVAL256_4(message, format = arrayType()) {
    const hash = new Haval256_4();
    hash.update(formatMessage(message));
    var digestbytes = hash.digest();
    if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    else if (format == "hex") {
        return toHex(digestbytes);
    }
    return digestbytes;
}
exports.HAVAL256_4 = HAVAL256_4;
/**
 * Creates a 32 byte 4 rounds keyed Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HAVAL256_4_HMAC(message, key, format = arrayType()) {
    const hash = new Haval256_4();
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
exports.HAVAL256_4_HMAC = HAVAL256_4_HMAC;
/**
 * Creates a 32 byte 5 rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HAVAL256_5(message, format = arrayType()) {
    const hash = new Haval256_5();
    hash.update(formatMessage(message));
    var digestbytes = hash.digest();
    if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    else if (format == "hex") {
        return toHex(digestbytes);
    }
    return digestbytes;
}
exports.HAVAL256_5 = HAVAL256_5;
/**
 * Creates a 32 byte 5 rounds keyed Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HAVAL256_5_HMAC(message, key, format = arrayType()) {
    const hash = new Haval256_5();
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
exports.HAVAL256_5_HMAC = HAVAL256_5_HMAC;
/**
 * Creates a vary byte vary rounds Hash of Variable Length (HAVAL) hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {128|160|192|224|256} bitLen - hash length in bits (default 256 AKA 32 bytes)
 * @param {3|4|5} rounds - rounds to hash (default 3)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function _HAVAL(message, bitLen = 256, rounds = 3, format = arrayType()) {
    var hash;
    switch (bitLen) {
        case 128:
            switch (rounds) {
                case 3:
                    hash = new Haval128_3();
                    break;
                case 4:
                    hash = new Haval128_4();
                    break;
                case 5:
                    hash = new Haval128_5();
                    break;
                default:
                    hash = new Haval128_3();
                    break;
            }
            break;
        case 160:
            switch (rounds) {
                case 3:
                    hash = new Haval160_3();
                    break;
                case 4:
                    hash = new Haval160_4();
                    break;
                case 5:
                    hash = new Haval160_5();
                    break;
                default:
                    hash = new Haval160_3();
                    break;
            }
            break;
        case 192:
            switch (rounds) {
                case 3:
                    hash = new Haval192_3();
                    break;
                case 4:
                    hash = new Haval192_4();
                    break;
                case 5:
                    hash = new Haval192_5();
                    break;
                default:
                    hash = new Haval192_3();
                    break;
            }
            break;
        case 224:
            switch (rounds) {
                case 3:
                    hash = new Haval224_3();
                    break;
                case 4:
                    hash = new Haval224_4();
                    break;
                case 5:
                    hash = new Haval224_5();
                    break;
                default:
                    hash = new Haval224_3();
                    break;
            }
            break;
        case 256:
            switch (rounds) {
                case 3:
                    hash = new Haval256_3();
                    break;
                case 4:
                    hash = new Haval256_4();
                    break;
                case 5:
                    hash = new Haval256_5();
                    break;
                default:
                    hash = new Haval256_3();
                    break;
            }
            break;
        default:
            hash = new Haval256_3();
            break;
    }
    hash.update(formatMessage(message));
    var digestbytes = hash.digest();
    if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    else if (format == "hex") {
        return toHex(digestbytes);
    }
    return digestbytes;
}
exports._HAVAL = _HAVAL;
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
function HAVAL_HMAC(message, key, bitLen = 256, rounds = 3, format = arrayType()) {
    var hash;
    switch (bitLen) {
        case 128:
            switch (rounds) {
                case 3:
                    hash = new Haval128_3();
                    break;
                case 4:
                    hash = new Haval128_4();
                    break;
                case 5:
                    hash = new Haval128_5();
                    break;
                default:
                    hash = new Haval128_3();
                    break;
            }
            break;
        case 160:
            switch (rounds) {
                case 3:
                    hash = new Haval160_3();
                    break;
                case 4:
                    hash = new Haval160_4();
                    break;
                case 5:
                    hash = new Haval160_5();
                    break;
                default:
                    hash = new Haval160_3();
                    break;
            }
            break;
        case 192:
            switch (rounds) {
                case 3:
                    hash = new Haval192_3();
                    break;
                case 4:
                    hash = new Haval192_4();
                    break;
                case 5:
                    hash = new Haval192_5();
                    break;
                default:
                    hash = new Haval192_3();
                    break;
            }
            break;
        case 224:
            switch (rounds) {
                case 3:
                    hash = new Haval224_3();
                    break;
                case 4:
                    hash = new Haval224_4();
                    break;
                case 5:
                    hash = new Haval224_5();
                    break;
                default:
                    hash = new Haval224_3();
                    break;
            }
            break;
        case 256:
            switch (rounds) {
                case 3:
                    hash = new Haval256_3();
                    break;
                case 4:
                    hash = new Haval256_4();
                    break;
                case 5:
                    hash = new Haval256_5();
                    break;
                default:
                    hash = new Haval256_3();
                    break;
            }
            break;
        default:
            hash = new Haval256_3();
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
exports.HAVAL_HMAC = HAVAL_HMAC;
/**
 * Static class of all HAVAL functions and classes
 */
class HAVAL {
    /**
     * List of all hashes in class
     */
    static get FUNCTION_LIST() {
        return [
            "HAVAL",
            "HAVAL128",
            "HAVAL128_HMAC",
            "HAVAL128_3",
            "HAVAL128_3_HMAC",
            "HAVAL128_4",
            "HAVAL128_4_HMAC",
            "HAVAL128_5",
            "HAVAL128_5_HMAC",
            "HAVAL160",
            "HAVAL160_3",
            "HAVAL160_3_HMAC",
            "HAVAL160_4",
            "HAVAL160_4_HMAC",
            "HAVAL160_5",
            "HAVAL160_5_HMAC",
            "HAVAL160_HMAC",
            "HAVAL192",
            "HAVAL192_3",
            "HAVAL192_3_HMAC",
            "HAVAL192_4",
            "HAVAL192_4_HMAC",
            "HAVAL192_5",
            "HAVAL192_5_HMAC",
            "HAVAL192_HMAC",
            "HAVAL224",
            "HAVAL224_3",
            "HAVAL224_3_HMAC",
            "HAVAL224_4",
            "HAVAL224_4_HMAC",
            "HAVAL224_5",
            "HAVAL224_5_HMAC",
            "HAVAL224_HMAC",
            "HAVAL256",
            "HAVAL256_3",
            "HAVAL256_3_HMAC",
            "HAVAL256_4",
            "HAVAL256_4_HMAC",
            "HAVAL256_5",
            "HAVAL256_5_HMAC",
            "HAVAL256_HMAC",
            "HAVAL_HMAC",
        ];
    }
}
exports.HAVAL = HAVAL;
HAVAL.HAVAL = _HAVAL;
HAVAL.Haval128_3 = Haval128_3;
HAVAL.Haval128_4 = Haval128_4;
HAVAL.Haval128_5 = Haval128_5;
HAVAL.Haval160_3 = Haval160_3;
HAVAL.Haval160_4 = Haval160_4;
HAVAL.Haval160_5 = Haval160_5;
HAVAL.Haval192_3 = Haval192_3;
HAVAL.Haval192_4 = Haval192_4;
HAVAL.Haval192_5 = Haval192_5;
HAVAL.Haval224_3 = Haval224_3;
HAVAL.Haval224_4 = Haval224_4;
HAVAL.Haval224_5 = Haval224_5;
HAVAL.Haval256_3 = Haval256_3;
HAVAL.Haval256_4 = Haval256_4;
HAVAL.Haval256_5 = Haval256_5;
HAVAL.HAVAL128 = HAVAL128;
HAVAL.HAVAL128_HMAC = HAVAL128_HMAC;
HAVAL.HAVAL128_3 = HAVAL128_3;
HAVAL.HAVAL128_3_HMAC = HAVAL128_3_HMAC;
HAVAL.HAVAL128_4 = HAVAL128_4;
HAVAL.HAVAL128_4_HMAC = HAVAL128_4_HMAC;
HAVAL.HAVAL128_5 = HAVAL128_5;
HAVAL.HAVAL128_5_HMAC = HAVAL128_5_HMAC;
HAVAL.HAVAL160 = HAVAL160;
HAVAL.HAVAL160_3 = HAVAL160_3;
HAVAL.HAVAL160_3_HMAC = HAVAL160_3_HMAC;
HAVAL.HAVAL160_4 = HAVAL160_4;
HAVAL.HAVAL160_4_HMAC = HAVAL160_4_HMAC;
HAVAL.HAVAL160_5 = HAVAL160_5;
HAVAL.HAVAL160_5_HMAC = HAVAL160_5_HMAC;
HAVAL.HAVAL160_HMAC = HAVAL160_HMAC;
HAVAL.HAVAL192 = HAVAL192;
HAVAL.HAVAL192_3 = HAVAL192_3;
HAVAL.HAVAL192_3_HMAC = HAVAL192_3_HMAC;
HAVAL.HAVAL192_4 = HAVAL192_4;
HAVAL.HAVAL192_4_HMAC = HAVAL192_4_HMAC;
HAVAL.HAVAL192_5 = HAVAL192_5;
HAVAL.HAVAL192_5_HMAC = HAVAL192_5_HMAC;
HAVAL.HAVAL192_HMAC = HAVAL192_HMAC;
HAVAL.HAVAL224 = HAVAL224;
HAVAL.HAVAL224_3 = HAVAL224_3;
HAVAL.HAVAL224_3_HMAC = HAVAL224_3_HMAC;
HAVAL.HAVAL224_4 = HAVAL224_4;
HAVAL.HAVAL224_4_HMAC = HAVAL224_4_HMAC;
HAVAL.HAVAL224_5 = HAVAL224_5;
HAVAL.HAVAL224_5_HMAC = HAVAL224_5_HMAC;
HAVAL.HAVAL224_HMAC = HAVAL224_HMAC;
HAVAL.HAVAL256 = HAVAL256;
HAVAL.HAVAL256_3 = HAVAL256_3;
HAVAL.HAVAL256_3_HMAC = HAVAL256_3_HMAC;
HAVAL.HAVAL256_4 = HAVAL256_4;
HAVAL.HAVAL256_4_HMAC = HAVAL256_4_HMAC;
HAVAL.HAVAL256_5 = HAVAL256_5;
HAVAL.HAVAL256_5_HMAC = HAVAL256_5_HMAC;
HAVAL.HAVAL256_HMAC = HAVAL256_HMAC;
HAVAL.HAVAL_HMAC = HAVAL_HMAC;
;
//# sourceMappingURL=HAVAL.js.map