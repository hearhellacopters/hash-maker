"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.LUFFA = exports.LUFFA512_HMAC = exports.LUFFA512 = exports.LUFFA384_HMAC = exports.LUFFA384 = exports.LUFFA256_HMAC = exports.LUFFA256 = exports.LUFFA224_HMAC = exports.LUFFA224 = exports.LUFFA_HMAC = exports._LUFFA = exports.Luffa256 = exports.Luffa224 = exports.Luffa512 = exports.Luffa384 = void 0;
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
 * This class implements Luffa-224 and Luffa-256.
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
 * @version   $Revision: 240 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
class LuffaSmallCore extends DigestEngine {
    constructor() {
        super();
        this.V = new Int32Array(28);
        this.doInit();
    }
    /** @see DigestEngine */
    getInternalBlockLength() {
        return 32;
    }
    /** @see Digest */
    getBlockLength() {
        /*
         * Private communication from Luffa designer Watanabe Dai:
         *
         * << I think that there is no problem to use the same
         *    setting as CubeHash, namely B = 256*ceil(k / 256). >>
         */
        return -32;
    }
    /** @see DigestEngine */
    copyState(dst) {
        dst.V = this.V;
        return super.copyState(dst);
    }
    /** @see DigestEngine */
    engineReset() {
        this.V = new Int32Array(28);
        this.V[0] = LuffaSmallCore.IV[0];
        this.V[1] = LuffaSmallCore.IV[1];
        this.V[2] = LuffaSmallCore.IV[2];
        this.V[3] = LuffaSmallCore.IV[3];
        this.V[4] = LuffaSmallCore.IV[4];
        this.V[5] = LuffaSmallCore.IV[5];
        this.V[6] = LuffaSmallCore.IV[6];
        this.V[7] = LuffaSmallCore.IV[7];
        this.V[10] = LuffaSmallCore.IV[8];
        this.V[11] = LuffaSmallCore.IV[9];
        this.V[12] = LuffaSmallCore.IV[10];
        this.V[13] = LuffaSmallCore.IV[11];
        this.V[14] = LuffaSmallCore.IV[12];
        this.V[15] = LuffaSmallCore.IV[13];
        this.V[16] = LuffaSmallCore.IV[14];
        this.V[17] = LuffaSmallCore.IV[15];
        this.V[20] = LuffaSmallCore.IV[16];
        this.V[21] = LuffaSmallCore.IV[17];
        this.V[22] = LuffaSmallCore.IV[18];
        this.V[23] = LuffaSmallCore.IV[19];
        this.V[24] = LuffaSmallCore.IV[20];
        this.V[25] = LuffaSmallCore.IV[21];
        this.V[26] = LuffaSmallCore.IV[22];
        this.V[27] = LuffaSmallCore.IV[23];
    }
    /** @see DigestEngine */
    doPadding(output, outputOffset) {
        var ptr = this.flush();
        this.tmpBuf[ptr] = 0x80;
        for (let i = ptr + 1; i < 32; i++) {
            this.tmpBuf[i] = 0x00;
        }
        this.update(this.tmpBuf, ptr, 32 - ptr);
        for (let i = 0; i < ptr + 1; i++) {
            this.tmpBuf[i] = 0x00;
        }
        this.update(this.tmpBuf, 0, 32);
        this.encodeBEInt(this.V[0] ^ this.V[10] ^ this.V[20], output, outputOffset + 0);
        this.encodeBEInt(this.V[1] ^ this.V[11] ^ this.V[21], output, outputOffset + 4);
        this.encodeBEInt(this.V[2] ^ this.V[12] ^ this.V[22], output, outputOffset + 8);
        this.encodeBEInt(this.V[3] ^ this.V[13] ^ this.V[23], output, outputOffset + 12);
        this.encodeBEInt(this.V[4] ^ this.V[14] ^ this.V[24], output, outputOffset + 16);
        this.encodeBEInt(this.V[5] ^ this.V[15] ^ this.V[25], output, outputOffset + 20);
        this.encodeBEInt(this.V[6] ^ this.V[16] ^ this.V[26], output, outputOffset + 24);
        if (this.getDigestLength() == 32) {
            this.encodeBEInt(this.V[7] ^ this.V[17] ^ this.V[27], output, outputOffset + 28);
        }
    }
    /** @see DigestEngine */
    doInit() {
        this.tmpBuf = new Uint8Array(32);
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
        buf[off + 0] = (val >> 24) & 0xFF;
        buf[off + 1] = (val >> 16) & 0xFF;
        buf[off + 2] = (val >> 8) & 0xFF;
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
    /** @see DigestEngine */
    processBlock(data) {
        var tmp;
        const a = new Int32Array(8);
        const M = new Int32Array(8);
        M[0] = this.decodeBEInt(data, 0);
        M[1] = this.decodeBEInt(data, 4);
        M[2] = this.decodeBEInt(data, 8);
        M[3] = this.decodeBEInt(data, 12);
        M[4] = this.decodeBEInt(data, 16);
        M[5] = this.decodeBEInt(data, 20);
        M[6] = this.decodeBEInt(data, 24);
        M[7] = this.decodeBEInt(data, 28);
        a[0] = this.V[0] ^ this.V[10];
        a[1] = this.V[1] ^ this.V[11];
        a[2] = this.V[2] ^ this.V[12];
        a[3] = this.V[3] ^ this.V[13];
        a[4] = this.V[4] ^ this.V[14];
        a[5] = this.V[5] ^ this.V[15];
        a[6] = this.V[6] ^ this.V[16];
        a[7] = this.V[7] ^ this.V[17];
        a[0] = a[0] ^ this.V[20];
        a[1] = a[1] ^ this.V[21];
        a[2] = a[2] ^ this.V[22];
        a[3] = a[3] ^ this.V[23];
        a[4] = a[4] ^ this.V[24];
        a[5] = a[5] ^ this.V[25];
        a[6] = a[6] ^ this.V[26];
        a[7] = a[7] ^ this.V[27];
        tmp = a[7];
        a[7] = a[6];
        a[6] = a[5];
        a[5] = a[4];
        a[4] = a[3] ^ tmp;
        a[3] = a[2] ^ tmp;
        a[2] = a[1];
        a[1] = a[0] ^ tmp;
        a[0] = tmp;
        this.V[0] = a[0] ^ this.V[0];
        this.V[1] = a[1] ^ this.V[1];
        this.V[2] = a[2] ^ this.V[2];
        this.V[3] = a[3] ^ this.V[3];
        this.V[4] = a[4] ^ this.V[4];
        this.V[5] = a[5] ^ this.V[5];
        this.V[6] = a[6] ^ this.V[6];
        this.V[7] = a[7] ^ this.V[7];
        this.V[0] = M[0] ^ this.V[0];
        this.V[1] = M[1] ^ this.V[1];
        this.V[2] = M[2] ^ this.V[2];
        this.V[3] = M[3] ^ this.V[3];
        this.V[4] = M[4] ^ this.V[4];
        this.V[5] = M[5] ^ this.V[5];
        this.V[6] = M[6] ^ this.V[6];
        this.V[7] = M[7] ^ this.V[7];
        tmp = M[7];
        M[7] = M[6];
        M[6] = M[5];
        M[5] = M[4];
        M[4] = M[3] ^ tmp;
        M[3] = M[2] ^ tmp;
        M[2] = M[1];
        M[1] = M[0] ^ tmp;
        M[0] = tmp;
        this.V[10] = a[0] ^ this.V[10];
        this.V[11] = a[1] ^ this.V[11];
        this.V[12] = a[2] ^ this.V[12];
        this.V[13] = a[3] ^ this.V[13];
        this.V[14] = a[4] ^ this.V[14];
        this.V[15] = a[5] ^ this.V[15];
        this.V[16] = a[6] ^ this.V[16];
        this.V[17] = a[7] ^ this.V[17];
        this.V[10] = M[0] ^ this.V[10];
        this.V[11] = M[1] ^ this.V[11];
        this.V[12] = M[2] ^ this.V[12];
        this.V[13] = M[3] ^ this.V[13];
        this.V[14] = M[4] ^ this.V[14];
        this.V[15] = M[5] ^ this.V[15];
        this.V[16] = M[6] ^ this.V[16];
        this.V[17] = M[7] ^ this.V[17];
        tmp = M[7];
        M[7] = M[6];
        M[6] = M[5];
        M[5] = M[4];
        M[4] = M[3] ^ tmp;
        M[3] = M[2] ^ tmp;
        M[2] = M[1];
        M[1] = M[0] ^ tmp;
        M[0] = tmp;
        this.V[20] = a[0] ^ this.V[20];
        this.V[21] = a[1] ^ this.V[21];
        this.V[22] = a[2] ^ this.V[22];
        this.V[23] = a[3] ^ this.V[23];
        this.V[24] = a[4] ^ this.V[24];
        this.V[25] = a[5] ^ this.V[25];
        this.V[26] = a[6] ^ this.V[26];
        this.V[27] = a[7] ^ this.V[27];
        this.V[20] = M[0] ^ this.V[20];
        this.V[21] = M[1] ^ this.V[21];
        this.V[22] = M[2] ^ this.V[22];
        this.V[23] = M[3] ^ this.V[23];
        this.V[24] = M[4] ^ this.V[24];
        this.V[25] = M[5] ^ this.V[25];
        this.V[26] = M[6] ^ this.V[26];
        this.V[27] = M[7] ^ this.V[27];
        this.V[14] = (this.V[14] << 1) | (this.V[14] >>> 31);
        this.V[15] = (this.V[15] << 1) | (this.V[15] >>> 31);
        this.V[16] = (this.V[16] << 1) | (this.V[16] >>> 31);
        this.V[17] = (this.V[17] << 1) | (this.V[17] >>> 31);
        this.V[24] = (this.V[24] << 2) | (this.V[24] >>> 30);
        this.V[25] = (this.V[25] << 2) | (this.V[25] >>> 30);
        this.V[26] = (this.V[26] << 2) | (this.V[26] >>> 30);
        this.V[27] = (this.V[27] << 2) | (this.V[27] >>> 30);
        for (let r = 0; r < 8; r++) {
            tmp = this.V[0];
            this.V[0] |= this.V[1];
            this.V[2] ^= this.V[3];
            this.V[1] = ~this.V[1];
            this.V[0] ^= this.V[3];
            this.V[3] &= tmp;
            this.V[1] ^= this.V[3];
            this.V[3] ^= this.V[2];
            this.V[2] &= this.V[0];
            this.V[0] = ~this.V[0];
            this.V[2] ^= this.V[1];
            this.V[1] |= this.V[3];
            tmp ^= this.V[1];
            this.V[3] ^= this.V[2];
            this.V[2] &= this.V[1];
            this.V[1] ^= this.V[0];
            this.V[0] = tmp;
            tmp = this.V[5];
            this.V[5] |= this.V[6];
            this.V[7] ^= this.V[4];
            this.V[6] = ~this.V[6];
            this.V[5] ^= this.V[4];
            this.V[4] &= tmp;
            this.V[6] ^= this.V[4];
            this.V[4] ^= this.V[7];
            this.V[7] &= this.V[5];
            this.V[5] = ~this.V[5];
            this.V[7] ^= this.V[6];
            this.V[6] |= this.V[4];
            tmp ^= this.V[6];
            this.V[4] ^= this.V[7];
            this.V[7] &= this.V[6];
            this.V[6] ^= this.V[5];
            this.V[5] = tmp;
            this.V[4] ^= this.V[0];
            this.V[0] = ((this.V[0] << 2) | (this.V[0] >>> 30)) ^ this.V[4];
            this.V[4] = ((this.V[4] << 14) | (this.V[4] >>> 18)) ^ this.V[0];
            this.V[0] = ((this.V[0] << 10) | (this.V[0] >>> 22)) ^ this.V[4];
            this.V[4] = (this.V[4] << 1) | (this.V[4] >>> 31);
            this.V[5] ^= this.V[1];
            this.V[1] = ((this.V[1] << 2) | (this.V[1] >>> 30)) ^ this.V[5];
            this.V[5] = ((this.V[5] << 14) | (this.V[5] >>> 18)) ^ this.V[1];
            this.V[1] = ((this.V[1] << 10) | (this.V[1] >>> 22)) ^ this.V[5];
            this.V[5] = (this.V[5] << 1) | (this.V[5] >>> 31);
            this.V[6] ^= this.V[2];
            this.V[2] = ((this.V[2] << 2) | (this.V[2] >>> 30)) ^ this.V[6];
            this.V[6] = ((this.V[6] << 14) | (this.V[6] >>> 18)) ^ this.V[2];
            this.V[2] = ((this.V[2] << 10) | (this.V[2] >>> 22)) ^ this.V[6];
            this.V[6] = (this.V[6] << 1) | (this.V[6] >>> 31);
            this.V[7] ^= this.V[3];
            this.V[3] = ((this.V[3] << 2) | (this.V[3] >>> 30)) ^ this.V[7];
            this.V[7] = ((this.V[7] << 14) | (this.V[7] >>> 18)) ^ this.V[3];
            this.V[3] = ((this.V[3] << 10) | (this.V[3] >>> 22)) ^ this.V[7];
            this.V[7] = (this.V[7] << 1) | (this.V[7] >>> 31);
            this.V[0] ^= LuffaSmallCore.RC00[r];
            this.V[4] ^= LuffaSmallCore.RC04[r];
        }
        for (let r = 0; r < 8; r++) {
            tmp = this.V[10];
            this.V[10] |= this.V[11];
            this.V[12] ^= this.V[13];
            this.V[11] = ~this.V[11];
            this.V[10] ^= this.V[13];
            this.V[13] &= tmp;
            this.V[11] ^= this.V[13];
            this.V[13] ^= this.V[12];
            this.V[12] &= this.V[10];
            this.V[10] = ~this.V[10];
            this.V[12] ^= this.V[11];
            this.V[11] |= this.V[13];
            tmp ^= this.V[11];
            this.V[13] ^= this.V[12];
            this.V[12] &= this.V[11];
            this.V[11] ^= this.V[10];
            this.V[10] = tmp;
            tmp = this.V[15];
            this.V[15] |= this.V[16];
            this.V[17] ^= this.V[14];
            this.V[16] = ~this.V[16];
            this.V[15] ^= this.V[14];
            this.V[14] &= tmp;
            this.V[16] ^= this.V[14];
            this.V[14] ^= this.V[17];
            this.V[17] &= this.V[15];
            this.V[15] = ~this.V[15];
            this.V[17] ^= this.V[16];
            this.V[16] |= this.V[14];
            tmp ^= this.V[16];
            this.V[14] ^= this.V[17];
            this.V[17] &= this.V[16];
            this.V[16] ^= this.V[15];
            this.V[15] = tmp;
            this.V[14] ^= this.V[10];
            this.V[10] = ((this.V[10] << 2) | (this.V[10] >>> 30)) ^ this.V[14];
            this.V[14] = ((this.V[14] << 14) | (this.V[14] >>> 18)) ^ this.V[10];
            this.V[10] = ((this.V[10] << 10) | (this.V[10] >>> 22)) ^ this.V[14];
            this.V[14] = (this.V[14] << 1) | (this.V[14] >>> 31);
            this.V[15] ^= this.V[11];
            this.V[11] = ((this.V[11] << 2) | (this.V[11] >>> 30)) ^ this.V[15];
            this.V[15] = ((this.V[15] << 14) | (this.V[15] >>> 18)) ^ this.V[11];
            this.V[11] = ((this.V[11] << 10) | (this.V[11] >>> 22)) ^ this.V[15];
            this.V[15] = (this.V[15] << 1) | (this.V[15] >>> 31);
            this.V[16] ^= this.V[12];
            this.V[12] = ((this.V[12] << 2) | (this.V[12] >>> 30)) ^ this.V[16];
            this.V[16] = ((this.V[16] << 14) | (this.V[16] >>> 18)) ^ this.V[12];
            this.V[12] = ((this.V[12] << 10) | (this.V[12] >>> 22)) ^ this.V[16];
            this.V[16] = (this.V[16] << 1) | (this.V[16] >>> 31);
            this.V[17] ^= this.V[13];
            this.V[13] = ((this.V[13] << 2) | (this.V[13] >>> 30)) ^ this.V[17];
            this.V[17] = ((this.V[17] << 14) | (this.V[17] >>> 18)) ^ this.V[13];
            this.V[13] = ((this.V[13] << 10) | (this.V[13] >>> 22)) ^ this.V[17];
            this.V[17] = (this.V[17] << 1) | (this.V[17] >>> 31);
            this.V[10] ^= LuffaSmallCore.RC10[r];
            this.V[14] ^= LuffaSmallCore.RC14[r];
        }
        for (let r = 0; r < 8; r++) {
            tmp = this.V[20];
            this.V[20] |= this.V[21];
            this.V[22] ^= this.V[23];
            this.V[21] = ~this.V[21];
            this.V[20] ^= this.V[23];
            this.V[23] &= tmp;
            this.V[21] ^= this.V[23];
            this.V[23] ^= this.V[22];
            this.V[22] &= this.V[20];
            this.V[20] = ~this.V[20];
            this.V[22] ^= this.V[21];
            this.V[21] |= this.V[23];
            tmp ^= this.V[21];
            this.V[23] ^= this.V[22];
            this.V[22] &= this.V[21];
            this.V[21] ^= this.V[20];
            this.V[20] = tmp;
            tmp = this.V[25];
            this.V[25] |= this.V[26];
            this.V[27] ^= this.V[24];
            this.V[26] = ~this.V[26];
            this.V[25] ^= this.V[24];
            this.V[24] &= tmp;
            this.V[26] ^= this.V[24];
            this.V[24] ^= this.V[27];
            this.V[27] &= this.V[25];
            this.V[25] = ~this.V[25];
            this.V[27] ^= this.V[26];
            this.V[26] |= this.V[24];
            tmp ^= this.V[26];
            this.V[24] ^= this.V[27];
            this.V[27] &= this.V[26];
            this.V[26] ^= this.V[25];
            this.V[25] = tmp;
            this.V[24] ^= this.V[20];
            this.V[20] = ((this.V[20] << 2) | (this.V[20] >>> 30)) ^ this.V[24];
            this.V[24] = ((this.V[24] << 14) | (this.V[24] >>> 18)) ^ this.V[20];
            this.V[20] = ((this.V[20] << 10) | (this.V[20] >>> 22)) ^ this.V[24];
            this.V[24] = (this.V[24] << 1) | (this.V[24] >>> 31);
            this.V[25] ^= this.V[21];
            this.V[21] = ((this.V[21] << 2) | (this.V[21] >>> 30)) ^ this.V[25];
            this.V[25] = ((this.V[25] << 14) | (this.V[25] >>> 18)) ^ this.V[21];
            this.V[21] = ((this.V[21] << 10) | (this.V[21] >>> 22)) ^ this.V[25];
            this.V[25] = (this.V[25] << 1) | (this.V[25] >>> 31);
            this.V[26] ^= this.V[22];
            this.V[22] = ((this.V[22] << 2) | (this.V[22] >>> 30)) ^ this.V[26];
            this.V[26] = ((this.V[26] << 14) | (this.V[26] >>> 18)) ^ this.V[22];
            this.V[22] = ((this.V[22] << 10) | (this.V[22] >>> 22)) ^ this.V[26];
            this.V[26] = (this.V[26] << 1) | (this.V[26] >>> 31);
            this.V[27] ^= this.V[23];
            this.V[23] = ((this.V[23] << 2) | (this.V[23] >>> 30)) ^ this.V[27];
            this.V[27] = ((this.V[27] << 14) | (this.V[27] >>> 18)) ^ this.V[23];
            this.V[23] = ((this.V[23] << 10) | (this.V[23] >>> 22)) ^ this.V[27];
            this.V[27] = (this.V[27] << 1) | (this.V[27] >>> 31);
            this.V[20] ^= LuffaSmallCore.RC20[r];
            this.V[24] ^= LuffaSmallCore.RC24[r];
        }
    }
    /** @see Digest */
    toString() {
        return "Luffa-" + (this.getDigestLength() << 3);
    }
}
LuffaSmallCore.IV = new Int32Array([
    0x6d251e69, 0x44b051e0, 0x4eaa6fb4, 0xdbf78465,
    0x6e292011, 0x90152df4, 0xee058139, 0xdef610bb,
    0xc3b44b95, 0xd9d2f256, 0x70eee9a0, 0xde099fa3,
    0x5d9b0557, 0x8fc944b3, 0xcf1ccf0e, 0x746cd581,
    0xf7efc89d, 0x5dba5781, 0x04016ce5, 0xad659c05,
    0x0306194f, 0x666d1836, 0x24aa230a, 0x8b264ae7
]);
LuffaSmallCore.RC00 = new Int32Array([
    0x303994a6, 0xc0e65299, 0x6cc33a12, 0xdc56983e,
    0x1e00108f, 0x7800423d, 0x8f5b7882, 0x96e1db12
]);
LuffaSmallCore.RC04 = new Int32Array([
    0xe0337818, 0x441ba90d, 0x7f34d442, 0x9389217f,
    0xe5a8bce6, 0x5274baf4, 0x26889ba7, 0x9a226e9d
]);
LuffaSmallCore.RC10 = new Int32Array([
    0xb6de10ed, 0x70f47aae, 0x0707a3d4, 0x1c1e8f51,
    0x707a3d45, 0xaeb28562, 0xbaca1589, 0x40a46f3e
]);
LuffaSmallCore.RC14 = new Int32Array([
    0x01685f3d, 0x05a17cf4, 0xbd09caca, 0xf4272b28,
    0x144ae5cc, 0xfaa7ae2b, 0x2e48f1c1, 0xb923c704
]);
LuffaSmallCore.RC20 = new Int32Array([
    0xfc20d9d2, 0x34552e25, 0x7ad8818f, 0x8438764a,
    0xbb6de032, 0xedb780c8, 0xd9847356, 0xa2c78434
]);
LuffaSmallCore.RC24 = new Int32Array([
    0xe25e72c1, 0xe623bb72, 0x5c58a4a4, 0x1e38e2e7,
    0x78e38b9d, 0x27586719, 0x36eda57f, 0x703aace7
]);
/**
 * <p>This class implements Luffa-384 digest algorithm under the
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
 * @version   $Revision: 235 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
class Luffa384 extends DigestEngine {
    /**
     * Create the engine.
     */
    constructor() {
        super();
        this.V = new Int32Array(38);
        this.doInit();
    }
    /** @see DigestEngine */
    getInternalBlockLength() {
        return 32;
    }
    /** @see Digest */
    getBlockLength() {
        /*
         * Private communication for Luffa designer Watanabe Dai:
         *
         * << I think that there is no problem to use the same
         *    setting as CubeHash, namely B = 256*ceil(k / 256). >>
         */
        return -32;
    }
    /** @see Digest */
    getDigestLength() {
        return 48;
    }
    /** @see Digest */
    copy() {
        return this.copyState(new Luffa384());
    }
    /** @see DigestEngine */
    copyState(dst) {
        dst.V = this.V;
        return super.copyState(dst);
    }
    /** @see DigestEngine */
    engineReset() {
        this.V[0] = Luffa384.IV[0];
        this.V[1] = Luffa384.IV[1];
        this.V[2] = Luffa384.IV[2];
        this.V[3] = Luffa384.IV[3];
        this.V[4] = Luffa384.IV[4];
        this.V[5] = Luffa384.IV[5];
        this.V[6] = Luffa384.IV[6];
        this.V[7] = Luffa384.IV[7];
        this.V[10] = Luffa384.IV[8];
        this.V[11] = Luffa384.IV[9];
        this.V[12] = Luffa384.IV[10];
        this.V[13] = Luffa384.IV[11];
        this.V[14] = Luffa384.IV[12];
        this.V[15] = Luffa384.IV[13];
        this.V[16] = Luffa384.IV[14];
        this.V[17] = Luffa384.IV[15];
        this.V[20] = Luffa384.IV[16];
        this.V[21] = Luffa384.IV[17];
        this.V[22] = Luffa384.IV[18];
        this.V[23] = Luffa384.IV[19];
        this.V[24] = Luffa384.IV[20];
        this.V[25] = Luffa384.IV[21];
        this.V[26] = Luffa384.IV[22];
        this.V[27] = Luffa384.IV[23];
        this.V[30] = Luffa384.IV[24];
        this.V[31] = Luffa384.IV[25];
        this.V[32] = Luffa384.IV[26];
        this.V[33] = Luffa384.IV[27];
        this.V[34] = Luffa384.IV[28];
        this.V[35] = Luffa384.IV[29];
        this.V[36] = Luffa384.IV[30];
        this.V[37] = Luffa384.IV[31];
    }
    /** @see DigestEngine */
    doPadding(output, outputOffset) {
        var ptr = this.flush();
        this.tmpBuf[ptr] = 0x80;
        for (let i = ptr + 1; i < 32; i++) {
            this.tmpBuf[i] = 0x00;
        }
        this.update(this.tmpBuf, ptr, 32 - ptr);
        for (let i = 0; i < ptr + 1; i++) {
            this.tmpBuf[i] = 0x00;
        }
        this.update(this.tmpBuf, 0, 32);
        this.encodeBEInt(this.V[0] ^ this.V[10] ^ this.V[20] ^ this.V[30], output, outputOffset + 0);
        this.encodeBEInt(this.V[1] ^ this.V[11] ^ this.V[21] ^ this.V[31], output, outputOffset + 4);
        this.encodeBEInt(this.V[2] ^ this.V[12] ^ this.V[22] ^ this.V[32], output, outputOffset + 8);
        this.encodeBEInt(this.V[3] ^ this.V[13] ^ this.V[23] ^ this.V[33], output, outputOffset + 12);
        this.encodeBEInt(this.V[4] ^ this.V[14] ^ this.V[24] ^ this.V[34], output, outputOffset + 16);
        this.encodeBEInt(this.V[5] ^ this.V[15] ^ this.V[25] ^ this.V[35], output, outputOffset + 20);
        this.encodeBEInt(this.V[6] ^ this.V[16] ^ this.V[26] ^ this.V[36], output, outputOffset + 24);
        this.encodeBEInt(this.V[7] ^ this.V[17] ^ this.V[27] ^ this.V[37], output, outputOffset + 28);
        this.update(this.tmpBuf, 0, 32);
        this.encodeBEInt(this.V[0] ^ this.V[10] ^ this.V[20] ^ this.V[30], output, outputOffset + 32);
        this.encodeBEInt(this.V[1] ^ this.V[11] ^ this.V[21] ^ this.V[31], output, outputOffset + 36);
        this.encodeBEInt(this.V[2] ^ this.V[12] ^ this.V[22] ^ this.V[32], output, outputOffset + 40);
        this.encodeBEInt(this.V[3] ^ this.V[13] ^ this.V[23] ^ this.V[33], output, outputOffset + 44);
    }
    /** @see DigestEngine */
    doInit() {
        this.V = new Int32Array(38);
        this.tmpBuf = new Uint8Array(32);
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
        buf[off + 0] = (val >>> 24);
        buf[off + 1] = (val >>> 16);
        buf[off + 2] = (val >>> 8);
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
    /** @see DigestEngine */
    processBlock(data) {
        var tmp;
        const a = new Int32Array(8);
        const b = new Int32Array(8);
        const M = new Int32Array(8);
        M[0] = this.decodeBEInt(data, 0);
        M[1] = this.decodeBEInt(data, 4);
        M[2] = this.decodeBEInt(data, 8);
        M[3] = this.decodeBEInt(data, 12);
        M[4] = this.decodeBEInt(data, 16);
        M[5] = this.decodeBEInt(data, 20);
        M[6] = this.decodeBEInt(data, 24);
        M[7] = this.decodeBEInt(data, 28);
        a[0] = this.V[0] ^ this.V[10];
        a[1] = this.V[1] ^ this.V[11];
        a[2] = this.V[2] ^ this.V[12];
        a[3] = this.V[3] ^ this.V[13];
        a[4] = this.V[4] ^ this.V[14];
        a[5] = this.V[5] ^ this.V[15];
        a[6] = this.V[6] ^ this.V[16];
        a[7] = this.V[7] ^ this.V[17];
        b[0] = this.V[20] ^ this.V[30];
        b[1] = this.V[21] ^ this.V[31];
        b[2] = this.V[22] ^ this.V[32];
        b[3] = this.V[23] ^ this.V[33];
        b[4] = this.V[24] ^ this.V[34];
        b[5] = this.V[25] ^ this.V[35];
        b[6] = this.V[26] ^ this.V[36];
        b[7] = this.V[27] ^ this.V[37];
        a[0] = a[0] ^ b[0];
        a[1] = a[1] ^ b[1];
        a[2] = a[2] ^ b[2];
        a[3] = a[3] ^ b[3];
        a[4] = a[4] ^ b[4];
        a[5] = a[5] ^ b[5];
        a[6] = a[6] ^ b[6];
        a[7] = a[7] ^ b[7];
        tmp = a[7];
        a[7] = a[6];
        a[6] = a[5];
        a[5] = a[4];
        a[4] = a[3] ^ tmp;
        a[3] = a[2] ^ tmp;
        a[2] = a[1];
        a[1] = a[0] ^ tmp;
        a[0] = tmp;
        this.V[0] = a[0] ^ this.V[0];
        this.V[1] = a[1] ^ this.V[1];
        this.V[2] = a[2] ^ this.V[2];
        this.V[3] = a[3] ^ this.V[3];
        this.V[4] = a[4] ^ this.V[4];
        this.V[5] = a[5] ^ this.V[5];
        this.V[6] = a[6] ^ this.V[6];
        this.V[7] = a[7] ^ this.V[7];
        this.V[10] = a[0] ^ this.V[10];
        this.V[11] = a[1] ^ this.V[11];
        this.V[12] = a[2] ^ this.V[12];
        this.V[13] = a[3] ^ this.V[13];
        this.V[14] = a[4] ^ this.V[14];
        this.V[15] = a[5] ^ this.V[15];
        this.V[16] = a[6] ^ this.V[16];
        this.V[17] = a[7] ^ this.V[17];
        this.V[20] = a[0] ^ this.V[20];
        this.V[21] = a[1] ^ this.V[21];
        this.V[22] = a[2] ^ this.V[22];
        this.V[23] = a[3] ^ this.V[23];
        this.V[24] = a[4] ^ this.V[24];
        this.V[25] = a[5] ^ this.V[25];
        this.V[26] = a[6] ^ this.V[26];
        this.V[27] = a[7] ^ this.V[27];
        this.V[30] = a[0] ^ this.V[30];
        this.V[31] = a[1] ^ this.V[31];
        this.V[32] = a[2] ^ this.V[32];
        this.V[33] = a[3] ^ this.V[33];
        this.V[34] = a[4] ^ this.V[34];
        this.V[35] = a[5] ^ this.V[35];
        this.V[36] = a[6] ^ this.V[36];
        this.V[37] = a[7] ^ this.V[37];
        tmp = this.V[7];
        b[7] = this.V[6];
        b[6] = this.V[5];
        b[5] = this.V[4];
        b[4] = this.V[3] ^ tmp;
        b[3] = this.V[2] ^ tmp;
        b[2] = this.V[1];
        b[1] = this.V[0] ^ tmp;
        b[0] = tmp;
        b[0] = b[0] ^ this.V[30];
        b[1] = b[1] ^ this.V[31];
        b[2] = b[2] ^ this.V[32];
        b[3] = b[3] ^ this.V[33];
        b[4] = b[4] ^ this.V[34];
        b[5] = b[5] ^ this.V[35];
        b[6] = b[6] ^ this.V[36];
        b[7] = b[7] ^ this.V[37];
        tmp = this.V[37];
        this.V[37] = this.V[36];
        this.V[36] = this.V[35];
        this.V[35] = this.V[34];
        this.V[34] = this.V[33] ^ tmp;
        this.V[33] = this.V[32] ^ tmp;
        this.V[32] = this.V[31];
        this.V[31] = this.V[30] ^ tmp;
        this.V[30] = tmp;
        this.V[30] = this.V[30] ^ this.V[20];
        this.V[31] = this.V[31] ^ this.V[21];
        this.V[32] = this.V[32] ^ this.V[22];
        this.V[33] = this.V[33] ^ this.V[23];
        this.V[34] = this.V[34] ^ this.V[24];
        this.V[35] = this.V[35] ^ this.V[25];
        this.V[36] = this.V[36] ^ this.V[26];
        this.V[37] = this.V[37] ^ this.V[27];
        tmp = this.V[27];
        this.V[27] = this.V[26];
        this.V[26] = this.V[25];
        this.V[25] = this.V[24];
        this.V[24] = this.V[23] ^ tmp;
        this.V[23] = this.V[22] ^ tmp;
        this.V[22] = this.V[21];
        this.V[21] = this.V[20] ^ tmp;
        this.V[20] = tmp;
        this.V[20] = this.V[20] ^ this.V[10];
        this.V[21] = this.V[21] ^ this.V[11];
        this.V[22] = this.V[22] ^ this.V[12];
        this.V[23] = this.V[23] ^ this.V[13];
        this.V[24] = this.V[24] ^ this.V[14];
        this.V[25] = this.V[25] ^ this.V[15];
        this.V[26] = this.V[26] ^ this.V[16];
        this.V[27] = this.V[27] ^ this.V[17];
        tmp = this.V[17];
        this.V[17] = this.V[16];
        this.V[16] = this.V[15];
        this.V[15] = this.V[14];
        this.V[14] = this.V[13] ^ tmp;
        this.V[13] = this.V[12] ^ tmp;
        this.V[12] = this.V[11];
        this.V[11] = this.V[10] ^ tmp;
        this.V[10] = tmp;
        this.V[10] = this.V[10] ^ this.V[0];
        this.V[11] = this.V[11] ^ this.V[1];
        this.V[12] = this.V[12] ^ this.V[2];
        this.V[13] = this.V[13] ^ this.V[3];
        this.V[14] = this.V[14] ^ this.V[4];
        this.V[15] = this.V[15] ^ this.V[5];
        this.V[16] = this.V[16] ^ this.V[6];
        this.V[17] = this.V[17] ^ this.V[7];
        this.V[0] = b[0] ^ M[0];
        this.V[1] = b[1] ^ M[1];
        this.V[2] = b[2] ^ M[2];
        this.V[3] = b[3] ^ M[3];
        this.V[4] = b[4] ^ M[4];
        this.V[5] = b[5] ^ M[5];
        this.V[6] = b[6] ^ M[6];
        this.V[7] = b[7] ^ M[7];
        tmp = M[7];
        M[7] = M[6];
        M[6] = M[5];
        M[5] = M[4];
        M[4] = M[3] ^ tmp;
        M[3] = M[2] ^ tmp;
        M[2] = M[1];
        M[1] = M[0] ^ tmp;
        M[0] = tmp;
        this.V[10] = this.V[10] ^ M[0];
        this.V[11] = this.V[11] ^ M[1];
        this.V[12] = this.V[12] ^ M[2];
        this.V[13] = this.V[13] ^ M[3];
        this.V[14] = this.V[14] ^ M[4];
        this.V[15] = this.V[15] ^ M[5];
        this.V[16] = this.V[16] ^ M[6];
        this.V[17] = this.V[17] ^ M[7];
        tmp = M[7];
        M[7] = M[6];
        M[6] = M[5];
        M[5] = M[4];
        M[4] = M[3] ^ tmp;
        M[3] = M[2] ^ tmp;
        M[2] = M[1];
        M[1] = M[0] ^ tmp;
        M[0] = tmp;
        this.V[20] = this.V[20] ^ M[0];
        this.V[21] = this.V[21] ^ M[1];
        this.V[22] = this.V[22] ^ M[2];
        this.V[23] = this.V[23] ^ M[3];
        this.V[24] = this.V[24] ^ M[4];
        this.V[25] = this.V[25] ^ M[5];
        this.V[26] = this.V[26] ^ M[6];
        this.V[27] = this.V[27] ^ M[7];
        tmp = M[7];
        M[7] = M[6];
        M[6] = M[5];
        M[5] = M[4];
        M[4] = M[3] ^ tmp;
        M[3] = M[2] ^ tmp;
        M[2] = M[1];
        M[1] = M[0] ^ tmp;
        M[0] = tmp;
        this.V[30] = this.V[30] ^ M[0];
        this.V[31] = this.V[31] ^ M[1];
        this.V[32] = this.V[32] ^ M[2];
        this.V[33] = this.V[33] ^ M[3];
        this.V[34] = this.V[34] ^ M[4];
        this.V[35] = this.V[35] ^ M[5];
        this.V[36] = this.V[36] ^ M[6];
        this.V[37] = this.V[37] ^ M[7];
        this.V[14] = (this.V[14] << 1) | (this.V[14] >>> 31);
        this.V[15] = (this.V[15] << 1) | (this.V[15] >>> 31);
        this.V[16] = (this.V[16] << 1) | (this.V[16] >>> 31);
        this.V[17] = (this.V[17] << 1) | (this.V[17] >>> 31);
        this.V[24] = (this.V[24] << 2) | (this.V[24] >>> 30);
        this.V[25] = (this.V[25] << 2) | (this.V[25] >>> 30);
        this.V[26] = (this.V[26] << 2) | (this.V[26] >>> 30);
        this.V[27] = (this.V[27] << 2) | (this.V[27] >>> 30);
        this.V[34] = (this.V[34] << 3) | (this.V[34] >>> 29);
        this.V[35] = (this.V[35] << 3) | (this.V[35] >>> 29);
        this.V[36] = (this.V[36] << 3) | (this.V[36] >>> 29);
        this.V[37] = (this.V[37] << 3) | (this.V[37] >>> 29);
        for (let r = 0; r < 8; r++) {
            tmp = this.V[0];
            this.V[0] |= this.V[1];
            this.V[2] ^= this.V[3];
            this.V[1] = ~this.V[1];
            this.V[0] ^= this.V[3];
            this.V[3] &= tmp;
            this.V[1] ^= this.V[3];
            this.V[3] ^= this.V[2];
            this.V[2] &= this.V[0];
            this.V[0] = ~this.V[0];
            this.V[2] ^= this.V[1];
            this.V[1] |= this.V[3];
            tmp ^= this.V[1];
            this.V[3] ^= this.V[2];
            this.V[2] &= this.V[1];
            this.V[1] ^= this.V[0];
            this.V[0] = tmp;
            tmp = this.V[5];
            this.V[5] |= this.V[6];
            this.V[7] ^= this.V[4];
            this.V[6] = ~this.V[6];
            this.V[5] ^= this.V[4];
            this.V[4] &= tmp;
            this.V[6] ^= this.V[4];
            this.V[4] ^= this.V[7];
            this.V[7] &= this.V[5];
            this.V[5] = ~this.V[5];
            this.V[7] ^= this.V[6];
            this.V[6] |= this.V[4];
            tmp ^= this.V[6];
            this.V[4] ^= this.V[7];
            this.V[7] &= this.V[6];
            this.V[6] ^= this.V[5];
            this.V[5] = tmp;
            this.V[4] ^= this.V[0];
            this.V[0] = ((this.V[0] << 2) | (this.V[0] >>> 30)) ^ this.V[4];
            this.V[4] = ((this.V[4] << 14) | (this.V[4] >>> 18)) ^ this.V[0];
            this.V[0] = ((this.V[0] << 10) | (this.V[0] >>> 22)) ^ this.V[4];
            this.V[4] = (this.V[4] << 1) | (this.V[4] >>> 31);
            this.V[5] ^= this.V[1];
            this.V[1] = ((this.V[1] << 2) | (this.V[1] >>> 30)) ^ this.V[5];
            this.V[5] = ((this.V[5] << 14) | (this.V[5] >>> 18)) ^ this.V[1];
            this.V[1] = ((this.V[1] << 10) | (this.V[1] >>> 22)) ^ this.V[5];
            this.V[5] = (this.V[5] << 1) | (this.V[5] >>> 31);
            this.V[6] ^= this.V[2];
            this.V[2] = ((this.V[2] << 2) | (this.V[2] >>> 30)) ^ this.V[6];
            this.V[6] = ((this.V[6] << 14) | (this.V[6] >>> 18)) ^ this.V[2];
            this.V[2] = ((this.V[2] << 10) | (this.V[2] >>> 22)) ^ this.V[6];
            this.V[6] = (this.V[6] << 1) | (this.V[6] >>> 31);
            this.V[7] ^= this.V[3];
            this.V[3] = ((this.V[3] << 2) | (this.V[3] >>> 30)) ^ this.V[7];
            this.V[7] = ((this.V[7] << 14) | (this.V[7] >>> 18)) ^ this.V[3];
            this.V[3] = ((this.V[3] << 10) | (this.V[3] >>> 22)) ^ this.V[7];
            this.V[7] = (this.V[7] << 1) | (this.V[7] >>> 31);
            this.V[0] ^= Luffa384.RC00[r];
            this.V[4] ^= Luffa384.RC04[r];
        }
        for (let r = 0; r < 8; r++) {
            tmp = this.V[10];
            this.V[10] |= this.V[11];
            this.V[12] ^= this.V[13];
            this.V[11] = ~this.V[11];
            this.V[10] ^= this.V[13];
            this.V[13] &= tmp;
            this.V[11] ^= this.V[13];
            this.V[13] ^= this.V[12];
            this.V[12] &= this.V[10];
            this.V[10] = ~this.V[10];
            this.V[12] ^= this.V[11];
            this.V[11] |= this.V[13];
            tmp ^= this.V[11];
            this.V[13] ^= this.V[12];
            this.V[12] &= this.V[11];
            this.V[11] ^= this.V[10];
            this.V[10] = tmp;
            tmp = this.V[15];
            this.V[15] |= this.V[16];
            this.V[17] ^= this.V[14];
            this.V[16] = ~this.V[16];
            this.V[15] ^= this.V[14];
            this.V[14] &= tmp;
            this.V[16] ^= this.V[14];
            this.V[14] ^= this.V[17];
            this.V[17] &= this.V[15];
            this.V[15] = ~this.V[15];
            this.V[17] ^= this.V[16];
            this.V[16] |= this.V[14];
            tmp ^= this.V[16];
            this.V[14] ^= this.V[17];
            this.V[17] &= this.V[16];
            this.V[16] ^= this.V[15];
            this.V[15] = tmp;
            this.V[14] ^= this.V[10];
            this.V[10] = ((this.V[10] << 2) | (this.V[10] >>> 30)) ^ this.V[14];
            this.V[14] = ((this.V[14] << 14) | (this.V[14] >>> 18)) ^ this.V[10];
            this.V[10] = ((this.V[10] << 10) | (this.V[10] >>> 22)) ^ this.V[14];
            this.V[14] = (this.V[14] << 1) | (this.V[14] >>> 31);
            this.V[15] ^= this.V[11];
            this.V[11] = ((this.V[11] << 2) | (this.V[11] >>> 30)) ^ this.V[15];
            this.V[15] = ((this.V[15] << 14) | (this.V[15] >>> 18)) ^ this.V[11];
            this.V[11] = ((this.V[11] << 10) | (this.V[11] >>> 22)) ^ this.V[15];
            this.V[15] = (this.V[15] << 1) | (this.V[15] >>> 31);
            this.V[16] ^= this.V[12];
            this.V[12] = ((this.V[12] << 2) | (this.V[12] >>> 30)) ^ this.V[16];
            this.V[16] = ((this.V[16] << 14) | (this.V[16] >>> 18)) ^ this.V[12];
            this.V[12] = ((this.V[12] << 10) | (this.V[12] >>> 22)) ^ this.V[16];
            this.V[16] = (this.V[16] << 1) | (this.V[16] >>> 31);
            this.V[17] ^= this.V[13];
            this.V[13] = ((this.V[13] << 2) | (this.V[13] >>> 30)) ^ this.V[17];
            this.V[17] = ((this.V[17] << 14) | (this.V[17] >>> 18)) ^ this.V[13];
            this.V[13] = ((this.V[13] << 10) | (this.V[13] >>> 22)) ^ this.V[17];
            this.V[17] = (this.V[17] << 1) | (this.V[17] >>> 31);
            this.V[10] ^= Luffa384.RC10[r];
            this.V[14] ^= Luffa384.RC14[r];
        }
        for (let r = 0; r < 8; r++) {
            tmp = this.V[20];
            this.V[20] |= this.V[21];
            this.V[22] ^= this.V[23];
            this.V[21] = ~this.V[21];
            this.V[20] ^= this.V[23];
            this.V[23] &= tmp;
            this.V[21] ^= this.V[23];
            this.V[23] ^= this.V[22];
            this.V[22] &= this.V[20];
            this.V[20] = ~this.V[20];
            this.V[22] ^= this.V[21];
            this.V[21] |= this.V[23];
            tmp ^= this.V[21];
            this.V[23] ^= this.V[22];
            this.V[22] &= this.V[21];
            this.V[21] ^= this.V[20];
            this.V[20] = tmp;
            tmp = this.V[25];
            this.V[25] |= this.V[26];
            this.V[27] ^= this.V[24];
            this.V[26] = ~this.V[26];
            this.V[25] ^= this.V[24];
            this.V[24] &= tmp;
            this.V[26] ^= this.V[24];
            this.V[24] ^= this.V[27];
            this.V[27] &= this.V[25];
            this.V[25] = ~this.V[25];
            this.V[27] ^= this.V[26];
            this.V[26] |= this.V[24];
            tmp ^= this.V[26];
            this.V[24] ^= this.V[27];
            this.V[27] &= this.V[26];
            this.V[26] ^= this.V[25];
            this.V[25] = tmp;
            this.V[24] ^= this.V[20];
            this.V[20] = ((this.V[20] << 2) | (this.V[20] >>> 30)) ^ this.V[24];
            this.V[24] = ((this.V[24] << 14) | (this.V[24] >>> 18)) ^ this.V[20];
            this.V[20] = ((this.V[20] << 10) | (this.V[20] >>> 22)) ^ this.V[24];
            this.V[24] = (this.V[24] << 1) | (this.V[24] >>> 31);
            this.V[25] ^= this.V[21];
            this.V[21] = ((this.V[21] << 2) | (this.V[21] >>> 30)) ^ this.V[25];
            this.V[25] = ((this.V[25] << 14) | (this.V[25] >>> 18)) ^ this.V[21];
            this.V[21] = ((this.V[21] << 10) | (this.V[21] >>> 22)) ^ this.V[25];
            this.V[25] = (this.V[25] << 1) | (this.V[25] >>> 31);
            this.V[26] ^= this.V[22];
            this.V[22] = ((this.V[22] << 2) | (this.V[22] >>> 30)) ^ this.V[26];
            this.V[26] = ((this.V[26] << 14) | (this.V[26] >>> 18)) ^ this.V[22];
            this.V[22] = ((this.V[22] << 10) | (this.V[22] >>> 22)) ^ this.V[26];
            this.V[26] = (this.V[26] << 1) | (this.V[26] >>> 31);
            this.V[27] ^= this.V[23];
            this.V[23] = ((this.V[23] << 2) | (this.V[23] >>> 30)) ^ this.V[27];
            this.V[27] = ((this.V[27] << 14) | (this.V[27] >>> 18)) ^ this.V[23];
            this.V[23] = ((this.V[23] << 10) | (this.V[23] >>> 22)) ^ this.V[27];
            this.V[27] = (this.V[27] << 1) | (this.V[27] >>> 31);
            this.V[20] ^= Luffa384.RC20[r];
            this.V[24] ^= Luffa384.RC24[r];
        }
        for (let r = 0; r < 8; r++) {
            tmp = this.V[30];
            this.V[30] |= this.V[31];
            this.V[32] ^= this.V[33];
            this.V[31] = ~this.V[31];
            this.V[30] ^= this.V[33];
            this.V[33] &= tmp;
            this.V[31] ^= this.V[33];
            this.V[33] ^= this.V[32];
            this.V[32] &= this.V[30];
            this.V[30] = ~this.V[30];
            this.V[32] ^= this.V[31];
            this.V[31] |= this.V[33];
            tmp ^= this.V[31];
            this.V[33] ^= this.V[32];
            this.V[32] &= this.V[31];
            this.V[31] ^= this.V[30];
            this.V[30] = tmp;
            tmp = this.V[35];
            this.V[35] |= this.V[36];
            this.V[37] ^= this.V[34];
            this.V[36] = ~this.V[36];
            this.V[35] ^= this.V[34];
            this.V[34] &= tmp;
            this.V[36] ^= this.V[34];
            this.V[34] ^= this.V[37];
            this.V[37] &= this.V[35];
            this.V[35] = ~this.V[35];
            this.V[37] ^= this.V[36];
            this.V[36] |= this.V[34];
            tmp ^= this.V[36];
            this.V[34] ^= this.V[37];
            this.V[37] &= this.V[36];
            this.V[36] ^= this.V[35];
            this.V[35] = tmp;
            this.V[34] ^= this.V[30];
            this.V[30] = ((this.V[30] << 2) | (this.V[30] >>> 30)) ^ this.V[34];
            this.V[34] = ((this.V[34] << 14) | (this.V[34] >>> 18)) ^ this.V[30];
            this.V[30] = ((this.V[30] << 10) | (this.V[30] >>> 22)) ^ this.V[34];
            this.V[34] = (this.V[34] << 1) | (this.V[34] >>> 31);
            this.V[35] ^= this.V[31];
            this.V[31] = ((this.V[31] << 2) | (this.V[31] >>> 30)) ^ this.V[35];
            this.V[35] = ((this.V[35] << 14) | (this.V[35] >>> 18)) ^ this.V[31];
            this.V[31] = ((this.V[31] << 10) | (this.V[31] >>> 22)) ^ this.V[35];
            this.V[35] = (this.V[35] << 1) | (this.V[35] >>> 31);
            this.V[36] ^= this.V[32];
            this.V[32] = ((this.V[32] << 2) | (this.V[32] >>> 30)) ^ this.V[36];
            this.V[36] = ((this.V[36] << 14) | (this.V[36] >>> 18)) ^ this.V[32];
            this.V[32] = ((this.V[32] << 10) | (this.V[32] >>> 22)) ^ this.V[36];
            this.V[36] = (this.V[36] << 1) | (this.V[36] >>> 31);
            this.V[37] ^= this.V[33];
            this.V[33] = ((this.V[33] << 2) | (this.V[33] >>> 30)) ^ this.V[37];
            this.V[37] = ((this.V[37] << 14) | (this.V[37] >>> 18)) ^ this.V[33];
            this.V[33] = ((this.V[33] << 10) | (this.V[33] >>> 22)) ^ this.V[37];
            this.V[37] = (this.V[37] << 1) | (this.V[37] >>> 31);
            this.V[30] ^= Luffa384.RC30[r];
            this.V[34] ^= Luffa384.RC34[r];
        }
    }
    /** @see Digest */
    toString() {
        return "Luffa-384";
    }
}
exports.Luffa384 = Luffa384;
Luffa384.IV = new Int32Array([
    0x6d251e69, 0x44b051e0, 0x4eaa6fb4, 0xdbf78465,
    0x6e292011, 0x90152df4, 0xee058139, 0xdef610bb,
    0xc3b44b95, 0xd9d2f256, 0x70eee9a0, 0xde099fa3,
    0x5d9b0557, 0x8fc944b3, 0xcf1ccf0e, 0x746cd581,
    0xf7efc89d, 0x5dba5781, 0x04016ce5, 0xad659c05,
    0x0306194f, 0x666d1836, 0x24aa230a, 0x8b264ae7,
    0x858075d5, 0x36d79cce, 0xe571f7d7, 0x204b1f67,
    0x35870c6a, 0x57e9e923, 0x14bcb808, 0x7cde72ce
]);
Luffa384.RC00 = new Int32Array([
    0x303994a6, 0xc0e65299, 0x6cc33a12, 0xdc56983e,
    0x1e00108f, 0x7800423d, 0x8f5b7882, 0x96e1db12
]);
Luffa384.RC04 = new Int32Array([
    0xe0337818, 0x441ba90d, 0x7f34d442, 0x9389217f,
    0xe5a8bce6, 0x5274baf4, 0x26889ba7, 0x9a226e9d
]);
Luffa384.RC10 = new Int32Array([
    0xb6de10ed, 0x70f47aae, 0x0707a3d4, 0x1c1e8f51,
    0x707a3d45, 0xaeb28562, 0xbaca1589, 0x40a46f3e
]);
Luffa384.RC14 = new Int32Array([
    0x01685f3d, 0x05a17cf4, 0xbd09caca, 0xf4272b28,
    0x144ae5cc, 0xfaa7ae2b, 0x2e48f1c1, 0xb923c704
]);
Luffa384.RC20 = new Int32Array([
    0xfc20d9d2, 0x34552e25, 0x7ad8818f, 0x8438764a,
    0xbb6de032, 0xedb780c8, 0xd9847356, 0xa2c78434
]);
Luffa384.RC24 = new Int32Array([
    0xe25e72c1, 0xe623bb72, 0x5c58a4a4, 0x1e38e2e7,
    0x78e38b9d, 0x27586719, 0x36eda57f, 0x703aace7
]);
Luffa384.RC30 = new Int32Array([
    0xb213afa5, 0xc84ebe95, 0x4e608a22, 0x56d858fe,
    0x343b138f, 0xd0ec4e3d, 0x2ceb4882, 0xb3ad2208
]);
Luffa384.RC34 = new Int32Array([
    0xe028c9bf, 0x44756f91, 0x7e8fce32, 0x956548be,
    0xfe191be2, 0x3cb226e5, 0x5944a28e, 0xa1c4c355
]);
/**
 * <p>This class implements Luffa-512 digest algorithm under the
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
 * @version   $Revision: 235 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
class Luffa512 extends DigestEngine {
    /**
     * Create the engine.
     */
    constructor() {
        super();
        this.V = new Int32Array(38);
        this.doInit();
    }
    /** @see DigestEngine */
    getInternalBlockLength() {
        return 32;
    }
    /** @see Digest */
    getBlockLength() {
        /*
         * Private communication for Luffa designer Watanabe Dai:
         *
         * << I think that there is no problem to use the same
         *    setting as CubeHash, namely B = 256*ceil(k / 256). >>
         */
        return -32;
    }
    /** @see Digest */
    getDigestLength() {
        return 64;
    }
    /** @see Digest */
    copy() {
        return this.copyState(new Luffa512());
    }
    /** @see DigestEngine */
    copyState(dst) {
        dst.V = this.V;
        return super.copyState(dst);
    }
    /** @see DigestEngine */
    engineReset() {
        this.V[0] = Luffa512.IV[0];
        this.V[1] = Luffa512.IV[1];
        this.V[2] = Luffa512.IV[2];
        this.V[3] = Luffa512.IV[3];
        this.V[4] = Luffa512.IV[4];
        this.V[5] = Luffa512.IV[5];
        this.V[6] = Luffa512.IV[6];
        this.V[7] = Luffa512.IV[7];
        this.V[10] = Luffa512.IV[8];
        this.V[11] = Luffa512.IV[9];
        this.V[12] = Luffa512.IV[10];
        this.V[13] = Luffa512.IV[11];
        this.V[14] = Luffa512.IV[12];
        this.V[15] = Luffa512.IV[13];
        this.V[16] = Luffa512.IV[14];
        this.V[17] = Luffa512.IV[15];
        this.V[20] = Luffa512.IV[16];
        this.V[21] = Luffa512.IV[17];
        this.V[22] = Luffa512.IV[18];
        this.V[23] = Luffa512.IV[19];
        this.V[24] = Luffa512.IV[20];
        this.V[25] = Luffa512.IV[21];
        this.V[26] = Luffa512.IV[22];
        this.V[27] = Luffa512.IV[23];
        this.V[30] = Luffa512.IV[24];
        this.V[31] = Luffa512.IV[25];
        this.V[32] = Luffa512.IV[26];
        this.V[33] = Luffa512.IV[27];
        this.V[34] = Luffa512.IV[28];
        this.V[35] = Luffa512.IV[29];
        this.V[36] = Luffa512.IV[30];
        this.V[37] = Luffa512.IV[31];
        this.V[40] = Luffa512.IV[32];
        this.V[41] = Luffa512.IV[33];
        this.V[42] = Luffa512.IV[34];
        this.V[43] = Luffa512.IV[35];
        this.V[44] = Luffa512.IV[36];
        this.V[45] = Luffa512.IV[37];
        this.V[46] = Luffa512.IV[38];
        this.V[47] = Luffa512.IV[39];
    }
    /** @see DigestEngine */
    doPadding(out, off) {
        var ptr = this.flush();
        this.tmpBuf[ptr] = 0x80;
        for (let i = ptr + 1; i < 32; i++) {
            this.tmpBuf[i] = 0x00;
        }
        this.update(this.tmpBuf, ptr, 32 - ptr);
        for (let i = 0; i < ptr + 1; i++) {
            this.tmpBuf[i] = 0x00;
        }
        this.update(this.tmpBuf, 0, 32);
        this.encodeBEInt(this.V[0] ^ this.V[10] ^ this.V[20] ^ this.V[30] ^ this.V[40], out, off + 0);
        this.encodeBEInt(this.V[1] ^ this.V[11] ^ this.V[21] ^ this.V[31] ^ this.V[41], out, off + 4);
        this.encodeBEInt(this.V[2] ^ this.V[12] ^ this.V[22] ^ this.V[32] ^ this.V[42], out, off + 8);
        this.encodeBEInt(this.V[3] ^ this.V[13] ^ this.V[23] ^ this.V[33] ^ this.V[43], out, off + 12);
        this.encodeBEInt(this.V[4] ^ this.V[14] ^ this.V[24] ^ this.V[34] ^ this.V[44], out, off + 16);
        this.encodeBEInt(this.V[5] ^ this.V[15] ^ this.V[25] ^ this.V[35] ^ this.V[45], out, off + 20);
        this.encodeBEInt(this.V[6] ^ this.V[16] ^ this.V[26] ^ this.V[36] ^ this.V[46], out, off + 24);
        this.encodeBEInt(this.V[7] ^ this.V[17] ^ this.V[27] ^ this.V[37] ^ this.V[47], out, off + 28);
        this.update(this.tmpBuf, 0, 32);
        this.encodeBEInt(this.V[0] ^ this.V[10] ^ this.V[20] ^ this.V[30] ^ this.V[40], out, off + 32);
        this.encodeBEInt(this.V[1] ^ this.V[11] ^ this.V[21] ^ this.V[31] ^ this.V[41], out, off + 36);
        this.encodeBEInt(this.V[2] ^ this.V[12] ^ this.V[22] ^ this.V[32] ^ this.V[42], out, off + 40);
        this.encodeBEInt(this.V[3] ^ this.V[13] ^ this.V[23] ^ this.V[33] ^ this.V[43], out, off + 44);
        this.encodeBEInt(this.V[4] ^ this.V[14] ^ this.V[24] ^ this.V[34] ^ this.V[44], out, off + 48);
        this.encodeBEInt(this.V[5] ^ this.V[15] ^ this.V[25] ^ this.V[35] ^ this.V[45], out, off + 52);
        this.encodeBEInt(this.V[6] ^ this.V[16] ^ this.V[26] ^ this.V[36] ^ this.V[46], out, off + 56);
        this.encodeBEInt(this.V[7] ^ this.V[17] ^ this.V[27] ^ this.V[37] ^ this.V[47], out, off + 60);
    }
    /** @see DigestEngine */
    doInit() {
        this.V = new Int32Array(48);
        this.tmpBuf = new Uint8Array(32);
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
        buf[off + 0] = (val >>> 24);
        buf[off + 1] = (val >>> 16);
        buf[off + 2] = (val >>> 8);
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
    /** @see DigestEngine */
    processBlock(data) {
        var tmp;
        const a = new Int32Array(8);
        const b = new Int32Array(8);
        const M = new Int32Array(8);
        M[0] = this.decodeBEInt(data, 0);
        M[1] = this.decodeBEInt(data, 4);
        M[2] = this.decodeBEInt(data, 8);
        M[3] = this.decodeBEInt(data, 12);
        M[4] = this.decodeBEInt(data, 16);
        M[5] = this.decodeBEInt(data, 20);
        M[6] = this.decodeBEInt(data, 24);
        M[7] = this.decodeBEInt(data, 28);
        a[0] = this.V[0] ^ this.V[10];
        a[1] = this.V[1] ^ this.V[11];
        a[2] = this.V[2] ^ this.V[12];
        a[3] = this.V[3] ^ this.V[13];
        a[4] = this.V[4] ^ this.V[14];
        a[5] = this.V[5] ^ this.V[15];
        a[6] = this.V[6] ^ this.V[16];
        a[7] = this.V[7] ^ this.V[17];
        b[0] = this.V[20] ^ this.V[30];
        b[1] = this.V[21] ^ this.V[31];
        b[2] = this.V[22] ^ this.V[32];
        b[3] = this.V[23] ^ this.V[33];
        b[4] = this.V[24] ^ this.V[34];
        b[5] = this.V[25] ^ this.V[35];
        b[6] = this.V[26] ^ this.V[36];
        b[7] = this.V[27] ^ this.V[37];
        a[0] = a[0] ^ b[0];
        a[1] = a[1] ^ b[1];
        a[2] = a[2] ^ b[2];
        a[3] = a[3] ^ b[3];
        a[4] = a[4] ^ b[4];
        a[5] = a[5] ^ b[5];
        a[6] = a[6] ^ b[6];
        a[7] = a[7] ^ b[7];
        a[0] = a[0] ^ this.V[40];
        a[1] = a[1] ^ this.V[41];
        a[2] = a[2] ^ this.V[42];
        a[3] = a[3] ^ this.V[43];
        a[4] = a[4] ^ this.V[44];
        a[5] = a[5] ^ this.V[45];
        a[6] = a[6] ^ this.V[46];
        a[7] = a[7] ^ this.V[47];
        tmp = a[7];
        a[7] = a[6];
        a[6] = a[5];
        a[5] = a[4];
        a[4] = a[3] ^ tmp;
        a[3] = a[2] ^ tmp;
        a[2] = a[1];
        a[1] = a[0] ^ tmp;
        a[0] = tmp;
        this.V[0] = a[0] ^ this.V[0];
        this.V[1] = a[1] ^ this.V[1];
        this.V[2] = a[2] ^ this.V[2];
        this.V[3] = a[3] ^ this.V[3];
        this.V[4] = a[4] ^ this.V[4];
        this.V[5] = a[5] ^ this.V[5];
        this.V[6] = a[6] ^ this.V[6];
        this.V[7] = a[7] ^ this.V[7];
        this.V[10] = a[0] ^ this.V[10];
        this.V[11] = a[1] ^ this.V[11];
        this.V[12] = a[2] ^ this.V[12];
        this.V[13] = a[3] ^ this.V[13];
        this.V[14] = a[4] ^ this.V[14];
        this.V[15] = a[5] ^ this.V[15];
        this.V[16] = a[6] ^ this.V[16];
        this.V[17] = a[7] ^ this.V[17];
        this.V[20] = a[0] ^ this.V[20];
        this.V[21] = a[1] ^ this.V[21];
        this.V[22] = a[2] ^ this.V[22];
        this.V[23] = a[3] ^ this.V[23];
        this.V[24] = a[4] ^ this.V[24];
        this.V[25] = a[5] ^ this.V[25];
        this.V[26] = a[6] ^ this.V[26];
        this.V[27] = a[7] ^ this.V[27];
        this.V[30] = a[0] ^ this.V[30];
        this.V[31] = a[1] ^ this.V[31];
        this.V[32] = a[2] ^ this.V[32];
        this.V[33] = a[3] ^ this.V[33];
        this.V[34] = a[4] ^ this.V[34];
        this.V[35] = a[5] ^ this.V[35];
        this.V[36] = a[6] ^ this.V[36];
        this.V[37] = a[7] ^ this.V[37];
        this.V[40] = a[0] ^ this.V[40];
        this.V[41] = a[1] ^ this.V[41];
        this.V[42] = a[2] ^ this.V[42];
        this.V[43] = a[3] ^ this.V[43];
        this.V[44] = a[4] ^ this.V[44];
        this.V[45] = a[5] ^ this.V[45];
        this.V[46] = a[6] ^ this.V[46];
        this.V[47] = a[7] ^ this.V[47];
        tmp = this.V[7];
        b[7] = this.V[6];
        b[6] = this.V[5];
        b[5] = this.V[4];
        b[4] = this.V[3] ^ tmp;
        b[3] = this.V[2] ^ tmp;
        b[2] = this.V[1];
        b[1] = this.V[0] ^ tmp;
        b[0] = tmp;
        b[0] = b[0] ^ this.V[10];
        b[1] = b[1] ^ this.V[11];
        b[2] = b[2] ^ this.V[12];
        b[3] = b[3] ^ this.V[13];
        b[4] = b[4] ^ this.V[14];
        b[5] = b[5] ^ this.V[15];
        b[6] = b[6] ^ this.V[16];
        b[7] = b[7] ^ this.V[17];
        tmp = this.V[17];
        this.V[17] = this.V[16];
        this.V[16] = this.V[15];
        this.V[15] = this.V[14];
        this.V[14] = this.V[13] ^ tmp;
        this.V[13] = this.V[12] ^ tmp;
        this.V[12] = this.V[11];
        this.V[11] = this.V[10] ^ tmp;
        this.V[10] = tmp;
        this.V[10] = this.V[10] ^ this.V[20];
        this.V[11] = this.V[11] ^ this.V[21];
        this.V[12] = this.V[12] ^ this.V[22];
        this.V[13] = this.V[13] ^ this.V[23];
        this.V[14] = this.V[14] ^ this.V[24];
        this.V[15] = this.V[15] ^ this.V[25];
        this.V[16] = this.V[16] ^ this.V[26];
        this.V[17] = this.V[17] ^ this.V[27];
        tmp = this.V[27];
        this.V[27] = this.V[26];
        this.V[26] = this.V[25];
        this.V[25] = this.V[24];
        this.V[24] = this.V[23] ^ tmp;
        this.V[23] = this.V[22] ^ tmp;
        this.V[22] = this.V[21];
        this.V[21] = this.V[20] ^ tmp;
        this.V[20] = tmp;
        this.V[20] = this.V[20] ^ this.V[30];
        this.V[21] = this.V[21] ^ this.V[31];
        this.V[22] = this.V[22] ^ this.V[32];
        this.V[23] = this.V[23] ^ this.V[33];
        this.V[24] = this.V[24] ^ this.V[34];
        this.V[25] = this.V[25] ^ this.V[35];
        this.V[26] = this.V[26] ^ this.V[36];
        this.V[27] = this.V[27] ^ this.V[37];
        tmp = this.V[37];
        this.V[37] = this.V[36];
        this.V[36] = this.V[35];
        this.V[35] = this.V[34];
        this.V[34] = this.V[33] ^ tmp;
        this.V[33] = this.V[32] ^ tmp;
        this.V[32] = this.V[31];
        this.V[31] = this.V[30] ^ tmp;
        this.V[30] = tmp;
        this.V[30] = this.V[30] ^ this.V[40];
        this.V[31] = this.V[31] ^ this.V[41];
        this.V[32] = this.V[32] ^ this.V[42];
        this.V[33] = this.V[33] ^ this.V[43];
        this.V[34] = this.V[34] ^ this.V[44];
        this.V[35] = this.V[35] ^ this.V[45];
        this.V[36] = this.V[36] ^ this.V[46];
        this.V[37] = this.V[37] ^ this.V[47];
        tmp = this.V[47];
        this.V[47] = this.V[46];
        this.V[46] = this.V[45];
        this.V[45] = this.V[44];
        this.V[44] = this.V[43] ^ tmp;
        this.V[43] = this.V[42] ^ tmp;
        this.V[42] = this.V[41];
        this.V[41] = this.V[40] ^ tmp;
        this.V[40] = tmp;
        this.V[40] = this.V[40] ^ this.V[0];
        this.V[41] = this.V[41] ^ this.V[1];
        this.V[42] = this.V[42] ^ this.V[2];
        this.V[43] = this.V[43] ^ this.V[3];
        this.V[44] = this.V[44] ^ this.V[4];
        this.V[45] = this.V[45] ^ this.V[5];
        this.V[46] = this.V[46] ^ this.V[6];
        this.V[47] = this.V[47] ^ this.V[7];
        tmp = b[7];
        this.V[7] = b[6];
        this.V[6] = b[5];
        this.V[5] = b[4];
        this.V[4] = b[3] ^ tmp;
        this.V[3] = b[2] ^ tmp;
        this.V[2] = b[1];
        this.V[1] = b[0] ^ tmp;
        this.V[0] = tmp;
        this.V[0] = this.V[0] ^ this.V[40];
        this.V[1] = this.V[1] ^ this.V[41];
        this.V[2] = this.V[2] ^ this.V[42];
        this.V[3] = this.V[3] ^ this.V[43];
        this.V[4] = this.V[4] ^ this.V[44];
        this.V[5] = this.V[5] ^ this.V[45];
        this.V[6] = this.V[6] ^ this.V[46];
        this.V[7] = this.V[7] ^ this.V[47];
        tmp = this.V[47];
        this.V[47] = this.V[46];
        this.V[46] = this.V[45];
        this.V[45] = this.V[44];
        this.V[44] = this.V[43] ^ tmp;
        this.V[43] = this.V[42] ^ tmp;
        this.V[42] = this.V[41];
        this.V[41] = this.V[40] ^ tmp;
        this.V[40] = tmp;
        this.V[40] = this.V[40] ^ this.V[30];
        this.V[41] = this.V[41] ^ this.V[31];
        this.V[42] = this.V[42] ^ this.V[32];
        this.V[43] = this.V[43] ^ this.V[33];
        this.V[44] = this.V[44] ^ this.V[34];
        this.V[45] = this.V[45] ^ this.V[35];
        this.V[46] = this.V[46] ^ this.V[36];
        this.V[47] = this.V[47] ^ this.V[37];
        tmp = this.V[37];
        this.V[37] = this.V[36];
        this.V[36] = this.V[35];
        this.V[35] = this.V[34];
        this.V[34] = this.V[33] ^ tmp;
        this.V[33] = this.V[32] ^ tmp;
        this.V[32] = this.V[31];
        this.V[31] = this.V[30] ^ tmp;
        this.V[30] = tmp;
        this.V[30] = this.V[30] ^ this.V[20];
        this.V[31] = this.V[31] ^ this.V[21];
        this.V[32] = this.V[32] ^ this.V[22];
        this.V[33] = this.V[33] ^ this.V[23];
        this.V[34] = this.V[34] ^ this.V[24];
        this.V[35] = this.V[35] ^ this.V[25];
        this.V[36] = this.V[36] ^ this.V[26];
        this.V[37] = this.V[37] ^ this.V[27];
        tmp = this.V[27];
        this.V[27] = this.V[26];
        this.V[26] = this.V[25];
        this.V[25] = this.V[24];
        this.V[24] = this.V[23] ^ tmp;
        this.V[23] = this.V[22] ^ tmp;
        this.V[22] = this.V[21];
        this.V[21] = this.V[20] ^ tmp;
        this.V[20] = tmp;
        this.V[20] = this.V[20] ^ this.V[10];
        this.V[21] = this.V[21] ^ this.V[11];
        this.V[22] = this.V[22] ^ this.V[12];
        this.V[23] = this.V[23] ^ this.V[13];
        this.V[24] = this.V[24] ^ this.V[14];
        this.V[25] = this.V[25] ^ this.V[15];
        this.V[26] = this.V[26] ^ this.V[16];
        this.V[27] = this.V[27] ^ this.V[17];
        tmp = this.V[17];
        this.V[17] = this.V[16];
        this.V[16] = this.V[15];
        this.V[15] = this.V[14];
        this.V[14] = this.V[13] ^ tmp;
        this.V[13] = this.V[12] ^ tmp;
        this.V[12] = this.V[11];
        this.V[11] = this.V[10] ^ tmp;
        this.V[10] = tmp;
        this.V[10] = this.V[10] ^ b[0];
        this.V[11] = this.V[11] ^ b[1];
        this.V[12] = this.V[12] ^ b[2];
        this.V[13] = this.V[13] ^ b[3];
        this.V[14] = this.V[14] ^ b[4];
        this.V[15] = this.V[15] ^ b[5];
        this.V[16] = this.V[16] ^ b[6];
        this.V[17] = this.V[17] ^ b[7];
        this.V[0] = this.V[0] ^ M[0];
        this.V[1] = this.V[1] ^ M[1];
        this.V[2] = this.V[2] ^ M[2];
        this.V[3] = this.V[3] ^ M[3];
        this.V[4] = this.V[4] ^ M[4];
        this.V[5] = this.V[5] ^ M[5];
        this.V[6] = this.V[6] ^ M[6];
        this.V[7] = this.V[7] ^ M[7];
        tmp = M[7];
        M[7] = M[6];
        M[6] = M[5];
        M[5] = M[4];
        M[4] = M[3] ^ tmp;
        M[3] = M[2] ^ tmp;
        M[2] = M[1];
        M[1] = M[0] ^ tmp;
        M[0] = tmp;
        this.V[10] = this.V[10] ^ M[0];
        this.V[11] = this.V[11] ^ M[1];
        this.V[12] = this.V[12] ^ M[2];
        this.V[13] = this.V[13] ^ M[3];
        this.V[14] = this.V[14] ^ M[4];
        this.V[15] = this.V[15] ^ M[5];
        this.V[16] = this.V[16] ^ M[6];
        this.V[17] = this.V[17] ^ M[7];
        tmp = M[7];
        M[7] = M[6];
        M[6] = M[5];
        M[5] = M[4];
        M[4] = M[3] ^ tmp;
        M[3] = M[2] ^ tmp;
        M[2] = M[1];
        M[1] = M[0] ^ tmp;
        M[0] = tmp;
        this.V[20] = this.V[20] ^ M[0];
        this.V[21] = this.V[21] ^ M[1];
        this.V[22] = this.V[22] ^ M[2];
        this.V[23] = this.V[23] ^ M[3];
        this.V[24] = this.V[24] ^ M[4];
        this.V[25] = this.V[25] ^ M[5];
        this.V[26] = this.V[26] ^ M[6];
        this.V[27] = this.V[27] ^ M[7];
        tmp = M[7];
        M[7] = M[6];
        M[6] = M[5];
        M[5] = M[4];
        M[4] = M[3] ^ tmp;
        M[3] = M[2] ^ tmp;
        M[2] = M[1];
        M[1] = M[0] ^ tmp;
        M[0] = tmp;
        this.V[30] = this.V[30] ^ M[0];
        this.V[31] = this.V[31] ^ M[1];
        this.V[32] = this.V[32] ^ M[2];
        this.V[33] = this.V[33] ^ M[3];
        this.V[34] = this.V[34] ^ M[4];
        this.V[35] = this.V[35] ^ M[5];
        this.V[36] = this.V[36] ^ M[6];
        this.V[37] = this.V[37] ^ M[7];
        tmp = M[7];
        M[7] = M[6];
        M[6] = M[5];
        M[5] = M[4];
        M[4] = M[3] ^ tmp;
        M[3] = M[2] ^ tmp;
        M[2] = M[1];
        M[1] = M[0] ^ tmp;
        M[0] = tmp;
        this.V[40] = this.V[40] ^ M[0];
        this.V[41] = this.V[41] ^ M[1];
        this.V[42] = this.V[42] ^ M[2];
        this.V[43] = this.V[43] ^ M[3];
        this.V[44] = this.V[44] ^ M[4];
        this.V[45] = this.V[45] ^ M[5];
        this.V[46] = this.V[46] ^ M[6];
        this.V[47] = this.V[47] ^ M[7];
        this.V[14] = (this.V[14] << 1) | (this.V[14] >>> 31);
        this.V[15] = (this.V[15] << 1) | (this.V[15] >>> 31);
        this.V[16] = (this.V[16] << 1) | (this.V[16] >>> 31);
        this.V[17] = (this.V[17] << 1) | (this.V[17] >>> 31);
        this.V[24] = (this.V[24] << 2) | (this.V[24] >>> 30);
        this.V[25] = (this.V[25] << 2) | (this.V[25] >>> 30);
        this.V[26] = (this.V[26] << 2) | (this.V[26] >>> 30);
        this.V[27] = (this.V[27] << 2) | (this.V[27] >>> 30);
        this.V[34] = (this.V[34] << 3) | (this.V[34] >>> 29);
        this.V[35] = (this.V[35] << 3) | (this.V[35] >>> 29);
        this.V[36] = (this.V[36] << 3) | (this.V[36] >>> 29);
        this.V[37] = (this.V[37] << 3) | (this.V[37] >>> 29);
        this.V[44] = (this.V[44] << 4) | (this.V[44] >>> 28);
        this.V[45] = (this.V[45] << 4) | (this.V[45] >>> 28);
        this.V[46] = (this.V[46] << 4) | (this.V[46] >>> 28);
        this.V[47] = (this.V[47] << 4) | (this.V[47] >>> 28);
        for (let r = 0; r < 8; r++) {
            tmp = this.V[0];
            this.V[0] |= this.V[1];
            this.V[2] ^= this.V[3];
            this.V[1] = ~this.V[1];
            this.V[0] ^= this.V[3];
            this.V[3] &= tmp;
            this.V[1] ^= this.V[3];
            this.V[3] ^= this.V[2];
            this.V[2] &= this.V[0];
            this.V[0] = ~this.V[0];
            this.V[2] ^= this.V[1];
            this.V[1] |= this.V[3];
            tmp ^= this.V[1];
            this.V[3] ^= this.V[2];
            this.V[2] &= this.V[1];
            this.V[1] ^= this.V[0];
            this.V[0] = tmp;
            tmp = this.V[5];
            this.V[5] |= this.V[6];
            this.V[7] ^= this.V[4];
            this.V[6] = ~this.V[6];
            this.V[5] ^= this.V[4];
            this.V[4] &= tmp;
            this.V[6] ^= this.V[4];
            this.V[4] ^= this.V[7];
            this.V[7] &= this.V[5];
            this.V[5] = ~this.V[5];
            this.V[7] ^= this.V[6];
            this.V[6] |= this.V[4];
            tmp ^= this.V[6];
            this.V[4] ^= this.V[7];
            this.V[7] &= this.V[6];
            this.V[6] ^= this.V[5];
            this.V[5] = tmp;
            this.V[4] ^= this.V[0];
            this.V[0] = ((this.V[0] << 2) | (this.V[0] >>> 30)) ^ this.V[4];
            this.V[4] = ((this.V[4] << 14) | (this.V[4] >>> 18)) ^ this.V[0];
            this.V[0] = ((this.V[0] << 10) | (this.V[0] >>> 22)) ^ this.V[4];
            this.V[4] = (this.V[4] << 1) | (this.V[4] >>> 31);
            this.V[5] ^= this.V[1];
            this.V[1] = ((this.V[1] << 2) | (this.V[1] >>> 30)) ^ this.V[5];
            this.V[5] = ((this.V[5] << 14) | (this.V[5] >>> 18)) ^ this.V[1];
            this.V[1] = ((this.V[1] << 10) | (this.V[1] >>> 22)) ^ this.V[5];
            this.V[5] = (this.V[5] << 1) | (this.V[5] >>> 31);
            this.V[6] ^= this.V[2];
            this.V[2] = ((this.V[2] << 2) | (this.V[2] >>> 30)) ^ this.V[6];
            this.V[6] = ((this.V[6] << 14) | (this.V[6] >>> 18)) ^ this.V[2];
            this.V[2] = ((this.V[2] << 10) | (this.V[2] >>> 22)) ^ this.V[6];
            this.V[6] = (this.V[6] << 1) | (this.V[6] >>> 31);
            this.V[7] ^= this.V[3];
            this.V[3] = ((this.V[3] << 2) | (this.V[3] >>> 30)) ^ this.V[7];
            this.V[7] = ((this.V[7] << 14) | (this.V[7] >>> 18)) ^ this.V[3];
            this.V[3] = ((this.V[3] << 10) | (this.V[3] >>> 22)) ^ this.V[7];
            this.V[7] = (this.V[7] << 1) | (this.V[7] >>> 31);
            this.V[0] ^= Luffa512.RC00[r];
            this.V[4] ^= Luffa512.RC04[r];
        }
        for (let r = 0; r < 8; r++) {
            tmp = this.V[10];
            this.V[10] |= this.V[11];
            this.V[12] ^= this.V[13];
            this.V[11] = ~this.V[11];
            this.V[10] ^= this.V[13];
            this.V[13] &= tmp;
            this.V[11] ^= this.V[13];
            this.V[13] ^= this.V[12];
            this.V[12] &= this.V[10];
            this.V[10] = ~this.V[10];
            this.V[12] ^= this.V[11];
            this.V[11] |= this.V[13];
            tmp ^= this.V[11];
            this.V[13] ^= this.V[12];
            this.V[12] &= this.V[11];
            this.V[11] ^= this.V[10];
            this.V[10] = tmp;
            tmp = this.V[15];
            this.V[15] |= this.V[16];
            this.V[17] ^= this.V[14];
            this.V[16] = ~this.V[16];
            this.V[15] ^= this.V[14];
            this.V[14] &= tmp;
            this.V[16] ^= this.V[14];
            this.V[14] ^= this.V[17];
            this.V[17] &= this.V[15];
            this.V[15] = ~this.V[15];
            this.V[17] ^= this.V[16];
            this.V[16] |= this.V[14];
            tmp ^= this.V[16];
            this.V[14] ^= this.V[17];
            this.V[17] &= this.V[16];
            this.V[16] ^= this.V[15];
            this.V[15] = tmp;
            this.V[14] ^= this.V[10];
            this.V[10] = ((this.V[10] << 2) | (this.V[10] >>> 30)) ^ this.V[14];
            this.V[14] = ((this.V[14] << 14) | (this.V[14] >>> 18)) ^ this.V[10];
            this.V[10] = ((this.V[10] << 10) | (this.V[10] >>> 22)) ^ this.V[14];
            this.V[14] = (this.V[14] << 1) | (this.V[14] >>> 31);
            this.V[15] ^= this.V[11];
            this.V[11] = ((this.V[11] << 2) | (this.V[11] >>> 30)) ^ this.V[15];
            this.V[15] = ((this.V[15] << 14) | (this.V[15] >>> 18)) ^ this.V[11];
            this.V[11] = ((this.V[11] << 10) | (this.V[11] >>> 22)) ^ this.V[15];
            this.V[15] = (this.V[15] << 1) | (this.V[15] >>> 31);
            this.V[16] ^= this.V[12];
            this.V[12] = ((this.V[12] << 2) | (this.V[12] >>> 30)) ^ this.V[16];
            this.V[16] = ((this.V[16] << 14) | (this.V[16] >>> 18)) ^ this.V[12];
            this.V[12] = ((this.V[12] << 10) | (this.V[12] >>> 22)) ^ this.V[16];
            this.V[16] = (this.V[16] << 1) | (this.V[16] >>> 31);
            this.V[17] ^= this.V[13];
            this.V[13] = ((this.V[13] << 2) | (this.V[13] >>> 30)) ^ this.V[17];
            this.V[17] = ((this.V[17] << 14) | (this.V[17] >>> 18)) ^ this.V[13];
            this.V[13] = ((this.V[13] << 10) | (this.V[13] >>> 22)) ^ this.V[17];
            this.V[17] = (this.V[17] << 1) | (this.V[17] >>> 31);
            this.V[10] ^= Luffa512.RC10[r];
            this.V[14] ^= Luffa512.RC14[r];
        }
        for (let r = 0; r < 8; r++) {
            tmp = this.V[20];
            this.V[20] |= this.V[21];
            this.V[22] ^= this.V[23];
            this.V[21] = ~this.V[21];
            this.V[20] ^= this.V[23];
            this.V[23] &= tmp;
            this.V[21] ^= this.V[23];
            this.V[23] ^= this.V[22];
            this.V[22] &= this.V[20];
            this.V[20] = ~this.V[20];
            this.V[22] ^= this.V[21];
            this.V[21] |= this.V[23];
            tmp ^= this.V[21];
            this.V[23] ^= this.V[22];
            this.V[22] &= this.V[21];
            this.V[21] ^= this.V[20];
            this.V[20] = tmp;
            tmp = this.V[25];
            this.V[25] |= this.V[26];
            this.V[27] ^= this.V[24];
            this.V[26] = ~this.V[26];
            this.V[25] ^= this.V[24];
            this.V[24] &= tmp;
            this.V[26] ^= this.V[24];
            this.V[24] ^= this.V[27];
            this.V[27] &= this.V[25];
            this.V[25] = ~this.V[25];
            this.V[27] ^= this.V[26];
            this.V[26] |= this.V[24];
            tmp ^= this.V[26];
            this.V[24] ^= this.V[27];
            this.V[27] &= this.V[26];
            this.V[26] ^= this.V[25];
            this.V[25] = tmp;
            this.V[24] ^= this.V[20];
            this.V[20] = ((this.V[20] << 2) | (this.V[20] >>> 30)) ^ this.V[24];
            this.V[24] = ((this.V[24] << 14) | (this.V[24] >>> 18)) ^ this.V[20];
            this.V[20] = ((this.V[20] << 10) | (this.V[20] >>> 22)) ^ this.V[24];
            this.V[24] = (this.V[24] << 1) | (this.V[24] >>> 31);
            this.V[25] ^= this.V[21];
            this.V[21] = ((this.V[21] << 2) | (this.V[21] >>> 30)) ^ this.V[25];
            this.V[25] = ((this.V[25] << 14) | (this.V[25] >>> 18)) ^ this.V[21];
            this.V[21] = ((this.V[21] << 10) | (this.V[21] >>> 22)) ^ this.V[25];
            this.V[25] = (this.V[25] << 1) | (this.V[25] >>> 31);
            this.V[26] ^= this.V[22];
            this.V[22] = ((this.V[22] << 2) | (this.V[22] >>> 30)) ^ this.V[26];
            this.V[26] = ((this.V[26] << 14) | (this.V[26] >>> 18)) ^ this.V[22];
            this.V[22] = ((this.V[22] << 10) | (this.V[22] >>> 22)) ^ this.V[26];
            this.V[26] = (this.V[26] << 1) | (this.V[26] >>> 31);
            this.V[27] ^= this.V[23];
            this.V[23] = ((this.V[23] << 2) | (this.V[23] >>> 30)) ^ this.V[27];
            this.V[27] = ((this.V[27] << 14) | (this.V[27] >>> 18)) ^ this.V[23];
            this.V[23] = ((this.V[23] << 10) | (this.V[23] >>> 22)) ^ this.V[27];
            this.V[27] = (this.V[27] << 1) | (this.V[27] >>> 31);
            this.V[20] ^= Luffa512.RC20[r];
            this.V[24] ^= Luffa512.RC24[r];
        }
        for (let r = 0; r < 8; r++) {
            tmp = this.V[30];
            this.V[30] |= this.V[31];
            this.V[32] ^= this.V[33];
            this.V[31] = ~this.V[31];
            this.V[30] ^= this.V[33];
            this.V[33] &= tmp;
            this.V[31] ^= this.V[33];
            this.V[33] ^= this.V[32];
            this.V[32] &= this.V[30];
            this.V[30] = ~this.V[30];
            this.V[32] ^= this.V[31];
            this.V[31] |= this.V[33];
            tmp ^= this.V[31];
            this.V[33] ^= this.V[32];
            this.V[32] &= this.V[31];
            this.V[31] ^= this.V[30];
            this.V[30] = tmp;
            tmp = this.V[35];
            this.V[35] |= this.V[36];
            this.V[37] ^= this.V[34];
            this.V[36] = ~this.V[36];
            this.V[35] ^= this.V[34];
            this.V[34] &= tmp;
            this.V[36] ^= this.V[34];
            this.V[34] ^= this.V[37];
            this.V[37] &= this.V[35];
            this.V[35] = ~this.V[35];
            this.V[37] ^= this.V[36];
            this.V[36] |= this.V[34];
            tmp ^= this.V[36];
            this.V[34] ^= this.V[37];
            this.V[37] &= this.V[36];
            this.V[36] ^= this.V[35];
            this.V[35] = tmp;
            this.V[34] ^= this.V[30];
            this.V[30] = ((this.V[30] << 2) | (this.V[30] >>> 30)) ^ this.V[34];
            this.V[34] = ((this.V[34] << 14) | (this.V[34] >>> 18)) ^ this.V[30];
            this.V[30] = ((this.V[30] << 10) | (this.V[30] >>> 22)) ^ this.V[34];
            this.V[34] = (this.V[34] << 1) | (this.V[34] >>> 31);
            this.V[35] ^= this.V[31];
            this.V[31] = ((this.V[31] << 2) | (this.V[31] >>> 30)) ^ this.V[35];
            this.V[35] = ((this.V[35] << 14) | (this.V[35] >>> 18)) ^ this.V[31];
            this.V[31] = ((this.V[31] << 10) | (this.V[31] >>> 22)) ^ this.V[35];
            this.V[35] = (this.V[35] << 1) | (this.V[35] >>> 31);
            this.V[36] ^= this.V[32];
            this.V[32] = ((this.V[32] << 2) | (this.V[32] >>> 30)) ^ this.V[36];
            this.V[36] = ((this.V[36] << 14) | (this.V[36] >>> 18)) ^ this.V[32];
            this.V[32] = ((this.V[32] << 10) | (this.V[32] >>> 22)) ^ this.V[36];
            this.V[36] = (this.V[36] << 1) | (this.V[36] >>> 31);
            this.V[37] ^= this.V[33];
            this.V[33] = ((this.V[33] << 2) | (this.V[33] >>> 30)) ^ this.V[37];
            this.V[37] = ((this.V[37] << 14) | (this.V[37] >>> 18)) ^ this.V[33];
            this.V[33] = ((this.V[33] << 10) | (this.V[33] >>> 22)) ^ this.V[37];
            this.V[37] = (this.V[37] << 1) | (this.V[37] >>> 31);
            this.V[30] ^= Luffa512.RC30[r];
            this.V[34] ^= Luffa512.RC34[r];
        }
        for (let r = 0; r < 8; r++) {
            tmp = this.V[40];
            this.V[40] |= this.V[41];
            this.V[42] ^= this.V[43];
            this.V[41] = ~this.V[41];
            this.V[40] ^= this.V[43];
            this.V[43] &= tmp;
            this.V[41] ^= this.V[43];
            this.V[43] ^= this.V[42];
            this.V[42] &= this.V[40];
            this.V[40] = ~this.V[40];
            this.V[42] ^= this.V[41];
            this.V[41] |= this.V[43];
            tmp ^= this.V[41];
            this.V[43] ^= this.V[42];
            this.V[42] &= this.V[41];
            this.V[41] ^= this.V[40];
            this.V[40] = tmp;
            tmp = this.V[45];
            this.V[45] |= this.V[46];
            this.V[47] ^= this.V[44];
            this.V[46] = ~this.V[46];
            this.V[45] ^= this.V[44];
            this.V[44] &= tmp;
            this.V[46] ^= this.V[44];
            this.V[44] ^= this.V[47];
            this.V[47] &= this.V[45];
            this.V[45] = ~this.V[45];
            this.V[47] ^= this.V[46];
            this.V[46] |= this.V[44];
            tmp ^= this.V[46];
            this.V[44] ^= this.V[47];
            this.V[47] &= this.V[46];
            this.V[46] ^= this.V[45];
            this.V[45] = tmp;
            this.V[44] ^= this.V[40];
            this.V[40] = ((this.V[40] << 2) | (this.V[40] >>> 30)) ^ this.V[44];
            this.V[44] = ((this.V[44] << 14) | (this.V[44] >>> 18)) ^ this.V[40];
            this.V[40] = ((this.V[40] << 10) | (this.V[40] >>> 22)) ^ this.V[44];
            this.V[44] = (this.V[44] << 1) | (this.V[44] >>> 31);
            this.V[45] ^= this.V[41];
            this.V[41] = ((this.V[41] << 2) | (this.V[41] >>> 30)) ^ this.V[45];
            this.V[45] = ((this.V[45] << 14) | (this.V[45] >>> 18)) ^ this.V[41];
            this.V[41] = ((this.V[41] << 10) | (this.V[41] >>> 22)) ^ this.V[45];
            this.V[45] = (this.V[45] << 1) | (this.V[45] >>> 31);
            this.V[46] ^= this.V[42];
            this.V[42] = ((this.V[42] << 2) | (this.V[42] >>> 30)) ^ this.V[46];
            this.V[46] = ((this.V[46] << 14) | (this.V[46] >>> 18)) ^ this.V[42];
            this.V[42] = ((this.V[42] << 10) | (this.V[42] >>> 22)) ^ this.V[46];
            this.V[46] = (this.V[46] << 1) | (this.V[46] >>> 31);
            this.V[47] ^= this.V[43];
            this.V[43] = ((this.V[43] << 2) | (this.V[43] >>> 30)) ^ this.V[47];
            this.V[47] = ((this.V[47] << 14) | (this.V[47] >>> 18)) ^ this.V[43];
            this.V[43] = ((this.V[43] << 10) | (this.V[43] >>> 22)) ^ this.V[47];
            this.V[47] = (this.V[47] << 1) | (this.V[47] >>> 31);
            this.V[40] ^= Luffa512.RC40[r];
            this.V[44] ^= Luffa512.RC44[r];
        }
    }
    /** @see Digest */
    toString() {
        return "Luffa-512";
    }
}
exports.Luffa512 = Luffa512;
Luffa512.IV = new Int32Array([
    0x6d251e69, 0x44b051e0, 0x4eaa6fb4, 0xdbf78465,
    0x6e292011, 0x90152df4, 0xee058139, 0xdef610bb,
    0xc3b44b95, 0xd9d2f256, 0x70eee9a0, 0xde099fa3,
    0x5d9b0557, 0x8fc944b3, 0xcf1ccf0e, 0x746cd581,
    0xf7efc89d, 0x5dba5781, 0x04016ce5, 0xad659c05,
    0x0306194f, 0x666d1836, 0x24aa230a, 0x8b264ae7,
    0x858075d5, 0x36d79cce, 0xe571f7d7, 0x204b1f67,
    0x35870c6a, 0x57e9e923, 0x14bcb808, 0x7cde72ce,
    0x6c68e9be, 0x5ec41e22, 0xc825b7c7, 0xaffb4363,
    0xf5df3999, 0x0fc688f1, 0xb07224cc, 0x03e86cea
]);
Luffa512.RC00 = new Int32Array([
    0x303994a6, 0xc0e65299, 0x6cc33a12, 0xdc56983e,
    0x1e00108f, 0x7800423d, 0x8f5b7882, 0x96e1db12
]);
Luffa512.RC04 = new Int32Array([
    0xe0337818, 0x441ba90d, 0x7f34d442, 0x9389217f,
    0xe5a8bce6, 0x5274baf4, 0x26889ba7, 0x9a226e9d
]);
Luffa512.RC10 = new Int32Array([
    0xb6de10ed, 0x70f47aae, 0x0707a3d4, 0x1c1e8f51,
    0x707a3d45, 0xaeb28562, 0xbaca1589, 0x40a46f3e
]);
Luffa512.RC14 = new Int32Array([
    0x01685f3d, 0x05a17cf4, 0xbd09caca, 0xf4272b28,
    0x144ae5cc, 0xfaa7ae2b, 0x2e48f1c1, 0xb923c704
]);
Luffa512.RC20 = new Int32Array([
    0xfc20d9d2, 0x34552e25, 0x7ad8818f, 0x8438764a,
    0xbb6de032, 0xedb780c8, 0xd9847356, 0xa2c78434
]);
Luffa512.RC24 = new Int32Array([
    0xe25e72c1, 0xe623bb72, 0x5c58a4a4, 0x1e38e2e7,
    0x78e38b9d, 0x27586719, 0x36eda57f, 0x703aace7
]);
Luffa512.RC30 = new Int32Array([
    0xb213afa5, 0xc84ebe95, 0x4e608a22, 0x56d858fe,
    0x343b138f, 0xd0ec4e3d, 0x2ceb4882, 0xb3ad2208
]);
Luffa512.RC34 = new Int32Array([
    0xe028c9bf, 0x44756f91, 0x7e8fce32, 0x956548be,
    0xfe191be2, 0x3cb226e5, 0x5944a28e, 0xa1c4c355
]);
Luffa512.RC40 = new Int32Array([
    0xf0d2e9e3, 0xac11d7fa, 0x1bcb66f2, 0x6f2d9bc9,
    0x78602649, 0x8edae952, 0x3b6ba548, 0xedae9520
]);
Luffa512.RC44 = new Int32Array([
    0x5090d577, 0x2d1925ab, 0xb46496ac, 0xd1925ab0,
    0x29131ab6, 0x0fc053c3, 0x3f014f0c, 0xfc053c31
]);
/**
 * <p>This class implements the Luffa-224 digest algorithm under the
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
class Luffa224 extends LuffaSmallCore {
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
        return this.copyState(new Luffa224());
    }
}
exports.Luffa224 = Luffa224;
/**
 * <p>This class implements the Luffa-256 digest algorithm under the
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
class Luffa256 extends LuffaSmallCore {
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
        return this.copyState(new Luffa256());
    }
}
exports.Luffa256 = Luffa256;
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
/**
 * Creates a vary byte length LUFFA of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {224 | 256 | 384 | 512} bitLen - length of hash (default 512 bits AKA 64 bytes)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function _LUFFA(message, bitLen = 512, format = arrayType()) {
    var hash;
    switch (bitLen) {
        case 224:
            hash = new Luffa224();
            break;
        case 256:
            hash = new Luffa256();
            break;
        case 384:
            hash = new Luffa384();
            break;
        case 512:
            hash = new Luffa512();
            break;
        default:
            hash = new Luffa512();
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
exports._LUFFA = _LUFFA;
;
/**
 * Creates a vary byte length keyed LUFFA of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {224 | 256 | 384 | 512} bitLen - length of hash (default 512 bits AKA 64 bytes)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function LUFFA_HMAC(message, key, bitLen = 512, format = arrayType()) {
    var hash;
    switch (bitLen) {
        case 224:
            hash = new Luffa224();
            break;
        case 256:
            hash = new Luffa256();
            break;
        case 384:
            hash = new Luffa384();
            break;
        case 512:
            hash = new Luffa512();
            break;
        default:
            hash = new Luffa512();
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
exports.LUFFA_HMAC = LUFFA_HMAC;
;
/**
 * Creates a 28 byte LUFFA of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function LUFFA224(message, format = arrayType()) {
    const hash = new Luffa224();
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
exports.LUFFA224 = LUFFA224;
;
/**
 * Creates a 28 byte keyed LUFFA of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function LUFFA224_HMAC(message, key, format = arrayType()) {
    const hash = new Luffa224();
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
exports.LUFFA224_HMAC = LUFFA224_HMAC;
;
/**
 * Creates a 32 byte LUFFA of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function LUFFA256(message, format = arrayType()) {
    const hash = new Luffa256();
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
exports.LUFFA256 = LUFFA256;
;
/**
 * Creates a 32 byte keyed LUFFA of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function LUFFA256_HMAC(message, key, format = arrayType()) {
    const hash = new Luffa256();
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
exports.LUFFA256_HMAC = LUFFA256_HMAC;
;
/**
 * Creates a 48 byte LUFFA of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function LUFFA384(message, format = arrayType()) {
    const hash = new Luffa384();
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
exports.LUFFA384 = LUFFA384;
;
/**
 * Creates a 48 byte keyed LUFFA of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function LUFFA384_HMAC(message, key, format = arrayType()) {
    const hash = new Luffa384();
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
exports.LUFFA384_HMAC = LUFFA384_HMAC;
;
/**
 * Creates a 64 byte LUFFA of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function LUFFA512(message, format = arrayType()) {
    const hash = new Luffa512();
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
exports.LUFFA512 = LUFFA512;
;
/**
 * Creates a 64 byte keyed LUFFA of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function LUFFA512_HMAC(message, key, format = arrayType()) {
    const hash = new Luffa512();
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
exports.LUFFA512_HMAC = LUFFA512_HMAC;
;
/**
 * Static class of all LUFFA functions and classes
 */
class LUFFA {
    /**
     * List of all hashes in class
     */
    static get FUNCTION_LIST() {
        return [
            "LUFFA",
            "LUFFA224",
            "LUFFA224_HMAC",
            "LUFFA256",
            "LUFFA256_HMAC",
            "LUFFA384",
            "LUFFA384_HMAC",
            "LUFFA512",
            "LUFFA512_HMAC",
            "LUFFA_HMAC"
        ];
    }
}
exports.LUFFA = LUFFA;
LUFFA.LUFFA = _LUFFA;
LUFFA.Luffa256 = Luffa256;
LUFFA.LUFFA256 = LUFFA256;
LUFFA.LUFFA256_HMAC = LUFFA256_HMAC;
LUFFA.Luffa224 = Luffa224;
LUFFA.LUFFA224 = LUFFA224;
LUFFA.LUFFA224_HMAC = LUFFA224_HMAC;
LUFFA.Luffa384 = Luffa384;
LUFFA.LUFFA384 = LUFFA384;
LUFFA.LUFFA384_HMAC = LUFFA384_HMAC;
LUFFA.Luffa512 = Luffa512;
LUFFA.LUFFA512 = LUFFA512;
LUFFA.LUFFA512_HMAC = LUFFA512_HMAC;
LUFFA.LUFFA_HMAC = LUFFA_HMAC;
//# sourceMappingURL=LUFFA.js.map