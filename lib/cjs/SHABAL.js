"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SHABAL = exports.SHABAL512_HMAC = exports.SHABAL512 = exports.SHABAL384_HMAC = exports.SHABAL384 = exports.SHABAL256_HMAC = exports.SHABAL256 = exports.SHABAL224_HMAC = exports.SHABAL224 = exports.SHABAL192_HMAC = exports.SHABAL192 = exports.SHABAL_HMAC = exports._SHABAL = exports.Shabal512 = exports.Shabal384 = exports.Shabal256 = exports.Shabal224 = exports.Shabal192 = void 0;
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
 * This class implements Shabal for all output sizes from 32 to 512 bits
 * (inclusive, only multiples of 32 are supported). The output size must
 * be provided as parameter to the constructor. Alternatively, you may
 * use the specific size classes which offer a nullary constructor.
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
 * @version   $Revision: 231 $
 * @author    Thomas Pornin <thomas.pornin@cryptolog.com>
 */
class ShabalGeneric {
    constructor(outSize) {
        this.outSizeW32 = 0;
        this.IVs = new Array(16);
        this.buf = new Uint8Array(64);
        this.state = new Int32Array(44);
        if (outSize != undefined) {
            this.outSize = outSize;
            if (outSize < 32 || outSize > 512 || (outSize & 31) != 0) {
                throw new Error("invalid Shabal output size: " + outSize);
            }
            this.outSizeW32 = outSize >>> 5;
            this.reset();
        }
    }
    update(arg1, arg2, arg3) {
        if (typeof arg1 === 'number') {
            this.buf[this.ptr++] = arg1 & 0xFF;
            if (this.ptr === 64) {
                this.core(this.buf, 0, 1);
                this.ptr = 0;
            }
        }
        else if (arg2 === undefined || arg3 === undefined) {
            this.update(arg1, 0, arg1.length);
        }
        else {
            if (this.ptr !== 0) {
                const rlen = 64 - this.ptr;
                if (arg3 < rlen) {
                    arraycopy(arg1, arg2, this.buf, this.ptr, arg3);
                    this.ptr += arg3;
                    return;
                }
                else {
                    arraycopy(arg1, arg2, this.buf, this.ptr, rlen);
                    arg2 += rlen;
                    arg3 -= rlen;
                    this.core(this.buf, 0, 1);
                }
            }
            let num = arg3 >>> 6;
            if (num > 0) {
                this.core(arg1, arg2, num);
                arg2 += num << 6;
                arg3 &= 63;
            }
            arraycopy(arg1, arg2, this.buf, 0, arg3);
            this.ptr = arg3;
        }
    }
    getDigestLength() {
        return this.outSizeW32 << 2;
    }
    digest(input, offset, len) {
        if (input == undefined) {
            const n = this.getDigestLength();
            const out = new Uint8Array(n);
            this.digest(out, 0, n);
            return out;
        }
        else if (offset == undefined || len == undefined) {
            this.update(input, 0, input.length);
            return this.digest();
        }
        else {
            const dlen = this.getDigestLength();
            if (len > dlen) {
                len = dlen;
            }
            this.buf[this.ptr++] = 0x80;
            for (let i = this.ptr; i < 64; i++) {
                this.buf[i] = 0;
            }
            for (let i = 0; i < 4; i++) {
                this.core(this.buf, 0, 1);
                this.W--;
            }
            var j = 44 - (dlen >>> 2);
            var w = 0;
            for (let i = 0; i < len; i++) {
                if ((i & 3) == 0)
                    w = this.state[j++];
                input[i] = w;
                w >>>= 8;
            }
            this.reset();
            return len;
        }
    }
    getIV(outSizeW32) {
        var iv = this.IVs[outSizeW32 - 1];
        if (iv == undefined) {
            var outSize = outSizeW32 << 5;
            const sg = new ShabalGeneric();
            for (let i = 0; i < 44; i++) {
                sg.state[i] = 0;
            }
            sg.W = BigInt(-1);
            for (let i = 0; i < 16; i++) {
                sg.buf[(i << 2) + 0] = (outSize + i);
                sg.buf[(i << 2) + 1] = ((outSize + i) >>> 8);
            }
            sg.core(sg.buf, 0, 1);
            for (let i = 0; i < 16; i++) {
                sg.buf[(i << 2) + 0] = (outSize + i + 16);
                sg.buf[(i << 2) + 1] = ((outSize + i + 16) >>> 8);
            }
            sg.core(sg.buf, 0, 1);
            iv = this.IVs[outSizeW32 - 1] = sg.state;
        }
        return iv;
    }
    reset() {
        arraycopy(this.getIV(this.outSizeW32), 0, this.state, 0, 44);
        this.W = BigInt(1);
        this.ptr = 0;
    }
    copy() {
        const d = this.dup();
        d.outSizeW32 = this.outSizeW32;
        arraycopy(this.buf, 0, d.buf, 0, this.ptr);
        d.ptr = this.ptr;
        arraycopy(this.state, 0, d.state, 0, 44);
        d.W = this.W;
        return d;
    }
    dup() {
        return new ShabalGeneric();
    }
    getBlockLength() {
        return 64;
    }
    //private M = new Int32Array(16);
    decodeLEInt(data, off) {
        return ((data[off + 3] & 0xFF) << 24)
            | ((data[off + 2] & 0xFF) << 16)
            | ((data[off + 1] & 0xFF) << 8)
            | (data[off + 0] & 0xFF);
    }
    core(data, off, num) {
        const A = new Int32Array(12);
        const B = new Int32Array(16);
        const C = new Int32Array(16);
        const M = new Int32Array(16);
        A[0] = this.state[0];
        A[1] = this.state[1];
        A[2] = this.state[2];
        A[3] = this.state[3];
        A[4] = this.state[4];
        A[5] = this.state[5];
        A[6] = this.state[6];
        A[7] = this.state[7];
        A[8] = this.state[8];
        A[9] = this.state[9];
        A[10] = this.state[10];
        A[11] = this.state[11];
        B[0] = this.state[12];
        B[1] = this.state[13];
        B[2] = this.state[14];
        B[3] = this.state[15];
        B[4] = this.state[16];
        B[5] = this.state[17];
        B[6] = this.state[18];
        B[7] = this.state[19];
        B[8] = this.state[20];
        B[9] = this.state[21];
        B[10] = this.state[22];
        B[11] = this.state[23];
        B[12] = this.state[24];
        B[13] = this.state[25];
        B[14] = this.state[26];
        B[15] = this.state[27];
        C[0] = this.state[28];
        C[1] = this.state[29];
        C[2] = this.state[30];
        C[3] = this.state[31];
        C[4] = this.state[32];
        C[5] = this.state[33];
        C[6] = this.state[34];
        C[7] = this.state[35];
        C[8] = this.state[36];
        C[9] = this.state[37];
        C[10] = this.state[38];
        C[11] = this.state[39];
        C[12] = this.state[40];
        C[13] = this.state[41];
        C[14] = this.state[42];
        C[15] = this.state[43];
        while (num-- > 0) {
            M[0] = this.decodeLEInt(data, off + 0);
            B[0] += M[0];
            B[0] = (B[0] << 17) | (B[0] >>> 15);
            M[1] = this.decodeLEInt(data, off + 4);
            B[1] += M[1];
            B[1] = (B[1] << 17) | (B[1] >>> 15);
            M[2] = this.decodeLEInt(data, off + 8);
            B[2] += M[2];
            B[2] = (B[2] << 17) | (B[2] >>> 15);
            M[3] = this.decodeLEInt(data, off + 12);
            B[3] += M[3];
            B[3] = (B[3] << 17) | (B[3] >>> 15);
            M[4] = this.decodeLEInt(data, off + 16);
            B[4] += M[4];
            B[4] = (B[4] << 17) | (B[4] >>> 15);
            M[5] = this.decodeLEInt(data, off + 20);
            B[5] += M[5];
            B[5] = (B[5] << 17) | (B[5] >>> 15);
            M[6] = this.decodeLEInt(data, off + 24);
            B[6] += M[6];
            B[6] = (B[6] << 17) | (B[6] >>> 15);
            M[7] = this.decodeLEInt(data, off + 28);
            B[7] += M[7];
            B[7] = (B[7] << 17) | (B[7] >>> 15);
            M[8] = this.decodeLEInt(data, off + 32);
            B[8] += M[8];
            B[8] = (B[8] << 17) | (B[8] >>> 15);
            M[9] = this.decodeLEInt(data, off + 36);
            B[9] += M[9];
            B[9] = (B[9] << 17) | (B[9] >>> 15);
            M[10] = this.decodeLEInt(data, off + 40);
            B[10] += M[10];
            B[10] = (B[10] << 17) | (B[10] >>> 15);
            M[11] = this.decodeLEInt(data, off + 44);
            B[11] += M[11];
            B[11] = (B[11] << 17) | (B[11] >>> 15);
            M[12] = this.decodeLEInt(data, off + 48);
            B[12] += M[12];
            B[12] = (B[12] << 17) | (B[12] >>> 15);
            M[13] = this.decodeLEInt(data, off + 52);
            B[13] += M[13];
            B[13] = (B[13] << 17) | (B[13] >>> 15);
            M[14] = this.decodeLEInt(data, off + 56);
            B[14] += M[14];
            B[14] = (B[14] << 17) | (B[14] >>> 15);
            M[15] = this.decodeLEInt(data, off + 60);
            B[15] += M[15];
            B[15] = (B[15] << 17) | (B[15] >>> 15);
            off += 64;
            A[0] ^= Number(this.W);
            A[1] ^= Number(this.W >> BigInt(32));
            this.W++;
            A[0] = ((A[0] ^ (((A[11] << 15) | (A[11] >>> 17)) * 5) ^ C[8]) * 3)
                ^ B[13] ^ (B[9] & ~B[6]) ^ M[0];
            B[0] = ~((B[0] << 1) | (B[0] >>> 31)) ^ A[0];
            A[1] = ((A[1] ^ (((A[0] << 15) | (A[0] >>> 17)) * 5) ^ C[7]) * 3)
                ^ B[14] ^ (B[10] & ~B[7]) ^ M[1];
            B[1] = ~((B[1] << 1) | (B[1] >>> 31)) ^ A[1];
            A[2] = ((A[2] ^ (((A[1] << 15) | (A[1] >>> 17)) * 5) ^ C[6]) * 3)
                ^ B[15] ^ (B[11] & ~B[8]) ^ M[2];
            B[2] = ~((B[2] << 1) | (B[2] >>> 31)) ^ A[2];
            A[3] = ((A[3] ^ (((A[2] << 15) | (A[2] >>> 17)) * 5) ^ C[5]) * 3)
                ^ B[0] ^ (B[12] & ~B[9]) ^ M[3];
            B[3] = ~((B[3] << 1) | (B[3] >>> 31)) ^ A[3];
            A[4] = ((A[4] ^ (((A[3] << 15) | (A[3] >>> 17)) * 5) ^ C[4]) * 3)
                ^ B[1] ^ (B[13] & ~B[10]) ^ M[4];
            B[4] = ~((B[4] << 1) | (B[4] >>> 31)) ^ A[4];
            A[5] = ((A[5] ^ (((A[4] << 15) | (A[4] >>> 17)) * 5) ^ C[3]) * 3)
                ^ B[2] ^ (B[14] & ~B[11]) ^ M[5];
            B[5] = ~((B[5] << 1) | (B[5] >>> 31)) ^ A[5];
            A[6] = ((A[6] ^ (((A[5] << 15) | (A[5] >>> 17)) * 5) ^ C[2]) * 3)
                ^ B[3] ^ (B[15] & ~B[12]) ^ M[6];
            B[6] = ~((B[6] << 1) | (B[6] >>> 31)) ^ A[6];
            A[7] = ((A[7] ^ (((A[6] << 15) | (A[6] >>> 17)) * 5) ^ C[1]) * 3)
                ^ B[4] ^ (B[0] & ~B[13]) ^ M[7];
            B[7] = ~((B[7] << 1) | (B[7] >>> 31)) ^ A[7];
            A[8] = ((A[8] ^ (((A[7] << 15) | (A[7] >>> 17)) * 5) ^ C[0]) * 3)
                ^ B[5] ^ (B[1] & ~B[14]) ^ M[8];
            B[8] = ~((B[8] << 1) | (B[8] >>> 31)) ^ A[8];
            A[9] = ((A[9] ^ (((A[8] << 15) | (A[8] >>> 17)) * 5) ^ C[15]) * 3)
                ^ B[6] ^ (B[2] & ~B[15]) ^ M[9];
            B[9] = ~((B[9] << 1) | (B[9] >>> 31)) ^ A[9];
            A[10] = ((A[10] ^ (((A[9] << 15) | (A[9] >>> 17)) * 5) ^ C[14]) * 3)
                ^ B[7] ^ (B[3] & ~B[0]) ^ M[10];
            B[10] = ~((B[10] << 1) | (B[10] >>> 31)) ^ A[10];
            A[11] = ((A[11] ^ (((A[10] << 15) | (A[10] >>> 17)) * 5) ^ C[13]) * 3)
                ^ B[8] ^ (B[4] & ~B[1]) ^ M[11];
            B[11] = ~((B[11] << 1) | (B[11] >>> 31)) ^ A[11];
            A[0] = ((A[0] ^ (((A[11] << 15) | (A[11] >>> 17)) * 5) ^ C[12]) * 3)
                ^ B[9] ^ (B[5] & ~B[2]) ^ M[12];
            B[12] = ~((B[12] << 1) | (B[12] >>> 31)) ^ A[0];
            A[1] = ((A[1] ^ (((A[0] << 15) | (A[0] >>> 17)) * 5) ^ C[11]) * 3)
                ^ B[10] ^ (B[6] & ~B[3]) ^ M[13];
            B[13] = ~((B[13] << 1) | (B[13] >>> 31)) ^ A[1];
            A[2] = ((A[2] ^ (((A[1] << 15) | (A[1] >>> 17)) * 5) ^ C[10]) * 3)
                ^ B[11] ^ (B[7] & ~B[4]) ^ M[14];
            B[14] = ~((B[14] << 1) | (B[14] >>> 31)) ^ A[2];
            A[3] = ((A[3] ^ (((A[2] << 15) | (A[2] >>> 17)) * 5) ^ C[9]) * 3)
                ^ B[12] ^ (B[8] & ~B[5]) ^ M[15];
            B[15] = ~((B[15] << 1) | (B[15] >>> 31)) ^ A[3];
            A[4] = ((A[4] ^ (((A[3] << 15) | (A[3] >>> 17)) * 5) ^ C[8]) * 3)
                ^ B[13] ^ (B[9] & ~B[6]) ^ M[0];
            B[0] = ~((B[0] << 1) | (B[0] >>> 31)) ^ A[4];
            A[5] = ((A[5] ^ (((A[4] << 15) | (A[4] >>> 17)) * 5) ^ C[7]) * 3)
                ^ B[14] ^ (B[10] & ~B[7]) ^ M[1];
            B[1] = ~((B[1] << 1) | (B[1] >>> 31)) ^ A[5];
            A[6] = ((A[6] ^ (((A[5] << 15) | (A[5] >>> 17)) * 5) ^ C[6]) * 3)
                ^ B[15] ^ (B[11] & ~B[8]) ^ M[2];
            B[2] = ~((B[2] << 1) | (B[2] >>> 31)) ^ A[6];
            A[7] = ((A[7] ^ (((A[6] << 15) | (A[6] >>> 17)) * 5) ^ C[5]) * 3)
                ^ B[0] ^ (B[12] & ~B[9]) ^ M[3];
            B[3] = ~((B[3] << 1) | (B[3] >>> 31)) ^ A[7];
            A[8] = ((A[8] ^ (((A[7] << 15) | (A[7] >>> 17)) * 5) ^ C[4]) * 3)
                ^ B[1] ^ (B[13] & ~B[10]) ^ M[4];
            B[4] = ~((B[4] << 1) | (B[4] >>> 31)) ^ A[8];
            A[9] = ((A[9] ^ (((A[8] << 15) | (A[8] >>> 17)) * 5) ^ C[3]) * 3)
                ^ B[2] ^ (B[14] & ~B[11]) ^ M[5];
            B[5] = ~((B[5] << 1) | (B[5] >>> 31)) ^ A[9];
            A[10] = ((A[10] ^ (((A[9] << 15) | (A[9] >>> 17)) * 5) ^ C[2]) * 3)
                ^ B[3] ^ (B[15] & ~B[12]) ^ M[6];
            B[6] = ~((B[6] << 1) | (B[6] >>> 31)) ^ A[10];
            A[11] = ((A[11] ^ (((A[10] << 15) | (A[10] >>> 17)) * 5) ^ C[1]) * 3)
                ^ B[4] ^ (B[0] & ~B[13]) ^ M[7];
            B[7] = ~((B[7] << 1) | (B[7] >>> 31)) ^ A[11];
            A[0] = ((A[0] ^ (((A[11] << 15) | (A[11] >>> 17)) * 5) ^ C[0]) * 3)
                ^ B[5] ^ (B[1] & ~B[14]) ^ M[8];
            B[8] = ~((B[8] << 1) | (B[8] >>> 31)) ^ A[0];
            A[1] = ((A[1] ^ (((A[0] << 15) | (A[0] >>> 17)) * 5) ^ C[15]) * 3)
                ^ B[6] ^ (B[2] & ~B[15]) ^ M[9];
            B[9] = ~((B[9] << 1) | (B[9] >>> 31)) ^ A[1];
            A[2] = ((A[2] ^ (((A[1] << 15) | (A[1] >>> 17)) * 5) ^ C[14]) * 3)
                ^ B[7] ^ (B[3] & ~B[0]) ^ M[10];
            B[10] = ~((B[10] << 1) | (B[10] >>> 31)) ^ A[2];
            A[3] = ((A[3] ^ (((A[2] << 15) | (A[2] >>> 17)) * 5) ^ C[13]) * 3)
                ^ B[8] ^ (B[4] & ~B[1]) ^ M[11];
            B[11] = ~((B[11] << 1) | (B[11] >>> 31)) ^ A[3];
            A[4] = ((A[4] ^ (((A[3] << 15) | (A[3] >>> 17)) * 5) ^ C[12]) * 3)
                ^ B[9] ^ (B[5] & ~B[2]) ^ M[12];
            B[12] = ~((B[12] << 1) | (B[12] >>> 31)) ^ A[4];
            A[5] = ((A[5] ^ (((A[4] << 15) | (A[4] >>> 17)) * 5) ^ C[11]) * 3)
                ^ B[10] ^ (B[6] & ~B[3]) ^ M[13];
            B[13] = ~((B[13] << 1) | (B[13] >>> 31)) ^ A[5];
            A[6] = ((A[6] ^ (((A[5] << 15) | (A[5] >>> 17)) * 5) ^ C[10]) * 3)
                ^ B[11] ^ (B[7] & ~B[4]) ^ M[14];
            B[14] = ~((B[14] << 1) | (B[14] >>> 31)) ^ A[6];
            A[7] = ((A[7] ^ (((A[6] << 15) | (A[6] >>> 17)) * 5) ^ C[9]) * 3)
                ^ B[12] ^ (B[8] & ~B[5]) ^ M[15];
            B[15] = ~((B[15] << 1) | (B[15] >>> 31)) ^ A[7];
            A[8] = ((A[8] ^ (((A[7] << 15) | (A[7] >>> 17)) * 5) ^ C[8]) * 3)
                ^ B[13] ^ (B[9] & ~B[6]) ^ M[0];
            B[0] = ~((B[0] << 1) | (B[0] >>> 31)) ^ A[8];
            A[9] = ((A[9] ^ (((A[8] << 15) | (A[8] >>> 17)) * 5) ^ C[7]) * 3)
                ^ B[14] ^ (B[10] & ~B[7]) ^ M[1];
            B[1] = ~((B[1] << 1) | (B[1] >>> 31)) ^ A[9];
            A[10] = ((A[10] ^ (((A[9] << 15) | (A[9] >>> 17)) * 5) ^ C[6]) * 3)
                ^ B[15] ^ (B[11] & ~B[8]) ^ M[2];
            B[2] = ~((B[2] << 1) | (B[2] >>> 31)) ^ A[10];
            A[11] = ((A[11] ^ (((A[10] << 15) | (A[10] >>> 17)) * 5) ^ C[5]) * 3)
                ^ B[0] ^ (B[12] & ~B[9]) ^ M[3];
            B[3] = ~((B[3] << 1) | (B[3] >>> 31)) ^ A[11];
            A[0] = ((A[0] ^ (((A[11] << 15) | (A[11] >>> 17)) * 5) ^ C[4]) * 3)
                ^ B[1] ^ (B[13] & ~B[10]) ^ M[4];
            B[4] = ~((B[4] << 1) | (B[4] >>> 31)) ^ A[0];
            A[1] = ((A[1] ^ (((A[0] << 15) | (A[0] >>> 17)) * 5) ^ C[3]) * 3)
                ^ B[2] ^ (B[14] & ~B[11]) ^ M[5];
            B[5] = ~((B[5] << 1) | (B[5] >>> 31)) ^ A[1];
            A[2] = ((A[2] ^ (((A[1] << 15) | (A[1] >>> 17)) * 5) ^ C[2]) * 3)
                ^ B[3] ^ (B[15] & ~B[12]) ^ M[6];
            B[6] = ~((B[6] << 1) | (B[6] >>> 31)) ^ A[2];
            A[3] = ((A[3] ^ (((A[2] << 15) | (A[2] >>> 17)) * 5) ^ C[1]) * 3)
                ^ B[4] ^ (B[0] & ~B[13]) ^ M[7];
            B[7] = ~((B[7] << 1) | (B[7] >>> 31)) ^ A[3];
            A[4] = ((A[4] ^ (((A[3] << 15) | (A[3] >>> 17)) * 5) ^ C[0]) * 3)
                ^ B[5] ^ (B[1] & ~B[14]) ^ M[8];
            B[8] = ~((B[8] << 1) | (B[8] >>> 31)) ^ A[4];
            A[5] = ((A[5] ^ (((A[4] << 15) | (A[4] >>> 17)) * 5) ^ C[15]) * 3)
                ^ B[6] ^ (B[2] & ~B[15]) ^ M[9];
            B[9] = ~((B[9] << 1) | (B[9] >>> 31)) ^ A[5];
            A[6] = ((A[6] ^ (((A[5] << 15) | (A[5] >>> 17)) * 5) ^ C[14]) * 3)
                ^ B[7] ^ (B[3] & ~B[0]) ^ M[10];
            B[10] = ~((B[10] << 1) | (B[10] >>> 31)) ^ A[6];
            A[7] = ((A[7] ^ (((A[6] << 15) | (A[6] >>> 17)) * 5) ^ C[13]) * 3)
                ^ B[8] ^ (B[4] & ~B[1]) ^ M[11];
            B[11] = ~((B[11] << 1) | (B[11] >>> 31)) ^ A[7];
            A[8] = ((A[8] ^ (((A[7] << 15) | (A[7] >>> 17)) * 5) ^ C[12]) * 3)
                ^ B[9] ^ (B[5] & ~B[2]) ^ M[12];
            B[12] = ~((B[12] << 1) | (B[12] >>> 31)) ^ A[8];
            A[9] = ((A[9] ^ (((A[8] << 15) | (A[8] >>> 17)) * 5) ^ C[11]) * 3)
                ^ B[10] ^ (B[6] & ~B[3]) ^ M[13];
            B[13] = ~((B[13] << 1) | (B[13] >>> 31)) ^ A[9];
            A[10] = ((A[10] ^ (((A[9] << 15) | (A[9] >>> 17)) * 5) ^ C[10]) * 3)
                ^ B[11] ^ (B[7] & ~B[4]) ^ M[14];
            B[14] = ~((B[14] << 1) | (B[14] >>> 31)) ^ A[10];
            A[11] = ((A[11] ^ (((A[10] << 15) | (A[10] >>> 17)) * 5) ^ C[9]) * 3)
                ^ B[12] ^ (B[8] & ~B[5]) ^ M[15];
            B[15] = ~((B[15] << 1) | (B[15] >>> 31)) ^ A[11];
            A[11] += C[6] + C[10] + C[14];
            A[10] += C[5] + C[9] + C[13];
            A[9] += C[4] + C[8] + C[12];
            A[8] += C[3] + C[7] + C[11];
            A[7] += C[2] + C[6] + C[10];
            A[6] += C[1] + C[5] + C[9];
            A[5] += C[0] + C[4] + C[8];
            A[4] += C[15] + C[3] + C[7];
            A[3] += C[14] + C[2] + C[6];
            A[2] += C[13] + C[1] + C[5];
            A[1] += C[12] + C[0] + C[4];
            A[0] += C[11] + C[15] + C[3];
            var tmp;
            tmp = B[0];
            B[0] = C[0] - M[0];
            C[0] = tmp;
            tmp = B[1];
            B[1] = C[1] - M[1];
            C[1] = tmp;
            tmp = B[2];
            B[2] = C[2] - M[2];
            C[2] = tmp;
            tmp = B[3];
            B[3] = C[3] - M[3];
            C[3] = tmp;
            tmp = B[4];
            B[4] = C[4] - M[4];
            C[4] = tmp;
            tmp = B[5];
            B[5] = C[5] - M[5];
            C[5] = tmp;
            tmp = B[6];
            B[6] = C[6] - M[6];
            C[6] = tmp;
            tmp = B[7];
            B[7] = C[7] - M[7];
            C[7] = tmp;
            tmp = B[8];
            B[8] = C[8] - M[8];
            C[8] = tmp;
            tmp = B[9];
            B[9] = C[9] - M[9];
            C[9] = tmp;
            tmp = B[10];
            B[10] = C[10] - M[10];
            C[10] = tmp;
            tmp = B[11];
            B[11] = C[11] - M[11];
            C[11] = tmp;
            tmp = B[12];
            B[12] = C[12] - M[12];
            C[12] = tmp;
            tmp = B[13];
            B[13] = C[13] - M[13];
            C[13] = tmp;
            tmp = B[14];
            B[14] = C[14] - M[14];
            C[14] = tmp;
            tmp = B[15];
            B[15] = C[15] - M[15];
            C[15] = tmp;
        }
        this.state[0] = A[0];
        this.state[1] = A[1];
        this.state[2] = A[2];
        this.state[3] = A[3];
        this.state[4] = A[4];
        this.state[5] = A[5];
        this.state[6] = A[6];
        this.state[7] = A[7];
        this.state[8] = A[8];
        this.state[9] = A[9];
        this.state[10] = A[10];
        this.state[11] = A[11];
        this.state[12] = B[0];
        this.state[13] = B[1];
        this.state[14] = B[2];
        this.state[15] = B[3];
        this.state[16] = B[4];
        this.state[17] = B[5];
        this.state[18] = B[6];
        this.state[19] = B[7];
        this.state[20] = B[8];
        this.state[21] = B[9];
        this.state[22] = B[10];
        this.state[23] = B[11];
        this.state[24] = B[12];
        this.state[25] = B[13];
        this.state[26] = B[14];
        this.state[27] = B[15];
        this.state[28] = C[0];
        this.state[29] = C[1];
        this.state[30] = C[2];
        this.state[31] = C[3];
        this.state[32] = C[4];
        this.state[33] = C[5];
        this.state[34] = C[6];
        this.state[35] = C[7];
        this.state[36] = C[8];
        this.state[37] = C[9];
        this.state[38] = C[10];
        this.state[39] = C[11];
        this.state[40] = C[12];
        this.state[41] = C[13];
        this.state[42] = C[14];
        this.state[43] = C[15];
    }
    toString() {
        return "Shabal-" + (this.getDigestLength() << 3);
    }
}
/**
 * <p>This class implements the Shabal-192 digest algorithm under the
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
 * @version   $Revision: 213 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
class Shabal192 extends ShabalGeneric {
    /**
     * Create the engine.
     */
    constructor() {
        super(192);
    }
    /** @see ShabalGeneric */
    dup() {
        return new Shabal192();
    }
}
exports.Shabal192 = Shabal192;
/**
 * <p>This class implements the Shabal-224 digest algorithm under the
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
 * @version   $Revision: 213 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
class Shabal224 extends ShabalGeneric {
    /**
     * Create the engine.
     */
    constructor() {
        super(224);
    }
    /** @see ShabalGeneric */
    dup() {
        return new Shabal224();
    }
}
exports.Shabal224 = Shabal224;
/**
 * <p>This class implements the Shabal-256 digest algorithm under the
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
 * @version   $Revision: 213 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
class Shabal256 extends ShabalGeneric {
    /**
     * Create the engine.
     */
    constructor() {
        super(256);
    }
    /** @see ShabalGeneric */
    dup() {
        return new Shabal256();
    }
}
exports.Shabal256 = Shabal256;
/**
 * <p>This class implements the Shabal-384 digest algorithm under the
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
 * @version   $Revision: 213 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
class Shabal384 extends ShabalGeneric {
    /**
     * Create the engine.
     */
    constructor() {
        super(384);
    }
    /** @see ShabalGeneric */
    dup() {
        return new Shabal384();
    }
}
exports.Shabal384 = Shabal384;
/**
 * <p>This class implements the Shabal-512 digest algorithm under the
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
 * @version   $Revision: 213 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
class Shabal512 extends ShabalGeneric {
    /**
     * Create the engine.
     */
    constructor() {
        super(512);
    }
    /** @see ShabalGeneric */
    dup() {
        return new Shabal512();
    }
}
exports.Shabal512 = Shabal512;
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
 * Creates a vary byte length SHABAL hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {192 |224 | 256 | 384 | 512} bitLen - length of hash (default 512 bits AKA 64 bytes)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function _SHABAL(message, bitLen = 256, format = arrayType()) {
    var hash;
    switch (bitLen) {
        case 192:
            hash = new Shabal192();
            break;
        case 224:
            hash = new Shabal224();
            break;
        case 256:
            hash = new Shabal256();
            break;
        case 384:
            hash = new Shabal384();
            break;
        case 512:
            hash = new Shabal512();
            break;
        default:
            hash = new Shabal512();
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
exports._SHABAL = _SHABAL;
;
/**
 * Creates a vary byte length keyed SHABAL hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {192 |224 | 256 | 384 | 512} bitLen - length of hash (default 512 bits AKA 64 bytes)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function SHABAL_HMAC(message, key, bitLen = 256, format = arrayType()) {
    var hash;
    switch (bitLen) {
        case 192:
            hash = new Shabal192();
            break;
        case 224:
            hash = new Shabal224();
            break;
        case 256:
            hash = new Shabal256();
            break;
        case 384:
            hash = new Shabal384();
            break;
        case 512:
            hash = new Shabal512();
            break;
        default:
            hash = new Shabal512();
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
exports.SHABAL_HMAC = SHABAL_HMAC;
;
/**
 * Creates a 24 byte SHABAL hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function SHABAL192(message, format = arrayType()) {
    const hash = new Shabal192();
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
exports.SHABAL192 = SHABAL192;
;
/**
 * Creates a 24 byte keyed SHABAL hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function SHABAL192_HMAC(message, key, format = arrayType()) {
    const hash = new Shabal192();
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
exports.SHABAL192_HMAC = SHABAL192_HMAC;
;
/**
 * Creates a 28 byte SHABAL hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function SHABAL224(message, format = arrayType()) {
    const hash = new Shabal224();
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
exports.SHABAL224 = SHABAL224;
;
/**
 * Creates a 28 byte keyed SHABAL hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function SHABAL224_HMAC(message, key, format = arrayType()) {
    const hash = new Shabal224();
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
exports.SHABAL224_HMAC = SHABAL224_HMAC;
;
/**
 * Creates a 32 byte SHABAL hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function SHABAL256(message, format = arrayType()) {
    const hash = new Shabal256();
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
exports.SHABAL256 = SHABAL256;
;
/**
 * Creates a 32 byte keyed SHABAL hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function SHABAL256_HMAC(message, key, format = arrayType()) {
    const hash = new Shabal256();
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
exports.SHABAL256_HMAC = SHABAL256_HMAC;
;
/**
 * Creates a 48 byte SHABAL hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function SHABAL384(message, format = arrayType()) {
    const hash = new Shabal384();
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
exports.SHABAL384 = SHABAL384;
;
/**
 * Creates a 48 byte keyed SHABAL hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function SHABAL384_HMAC(message, key, format = arrayType()) {
    const hash = new Shabal384();
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
exports.SHABAL384_HMAC = SHABAL384_HMAC;
;
/**
 * Creates a 64 byte SHABAL hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function SHABAL512(message, format = arrayType()) {
    const hash = new Shabal512();
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
exports.SHABAL512 = SHABAL512;
;
/**
 * Creates a 64 byte keyed SHABAL hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function SHABAL512_HMAC(message, key, format = arrayType()) {
    const hash = new Shabal512();
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
exports.SHABAL512_HMAC = SHABAL512_HMAC;
;
/**
 * Static class of all SHABAL functions and classes
 */
class SHABAL {
    /**
     * List of all hashes in class
     */
    static get FUNCTION_LIST() {
        return [
            "SHABAL",
            "SHABAL192",
            "SHABAL192_HMAC",
            "SHABAL224",
            "SHABAL224_HMAC",
            "SHABAL256",
            "SHABAL256_HMAC",
            "SHABAL384",
            "SHABAL384_HMAC",
            "SHABAL512",
            "SHABAL512_HMAC",
            "SHABAL_HMAC",
        ];
    }
}
exports.SHABAL = SHABAL;
SHABAL.SHABAL = _SHABAL;
SHABAL.Shabal192 = Shabal192;
SHABAL.SHABAL192 = SHABAL192;
SHABAL.SHABAL192_HMAC = SHABAL192_HMAC;
SHABAL.Shabal224 = Shabal224;
SHABAL.SHABAL224 = SHABAL224;
SHABAL.SHABAL224_HMAC = SHABAL224_HMAC;
SHABAL.Shabal256 = Shabal256;
SHABAL.SHABAL256 = SHABAL256;
SHABAL.SHABAL256_HMAC = SHABAL256_HMAC;
SHABAL.Shabal384 = Shabal384;
SHABAL.SHABAL384 = SHABAL384;
SHABAL.SHABAL384_HMAC = SHABAL384_HMAC;
SHABAL.Shabal512 = Shabal512;
SHABAL.SHABAL512 = SHABAL512;
SHABAL.SHABAL512_HMAC = SHABAL512_HMAC;
SHABAL.SHABAL_HMAC = SHABAL_HMAC;
//# sourceMappingURL=SHABAL.js.map