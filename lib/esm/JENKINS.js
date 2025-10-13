"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.JENKINS = exports.JENKINS_SPOOKY_32 = exports.JENKINS_SPOOKY_64 = exports.JENKINS_SPOOKY_128 = exports.JENKINS_SPOOKY = exports.JENKINS_LOOKUP2 = exports.JENKINS_OAAT = exports.Lookup2 = void 0;
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
function bytesToHex(bytes) {
    for (var hex = [], i = 0; i < bytes.length; i++) {
        hex.push((bytes[i] >>> 4).toString(16));
        hex.push((bytes[i] & 0xF).toString(16));
    }
    return hex.join("");
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
 * Implementation of Jenkins' Lookup2 hash function ("My Hash"), converted from the C code.
 * This is a non-cryptographic 32-bit hash for variable-length data.
 *
 * Removed streaming: Assume full data in updates; concatenate all input and compute in doPadding.
 * No getByte; use array indexing on concatenated data.
 * Output big-endian 4 bytes.
 * Block length arbitrary (64 bytes) for HMAC.
 */
class Lookup2 extends DigestEngine {
    constructor() {
        super(...arguments);
        this.fullData = [];
        this.initval = 0;
        this.state = 0;
    }
    setSeed(seed) {
        this.initval = seed;
    }
    ;
    doInit() {
        this.engineReset();
    }
    engineReset() {
        this.fullData = [];
    }
    processBlock(data) {
        // Empty; computation in doPadding
    }
    update(arg1, arg2, arg3) {
        if (typeof arg1 === 'number') {
            this.fullData.push(arg1 & 0xFF);
        }
        else if (arg2 === undefined && arg3 === undefined) {
            this.update(arg1, 0, arg1.length);
        }
        else {
            for (let i = arg2; i < arg2 + arg3; i++) {
                this.fullData.push(arg1[i]);
            }
        }
    }
    doPadding(buf, off) {
        const totalLen = this.fullData.length;
        let a = 0x9e3779b9 >>> 0;
        let b = 0x9e3779b9 >>> 0;
        let c = this.initval >>> 0; // initval = 0
        let i = 0;
        let len = totalLen;
        while (len >= 12) {
            a = (a + this.fullData[i] + (this.fullData[i + 1] << 8) + (this.fullData[i + 2] << 16) + (this.fullData[i + 3] << 24)) >>> 0;
            b = (b + this.fullData[i + 4] + (this.fullData[i + 5] << 8) + (this.fullData[i + 6] << 16) + (this.fullData[i + 7] << 24)) >>> 0;
            c = (c + this.fullData[i + 8] + (this.fullData[i + 9] << 8) + (this.fullData[i + 10] << 16) + (this.fullData[i + 11] << 24)) >>> 0;
            a = (a - b) >>> 0;
            a = (a - c) >>> 0;
            a = (a ^ (c >>> 13)) >>> 0;
            b = (b - c) >>> 0;
            b = (b - a) >>> 0;
            b = (b ^ (a << 8)) >>> 0;
            c = (c - a) >>> 0;
            c = (c - b) >>> 0;
            c = (c ^ (b >>> 13)) >>> 0;
            a = (a - b) >>> 0;
            a = (a - c) >>> 0;
            a = (a ^ (c >>> 12)) >>> 0;
            b = (b - c) >>> 0;
            b = (b - a) >>> 0;
            b = (b ^ (a << 16)) >>> 0;
            c = (c - a) >>> 0;
            c = (c - b) >>> 0;
            c = (c ^ (b >>> 5)) >>> 0;
            a = (a - b) >>> 0;
            a = (a - c) >>> 0;
            a = (a ^ (c >>> 3)) >>> 0;
            b = (b - c) >>> 0;
            b = (b - a) >>> 0;
            b = (b ^ (a << 10)) >>> 0;
            c = (c - a) >>> 0;
            c = (c - b) >>> 0;
            c = (c ^ (b >>> 15)) >>> 0;
            i += 12;
            len -= 12;
        }
        c = (c + totalLen) >>> 0;
        switch (len) {
            // @ts-ignore
            case 11: c = (c + (this.fullData[i + 10] << 24)) >>> 0; // Fall through
            // @ts-ignore
            case 10: c = (c + (this.fullData[i + 9] << 16)) >>> 0; // Fall through
            // @ts-ignore
            case 9: c = (c + (this.fullData[i + 8] << 8)) >>> 0; // Fall through
            // @ts-ignore
            case 8: b = (b + (this.fullData[i + 7] << 24)) >>> 0; // Fall through
            // @ts-ignore
            case 7: b = (b + (this.fullData[i + 6] << 16)) >>> 0; // Fall through
            // @ts-ignore
            case 6: b = (b + (this.fullData[i + 5] << 8)) >>> 0; // Fall through
            // @ts-ignore
            case 5: b = (b + this.fullData[i + 4]) >>> 0; // Fall through
            // @ts-ignore
            case 4: a = (a + (this.fullData[i + 3] << 24)) >>> 0; // Fall through
            // @ts-ignore
            case 3: a = (a + (this.fullData[i + 2] << 16)) >>> 0; // Fall through
            // @ts-ignore
            case 2: a = (a + (this.fullData[i + 1] << 8)) >>> 0; // Fall through
            // @ts-ignore
            case 1: a = (a + this.fullData[i]) >>> 0; // Fall through
            case 0: break;
        }
        a = (a - b) >>> 0;
        a = (a - c) >>> 0;
        a = (a ^ (c >>> 13)) >>> 0;
        b = (b - c) >>> 0;
        b = (b - a) >>> 0;
        b = (b ^ (a << 8)) >>> 0;
        c = (c - a) >>> 0;
        c = (c - b) >>> 0;
        c = (c ^ (b >>> 13)) >>> 0;
        a = (a - b) >>> 0;
        a = (a - c) >>> 0;
        a = (a ^ (c >>> 12)) >>> 0;
        b = (b - c) >>> 0;
        b = (b - a) >>> 0;
        b = (b ^ (a << 16)) >>> 0;
        c = (c - a) >>> 0;
        c = (c - b) >>> 0;
        c = (c ^ (b >>> 5)) >>> 0;
        a = (a - b) >>> 0;
        a = (a - c) >>> 0;
        a = (a ^ (c >>> 3)) >>> 0;
        b = (b - c) >>> 0;
        b = (b - a) >>> 0;
        b = (b ^ (a << 10)) >>> 0;
        c = (c - a) >>> 0;
        c = (c - b) >>> 0;
        c = (c ^ (b >>> 15)) >>> 0;
        const finalHash = c >>> 0;
        this.initval = finalHash;
        this.state = finalHash;
        buf[off] = (finalHash >>> 24) & 0xFF;
        buf[off + 1] = (finalHash >>> 16) & 0xFF;
        buf[off + 2] = (finalHash >>> 8) & 0xFF;
        buf[off + 3] = finalHash & 0xFF;
    }
    getDigestLength() {
        return 4;
    }
    getBlockLength() {
        return 64;
    }
    getInternalBlockLength() {
        return 1; //this.getBlockLength();
    }
    dup() {
        const x = new Lookup2();
        x.fullData = this.fullData.slice();
        return x;
    }
    getAlgorithmName() {
        return "Lookup2";
    }
}
exports.Lookup2 = Lookup2;
/**
 * Implementation of Jenkins' Lookup3 hash function, converted from the C code.
 * This is a non-cryptographic 32-bit hash for variable-length data, improvement on Lookup2.
 * Uses hashlittle() for little-endian, as most modern systems are.
 *
 * Removed streaming: Assume full data in updates; concatenate all input and compute in doPadding.
 * No getByte; use array indexing on concatenated data.
 * Initial value is 0.
 * Output is big-endian 4 bytes.
 * Block length arbitrary (64 bytes) for HMAC.
 */
class Lookup3 {
    /**
     *
     * @param {number} pc primary initval
     * @param {number} pb secondary initval
     */
    constructor(bitLen = 32, pc = 0, pb = 0) {
        this.pc = 0;
        this.pb = 0;
        this.bitLen = 32;
        this.pc = pc >>> 0;
        this.pb = pb >>> 0;
        if (bitLen != 32) {
            this.bitLen = 64;
        }
    }
    update(message) {
        message = formatMessage(message);
        if (this.bitLen == 32) {
            this.hashlittle2(message);
            return this.pc;
        }
        else {
            this.hashlittle2(message);
            return (BigInt(this.pc) << BigInt(32)) | BigInt(this.pb);
        }
    }
    digest() {
        if (this.bitLen == 32) {
            return this.pc;
        }
        else {
            return (BigInt(this.pc) << BigInt(32)) | BigInt(this.pb);
        }
    }
    load32(data, off) {
        return data[off] | data[off + 1] << 8 | data[off + 2] << 16 | data[off + 3] << 24;
    }
    rot(x, k) {
        return (((x) << (k)) | ((x) >>> (32 - (k)))) >>> 0;
    }
    mix(a, b, c) {
        a = (a - c) >>> 0;
        a = (a ^ this.rot(c, 4)) >>> 0;
        c = (c + b) >>> 0;
        b = (b - a) >>> 0;
        b = (b ^ this.rot(a, 6)) >>> 0;
        a = (a + c) >>> 0;
        c = (c - b) >>> 0;
        c = (c ^ this.rot(b, 8)) >>> 0;
        b = (b + a) >>> 0;
        a = (a - c) >>> 0;
        a = (a ^ this.rot(c, 16)) >>> 0;
        c = (c + b) >>> 0;
        b = (b - a) >>> 0;
        b = (b ^ this.rot(a, 19)) >>> 0;
        a = (a + c) >>> 0;
        c = (c - b) >>> 0;
        c = (c ^ this.rot(b, 4)) >>> 0;
        b = (b + a) >>> 0;
        return [a, b, c];
    }
    final(a, b, c) {
        c = (c ^ b) >>> 0;
        c = (c - this.rot(b, 14)) >>> 0;
        a = (a ^ c) >>> 0;
        a = (a - this.rot(c, 11)) >>> 0;
        b = (b ^ a) >>> 0;
        b = (b - this.rot(a, 25)) >>> 0;
        c = (c ^ b) >>> 0;
        c = (c - this.rot(b, 16)) >>> 0;
        a = (a ^ c) >>> 0;
        a = (a - this.rot(c, 4)) >>> 0;
        b = (b ^ a) >>> 0;
        b = (b - this.rot(a, 14)) >>> 0;
        c = (c ^ b) >>> 0;
        c = (c - this.rot(b, 24)) >>> 0;
        return [a, b, c];
    }
    hashlittle2(key, pc = this.pc, pb = this.pb) {
        var length = key.length;
        let a = 0xdeadbeef + length + pc >>> 0;
        let b = a >>> 0;
        let c = a >>> 0;
        c = (c + pb) >>> 0;
        let i = 0;
        while (length > 12) {
            a = (a + key[0] + (key[1] << 8) + (key[2] << 16) + (key[3] << 24)) >>> 0;
            b = (b + key[4] + (key[5] << 8) + (key[6] << 16) + (key[7] << 24)) >>> 0;
            c = (c + key[8] + (key[9] << 8) + (key[10] << 16) + (key[11] << 24)) >>> 0;
            [a, b, c] = this.mix(a, b, c);
            length -= 12;
            key = key.subarray(12, key.length);
            i += 12;
        }
        let k = key;
        switch (length) {
            // @ts-ignore
            case 12:
                c += this.load32(k, 4 * 2);
                b += this.load32(k, 4 * 1);
                a += this.load32(k, 0);
                break;
            // @ts-ignore
            case 11: c += (k[10]) << 16; /* fall through */
            // @ts-ignore
            case 10: c += (k[9]) << 8; /* fall through */
            // @ts-ignore
            case 9: c += k[8]; /* fall through */
            // @ts-ignore
            case 8:
                b += this.load32(k, 4 * 1);
                a += this.load32(k, 0);
                break;
            // @ts-ignore
            case 7: b += (k[6]) << 16; /* fall through */
            // @ts-ignore
            case 6: b += (k[5]) << 8; /* fall through */
            // @ts-ignore
            case 5: b += k[4]; /* fall through */
            // @ts-ignore
            case 4:
                a += this.load32(k, 0);
                break;
            // @ts-ignore
            case 3: a += (k[2]) << 16; /* fall through */
            // @ts-ignore
            case 2: a += (k[1]) << 8; /* fall through */
            // @ts-ignore
            case 1:
                a += k[0];
                break;
            case 0: return { pc: b, pb: c }; /* zero length strings require no mixing */
        }
        [a, b, c] = this.final(a, b, c);
        this.pc = c;
        this.pb = b;
        return { pc: c, pb: b };
    }
}
function rot64(x, k) {
    return ((x << k) | (x >> (BigInt(64) - k)));
}
function load64(data, off) {
    return BigInt(data[off]) | BigInt(data[off + 1]) << BigInt(8) | BigInt(data[off + 2]) << BigInt(16) | BigInt(data[off + 3]) << BigInt(24) |
        BigInt(data[off + 4]) << BigInt(32) | BigInt(data[off + 5]) << BigInt(40) | BigInt(data[off + 6]) << BigInt(48) | BigInt(data[off + 7]) << BigInt(56);
}
function load32(data, off) {
    return data[off] | data[off + 1] << 8 | data[off + 2] << 16 | data[off + 3] << 24;
}
function memcpy64(dst, src, elements) {
    // Create a new Uint8Array with the padded length and initialize it with zeros
    const paddedUint8Array = new Uint8Array(elements * 8);
    paddedUint8Array.set(src.subarray(0, elements * 8)); // Copy the original data
    for (let i = 0; i < elements; i++) {
        dst[i] = load64(paddedUint8Array, i * 8) || BigInt(0);
    }
}
;
function addValueToLast8Bits(base, hi8) {
    const mask56 = (BigInt(1) << BigInt(56)) - BigInt(1); // keep only the low 56 bits
    return ((BigInt(hi8) & BigInt(0xFF)) << BigInt(56)) | (base & mask56);
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
class SpookyHash {
    constructor(seed1 = BigInt(0), seed2 = BigInt(0)) {
        this.sc_numVars = 12;
        this.sc_blockSize = this.sc_numVars * 8;
        this.sc_bufSize = 2 * this.sc_blockSize;
        this.sc_const = BigInt("0xdeadbeefdeadbeef");
        this.hash1 = BigInt(0);
        this.hash2 = BigInt(0);
        this.hash1 = seed1;
        this.hash2 = seed2;
    }
    update(message) {
        message = formatMessage(message);
        this.hash128(message);
    }
    short_mix(h0, h1, h2, h3) {
        h2 = rot64(h2, BigInt(50));
        h2 = BigInt.asUintN(64, h2 + h3);
        h0 ^= h2;
        h3 = rot64(h3, BigInt(52));
        h3 = BigInt.asUintN(64, h3 + h0);
        h1 ^= h3;
        h0 = rot64(h0, BigInt(30));
        h0 = BigInt.asUintN(64, h0 + h1);
        h2 ^= h0;
        h1 = rot64(h1, BigInt(41));
        h1 = BigInt.asUintN(64, h1 + h2);
        h3 ^= h1;
        h2 = rot64(h2, BigInt(54));
        h2 = BigInt.asUintN(64, h2 + h3);
        h0 ^= h2;
        h3 = rot64(h3, BigInt(48));
        h3 = BigInt.asUintN(64, h3 + h0);
        h1 ^= h3;
        h0 = rot64(h0, BigInt(38));
        h0 = BigInt.asUintN(64, h0 + h1);
        h2 ^= h0;
        h1 = rot64(h1, BigInt(37));
        h1 = BigInt.asUintN(64, h1 + h2);
        h3 ^= h1;
        h2 = rot64(h2, BigInt(62));
        h2 = BigInt.asUintN(64, h2 + h3);
        h0 ^= h2;
        h3 = rot64(h3, BigInt(34));
        h3 = BigInt.asUintN(64, h3 + h0);
        h1 ^= h3;
        h0 = rot64(h0, BigInt(5));
        h0 = BigInt.asUintN(64, h0 + h1);
        h2 ^= h0;
        h1 = rot64(h1, BigInt(36));
        h1 = BigInt.asUintN(64, h1 + h2);
        h3 ^= h1;
        return [h0, h1, h2, h3];
    }
    mix(data, s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11) {
        s0 = BigInt.asUintN(64, s0 + data[0]);
        s2 ^= s10;
        s11 ^= s0;
        s0 = rot64(s0, BigInt(11));
        s11 = BigInt.asUintN(64, s11 + s1);
        s1 = BigInt.asUintN(64, s1 + data[1]);
        s3 ^= s11;
        s0 ^= s1;
        s1 = rot64(s1, BigInt(32));
        s0 = BigInt.asUintN(64, s0 + s2);
        s2 = BigInt.asUintN(64, s2 + data[2]);
        s4 ^= s0;
        s1 ^= s2;
        s2 = rot64(s2, BigInt(43));
        s1 = BigInt.asUintN(64, s1 + s3);
        s3 = BigInt.asUintN(64, s3 + data[3]);
        s5 ^= s1;
        s2 ^= s3;
        s3 = rot64(s3, BigInt(31));
        s2 = BigInt.asUintN(64, s2 + s4);
        s4 = BigInt.asUintN(64, s4 + data[4]);
        s6 ^= s2;
        s3 ^= s4;
        s4 = rot64(s4, BigInt(17));
        s3 = BigInt.asUintN(64, s3 + s5);
        s5 = BigInt.asUintN(64, s5 + data[5]);
        s7 ^= s3;
        s4 ^= s5;
        s5 = rot64(s5, BigInt(28));
        s4 = BigInt.asUintN(64, s4 + s6);
        s6 = BigInt.asUintN(64, s6 + data[6]);
        s8 ^= s4;
        s5 ^= s6;
        s6 = rot64(s6, BigInt(39));
        s5 = BigInt.asUintN(64, s5 + s7);
        s7 = BigInt.asUintN(64, s7 + data[7]);
        s9 ^= s5;
        s6 ^= s7;
        s7 = rot64(s7, BigInt(57));
        s6 = BigInt.asUintN(64, s6 + s8);
        s8 = BigInt.asUintN(64, s8 + data[8]);
        s10 ^= s6;
        s7 ^= s8;
        s8 = rot64(s8, BigInt(55));
        s7 = BigInt.asUintN(64, s7 + s9);
        s9 = BigInt.asUintN(64, s9 + data[9]);
        s11 ^= s7;
        s8 ^= s9;
        s9 = rot64(s9, BigInt(54));
        s8 = BigInt.asUintN(64, s8 + s10);
        s10 = BigInt.asUintN(64, s10 + data[10]);
        s0 ^= s8;
        s9 ^= s10;
        s10 = rot64(s10, BigInt(22));
        s9 = BigInt.asUintN(64, s9 + s11);
        s11 = BigInt.asUintN(64, s11 + data[11]);
        s1 ^= s9;
        s10 ^= s11;
        s11 = rot64(s11, BigInt(46));
        s10 = BigInt.asUintN(64, s10 + s0);
        return [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11];
    }
    short_end(h0, h1, h2, h3) {
        h3 = BigInt.asUintN(64, h3 ^ h2);
        h2 = rot64(h2, BigInt(15));
        h3 = BigInt.asUintN(64, h3 + h2);
        h0 = BigInt.asUintN(64, h0 ^ h3);
        h3 = rot64(h3, BigInt(52));
        h0 = BigInt.asUintN(64, h0 + h3);
        h1 = BigInt.asUintN(64, h1 ^ h0);
        h0 = rot64(h0, BigInt(26));
        h1 = BigInt.asUintN(64, h1 + h0);
        h2 = BigInt.asUintN(64, h2 ^ h1);
        h1 = rot64(h1, BigInt(51));
        h2 = BigInt.asUintN(64, h2 + h1);
        h3 = BigInt.asUintN(64, h3 ^ h2);
        h2 = rot64(h2, BigInt(28));
        h3 = BigInt.asUintN(64, h3 + h2);
        h0 = BigInt.asUintN(64, h0 ^ h3);
        h3 = rot64(h3, BigInt(9));
        h0 = BigInt.asUintN(64, h0 + h3);
        h1 = BigInt.asUintN(64, h1 ^ h0);
        h0 = rot64(h0, BigInt(47));
        h1 = BigInt.asUintN(64, h1 + h0);
        h2 = BigInt.asUintN(64, h2 ^ h1);
        h1 = rot64(h1, BigInt(54));
        h2 = BigInt.asUintN(64, h2 + h1);
        h3 = BigInt.asUintN(64, h3 ^ h2);
        h2 = rot64(h2, BigInt(32));
        h3 = BigInt.asUintN(64, h3 + h2);
        h0 = BigInt.asUintN(64, h0 ^ h3);
        h3 = rot64(h3, BigInt(25));
        h0 = BigInt.asUintN(64, h0 + h3);
        h1 = BigInt.asUintN(64, h1 ^ h0);
        h0 = rot64(h0, BigInt(63));
        h1 = BigInt.asUintN(64, h1 + h0);
        return [h0, h1, h2, h3];
    }
    short(message, hash1 = this.hash1, hash2 = this.hash2) {
        var length = message.byteLength;
        var remainder = length % 32;
        var a = hash1;
        var b = hash2;
        var c = this.sc_const;
        var d = this.sc_const;
        var i = 0;
        if (length > 15) {
            var end = ((length / 32) * 4) >>> 0;
            for (; i < end;) {
                c = BigInt.asUintN(64, c + load64(message, 0 * 8));
                d = BigInt.asUintN(64, d + load64(message, 1 * 8));
                [a, b, c, d] = this.short_mix(a, b, c, d);
                a = BigInt.asUintN(64, a + load64(message, 2 * 8));
                b = BigInt.asUintN(64, b + load64(message, 3 * 8));
                message = message.subarray(4 * 8, message.length);
                i += 4 * 8;
            }
            if (remainder >= 16) {
                c = BigInt.asUintN(64, c + load64(message, 0 * 8));
                d = BigInt.asUintN(64, d + load64(message, 1 * 8));
                [a, b, c, d] = this.short_mix(a, b, c, d);
                message = message.subarray(16, message.length);
                remainder -= 16;
            }
        }
        d = BigInt.asUintN(64, d + (BigInt(length) << BigInt(56)));
        switch (remainder) {
            // @ts-ignore
            case 15:
                d = BigInt.asUintN(64, d + ((load64(message, 14 * 8)) << BigInt(48)));
            // @ts-ignore
            case 14:
                d = BigInt.asUintN(64, d + ((load64(message, 13 * 8)) << BigInt(40)));
            // @ts-ignore
            case 13:
                d = BigInt.asUintN(64, d + ((load64(message, 12 * 8)) << BigInt(32)));
            case 12:
                d = BigInt.asUintN(64, d + (BigInt(load32(message, 2 * 4))));
                c = BigInt.asUintN(64, c + (load64(message, 0 * 8)));
                break;
            // @ts-ignore
            case 11:
                d = BigInt.asUintN(64, d + (BigInt(message[10] << 16)));
            // @ts-ignore
            case 10:
                d = BigInt.asUintN(64, d + (BigInt(message[9] << 8)));
            // @ts-ignore
            case 9:
                d = BigInt.asUintN(64, d + (BigInt(message[8])));
            case 8:
                c = BigInt.asUintN(64, c + (load64(message, 0)));
                break;
            // @ts-ignore
            case 7:
                c = BigInt.asUintN(64, c + ((BigInt(message[6])) << BigInt(48)));
            // @ts-ignore
            case 6:
                107;
                c = BigInt.asUintN(64, c + ((BigInt(message[5])) << BigInt(40)));
            // @ts-ignore
            case 5:
                c = BigInt.asUintN(64, c + ((BigInt(message[4])) << BigInt(32)));
            case 4:
                c = BigInt.asUintN(64, c + (BigInt(load32(message, 0))));
                break;
            // @ts-ignore
            case 3:
                c = BigInt.asUintN(64, c + ((BigInt(message[2])) << BigInt(16)));
            // @ts-ignore
            case 2:
                c = BigInt.asUintN(64, c + ((BigInt(message[1])) << BigInt(8)));
            case 1:
                c = BigInt.asUintN(64, c + BigInt(message[0]));
                break;
            case 0:
                c = BigInt.asUintN(64, c + this.sc_const);
                d = BigInt.asUintN(64, d + this.sc_const);
        }
        [a, b, c, d] = this.short_end(a, b, c, d);
        this.hash1 = a;
        this.hash2 = b;
        return [this.hash1, this.hash2];
    }
    end_partial(h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11) {
        h11 = BigInt.asUintN(64, h11 + h1);
        h2 ^= h11;
        h1 = rot64(h1, BigInt(44));
        h0 = BigInt.asUintN(64, h0 + h2);
        h3 ^= h0;
        h2 = rot64(h2, BigInt(15));
        h1 = BigInt.asUintN(64, h1 + h3);
        h4 ^= h1;
        h3 = rot64(h3, BigInt(34));
        h2 = BigInt.asUintN(64, h2 + h4);
        h5 ^= h2;
        h4 = rot64(h4, BigInt(21));
        h3 = BigInt.asUintN(64, h3 + h5);
        h6 ^= h3;
        h5 = rot64(h5, BigInt(38));
        h4 = BigInt.asUintN(64, h4 + h6);
        h7 ^= h4;
        h6 = rot64(h6, BigInt(33));
        h5 = BigInt.asUintN(64, h5 + h7);
        h8 ^= h5;
        h7 = rot64(h7, BigInt(10));
        h6 = BigInt.asUintN(64, h6 + h8);
        h9 ^= h6;
        h8 = rot64(h8, BigInt(13));
        h7 = BigInt.asUintN(64, h7 + h9);
        h10 ^= h7;
        h9 = rot64(h9, BigInt(38));
        h8 = BigInt.asUintN(64, h8 + h10);
        h11 ^= h8;
        h10 = rot64(h10, BigInt(53));
        h9 = BigInt.asUintN(64, h9 + h11);
        h0 ^= h9;
        h11 = rot64(h11, BigInt(42));
        h10 = BigInt.asUintN(64, h10 + h0);
        h1 ^= h10;
        h0 = rot64(h0, BigInt(54));
        return [h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11];
    }
    end(data, h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11) {
        h0 += data[0];
        h1 += data[1];
        h2 += data[2];
        h3 += data[3];
        h4 += data[4];
        h5 += data[5];
        h6 += data[6];
        h7 += data[7];
        h8 += data[8];
        h9 += data[9];
        h10 += data[10];
        h11 += data[11];
        [h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11] = this.end_partial(h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11);
        [h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11] = this.end_partial(h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11);
        [h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11] = this.end_partial(h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11);
        return [h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11];
    }
    hash128(message, hash1 = this.hash1, hash2 = this.hash2) {
        var length = message.byteLength;
        if (length < this.sc_bufSize) {
            return this.short(message, hash1, hash2);
        }
        var h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11;
        const buf = new BigUint64Array(this.sc_numVars);
        var end;
        var remainder;
        h0 = h3 = h6 = h9 = hash1;
        h1 = h4 = h7 = h10 = hash2;
        h2 = h5 = h8 = h11 = this.sc_const;
        end = length - ((length / this.sc_blockSize) * this.sc_numVars) >>> 0;
        let i = 0;
        while (i < end) {
            memcpy64(buf, message, this.sc_numVars);
            [h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11] = this.mix(buf, h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11);
            message = message.subarray(this.sc_numVars * 8, message.length);
            i += this.sc_numVars * 8;
        }
        remainder = length - i;
        memcpy64(buf, message, this.sc_numVars);
        buf[11] = addValueToLast8Bits(buf[11], remainder);
        [h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11] = this.end(buf, h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11);
        this.hash1 = h0;
        this.hash2 = h1;
        return [this.hash1, this.hash2];
    }
    encodeBELong(val, buf, off) {
        let endian = "big";
        let unsigned = true;
        const bigIntArray = new BigInt64Array(1);
        bigIntArray[0] = BigInt(val);
        // Use two 32-bit views to write the Int64
        const int32Array = new Int32Array(bigIntArray.buffer);
        for (let i = 0; i < 2; i++) {
            if (endian == "little") {
                // @ts-ignore
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
                // @ts-ignore
                if (unsigned == false) {
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
    digest(format) {
        var result;
        if (format == "buffer") {
            result = Buffer.alloc(16);
        }
        else {
            result = new Uint8Array(16);
        }
        this.encodeBELong(this.hash1, result, 0);
        this.encodeBELong(this.hash2, result, 8);
        if (format == "buffer") {
            return bytesToHex(result);
        }
        return result;
    }
}
/**
 * Creates a One At A Time 32 bit number from message.
 *
 * @param {Uint8Array} key - Message to hash
 * @param {number} [startingValue=0] - For updating / seeding
 * @returns `number`
 */
function JENKINS_OAAT(key, startingValue = 0) {
    const length = key.byteLength;
    var i = 0;
    const hash = new Uint32Array(1);
    hash[0] = startingValue;
    while (i != length) {
        hash[0] += key[i++];
        hash[0] += hash[0] << 10;
        hash[0] ^= hash[0] >> 6;
    }
    hash[0] += hash[0] << 3;
    hash[0] ^= hash[0] >> 11;
    hash[0] += hash[0] << 15;
    return hash[0];
}
exports.JENKINS_OAAT = JENKINS_OAAT;
;
/**
 * Creates a Jenkin's Lookup2 (MyHash) 32 bit number from message.
 *
 * @param {InputData} message - Message to hash
 * @param {number?} startingValue - For updating / seeding
 * @returns `number`
 */
function JENKINS_LOOKUP2(message, startingValue) {
    const hash = new Lookup2();
    if (startingValue) {
        hash.setSeed(startingValue);
    }
    hash.update(formatMessage(message));
    hash.digest(); //returns Uint8Array
    return hash.state;
}
exports.JENKINS_LOOKUP2 = JENKINS_LOOKUP2;
;
/**
 * Creates a Jenkin's Lookup3 (MyHash) hash from message.
 *
 * @param {InputData} message - Message to hash
 * @param {number?} [outLen=32] - output bit length, 64 will return a bigint (default 32 bit number)
 * @param {number} primaryInitval - primary seed value
 * @param {number} secondaryInitval - secondary seed value (only used on 64 bit)
 * @returns `number|bigint`
 */
function JENKINS_LOOKUP3(message, outLen = 32, primaryInitval, secondaryInitval) {
    const hash = new Lookup3(outLen, primaryInitval, secondaryInitval);
    hash.update(message);
    return hash.digest();
}
/**
 * Creates a Jenkin's Lookup3 (MyHash) 32 bit number from message.
 *
 * @param {InputData} message - Message to hash
 * @param {number} primaryInitval - primary seed value
 * @returns `number`
 */
function JENKINS_LOOKUP3_32(message, primaryInitval) {
    const hash = new Lookup3(32, primaryInitval);
    hash.update(message);
    return hash.digest();
}
/**
 * Creates a Jenkin's Lookup3 (MyHash) 64 bit bigint from message.
 *
 * @param {InputData} message - Message to hash
 * @param {number} primaryInitval - primary seed value
 * @param {number} secondaryInitval - secondary seed value
 * @returns `bigint`
 */
function JENKINS_LOOKUP3_64(message, primaryInitval, secondaryInitval) {
    const hash = new Lookup3(64, primaryInitval, secondaryInitval);
    hash.update(message);
    return hash.digest();
}
/**
 * Creates a Jenkin's Spooky up to 16 byte hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {32|64|128} bitLength - return hash bitlength (default 128 or 16 bytes)
 * @param {bigint} seed1 - First seed value
 * @param {bigint} seed1 - Second seed value
 * @returns `string|Uint8Array|Buffer`
 */
function JENKINS_SPOOKY(message, format = arrayType(), bitLength = 128, seed1, seed2) {
    const hash = new SpookyHash(seed1, seed2);
    hash.update(formatMessage(message));
    var digestbytes = hash.digest("array");
    if (bitLength == 32) {
        digestbytes = digestbytes.subarray(0, 4);
    }
    else if (bitLength == 64) {
        digestbytes = digestbytes.subarray(0, 8);
    }
    if (format === "hex") {
        return bytesToHex(digestbytes);
    }
    else if (format === "buffer") {
        return Buffer.from(digestbytes);
    }
    else {
        return digestbytes;
    }
}
exports.JENKINS_SPOOKY = JENKINS_SPOOKY;
;
/**
 * Creates a Jenkin's Spooky 16 byte hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {bigint} seed1 - First seed value
 * @param {bigint} seed1 - Second seed value
 * @returns `string|Uint8Array|Buffer`
 */
function JENKINS_SPOOKY_128(message, format = arrayType(), seed1, seed2) {
    return JENKINS_SPOOKY(message, format, 128, seed1, seed2);
}
exports.JENKINS_SPOOKY_128 = JENKINS_SPOOKY_128;
;
/**
 * Creates a Jenkin's Spooky 8 byte hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {bigint} seed1 - First seed value
 * @param {bigint} seed1 - Second seed value
 * @returns `string|Uint8Array|Buffer`
 */
function JENKINS_SPOOKY_64(message, format = arrayType(), seed1, seed2) {
    return JENKINS_SPOOKY(message, format, 64, seed1, seed2);
}
exports.JENKINS_SPOOKY_64 = JENKINS_SPOOKY_64;
;
/**
 * Creates a Jenkin's Spooky 4 byte hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {bigint} seed1 - First seed value
 * @param {bigint} seed1 - Second seed value
 * @returns `string|Uint8Array|Buffer`
 */
function JENKINS_SPOOKY_32(message, format = arrayType(), bitLength, seed1, seed2) {
    return JENKINS_SPOOKY(message, format, 32, seed1, seed2);
}
exports.JENKINS_SPOOKY_32 = JENKINS_SPOOKY_32;
;
/**
 * Creates a Jenkin's One At A Time 32 bit number from message.
 *
 * @param {InputData} message - Message to hash
 * @returns `number`
 */
function JENKINS_ONEATATIME(message) {
    return JENKINS_OAAT(formatMessage(message));
}
;
/**
 * Static class of all Jenkins functions
 */
class JENKINS {
    /**
     * List of all hashes in class
     */
    static get FUNCTION_LIST() {
        return [
            "ONEATATIME",
            "LOOKUP2",
            "LOOKUP3",
            "LOOKUP3_32",
            "LOOKUP3_64",
            "SPOOKY",
            "SPOOKY_32",
            "SPOOKY_64",
            "SPOOKY_128"
        ];
    }
}
exports.JENKINS = JENKINS;
JENKINS.ONEATATIME = JENKINS_ONEATATIME;
JENKINS.Lookup2 = Lookup2;
JENKINS.LOOKUP2 = JENKINS_LOOKUP2;
JENKINS.Lookup3 = Lookup3;
JENKINS.LOOKUP3 = JENKINS_LOOKUP3;
JENKINS.LOOKUP3_32 = JENKINS_LOOKUP3_32;
JENKINS.LOOKUP3_64 = JENKINS_LOOKUP3_64;
JENKINS.Spooky = SpookyHash;
JENKINS.SPOOKY = JENKINS_SPOOKY;
JENKINS.SPOOKY_32 = JENKINS_SPOOKY_32;
JENKINS.SPOOKY_64 = JENKINS_SPOOKY_64;
JENKINS.SPOOKY_128 = JENKINS_SPOOKY_128;
//# sourceMappingURL=JENKINS.js.map