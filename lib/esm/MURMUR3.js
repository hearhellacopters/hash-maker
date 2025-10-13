"use strict";
/*!
 * +----------------------------------------------------------------------------------+
 * | murmurHash3.js v3.0.0 (http://github.com/karanlyons/murmurHash3.js)              |
 * | A TypeScript/JavaScript implementation of MurmurHash3's hashing algorithms.      |
 * |----------------------------------------------------------------------------------|
 * | Copyright (c) 2012-2020 Karan Lyons. Freely distributable under the MIT license. |
 * +----------------------------------------------------------------------------------+
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.MURMUR3_X86_128 = exports.MURMUR3_X86_32 = exports.MURMUR3_X64_128 = void 0;
function arrayType() {
    if (typeof window !== 'undefined') {
        return "array";
    }
    else {
        return "buffer";
    }
}
;
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
function strToBuf(message) {
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
const hexLUT = Array.from({ length: 256 }, (_, i) => `00${i.toString(16)}`.slice(-2));
function bufToHex(bytes = new Uint8Array(0)) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
function mul32(m, n) {
    return ((m & 0xffff) * n) + ((((m >>> 16) * n) & 0xffff) << 16);
}
function rol32(n, r) {
    return (n << r) | (n >>> (32 - r));
}
function add64(m, n) {
    const ms = [m[0] >>> 16, m[0] & 0xffff, m[1] >>> 16, m[1] & 0xffff];
    const ns = [n[0] >>> 16, n[0] & 0xffff, n[1] >>> 16, n[1] & 0xffff];
    const os = [0x0, 0x0, 0x0, 0x0];
    os[3] += ms[3] + ns[3];
    os[2] += os[3] >>> 16;
    os[3] &= 0xffff;
    os[2] += ms[2] + ns[2];
    os[1] += os[2] >>> 16;
    os[2] &= 0xffff;
    os[1] += ms[1] + ns[1];
    os[0] += os[1] >>> 16;
    os[1] &= 0xffff;
    os[0] += ms[0] + ns[0];
    os[0] &= 0xffff;
    return [(os[0] << 16) | os[1], (os[2] << 16) | os[3]];
}
function mul64(m, n) {
    const ms = [m[0] >>> 16, m[0] & 0xffff, m[1] >>> 16, m[1] & 0xffff];
    const ns = [n[0] >>> 16, n[0] & 0xffff, n[1] >>> 16, n[1] & 0xffff];
    const os = [0x0, 0x0, 0x0, 0x0];
    os[3] += ms[3] * ns[3];
    os[2] += os[3] >>> 16;
    os[3] &= 0xffff;
    os[2] += ms[2] * ns[3];
    os[1] += os[2] >>> 16;
    os[2] &= 0xffff;
    os[2] += ms[3] * ns[2];
    os[1] += os[2] >>> 16;
    os[2] &= 0xffff;
    os[1] += ms[1] * ns[3];
    os[0] += os[1] >>> 16;
    os[1] &= 0xffff;
    os[1] += ms[2] * ns[2];
    os[0] += os[1] >>> 16;
    os[1] &= 0xffff;
    os[1] += ms[3] * ns[1];
    os[0] += os[1] >>> 16;
    os[1] &= 0xffff;
    os[0] += (ms[0] * ns[3]) + (ms[1] * ns[2]) + (ms[2] * ns[1]) + (ms[3] * ns[0]);
    os[0] &= 0xffff;
    return [(os[0] << 16) | os[1], (os[2] << 16) | os[3]];
}
function rol64(n, r) {
    r %= 64;
    // istanbul ignore if: here for completeness but never used.
    if (r === 32) {
        return [n[1], n[0]];
    }
    else if (r < 32) {
        return [
            (n[0] << r) | (n[1] >>> (32 - r)),
            (n[1] << r) | (n[0] >>> (32 - r)),
        ];
    }
    else {
        r -= 32;
        return [
            (n[1] << r) | (n[0] >>> (32 - r)),
            (n[0] << r) | (n[1] >>> (32 - r)),
        ];
    }
}
function shl64(n, s) {
    s %= 64;
    // istanbul ignore if: here for completeness but never used.
    if (s === 0) {
        return n;
    }
    else if (s < 32) {
        return [(n[0] << s) | (n[1] >>> (32 - s)), n[1] << s];
    }
    else {
        return [n[1] << (s - 32), 0x0];
    }
}
function xor64(a, b) {
    return [a[0] ^ b[0], a[1] ^ b[1]];
}
function x86fmix32(h) {
    h ^= h >>> 16;
    h = mul32(h, 0x85ebca6b);
    h ^= h >>> 13;
    h = mul32(h, 0xc2b2ae35);
    h ^= h >>> 16;
    return h;
}
const x86hash32c1 = 0xcc9e2d51;
const x86hash32c2 = 0x1b873593;
function x86mix32(h, k) {
    k = mul32(k, x86hash32c1);
    k = rol32(k, 15);
    k = mul32(k, x86hash32c2);
    h ^= k;
    h = rol32(h, 13);
    h = mul32(h, 5) + 0xe6546b64;
    return h;
}
function x86hash32(buf = new Uint8Array(0), state = 0x0, finalize = true) {
    // istanbul ignore else
    if (typeof buf === 'string') {
        buf = strToBuf(buf);
    }
    let h1;
    let i;
    let len;
    if (typeof state === 'number') {
        h1 = state;
        i = 0;
        len = 0;
    }
    else {
        ({ h1, len } = state);
        const rem = state.rem;
        if (rem.byteLength === 0) {
            i = 0;
        }
        else if (rem.byteLength + buf.byteLength >= 4) {
            len += 4;
            i = 4 - rem.byteLength;
            const blk = new Uint8Array(4);
            const dtv = new DataView(blk.buffer);
            blk.set(rem);
            blk.set(buf.subarray(0, i), rem.byteLength);
            h1 = x86mix32(h1, dtv.getUint32(0, true));
        }
        else {
            const newBuf = new Uint8Array(buf.byteLength + rem.byteLength);
            newBuf.set(rem);
            newBuf.set(buf, rem.byteLength);
            buf = newBuf;
            i = 0;
        }
    }
    const dtv = new DataView(buf.buffer, buf.byteOffset);
    const remainder = (buf.byteLength - i) % 4;
    const bytes = buf.byteLength - i - remainder;
    len += bytes;
    for (; i < bytes; i += 4) {
        h1 = x86mix32(h1, dtv.getUint32(i, true));
    }
    if (!finalize) {
        return {
            h1,
            len,
            rem: buf.slice(buf.byteLength - remainder),
        };
    }
    else {
        len += remainder;
        let k1 = 0x0;
        switch (remainder) {
            // @ts-ignore
            case 3: k1 ^= buf[i + 2] << 16;
            // @ts-ignore
            case 2: k1 ^= buf[i + 1] << 8;
            case 1:
                k1 ^= buf[i];
                k1 = mul32(k1, x86hash32c1);
                k1 = rol32(k1, 15);
                k1 = mul32(k1, x86hash32c2);
                h1 ^= k1;
        }
        h1 ^= len & 0xffffffff;
        h1 = x86fmix32(h1);
        return h1 >>> 0;
    }
}
const x86hash128c1 = 0x239b961b;
const x86hash128c2 = 0xab0e9789;
const x86hash128c3 = 0x38b34ae5;
const x86hash128c4 = 0xa1e38b93;
function x86mix128(h1, h2, h3, h4, k1, k2, k3, k4) {
    k1 = mul32(k1, x86hash128c1);
    k1 = rol32(k1, 15);
    k1 = mul32(k1, x86hash128c2);
    h1 ^= k1;
    h1 = rol32(h1, 19);
    h1 += h2;
    h1 = mul32(h1, 5) + 0x561ccd1b;
    k2 = mul32(k2, x86hash128c2);
    k2 = rol32(k2, 16);
    k2 = mul32(k2, x86hash128c3);
    h2 ^= k2;
    h2 = rol32(h2, 17);
    h2 += h3;
    h2 = mul32(h2, 5) + 0x0bcaa747;
    k3 = mul32(k3, x86hash128c3);
    k3 = rol32(k3, 17);
    k3 = mul32(k3, x86hash128c4);
    h3 ^= k3;
    h3 = rol32(h3, 15);
    h3 += h4;
    h3 = mul32(h3, 5) + 0x96cd1c35;
    k4 = mul32(k4, x86hash128c4);
    k4 = rol32(k4, 18);
    k4 = mul32(k4, x86hash128c1);
    h4 ^= k4;
    h4 = rol32(h4, 13);
    h4 += h1;
    h4 = mul32(h4, 5) + 0x32ac3b17;
    return [h1, h2, h3, h4];
}
function x86hash128(buf = new Uint8Array(0), state = 0x0, finalize = true) {
    let str;
    if (typeof buf === 'string') {
        buf = strToBuf(buf);
        str = true;
    }
    else {
        str = false;
    }
    let h1;
    let h2;
    let h3;
    let h4;
    let i;
    let len;
    if (typeof state === 'number') {
        h1 = h2 = h3 = h4 = state;
        i = 0;
        len = 0;
    }
    else {
        ({ h1, h2, h3, h4, len } = state);
        const rem = state.rem;
        if (rem.byteLength === 0) {
            i = 0;
        }
        else if (rem.byteLength + buf.byteLength >= 16) {
            len += 16;
            i = 16 - rem.byteLength;
            const blk = new Uint8Array(16);
            const dtv = new DataView(blk.buffer);
            blk.set(rem);
            blk.set(buf.subarray(0, i), rem.byteLength);
            [h1, h2, h3, h4] = x86mix128(h1, h2, h3, h4, dtv.getUint32(0, true), dtv.getUint32(4, true), dtv.getUint32(8, true), dtv.getUint32(12, true));
        }
        else {
            const newBuf = new Uint8Array(buf.byteLength + rem.byteLength);
            newBuf.set(rem);
            newBuf.set(buf, rem.byteLength);
            buf = newBuf;
            i = 0;
        }
    }
    const dtv = new DataView(buf.buffer, buf.byteOffset);
    const remainder = (buf.byteLength - i) % 16;
    const bytes = buf.byteLength - i - remainder;
    len += bytes;
    for (; i < bytes; i += 16) {
        [h1, h2, h3, h4] = x86mix128(h1, h2, h3, h4, dtv.getUint32(i, true), dtv.getUint32(i + 4, true), dtv.getUint32(i + 8, true), dtv.getUint32(i + 12, true));
    }
    if (!finalize) {
        return {
            h1, h2, h3, h4,
            len,
            rem: buf.subarray(buf.byteLength - remainder),
        };
    }
    else {
        len += remainder;
        let k1 = 0x0;
        let k2 = 0x0;
        let k3 = 0x0;
        let k4 = 0x0;
        switch (remainder) {
            // @ts-ignore
            case 15: k4 ^= buf[i + 14] << 16;
            // @ts-ignore
            case 14: k4 ^= buf[i + 13] << 8;
            // @ts-ignore
            case 13:
                k4 ^= buf[i + 12];
                k4 = mul32(k4, x86hash128c4);
                k4 = rol32(k4, 18);
                k4 = mul32(k4, x86hash128c1);
                h4 ^= k4;
            // @ts-ignore
            case 12: k3 ^= buf[i + 11] << 24;
            // @ts-ignore
            case 11: k3 ^= buf[i + 10] << 16;
            // @ts-ignore
            case 10: k3 ^= buf[i + 9] << 8;
            // @ts-ignore
            case 9:
                k3 ^= buf[i + 8];
                k3 = mul32(k3, x86hash128c3);
                k3 = rol32(k3, 17);
                k3 = mul32(k3, x86hash128c4);
                h3 ^= k3;
            // @ts-ignore
            case 8: k2 ^= buf[i + 7] << 24;
            // @ts-ignore
            case 7: k2 ^= buf[i + 6] << 16;
            // @ts-ignore
            case 6: k2 ^= buf[i + 5] << 8;
            // @ts-ignore
            case 5:
                k2 ^= buf[i + 4];
                k2 = mul32(k2, x86hash128c2);
                k2 = rol32(k2, 16);
                k2 = mul32(k2, x86hash128c3);
                h2 ^= k2;
            // @ts-ignore
            case 4: k1 ^= buf[i + 3] << 24;
            // @ts-ignore
            case 3: k1 ^= buf[i + 2] << 16;
            // @ts-ignore
            case 2: k1 ^= buf[i + 1] << 8;
            case 1:
                k1 ^= buf[i];
                k1 = mul32(k1, x86hash128c1);
                k1 = rol32(k1, 15);
                k1 = mul32(k1, x86hash128c2);
                h1 ^= k1;
        }
        h1 ^= len & 0xffffffff;
        h2 ^= len & 0xffffffff;
        h3 ^= len & 0xffffffff;
        h4 ^= len & 0xffffffff;
        h1 += h2 + h3 + h4;
        h2 += h1;
        h3 += h1;
        h4 += h1;
        h1 = x86fmix32(h1);
        h2 = x86fmix32(h2);
        h3 = x86fmix32(h3);
        h4 = x86fmix32(h4);
        h1 += h2 + h3 + h4;
        h2 += h1;
        h3 += h1;
        h4 += h1;
        const hash = new DataView(new ArrayBuffer(16));
        hash.setUint32(0, h1, false);
        hash.setUint32(4, h2, false);
        hash.setUint32(8, h3, false);
        hash.setUint32(12, h4, false);
        return new Uint8Array(hash.buffer);
    }
}
function x64fmix64(h) {
    // [0x0, h[0] >>> 1] is a 33 bit shr.
    h = xor64(h, [0x0, h[0] >>> 1]);
    h = mul64(h, [0xff51afd7, 0xed558ccd]);
    h = xor64(h, [0x0, h[0] >>> 1]);
    h = mul64(h, [0xc4ceb9fe, 0x1a85ec53]);
    h = xor64(h, [0x0, h[0] >>> 1]);
    return h;
}
const x64hash128c1 = [0x87c37b91, 0x114253d5];
const x64hash128c2 = [0x4cf5ad43, 0x2745937f];
function x64mix128(h1, h2, k1, k2) {
    k1 = mul64(k1, x64hash128c1);
    k1 = rol64(k1, 31);
    k1 = mul64(k1, x64hash128c2);
    h1 = xor64(h1, k1);
    h1 = rol64(h1, 27);
    h1 = add64(h1, h2);
    h1 = add64(mul64(h1, [0x0, 5]), [0x0, 0x52dce729]);
    k2 = mul64(k2, x64hash128c2);
    k2 = rol64(k2, 33);
    k2 = mul64(k2, x64hash128c1);
    h2 = xor64(h2, k2);
    h2 = rol64(h2, 31);
    h2 = add64(h2, h1);
    h2 = add64(mul64(h2, [0x0, 5]), [0x0, 0x38495ab5]);
    return [h1, h2];
}
function x64hash128(buf = new Uint8Array(0), state = 0x0, finalize = true) {
    let str;
    if (typeof buf === 'string') {
        buf = strToBuf(buf);
        str = true;
    }
    else {
        str = false;
    }
    let h1;
    let h2;
    let i;
    let len;
    if (typeof state === 'number') {
        h1 = [0x0, state];
        h2 = [0x0, state];
        i = 0;
        len = 0;
    }
    else {
        ({ h1, h2, len } = state);
        const rem = state.rem;
        if (rem.byteLength === 0) {
            i = 0;
        }
        else if (rem.byteLength + buf.byteLength >= 16) {
            len += 16;
            i = 16 - rem.byteLength;
            const blk = new Uint8Array(16);
            const dtv = new DataView(blk.buffer);
            blk.set(rem);
            blk.set(buf.subarray(0, i), rem.byteLength);
            [h1, h2] = x64mix128(h1, h2, [dtv.getUint32(4, true), dtv.getUint32(0, true)], [dtv.getUint32(12, true), dtv.getUint32(8, true)]);
        }
        else {
            const newBuf = new Uint8Array(buf.byteLength + rem.byteLength);
            newBuf.set(rem);
            newBuf.set(buf, rem.byteLength);
            buf = newBuf;
            i = 0;
        }
    }
    const dtv = new DataView(buf.buffer, buf.byteOffset);
    const remainder = (buf.byteLength - i) % 16;
    const bytes = buf.byteLength - i - remainder;
    len += bytes;
    for (; i < bytes; i += 16) {
        [h1, h2] = x64mix128(h1, h2, [dtv.getUint32(i + 4, true), dtv.getUint32(i, true)], [dtv.getUint32(i + 12, true), dtv.getUint32(i + 8, true)]);
    }
    if (!finalize) {
        return {
            h1, h2,
            len,
            rem: buf.subarray(buf.byteLength - remainder),
        };
    }
    else {
        len += remainder;
        let k1 = [0x0, 0x0];
        let k2 = [0x0, 0x0];
        switch (remainder) {
            // @ts-ignore
            case 15: k2 = xor64(k2, shl64([0x0, buf[i + 14]], 48));
            // @ts-ignore
            case 14: k2 = xor64(k2, shl64([0x0, buf[i + 13]], 40));
            // @ts-ignore
            case 13: k2 = xor64(k2, shl64([0x0, buf[i + 12]], 32));
            // @ts-ignore
            case 12: k2 = xor64(k2, shl64([0x0, buf[i + 11]], 24));
            // @ts-ignore
            case 11: k2 = xor64(k2, shl64([0x0, buf[i + 10]], 16));
            // @ts-ignore
            case 10: k2 = xor64(k2, shl64([0x0, buf[i + 9]], 8));
            // @ts-ignore
            case 9:
                k2 = xor64(k2, [0x0, buf[i + 8]]);
                k2 = mul64(k2, x64hash128c2);
                k2 = rol64(k2, 33);
                k2 = mul64(k2, x64hash128c1);
                h2 = xor64(h2, k2);
            // @ts-ignore
            case 8: k1 = xor64(k1, shl64([0x0, buf[i + 7]], 56));
            // @ts-ignore
            case 7: k1 = xor64(k1, shl64([0x0, buf[i + 6]], 48));
            // @ts-ignore
            case 6: k1 = xor64(k1, shl64([0x0, buf[i + 5]], 40));
            // @ts-ignore
            case 5: k1 = xor64(k1, shl64([0x0, buf[i + 4]], 32));
            // @ts-ignore
            case 4: k1 = xor64(k1, shl64([0x0, buf[i + 3]], 24));
            // @ts-ignore
            case 3: k1 = xor64(k1, shl64([0x0, buf[i + 2]], 16));
            // @ts-ignore
            case 2: k1 = xor64(k1, shl64([0x0, buf[i + 1]], 8));
            case 1:
                k1 = xor64(k1, [0x0, buf[i]]);
                k1 = mul64(k1, x64hash128c1);
                k1 = rol64(k1, 31);
                k1 = mul64(k1, x64hash128c2);
                h1 = xor64(h1, k1);
        }
        h1 = xor64(h1, [0x0, len & 0xffffffff]);
        h2 = xor64(h2, [0x0, len & 0xffffffff]);
        h1 = add64(h1, h2);
        h2 = add64(h2, h1);
        h1 = x64fmix64(h1);
        h2 = x64fmix64(h2);
        h1 = add64(h1, h2);
        h2 = add64(h2, h1);
        const hash = new DataView(new ArrayBuffer(16));
        hash.setUint32(0, h1[0], false);
        hash.setUint32(4, h1[1], false);
        hash.setUint32(8, h2[0], false);
        hash.setUint32(12, h2[1], false);
        return new Uint8Array(hash.buffer);
    }
}
/**
 * Murmur3 x64 128 bit message hash.
 *
 * @param {InputData} message - Message to hash
 * @param {number?} seed - starting value
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function MURMUR3_X64_128(message, seed = 0, format = arrayType()) {
    const digestbytes = x64hash128(formatMessage(message), seed, true);
    if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    else if (format == "hex") {
        return bufToHex(digestbytes);
    }
    return digestbytes;
}
exports.MURMUR3_X64_128 = MURMUR3_X64_128;
/**
 * Murmur3 x64 32 bit message hash as a int32 number.
 *
 * @param {InputData} message - Message to hash
 * @param {number?} seed - starting value
 * @returns `number`
 */
function MURMUR3_X86_32(message, seed = 0) {
    return x86hash32(formatMessage(message), seed, true);
}
exports.MURMUR3_X86_32 = MURMUR3_X86_32;
/**
 * Murmur3 x86 128 bit message hash.
 *
 * @param {InputData} message - Message to hash
 * @param {number?} seed - starting value
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function MURMUR3_X86_128(message, seed = 0, format = arrayType()) {
    const digestbytes = x86hash128(formatMessage(message), seed, true);
    if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    else if (format == "hex") {
        return bufToHex(digestbytes);
    }
    return digestbytes;
}
exports.MURMUR3_X86_128 = MURMUR3_X86_128;
//# sourceMappingURL=MURMUR3.js.map