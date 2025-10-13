"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BLAKE2b_HMAC = exports.BLAKE2b224_HMAC = exports.BLAKE2b224 = exports.BLAKE2b256_HMAC = exports.BLAKE2b256 = exports.BLAKE2b384_HMAC = exports.BLAKE2b384 = exports.BLAKE2b512_HMAC = exports.BLAKE2b512 = exports.BLAKE2b = exports.Blake2b = void 0;
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
        throw new Uint8Array(0);
    }
    if (typeof message === 'string') {
        return strToUint8Array(message);
    }
    if (message instanceof Uint8Array || Buffer.isBuffer(message)) {
        return message;
    }
    throw new Error('input is invalid type');
}
function ADD64AA(v, a, b) {
    const o0 = v[a] + v[b];
    let o1 = v[a + 1] + v[b + 1];
    if (o0 >= 0x100000000) {
        o1++;
    }
    v[a] = o0;
    v[a + 1] = o1;
}
function ADD64AC(v, a, b0, b1) {
    let o0 = v[a] + b0;
    if (b0 < 0) {
        o0 += 0x100000000;
    }
    let o1 = v[a + 1] + b1;
    if (o0 >= 0x100000000) {
        o1++;
    }
    v[a] = o0;
    v[a + 1] = o1;
}
function B2B_GET32(arr, i) {
    return arr[i] ^ (arr[i + 1] << 8) ^ (arr[i + 2] << 16) ^ (arr[i + 3] << 24);
}
function B2B_G(a, b, c, d, ix, iy) {
    const x0 = m[ix];
    const x1 = m[ix + 1];
    const y0 = m[iy];
    const y1 = m[iy + 1];
    ADD64AA(v, a, b);
    ADD64AC(v, a, x0, x1);
    let xor0 = v[d] ^ v[a];
    let xor1 = v[d + 1] ^ v[a + 1];
    v[d] = xor1;
    v[d + 1] = xor0;
    ADD64AA(v, c, d);
    xor0 = v[b] ^ v[c];
    xor1 = v[b + 1] ^ v[c + 1];
    v[b] = (xor0 >>> 24) ^ (xor1 << 8);
    v[b + 1] = (xor1 >>> 24) ^ (xor0 << 8);
    ADD64AA(v, a, b);
    ADD64AC(v, a, y0, y1);
    xor0 = v[d] ^ v[a];
    xor1 = v[d + 1] ^ v[a + 1];
    v[d] = (xor0 >>> 16) ^ (xor1 << 16);
    v[d + 1] = (xor1 >>> 16) ^ (xor0 << 16);
    ADD64AA(v, c, d);
    xor0 = v[b] ^ v[c];
    xor1 = v[b + 1] ^ v[c + 1];
    v[b] = (xor1 >>> 31) ^ (xor0 << 1);
    v[b + 1] = (xor0 >>> 31) ^ (xor1 << 1);
}
var BLAKE2B_IV32;
var SIGMA82;
var v;
var m;
var parameterBlock;
var inited = false;
/**
 * Static class of all Blake2b functions
 */
class Blake2b {
    constructor(outlen, key, salt, personal) {
        if (!inited) {
            parameterBlock = new Uint8Array(64);
            BLAKE2B_IV32 = new Uint32Array([
                0xf3bcc908, 0x6a09e667, 0x84caa73b, 0xbb67ae85, 0xfe94f82b, 0x3c6ef372,
                0x5f1d36f1, 0xa54ff53a, 0xade682d1, 0x510e527f, 0x2b3e6c1f, 0x9b05688c,
                0xfb41bd6b, 0x1f83d9ab, 0x137e2179, 0x5be0cd19
            ]);
            SIGMA82 = new Uint8Array([
                0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30,
                28, 20, 8, 16, 18, 30, 26, 12, 2, 24, 0, 4, 22, 14, 10, 6,
                22, 16, 24, 0, 10, 4, 30, 26, 20, 28, 6, 12, 14, 2, 18, 8,
                14, 18, 6, 2, 26, 24, 22, 28, 4, 12, 10, 20, 8, 0, 30, 16,
                18, 0, 10, 14, 4, 8, 20, 30, 28, 2, 22, 24, 12, 16, 6, 26,
                4, 24, 12, 20, 0, 22, 16, 6, 8, 26, 14, 10, 30, 28, 2, 18,
                24, 10, 2, 30, 28, 26, 8, 20, 0, 14, 12, 6, 18, 4, 16, 22,
                26, 22, 14, 28, 24, 2, 6, 18, 10, 0, 30, 8, 16, 12, 4, 20,
                12, 30, 28, 18, 22, 6, 0, 16, 24, 4, 26, 14, 2, 8, 20, 10,
                20, 4, 16, 8, 14, 12, 2, 10, 30, 22, 18, 28, 6, 24, 26, 0,
                0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30,
                28, 20, 8, 16, 18, 30, 26, 12, 2, 24, 0, 4, 22, 14, 10, 6
            ]);
            v = new Uint32Array(32);
            m = new Uint32Array(32);
            inited = true;
        }
        if (key) {
            key = formatMessage(key);
        }
        if (salt) {
            salt = formatMessage(salt);
        }
        if (personal) {
            personal = formatMessage(personal);
        }
        if (outlen === 0 || outlen > 64) {
            throw new Error('Illegal output length, expected 0 < length <= 64');
        }
        if (key && key.length > 64) {
            throw new Error('Illegal key, expected Uint8Array with 0 < length <= 64');
        }
        if (salt && salt.length !== 16) {
            throw new Error('Illegal salt, expected Uint8Array with length is 16');
        }
        if (personal && personal.length !== 16) {
            throw new Error('Illegal personal, expected Uint8Array with length is 16');
        }
        this.b = new Uint8Array(128);
        this.h = new Uint32Array(16);
        this.t = 0;
        this.c = 0;
        this.outlen = outlen;
        parameterBlock.fill(0);
        parameterBlock[0] = outlen;
        if (key)
            parameterBlock[1] = key.length;
        parameterBlock[2] = 1;
        parameterBlock[3] = 1;
        if (salt)
            parameterBlock.set(salt, 32);
        if (personal)
            parameterBlock.set(personal, 48);
        for (let i = 0; i < 16; i++) {
            this.h[i] = BLAKE2B_IV32[i] ^ B2B_GET32(parameterBlock, i * 4);
        }
        if (key) {
            this.blake2bUpdate(key);
            this.c = 128;
        }
    }
    blake2bUpdate(input) {
        for (let i = 0; i < input.length; i++) {
            if (this.c === 128) {
                this.t += this.c;
                this.blake2bCompress(false);
                this.c = 0;
            }
            this.b[this.c++] = input[i];
        }
    }
    blake2bCompress(last) {
        let i = 0;
        for (i = 0; i < 16; i++) {
            v[i] = this.h[i];
            v[i + 16] = BLAKE2B_IV32[i];
        }
        v[24] = v[24] ^ this.t;
        v[25] = v[25] ^ (this.t / 0x100000000);
        if (last) {
            v[28] = ~v[28];
            v[29] = ~v[29];
        }
        for (i = 0; i < 32; i++) {
            m[i] = B2B_GET32(this.b, 4 * i);
        }
        for (i = 0; i < 12; i++) {
            B2B_G(0, 8, 16, 24, SIGMA82[i * 16 + 0], SIGMA82[i * 16 + 1]);
            B2B_G(2, 10, 18, 26, SIGMA82[i * 16 + 2], SIGMA82[i * 16 + 3]);
            B2B_G(4, 12, 20, 28, SIGMA82[i * 16 + 4], SIGMA82[i * 16 + 5]);
            B2B_G(6, 14, 22, 30, SIGMA82[i * 16 + 6], SIGMA82[i * 16 + 7]);
            B2B_G(0, 10, 20, 30, SIGMA82[i * 16 + 8], SIGMA82[i * 16 + 9]);
            B2B_G(2, 12, 22, 24, SIGMA82[i * 16 + 10], SIGMA82[i * 16 + 11]);
            B2B_G(4, 14, 16, 26, SIGMA82[i * 16 + 12], SIGMA82[i * 16 + 13]);
            B2B_G(6, 8, 18, 28, SIGMA82[i * 16 + 14], SIGMA82[i * 16 + 15]);
        }
        for (i = 0; i < 16; i++) {
            this.h[i] = this.h[i] ^ v[i] ^ v[i + 16];
        }
    }
    blake2bFinal() {
        this.t += this.c;
        while (this.c < 128) {
            this.b[this.c++] = 0;
        }
        this.blake2bCompress(true);
        const out = new Uint8Array(this.outlen);
        for (let i = 0; i < this.outlen; i++) {
            out[i] = this.h[i >> 2] >> (8 * (i & 3));
        }
        return out;
    }
}
exports.Blake2b = Blake2b;
function blake2bHex(output) {
    return Array.from(output)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
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
 * Creates a vary length BLAKE2b of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {InputData?} key - key for hash
 * @param {number?} bitLen - length of hash (default 512 bits or 64 bytes)
 * @param {InputData?} salt - optional salt
 * @param {InputData?} personal - optional personal
 * @returns `string|Uint8Array|Buffer`
 */
function BLAKE2b(message, format = arrayType(), key, bitLen = 512, salt, personal) {
    // preprocess inputs
    const bits = bitLen ? bitLen / 8 : 64;
    message = formatMessage(message);
    const hash = new Blake2b(bits, key, salt, personal);
    hash.blake2bUpdate(message);
    const digestbytes = hash.blake2bFinal();
    if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    else if (format == "hex") {
        return blake2bHex(digestbytes);
    }
    return digestbytes;
}
exports.BLAKE2b = BLAKE2b;
;
/**
 * Creates a 64 byte BLAKE2b of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {InputData?} key - key for hash
 * @param {InputData?} salt - optional salt
 * @param {InputData?} personal - optional personal
 * @returns `string|Uint8Array|Buffer`
 */
function BLAKE2b512(message, format = arrayType(), key, salt, personal) {
    return BLAKE2b(message, format, key, 512, salt, personal);
}
exports.BLAKE2b512 = BLAKE2b512;
/**
 * Creates a 64 byte keyed BLAKE2b of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData?} key - key for hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {InputData?} salt - optional salt
 * @param {InputData?} personal - optional personal
 * @returns `string|Uint8Array|Buffer`
 */
function BLAKE2b512_HMAC(message, key, format = arrayType(), salt, personal) {
    return BLAKE2b_HMAC(message, key, 512, format, salt, personal);
}
exports.BLAKE2b512_HMAC = BLAKE2b512_HMAC;
/**
 * Creates a 48 byte BLAKE2b of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {InputData?} key - key for hash
 * @param {InputData?} salt - optional salt
 * @param {InputData?} personal - optional personal
 * @returns `string|Uint8Array|Buffer`
 */
function BLAKE2b384(message, format = arrayType(), key, salt, personal) {
    return BLAKE2b(message, format, key, 384, salt, personal);
}
exports.BLAKE2b384 = BLAKE2b384;
/**
 * Creates a 48 byte keyed BLAKE2b of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData?} key - key for hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {InputData?} salt - optional salt
 * @param {InputData?} personal - optional personal
 * @returns `string|Uint8Array|Buffer`
 */
function BLAKE2b384_HMAC(message, key, format = arrayType(), salt, personal) {
    return BLAKE2b_HMAC(message, key, 384, format, salt, personal);
}
exports.BLAKE2b384_HMAC = BLAKE2b384_HMAC;
;
/**
 * Creates a 32 byte BLAKE2b of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {InputData?} key - key for hash
 * @param {InputData?} salt - optional salt
 * @param {InputData?} personal - optional personal
 * @returns `string|Uint8Array|Buffer`
 */
function BLAKE2b256(message, format = arrayType(), key, salt, personal) {
    return BLAKE2b(message, format, key, 256, salt, personal);
}
exports.BLAKE2b256 = BLAKE2b256;
/**
 * Creates a 32 byte keyed BLAKE2b of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData?} key - key for hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {InputData?} salt - optional salt
 * @param {InputData?} personal - optional personal
 * @returns `string|Uint8Array|Buffer`
 */
function BLAKE2b256_HMAC(message, key, format = arrayType(), salt, personal) {
    return BLAKE2b_HMAC(message, key, 256, format, salt, personal);
}
exports.BLAKE2b256_HMAC = BLAKE2b256_HMAC;
;
/**
 * Creates a 28 byte BLAKE2b of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {InputData?} key - key for hash
 * @param {InputData?} salt - optional salt
 * @param {InputData?} personal - optional personal
 * @returns `string|Uint8Array|Buffer`
 */
function BLAKE2b224(message, format = arrayType(), key, salt, personal) {
    return BLAKE2b(message, format, key, 224, salt, personal);
}
exports.BLAKE2b224 = BLAKE2b224;
;
/**
 * Creates a 28 byte keyed BLAKE2b of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData?} key - key for hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {InputData?} salt - optional salt
 * @param {InputData?} personal - optional personal
 * @returns `string|Uint8Array|Buffer`
 */
function BLAKE2b224_HMAC(message, key, format = arrayType(), salt, personal) {
    return BLAKE2b_HMAC(message, key, 224, format, salt, personal);
}
exports.BLAKE2b224_HMAC = BLAKE2b224_HMAC;
;
/**
 * Creates a vary length keyed BLAKE2b of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData?} key - key for hash
 * @param {number?} bitLen - length of hash (default 512 bit or 64 bytes)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {InputData?} salt - optional salt
 * @param {InputData?} personal - optional personal
 * @returns `string|Uint8Array|Buffer`
 */
function BLAKE2b_HMAC(message, key, bitLen = 512, format = arrayType(), salt, personal) {
    // preprocess inputs
    const bits = bitLen ? bitLen / 8 : 64;
    message = formatMessage(message);
    // do the math
    const hash = new Blake2b(bits, formatMessage(key), salt, personal);
    hash.blake2bUpdate(message);
    const digestbytes = hash.blake2bFinal();
    if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    else if (format == "hex") {
        return blake2bHex(digestbytes);
    }
    return digestbytes;
}
exports.BLAKE2b_HMAC = BLAKE2b_HMAC;
;
//# sourceMappingURL=BLAKE2b.js.map