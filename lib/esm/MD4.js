"use strict";
// MD4 implementation in TypeScript
// Based on the C code from Projet RNRT SAPHIR
// Copyright (c) 2007-2010 Projet RNRT SAPHIR
// Licensed under MIT License (see original C code for details)
Object.defineProperty(exports, "__esModule", { value: true });
exports.MD4_HMAC = exports.MD4 = void 0;
// Constants for MD4
const IV = new Uint32Array([
    0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
]);
// Helper functions for MD4 operations
function F(B, C, D) {
    return (((C ^ D) & B) ^ D) >>> 0;
}
function G(B, C, D) {
    return ((D & C) | ((D | C) & B)) >>> 0;
}
function H(B, C, D) {
    return (B ^ C ^ D) >>> 0;
}
function ROTL(x, n) {
    return ((x << n) | (x >>> (32 - n))) >>> 0;
}
// MD4 round function
function md4Round(data, r) {
    // Read 16 x 32-bit words from data in little-endian
    const X = new Uint32Array(16);
    const view = new DataView(data.buffer, data.byteOffset, data.length);
    for (let i = 0; i < 16; i++) {
        X[i] = view.getUint32(i * 4, true);
    }
    let A = r[0];
    let B = r[1];
    let C = r[2];
    let D = r[3];
    // Round 1: F function
    A = ROTL((A + F(B, C, D) + X[0]) >>> 0, 3);
    D = ROTL((D + F(A, B, C) + X[1]) >>> 0, 7);
    C = ROTL((C + F(D, A, B) + X[2]) >>> 0, 11);
    B = ROTL((B + F(C, D, A) + X[3]) >>> 0, 19);
    A = ROTL((A + F(B, C, D) + X[4]) >>> 0, 3);
    D = ROTL((D + F(A, B, C) + X[5]) >>> 0, 7);
    C = ROTL((C + F(D, A, B) + X[6]) >>> 0, 11);
    B = ROTL((B + F(C, D, A) + X[7]) >>> 0, 19);
    A = ROTL((A + F(B, C, D) + X[8]) >>> 0, 3);
    D = ROTL((D + F(A, B, C) + X[9]) >>> 0, 7);
    C = ROTL((C + F(D, A, B) + X[10]) >>> 0, 11);
    B = ROTL((B + F(C, D, A) + X[11]) >>> 0, 19);
    A = ROTL((A + F(B, C, D) + X[12]) >>> 0, 3);
    D = ROTL((D + F(A, B, C) + X[13]) >>> 0, 7);
    C = ROTL((C + F(D, A, B) + X[14]) >>> 0, 11);
    B = ROTL((B + F(C, D, A) + X[15]) >>> 0, 19);
    // Round 2: G function
    A = ROTL((A + G(B, C, D) + X[0] + 0x5A827999) >>> 0, 3);
    D = ROTL((D + G(A, B, C) + X[4] + 0x5A827999) >>> 0, 5);
    C = ROTL((C + G(D, A, B) + X[8] + 0x5A827999) >>> 0, 9);
    B = ROTL((B + G(C, D, A) + X[12] + 0x5A827999) >>> 0, 13);
    A = ROTL((A + G(B, C, D) + X[1] + 0x5A827999) >>> 0, 3);
    D = ROTL((D + G(A, B, C) + X[5] + 0x5A827999) >>> 0, 5);
    C = ROTL((C + G(D, A, B) + X[9] + 0x5A827999) >>> 0, 9);
    B = ROTL((B + G(C, D, A) + X[13] + 0x5A827999) >>> 0, 13);
    A = ROTL((A + G(B, C, D) + X[2] + 0x5A827999) >>> 0, 3);
    D = ROTL((D + G(A, B, C) + X[6] + 0x5A827999) >>> 0, 5);
    C = ROTL((C + G(D, A, B) + X[10] + 0x5A827999) >>> 0, 9);
    B = ROTL((B + G(C, D, A) + X[14] + 0x5A827999) >>> 0, 13);
    A = ROTL((A + G(B, C, D) + X[3] + 0x5A827999) >>> 0, 3);
    D = ROTL((D + G(A, B, C) + X[7] + 0x5A827999) >>> 0, 5);
    C = ROTL((C + G(D, A, B) + X[11] + 0x5A827999) >>> 0, 9);
    B = ROTL((B + G(C, D, A) + X[15] + 0x5A827999) >>> 0, 13);
    // Round 3: H function
    A = ROTL((A + H(B, C, D) + X[0] + 0x6ED9EBA1) >>> 0, 3);
    D = ROTL((D + H(A, B, C) + X[8] + 0x6ED9EBA1) >>> 0, 9);
    C = ROTL((C + H(D, A, B) + X[4] + 0x6ED9EBA1) >>> 0, 11);
    B = ROTL((B + H(C, D, A) + X[12] + 0x6ED9EBA1) >>> 0, 15);
    A = ROTL((A + H(B, C, D) + X[2] + 0x6ED9EBA1) >>> 0, 3);
    D = ROTL((D + H(A, B, C) + X[10] + 0x6ED9EBA1) >>> 0, 9);
    C = ROTL((C + H(D, A, B) + X[6] + 0x6ED9EBA1) >>> 0, 11);
    B = ROTL((B + H(C, D, A) + X[14] + 0x6ED9EBA1) >>> 0, 15);
    A = ROTL((A + H(B, C, D) + X[1] + 0x6ED9EBA1) >>> 0, 3);
    D = ROTL((D + H(A, B, C) + X[9] + 0x6ED9EBA1) >>> 0, 9);
    C = ROTL((C + H(D, A, B) + X[5] + 0x6ED9EBA1) >>> 0, 11);
    B = ROTL((B + H(C, D, A) + X[13] + 0x6ED9EBA1) >>> 0, 15);
    A = ROTL((A + H(B, C, D) + X[3] + 0x6ED9EBA1) >>> 0, 3);
    D = ROTL((D + H(A, B, C) + X[11] + 0x6ED9EBA1) >>> 0, 9);
    C = ROTL((C + H(D, A, B) + X[7] + 0x6ED9EBA1) >>> 0, 11);
    B = ROTL((B + H(C, D, A) + X[15] + 0x6ED9EBA1) >>> 0, 15);
    // Update state
    r[0] = (r[0] + A) >>> 0;
    r[1] = (r[1] + B) >>> 0;
    r[2] = (r[2] + C) >>> 0;
    r[3] = (r[3] + D) >>> 0;
}
// Initialize MD4 context
function sphMD4Init() {
    return {
        val: new Uint32Array(IV),
        count: BigInt(0),
        buf: new Uint8Array(64)
    };
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
function formatMessage(message) {
    if (message === undefined) {
        throw new Error('input is invalid type');
    }
    if (typeof message === 'string') {
        return strToUint8Array(message);
    }
    if (message instanceof Uint8Array || Buffer.isBuffer(message)) {
        return message;
    }
    throw new Error('input is invalid type');
}
// Update MD4 context with input data
function sphMD4Update(sc, data) {
    let i = Number(sc.count & BigInt(63)); // Current position in buffer
    data = formatMessage(data);
    const len = data.length;
    sc.count += BigInt(len << 3); // Update bit count
    let ptr = 0;
    while (ptr < len) {
        const clen = Math.min(len - ptr, 64 - i);
        sc.buf.set(data.subarray(ptr, ptr + clen), i);
        ptr += clen;
        i += clen;
        if (i === 64) {
            md4Round(sc.buf, sc.val);
            i = 0;
        }
    }
}
// Finalize MD4 hash and output digest
function sphMD4Close(sc) {
    let i = Number(sc.count & BigInt(63));
    sc.buf[i++] = 0x80; // Padding
    while (i < 64) {
        sc.buf[i++] = 0;
    }
    // If not enough space for length, process current block and add another
    if (i > 56) {
        md4Round(sc.buf, sc.val);
        sc.buf.fill(0);
    }
    // Append length (in bits) as 64-bit little-endian
    const view = new DataView(sc.buf.buffer);
    view.setBigUint64(56, sc.count, true);
    md4Round(sc.buf, sc.val);
    // Output digest (16 bytes, little-endian)
    const digest = new Uint8Array(16);
    const digestView = new DataView(digest.buffer);
    for (let i = 0; i < 4; i++) {
        digestView.setUint32(i * 4, sc.val[i], true);
    }
    // Reset context
    Object.assign(sc, sphMD4Init());
    return digest;
}
function bytesToHex(bytes) {
    for (var hex = [], i = 0; i < bytes.length; i++) {
        hex.push((bytes[i] >>> 4).toString(16));
        hex.push((bytes[i] & 0xF).toString(16));
    }
    return hex.join("");
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
 * Creates MD4 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function MD4(message, format = arrayType()) {
    const ctx = sphMD4Init();
    sphMD4Update(ctx, message);
    var digestbytes = sphMD4Close(ctx);
    if (format == "hex") {
        return bytesToHex(digestbytes);
    }
    else if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    return digestbytes;
}
exports.MD4 = MD4;
;
/**
 * Creates a keyed MD4 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function MD4_HMAC(message, key, format = arrayType()) {
    const key_length = 64;
    const hash_len = 16;
    key = formatMessage(key);
    message = formatMessage(message);
    if (key.length > key_length) {
        key = MD4(key, "array");
    }
    if (key.length < key_length) {
        const tmp = new Uint8Array(key_length);
        tmp.set(key, 0);
        key = tmp;
    }
    // Generate inner and outer keys
    var innerKey = new Uint8Array(key_length);
    var outerKey = new Uint8Array(key_length);
    for (var i = 0; i < key_length; i++) {
        innerKey[i] = 0x36 ^ key[i];
        outerKey[i] = 0x5c ^ key[i];
    }
    // Append the innerKey
    var msg = new Uint8Array(message.length + key_length);
    msg.set(innerKey, 0);
    msg.set(message, key_length);
    // Hash the previous message and append the outerKey
    var result = new Uint8Array(key_length + hash_len);
    result.set(outerKey, 0);
    result.set(MD4(msg, "array"), key_length);
    var digestbytes = MD4(result);
    if (format == "hex") {
        return bytesToHex(digestbytes);
    }
    else if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    return digestbytes;
}
exports.MD4_HMAC = MD4_HMAC;
;
//# sourceMappingURL=MD4.js.map