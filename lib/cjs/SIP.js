"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SIP = exports.SIP128 = exports.SIP64 = exports.SIP32 = exports._SIP = void 0;
function toHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
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
 * Encode the 64-bit word {@code val} into the array
 * {@code buf} at offset {@code off}, in big-endian
 * convention (most significant byte first).
 *
 * @param val   the value to encode
 * @param buf   the destination buffer
 * @param off   the destination offset
 */
function encodeLELong(val, buf, off) {
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
function decodeLELong(buf, off) {
    let value = BigInt(0);
    let endian = "little";
    let unsigned = true;
    if (endian == "little") {
        for (let i = 0; i < 8; i++) {
            value = value | BigInt(buf[off]) << BigInt(8 * i);
            off++;
        }
        // @ts-ignore
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
        // @ts-ignore
        if (unsigned == false) {
            if (value & (BigInt(1) << BigInt(63))) {
                value -= BigInt(1) << BigInt(64);
            }
        }
    }
    return value;
}
function ROTL(x, n) {
    const mask = (BigInt(1) << BigInt(64)) - BigInt(1);
    const s = BigInt(n & 63);
    const ux = x & mask; // unsigned 64-bit
    const rotated = ((ux << s) | (ux >> (BigInt(64) - s))) & mask;
    const value = rotated >= (BigInt(1) << BigInt(63)) ? rotated - (BigInt(1) << BigInt(64)) : rotated;
    return value;
}
/**
 * Creates a vary byte keyed SipHash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData?} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {32 | 64 | 128} bitLen - output bit length (default 128 AKA 16 bytes)
 * @param {number?} cROUNDS - Primary rounds (default 2)
 * @param {number?} dROUNDS - Secondary rounds (default 4)
 */
function _SIP(message, key, format = arrayType(), bitLen = 128, cROUNDS = 2, dROUNDS = 4) {
    message = formatMessage(message);
    key = formatMessage(key);
    if (key.length > 16) {
        key = key.subarray(0, 16);
    }
    if (key.length < 16) {
        const new_key = new Uint8Array(16);
        for (let i = 0; i < key.length; i++) {
            new_key[i] = key[i];
        }
        key = new_key;
    }
    var out = new Uint8Array(16);
    var ni = message;
    const kk = key;
    const outlen = bitLen / 8;
    const v = new BigUint64Array(4);
    v[0] = BigInt("0x736f6d6570736575");
    v[1] = BigInt("0x646f72616e646f6d");
    v[2] = BigInt("0x6c7967656e657261");
    v[3] = BigInt("0x7465646279746573");
    const k = new BigUint64Array(2);
    k[0] = decodeLELong(kk, 0);
    k[1] = decodeLELong(kk, 8);
    var m;
    let i = 0;
    let z = 0;
    const inlen = message.length;
    const rounds = Math.floor(inlen / 8);
    const left = inlen - (rounds * 8);
    const b = new BigUint64Array(1);
    b[0] = BigInt(inlen) << BigInt(56);
    v[3] ^= k[1];
    v[2] ^= k[0];
    v[1] ^= k[1];
    v[0] ^= k[0];
    if (outlen == 16) {
        v[1] ^= BigInt(0xee);
    }
    for (i = 0; i < rounds; i++) {
        m = decodeLELong(ni, i * 8);
        v[3] ^= m;
        for (z = 0; z < cROUNDS; z++) {
            v[0] += v[1];
            v[1] = ROTL(v[1], 13);
            v[1] ^= v[0];
            v[0] = ROTL(v[0], 32);
            v[2] += v[3];
            v[3] = ROTL(v[3], 16);
            v[3] ^= v[2];
            v[0] += v[3];
            v[3] = ROTL(v[3], 21);
            v[3] ^= v[0];
            v[2] += v[1];
            v[1] = ROTL(v[1], 17);
            v[1] ^= v[2];
            v[2] = ROTL(v[2], 32);
        }
        v[0] ^= m;
    }
    ni = ni.subarray(rounds * 8, ni.length);
    switch (left) {
        //@ts-ignore
        case 7:
            b[0] |= (BigInt(ni[6])) << BigInt(48);
        //@ts-ignore
        case 6:
            b[0] |= (BigInt(ni[5])) << BigInt(40);
        //@ts-ignore
        case 5:
            b[0] |= (BigInt(ni[4])) << BigInt(32);
        //@ts-ignore
        case 4:
            b[0] |= (BigInt(ni[3])) << BigInt(24);
        //@ts-ignore
        case 3:
            b[0] |= (BigInt(ni[2])) << BigInt(16);
        //@ts-ignore
        case 2:
            b[0] |= (BigInt(ni[1])) << BigInt(8);
        //@ts-ignore
        case 1:
            b[0] |= BigInt(ni[0]);
        case 0:
            break;
    }
    v[3] ^= b[0];
    for (z = 0; z < cROUNDS; z++) {
        v[0] += v[1];
        v[1] = ROTL(v[1], 13);
        v[1] ^= v[0];
        v[0] = ROTL(v[0], 32);
        v[2] += v[3];
        v[3] = ROTL(v[3], 16);
        v[3] ^= v[2];
        v[0] += v[3];
        v[3] = ROTL(v[3], 21);
        v[3] ^= v[0];
        v[2] += v[1];
        v[1] = ROTL(v[1], 17);
        v[1] ^= v[2];
        v[2] = ROTL(v[2], 32);
    }
    v[0] ^= b[0];
    if (outlen == 16) {
        v[2] ^= BigInt(0xee);
    }
    else {
        v[2] ^= BigInt(0xff);
    }
    for (z = 0; z < dROUNDS; z++) {
        v[0] += v[1];
        v[1] = ROTL(v[1], 13);
        v[1] ^= v[0];
        v[0] = ROTL(v[0], 32);
        v[2] += v[3];
        v[3] = ROTL(v[3], 16);
        v[3] ^= v[2];
        v[0] += v[3];
        v[3] = ROTL(v[3], 21);
        v[3] ^= v[0];
        v[2] += v[1];
        v[1] = ROTL(v[1], 17);
        v[1] ^= v[2];
        v[2] = ROTL(v[2], 32);
    }
    b[0] = v[0] ^ v[1] ^ v[2] ^ v[3];
    encodeLELong(b[0], out, 0);
    v[1] ^= BigInt(0xdd);
    for (z = 0; z < dROUNDS; z++) {
        v[0] += v[1];
        v[1] = ROTL(v[1], 13);
        v[1] ^= v[0];
        v[0] = ROTL(v[0], 32);
        v[2] += v[3];
        v[3] = ROTL(v[3], 16);
        v[3] ^= v[2];
        v[0] += v[3];
        v[3] = ROTL(v[3], 21);
        v[3] ^= v[0];
        v[2] += v[1];
        v[1] = ROTL(v[1], 17);
        v[1] ^= v[2];
        v[2] = ROTL(v[2], 32);
    }
    b[0] = v[0] ^ v[1] ^ v[2] ^ v[3];
    encodeLELong(b[0], out, 8);
    out = out.subarray(0, outlen);
    if (format == "buffer") {
        return Buffer.from(out);
    }
    else if (format == "hex") {
        return toHex(out);
    }
    return out;
}
exports._SIP = _SIP;
/**
 * Creates a 4 byte keyed SipHash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData?} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {number} cROUNDS - Primary rounds (default 2)
 * @param {number} dROUNDS - Secondary rounds (default 4)
 */
function SIP32(message, key, format = arrayType(), cROUNDS = 2, dROUNDS = 4) {
    return _SIP(message, key, format, 32, cROUNDS, dROUNDS);
}
exports.SIP32 = SIP32;
/**
 * Creates a 8 byte keyed SipHash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData?} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {number} cROUNDS - Primary rounds
 * @param {number} dROUNDS - Secondary rounds
 */
function SIP64(message, key, format = arrayType(), cROUNDS = 2, dROUNDS = 4) {
    return _SIP(message, key, format, 64, cROUNDS, dROUNDS);
}
exports.SIP64 = SIP64;
/**
 * Creates a 16 byte keyed SipHash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData?} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {number} cROUNDS - Primary rounds
 * @param {number} dROUNDS - Secondary rounds
 */
function SIP128(message, key, format = arrayType(), cROUNDS = 2, dROUNDS = 4) {
    return _SIP(message, key, format, 128, cROUNDS, dROUNDS);
}
exports.SIP128 = SIP128;
/**
 * Static class of all SIP functions and classes
 */
class SIP {
    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST() {
        return [
            "SIP",
            "SIP32",
            "SIP64",
            "SIP128"
        ];
    }
}
exports.SIP = SIP;
SIP.SIP = _SIP;
SIP.SIP32 = SIP32;
SIP.SIP64 = SIP64;
SIP.SIP128 = SIP128;
//# sourceMappingURL=SIP.js.map