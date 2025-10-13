"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.HIGHWAY = exports.HIGHWAY256 = exports.HIGHWAY128 = exports.HIGHWAY64 = exports._HIGHWAY = exports.HighwayHash = void 0;
function arrayType() {
    if (typeof window !== 'undefined') {
        return "array";
    }
    else {
        return "buffer";
    }
}
;
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
function lshr(x, n) {
    return (x >> BigInt(n)) & ((BigInt(1) << (BigInt(64) - BigInt(n))) - BigInt(1));
}
/**
 * HighwayHash algorithm. See <a href="https://github.com/google/highwayhash">
 * HighwayHash on GitHub</a>
 */
class HighwayHash {
    /**
     *
     * @param {InputData} key 32 byte key
     */
    constructor(key) {
        this.v0 = new BigInt64Array(4);
        this.v1 = new BigInt64Array(4);
        this.mul0 = new BigInt64Array(4);
        this.mul1 = new BigInt64Array(4);
        this.done = false;
        key = formatMessage(key);
        if (key.length < 32) {
            const new_key = new Uint8Array(32);
            for (let i = 0; i < key.length; i++) {
                new_key[i] = key[i];
            }
            key = new_key;
        }
        else {
            key = key.subarray(0, 32);
        }
        const a0 = this.read64(key, 0);
        const a1 = this.read64(key, 8);
        const a2 = this.read64(key, 16);
        const a3 = this.read64(key, 24);
        this.reset(a0, a1, a2, a3);
    }
    /**
     * Updates the hash with 32 bytes of data. If you can read 4 long values
     * from your data efficiently, prefer using update() instead for more speed.
     * @param packet data array which has a length of at least pos + 32
     * @param pos position in the array to read the first of 32 bytes from
     */
    updatePacket(packet, pos) {
        if (pos < 0) {
            throw new Error(`Pos (${pos}) must be positive`);
        }
        if (pos + 32 > packet.length) {
            throw new Error("packet must have at least 32 bytes after pos");
        }
        var a0 = this.read64(packet, pos + 0);
        var a1 = this.read64(packet, pos + 8);
        var a2 = this.read64(packet, pos + 16);
        var a3 = this.read64(packet, pos + 24);
        this.update(a0, a1, a2, a3);
    }
    /**
     * Updates the hash with 32 bytes of data given as 4 longs. This function is
     * more efficient than updatePacket when you can use it.
     * @param a0 first 8 bytes in little endian 64-bit long
     * @param a1 next 8 bytes in little endian 64-bit long
     * @param a2 next 8 bytes in little endian 64-bit long
     * @param a3 last 8 bytes in little endian 64-bit long
     */
    update(a0, a1, a2, a3) {
        if (this.done) {
            throw new Error("Can compute a hash only once per instance");
        }
        this.v1[0] += this.mul0[0] + a0;
        this.v1[1] += this.mul0[1] + a1;
        this.v1[2] += this.mul0[2] + a2;
        this.v1[3] += this.mul0[3] + a3;
        for (let i = 0; i < 4; ++i) {
            this.mul0[i] ^= BigInt(this.v1[i] & BigInt(0xffffffff)) * BigInt(lshr(this.v0[i], 32));
            this.v0[i] += this.mul1[i];
            this.mul1[i] ^= BigInt(this.v0[i] & BigInt(0xffffffff)) * BigInt(lshr(this.v1[i], 32));
        }
        this.v0[0] += this.zipperMerge0(this.v1[1], this.v1[0]);
        this.v0[1] += this.zipperMerge1(this.v1[1], this.v1[0]);
        this.v0[2] += this.zipperMerge0(this.v1[3], this.v1[2]);
        this.v0[3] += this.zipperMerge1(this.v1[3], this.v1[2]);
        this.v1[0] += this.zipperMerge0(this.v0[1], this.v0[0]);
        this.v1[1] += this.zipperMerge1(this.v0[1], this.v0[0]);
        this.v1[2] += this.zipperMerge0(this.v0[3], this.v0[2]);
        this.v1[3] += this.zipperMerge1(this.v0[3], this.v0[2]);
    }
    /**
     * Updates the hash with the last 1 to 31 bytes of the data. You must use
     * updatePacket first per 32 bytes of the data, if and only if 1 to 31 bytes
     * of the data are not processed after that, updateRemainder must be used for
     * those final bytes.
     * @param bytes data array which has a length of at least pos + size_mod32
     * @param pos position in the array to start reading size_mod32 bytes from
     * @param size_mod32 the amount of bytes to read
     */
    updateRemainder(bytes, pos, size_mod32) {
        if (pos < 0) {
            throw new Error(`Pos (${pos}) must be positive`);
        }
        if (size_mod32 < 0 || size_mod32 >= 32) {
            throw new Error(`size_mod32 (${size_mod32}) must be between 0 and 31`);
        }
        if (pos + size_mod32 > bytes.length) {
            throw new Error("bytes must have at least size_mod32 bytes after pos");
        }
        var size_mod4 = size_mod32 & 3;
        var remainder = size_mod32 & ~3;
        const packet = new Uint8Array(32);
        for (let i = 0; i < 4; ++i) {
            this.v0[i] += (BigInt(size_mod32) << BigInt(32)) + BigInt(size_mod32);
        }
        this.rotate32By(size_mod32, this.v1);
        for (let i = 0; i < remainder; i++) {
            packet[i] = bytes[pos + i];
        }
        if ((size_mod32 & 16) != 0) {
            for (let i = 0; i < 4; i++) {
                packet[28 + i] = bytes[pos + remainder + i + size_mod4 - 4];
            }
        }
        else {
            if (size_mod4 != 0) {
                packet[16 + 0] = bytes[pos + remainder + 0];
                packet[16 + 1] = bytes[pos + remainder + (size_mod4 >>> 1)];
                packet[16 + 2] = bytes[pos + remainder + (size_mod4 - 1)];
            }
        }
        this.updatePacket(packet, 0);
    }
    /**
     * Computes the hash value after all bytes were processed. Invalidates the
     * state.
     *
     * NOTE: The 64-bit HighwayHash algorithm is declared stable and no longer subject to change.
     *
     * @return 64-bit hash
     */
    finalize64() {
        this.permuteAndUpdate();
        this.permuteAndUpdate();
        this.permuteAndUpdate();
        this.permuteAndUpdate();
        this.done = true;
        const value = this.v0[0] + this.v1[0] + this.mul0[0] + this.mul1[0];
        const ret = new Uint8Array(8);
        this.write64(value, ret, 0);
        return ret;
    }
    /**
     * Computes the hash value after all bytes were processed. Invalidates the state.
     *
     * @return array of size 2 containing 128-bit hash
     */
    finalize128() {
        this.permuteAndUpdate();
        this.permuteAndUpdate();
        this.permuteAndUpdate();
        this.permuteAndUpdate();
        this.permuteAndUpdate();
        this.permuteAndUpdate();
        this.done = true;
        const hash = new BigUint64Array(2);
        hash[0] = this.v0[0] + this.mul0[0] + this.v1[2] + this.mul1[2];
        hash[1] = this.v0[1] + this.mul0[1] + this.v1[3] + this.mul1[3];
        const ret = new Uint8Array(16);
        this.write64(hash[0], ret, 0);
        this.write64(hash[1], ret, 8);
        return ret;
    }
    /**
     * Computes the hash value after all bytes were processed. Invalidates the state.
     *
     * @return array of size 4 containing 256-bit hash
     */
    finalize256() {
        this.permuteAndUpdate();
        this.permuteAndUpdate();
        this.permuteAndUpdate();
        this.permuteAndUpdate();
        this.permuteAndUpdate();
        this.permuteAndUpdate();
        this.permuteAndUpdate();
        this.permuteAndUpdate();
        this.permuteAndUpdate();
        this.permuteAndUpdate();
        this.done = true;
        const hash = new BigInt64Array(4);
        this.modularReduction(this.v1[1] + this.mul1[1], this.v1[0] + this.mul1[0], this.v0[1] + this.mul0[1], this.v0[0] + this.mul0[0], hash, 0);
        this.modularReduction(this.v1[3] + this.mul1[3], this.v1[2] + this.mul1[2], this.v0[3] + this.mul0[3], this.v0[2] + this.mul0[2], hash, 2);
        const ret = new Uint8Array(32);
        this.write64(hash[0], ret, 0);
        this.write64(hash[1], ret, 8);
        this.write64(hash[3], ret, 16);
        this.write64(hash[4], ret, 24);
        return ret;
    }
    reset(key0, key1, key2, key3) {
        this.mul0[0] = BigInt("0xdbe6d5d5fe4cce2f");
        this.mul0[1] = BigInt("0xa4093822299f31d0");
        this.mul0[2] = BigInt("0x13198a2e03707344");
        this.mul0[3] = BigInt("0x243f6a8885a308d3");
        this.mul1[0] = BigInt("0x3bd39e10cb0ef593");
        this.mul1[1] = BigInt("0xc0acf169b5f18a8c");
        this.mul1[2] = BigInt("0xbe5466cf34e90c6c");
        this.mul1[3] = BigInt("0x452821e638d01377");
        this.v0[0] = this.mul0[0] ^ key0;
        this.v0[1] = this.mul0[1] ^ key1;
        this.v0[2] = this.mul0[2] ^ key2;
        this.v0[3] = this.mul0[3] ^ key3;
        this.v1[0] = this.mul1[0] ^ ((lshr(key0, 32)) | (key0 << BigInt(32)));
        this.v1[1] = this.mul1[1] ^ ((lshr(key1, 32)) | (key1 << BigInt(32)));
        this.v1[2] = this.mul1[2] ^ ((lshr(key2, 32)) | (key2 << BigInt(32)));
        this.v1[3] = this.mul1[3] ^ ((lshr(key3, 32)) | (key3 << BigInt(32)));
    }
    zipperMerge0(v1, v0) {
        return (lshr(((v0 & BigInt("0xff000000")) | (v1 & BigInt("0xff00000000"))), 24)) |
            (lshr(((v0 & BigInt("0xff0000000000")) | (v1 & BigInt("0xff000000000000"))), 16)) |
            (v0 & BigInt("0xff0000")) | ((v0 & BigInt("0xff00")) << BigInt(32)) |
            (lshr((v1 & BigInt("0xff00000000000000")), 8)) | (v0 << BigInt(56));
    }
    zipperMerge1(v1, v0) {
        return (lshr(((v1 & BigInt("0xff000000")) | (v0 & BigInt("0xff00000000"))), 24)) |
            (v1 & BigInt("0xff0000")) | (lshr((v1 & BigInt("0xff0000000000")), 16)) |
            ((v1 & BigInt("0xff00")) << BigInt(24)) | (lshr((v0 & BigInt("0xff000000000000")), 8)) |
            ((v1 & BigInt("0xff")) << BigInt(48)) | (v0 & BigInt("0xff00000000000000"));
    }
    read64(buf, off) {
        let value = BigInt(0);
        let endian = "little";
        let unsigned = false;
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
    write64(val, buf, off) {
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
    rotate32By(count, lanes) {
        for (let i = 0; i < 4; ++i) {
            var half0 = (lanes[i] & BigInt("0xffffffff"));
            var half1 = lshr(lanes[i], 32) & BigInt("0xffffffff");
            lanes[i] = ((half0 << BigInt(count)) & BigInt("0xffffffff")) | lshr(half0, (32 - count));
            lanes[i] |= BigInt(Number(((half1 << BigInt(count)) & BigInt("0xffffffff")) |
                lshr(half1, (32 - count)))) << BigInt(32);
        }
    }
    permuteAndUpdate() {
        this.update(lshr(this.v0[2], 32) | (this.v0[2] << BigInt(32)), lshr(this.v0[3], 32) | (this.v0[3] << BigInt(32)), lshr(this.v0[0], 32) | (this.v0[0] << BigInt(32)), lshr(this.v0[1], 32) | (this.v0[1] << BigInt(32)));
    }
    modularReduction(a3_unmasked, a2, a1, a0, hash, pos) {
        var a3 = a3_unmasked & BigInt("0x3FFFFFFFFFFFFFFF");
        hash[pos + 1] = a1 ^ ((a3 << BigInt(1)) | lshr(a2, 63)) ^ ((a3 << BigInt(2)) | lshr(a2, 62));
        hash[pos + 0] = a0 ^ (a2 << BigInt(1)) ^ (a2 << BigInt(2));
    }
    //////////////////////////////////////////////////////////////////////////////
    /**
     * NOTE: The 64-bit HighwayHash algorithm is declared stable and no longer subject to change.
     *
     * @param data array with data bytes
     * @param offset position of first byte of data to read from
     * @param length number of bytes from data to read
     * @param key array of size 4 with the key to initialize the hash with
     * @return 64-bit hash for the given data
     */
    static hash64(data, offset = 0, length = data.length, key) {
        const h = new HighwayHash(key);
        h.processAll(data, offset, length);
        return h.finalize64();
    }
    /**
     * @param data array with data bytes
     * @param offset position of first byte of data to read from
     * @param length number of bytes from data to read
     * @param key array of size 4 with the key to initialize the hash with
     * @return array of size 2 containing 128-bit hash for the given data
     */
    static hash128(data, offset = 0, length = data.length, key) {
        const h = new HighwayHash(key);
        h.processAll(data, offset, length);
        return h.finalize128();
    }
    /**
     * @param data array with data bytes
     * @param offset position of first byte of data to read from
     * @param length number of bytes from data to read
     * @param key array of size 4 with the key to initialize the hash with
     * @return array of size 4 containing 256-bit hash for the given data
     */
    static hash256(data, offset = 0, length = data.length, key) {
        const h = new HighwayHash(key);
        h.processAll(data, offset, length);
        return h.finalize256();
    }
    processAll(data, offset = 0, length = data.length) {
        var i;
        for (i = 0; i + 32 <= length; i += 32) {
            this.updatePacket(data, offset + i);
        }
        if ((length & 31) != 0) {
            this.updateRemainder(data, offset + i, length & 31);
        }
    }
}
exports.HighwayHash = HighwayHash;
/**
 * Creates a vary byte length keyed Highway Hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {64 | 128 | 256 } bitLen - length of hash (default 128 bits AKA 16 bytes)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function _HIGHWAY(message, key, bitLen = 128, format = arrayType()) {
    var hash = new HighwayHash(formatMessage(key));
    hash.processAll(formatMessage(message));
    var digestbytes;
    switch (bitLen) {
        case 64:
            digestbytes = hash.finalize64();
            break;
        case 128:
            digestbytes = hash.finalize128();
            break;
        case 256:
            digestbytes = hash.finalize256();
            break;
        default:
            digestbytes = hash.finalize128();
            break;
    }
    if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    else if (format == "hex") {
        return toHex(digestbytes);
    }
    return digestbytes;
}
exports._HIGHWAY = _HIGHWAY;
/**
 * Creates a 8 byte length keyed Highway Hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HIGHWAY64(message, key, format = arrayType()) {
    var hash = new HighwayHash(formatMessage(key));
    hash.processAll(formatMessage(message));
    const digestbytes = hash.finalize64();
    if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    else if (format == "hex") {
        return toHex(digestbytes);
    }
    return digestbytes;
}
exports.HIGHWAY64 = HIGHWAY64;
/**
 * Creates a 16 byte length keyed Highway Hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HIGHWAY128(message, key, format = arrayType()) {
    var hash = new HighwayHash(formatMessage(key));
    hash.processAll(formatMessage(message));
    const digestbytes = hash.finalize128();
    if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    else if (format == "hex") {
        return toHex(digestbytes);
    }
    return digestbytes;
}
exports.HIGHWAY128 = HIGHWAY128;
/**
 * Creates a 32 byte length keyed Highway Hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function HIGHWAY256(message, key, format = arrayType()) {
    var hash = new HighwayHash(formatMessage(key));
    hash.processAll(formatMessage(message));
    const digestbytes = hash.finalize256();
    if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    else if (format == "hex") {
        return toHex(digestbytes);
    }
    return digestbytes;
}
exports.HIGHWAY256 = HIGHWAY256;
/**
 * Static class of all Highway Hash functions and classes
 */
class HIGHWAY {
    /**
       * List of all hashes in class
       */
    static get FUNCTION_LIST() {
        return [
            "HIGHWAY",
            "HIGHWAY64",
            "HIGHWAY128",
            "HIGHWAY256",
        ];
    }
}
exports.HIGHWAY = HIGHWAY;
HIGHWAY.Highway = HighwayHash;
HIGHWAY.HIGHWAY = _HIGHWAY;
HIGHWAY.HIGHWAY64 = HIGHWAY64;
HIGHWAY.HIGHWAY128 = HIGHWAY128;
HIGHWAY.HIGHWAY256 = HIGHWAY256;
//# sourceMappingURL=HIGHWAY.js.map