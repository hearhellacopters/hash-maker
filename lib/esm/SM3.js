"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SM3 = exports.SM3_HMAC = exports._SM3 = exports.Sm3 = void 0;
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
 * Base hasher class
 * @interface
 */
class Hasher {
    /**
     * @param {Object} options
     * @constructor
     */
    constructor(options = {}) {
        this.state = { message: new Uint8Array(), length: 0, hash: [] };
        /**
         * Size of unit in bytes (4 = 32 bits)
         * @type {number}
         */
        this.unitSize = 4;
        /**
         * Bytes order in unit
         *   0 - normal
         *   1 - reverse
         * @type {number}
         */
        this.unitOrder = 0;
        /**
         * Size of block in units
         * @type {number}
         */
        this.blockSize = 16;
        /**
         * Size of block in bytes
         * @type {number}
         */
        this.blockSizeInBytes = this.blockSize * this.unitSize;
        this.options = options || {};
        this.reset();
    }
    /**
     * Reset hasher to initial state
     */
    reset() {
        /**
         * All algorithm variables that changed during process
         * @protected
         * @type {Object}
         * @property {Uint8Array} state.message - Unprocessed Message
         * @property {number} state.length - Length of message in bytes
         */
        this.state.message = new Uint8Array(0);
        this.state.length = 0;
        this.state.hash = [];
    }
    /**
     * Return current state
     *
     * @returns {Object}
     */
    getState() {
        return JSON.parse(JSON.stringify({
            message: Array.from(this.state.message),
            length: this.state.length
        }));
    }
    /**
     * Set current state
     *
     * @param {Object} state
     */
    setState(state) {
        this.state = {
            message: new Uint8Array(state.message || []),
            length: state.length || 0,
            hash: []
        };
    }
    /**
     * Update message from binary data
     *
     * @param {InputData} message
     */
    update(message) {
        // Convert various input types to Uint8Array
        const data = Hasher.convertToUint8Array(message);
        // Append to existing message
        const newMessage = new Uint8Array(this.state.message.length + data.length);
        newMessage.set(this.state.message);
        newMessage.set(data, this.state.message.length);
        this.state.message = newMessage;
        this.state.length += data.length;
        this.process();
    }
    /**
     * Convert various input types to Uint8Array
     *
     * @private
     * @param {InputData?} data
     * @returns {Uint8Array}
     */
    static convertToUint8Array(data) {
        if (data == undefined) {
            return new Uint8Array(0);
        }
        if (Buffer.isBuffer(data)) {
            return new Uint8Array(data);
        }
        if (data instanceof Uint8Array) {
            return data;
        }
        if (typeof data === 'string') {
            return strToUint8Array(data);
        }
        throw new Error('Unsupported input type for hash update');
    }
    /**
     * Process ready blocks
     *
     * @protected
     */
    process() {
    }
    /**
     * Finalize hash and return result
     *
     * @returns {Uint8Array}
     */
    finalize() {
        return new Uint8Array(0);
    }
    /**
     * Get hash from state
     *
     * @protected
     * @param {number} [size=this.state.hash.length] - Limit hash size (in chunks)
     * @returns {Uint8Array}
     */
    getStateHash(size) {
        return new Uint8Array(0);
    }
    /**
     * Add PKCS7 padding to message
     * Pad with bytes all of the same value as the number of padding bytes
     *
     * @protected
     * @param {number} length
     */
    addPaddingPKCS7(length) {
        const padding = new Uint8Array(length);
        padding.fill(length);
        this.state.message = this.concatUint8Arrays(this.state.message, padding);
    }
    /**
     * Add ISO7816-4 padding to message
     * Pad with 0x80 followed by zero bytes
     *
     * @protected
     * @param {number} length
     */
    addPaddingISO7816(length) {
        const padding = new Uint8Array(length);
        padding[0] = 0x80;
        this.state.message = this.concatUint8Arrays(this.state.message, padding);
    }
    /**
     * Add zero padding to message
     * Pad with 0x00 characters
     *
     * @protected
     * @param {number} length
     */
    addPaddingZero(length) {
        const padding = new Uint8Array(length);
        this.state.message = this.concatUint8Arrays(this.state.message, padding);
    }
    /**
     * Concatenate two Uint8Arrays
     *
     * @private
     * @param {Uint8Array} a
     * @param {Uint8Array} b
     * @returns {Uint8Array}
     */
    concatUint8Arrays(a, b) {
        const result = new Uint8Array(a.length + b.length);
        result.set(a);
        result.set(b, a.length);
        return result;
    }
}
/**
 * Hasher for 32 bit big endian blocks
 * @interface
 */
class Hasher32be extends Hasher {
    /**
     * @param {Object} [options]
     */
    constructor(options) {
        super(options);
        /**
         * Reverse order of bytes
         * @type {number}
         */
        this.unitOrder = 1;
        /**
         * Current block (only for speed optimization)
         * @private
         * @type {number[]}
         */
        this.blockUnits = [];
    }
    /**
     * Process ready blocks
     *
     * @protected
     */
    process() {
        while (this.state.message.length >= this.blockSizeInBytes) {
            this.blockUnits = [];
            for (let b = 0; b < this.blockSizeInBytes; b += 4) {
                this.blockUnits.push(this.state.message[b] << 24 |
                    this.state.message[b + 1] << 16 |
                    this.state.message[b + 2] << 8 |
                    this.state.message[b + 3]);
            }
            // Remove processed block from message
            this.state.message = this.state.message.subarray(this.blockSizeInBytes);
            this.processBlock(this.blockUnits);
        }
    }
    /**
     * Process ready blocks
     *
     * @protected
     * @param {number[]} M
     */
    processBlock(M) {
    }
    /**
     * Get hash from state
     *
     * @protected
     * @param {number} [size=this.state.hash.length] - Limit hash size (in chunks)
     * @returns {Uint8Array}
     */
    getStateHash(size) {
        size = size || this.state.hash.length;
        const hash = new Uint8Array(size * 4);
        for (let i = 0; i < size; i++) {
            const word = this.state.hash[i];
            hash[i * 4] = (word >> 24) & 0xff;
            hash[i * 4 + 1] = (word >> 16) & 0xff;
            hash[i * 4 + 2] = (word >> 8) & 0xff;
            hash[i * 4 + 3] = word & 0xff;
        }
        return hash;
    }
    /**
     * Add to message cumulative size of message in bits
     *
     * @protected
     */
    addLengthBits() {
        // Calculate length in bits (64-bit)
        const bitLength = BigInt(this.state.length) * BigInt(8);
        // Convert to 8 bytes (little-endian)
        const lengthBytes = new Uint8Array(8);
        lengthBytes[0] = Number((bitLength >> BigInt(56)) & BigInt(0xff));
        lengthBytes[1] = Number((bitLength >> BigInt(48)) & BigInt(0xff));
        lengthBytes[2] = Number((bitLength >> BigInt(40)) & BigInt(0xff));
        lengthBytes[3] = Number((bitLength >> BigInt(32)) & BigInt(0xff));
        lengthBytes[4] = Number((bitLength >> BigInt(24)) & BigInt(0xff));
        lengthBytes[5] = Number((bitLength >> BigInt(16)) & BigInt(0xff));
        lengthBytes[6] = Number((bitLength >> BigInt(8)) & BigInt(0xff));
        lengthBytes[7] = Number(bitLength & BigInt(0xff));
        this.state.message = this.concatUint8Arrays(this.state.message, lengthBytes);
    }
}
function rotateLeft(x, n) {
    return ((x << n) | (x >>> (32 - n))) | 0;
}
/**
 * Calculates [SM3](https://tools.ietf.org/id/draft-oscca-cfrg-sm3-02.html) hash
 */
class Sm3 extends Hasher32be {
    /**
     * @param {Object} [options]
     * @param {number} [options.rounds=64] - Number of rounds (Must be greater than 16)
     * @param {number} [options.length=256] - Length of hash result
     */
    constructor(options) {
        options = options || {};
        options.length = options.length || 256;
        options.rounds = options.rounds || 64;
        super(options);
        this.options = { length: 256, rounds: 64 };
        /**
         * Working variable (only for speed optimization)
         * @private
         * @ignore
         * @type {number[]}
         */
        this.W = new Array(132);
    }
    /**
     * Reset hasher to initial state
     */
    reset() {
        super.reset();
        this.state.hash = [
            0x7380166f | 0, 0x4914b2b9 | 0, 0x172442d7 | 0, 0xda8a0600 | 0,
            0xa96f30bc | 0, 0x163138aa | 0, 0xe38dee4d | 0, 0xb0fb0e4e | 0
        ];
    }
    /**
     * @protected
     * @ignore
     * @param {number} x
     * @returns {number}
     */
    static p0(x) {
        return x ^ rotateLeft(x, 9) ^ rotateLeft(x, 17);
    }
    /**
     * @protected
     * @ignore
     * @param {number} x
     * @returns {number}
     */
    static p1(x) {
        return x ^ rotateLeft(x, 15) ^ rotateLeft(x, 23);
    }
    /**
     * @protected
     * @ignore
     * @param {number} i
     * @returns {number}
     */
    static tj(i) {
        return i < 16 ? 0x79cc4519 : 0x7a879d8a;
    }
    /**
     * @protected
     * @ignore
     * @param {number} i
     * @param {number} a
     * @param {number} b
     * @param {number} c
     * @returns {number}
     */
    static ffj(i, a, b, c) {
        return i < 16 ? a ^ b ^ c : (a & b) | (a & c) | (b & c);
    }
    /**
     * @protected
     * @ignore
     * @param {number} i
     * @param {number} e
     * @param {number} f
     * @param {number} g
     * @returns {number}
     */
    static ggj(i, e, f, g) {
        return i < 16 ? e ^ f ^ g : (e & f) | (~e & g);
    }
    /**
     * Process ready blocks
     *
     * @protected
     * @ignore
     * @param {number[]} block - Block
     */
    processBlock(block) {
        // Working variables
        let a = this.state.hash[0] | 0;
        let b = this.state.hash[1] | 0;
        let c = this.state.hash[2] | 0;
        let d = this.state.hash[3] | 0;
        let e = this.state.hash[4] | 0;
        let f = this.state.hash[5] | 0;
        let g = this.state.hash[6] | 0;
        let h = this.state.hash[7] | 0;
        // Expand message
        for (let i = 0; i < 132; i++) {
            if (i < 16) {
                this.W[i] = block[i] | 0;
            }
            else if (i < 68) {
                this.W[i] = Sm3.p1(this.W[i - 16] ^ this.W[i - 9] ^ rotateLeft(this.W[i - 3], 15)) ^
                    rotateLeft(this.W[i - 13], 7) ^ this.W[i - 6];
            }
            else {
                this.W[i] = this.W[i - 68] ^ this.W[i - 64];
            }
        }
        // Calculate hash
        for (let i = 0; i < this.options.rounds; i++) {
            let ss1 = rotateLeft((rotateLeft(a, 12) + e + rotateLeft(Sm3.tj(i), i % 32)) | 0, 7);
            let ss2 = ss1 ^ rotateLeft(a, 12);
            let tt1 = (Sm3.ffj(i, a, b, c) + d + ss2 + this.W[i + 68]) | 0;
            let tt2 = (Sm3.ggj(i, e, f, g) + h + ss1 + this.W[i]) | 0;
            d = c;
            c = rotateLeft(b, 9);
            b = a;
            a = tt1;
            h = g;
            g = rotateLeft(f, 19);
            f = e;
            e = Sm3.p0(tt2);
        }
        this.state.hash[0] = this.state.hash[0] ^ a;
        this.state.hash[1] = this.state.hash[1] ^ b;
        this.state.hash[2] = this.state.hash[2] ^ c;
        this.state.hash[3] = this.state.hash[3] ^ d;
        this.state.hash[4] = this.state.hash[4] ^ e;
        this.state.hash[5] = this.state.hash[5] ^ f;
        this.state.hash[6] = this.state.hash[6] ^ g;
        this.state.hash[7] = this.state.hash[7] ^ h;
    }
    /**
     * Finalize hash and return result
     *
     * @returns {Uint8Array}
     */
    finalize() {
        this.addPaddingISO7816(this.state.message.length < 56 ?
            56 - this.state.message.length | 0 :
            120 - this.state.message.length | 0);
        this.addLengthBits();
        this.process();
        return this.getStateHash((this.options.length / 32) | 0);
    }
}
exports.Sm3 = Sm3;
function bytesToHex(bytes) {
    for (var hex = [], i = 0; i < bytes.length; i++) {
        hex.push((bytes[i] >>> 4).toString(16));
        hex.push((bytes[i] & 0xF).toString(16));
    }
    return hex.join("");
}
/**
 * Creates a 32 byte SM3 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @param {number?} rounds - cycles (default 64)
 * @returns `string|Uint8Array|Buffer`
 */
function _SM3(message, format = arrayType(), rounds = 64) {
    const hash = new Sm3({ length: 256, rounds: rounds || 64 });
    hash.update(message);
    var digestbytes = hash.finalize();
    if (format == "hex") {
        return bytesToHex(digestbytes);
    }
    else if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    return digestbytes;
}
exports._SM3 = _SM3;
/**
 * Creates a 32 byte keyed SM3 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @param {number?} rounds - cycles (default 64)
 * @returns `string|Uint8Array|Buffer`
 */
function SM3_HMAC(message, key, format = arrayType(), rounds = 64) {
    const key_length = 64;
    const hash_len = 64;
    key = Hasher.convertToUint8Array(key);
    message = Hasher.convertToUint8Array(message);
    if (key.length > key_length) {
        key = _SM3(key, "array", rounds);
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
    result.set(_SM3(msg, "array", rounds), key_length);
    var digestbytes = _SM3(result, "array", rounds);
    if (format == "hex") {
        return bytesToHex(digestbytes);
    }
    else if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    return digestbytes;
}
exports.SM3_HMAC = SM3_HMAC;
/**
 * Static class of all SM3 functions and classes
 */
class SM3 {
    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST() {
        return [
            "SM3",
            "SM3_HMAC"
        ];
    }
}
exports.SM3 = SM3;
SM3.Sm3 = Sm3;
SM3.SM3 = _SM3;
SM3.SM3_HMAC = SM3_HMAC;
;
//# sourceMappingURL=SM3.js.map