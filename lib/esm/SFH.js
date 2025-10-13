"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SFH = void 0;
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
 * Returns a 32-bit digest of the given message using the
 * {@link http://www.azillionmonkeys.com/qed/hash.html SuperFastHash}
 * algorithm.
 *
 * @param {Uint8Array} message The message.
 *
 * @returns `number` The 32-bit digest.
 */
function SuperFastHash(message) {
    let length = message.byteLength;
    let index = 0;
    let digest = length;
    for (let n = length >> 2; n > 0; n--) {
        digest = digest + (message[index++] | message[index++] << 8) >>> 0;
        digest ^= digest << 16 >>> 0 ^
            (message[index++] | message[index++] << 8) << 11;
        digest = digest + (digest >>> 11) >>> 0;
    }
    switch (length & 3) {
        case 3:
            digest = digest + (message[index++] | message[index++] << 8) >>> 0;
            digest ^= digest << 16 >>> 0;
            digest ^= message[index++] << 18;
            digest = digest + (digest >>> 11) >>> 0;
            break;
        case 2:
            digest = digest + (message[index++] | message[index++] << 8) >>> 0;
            digest ^= digest << 11 >>> 0;
            digest = digest + (digest >>> 17) >>> 0;
            break;
        case 1:
            digest = digest + message[index++] >>> 0;
            digest ^= digest << 10 >>> 0;
            digest = digest + (digest >>> 1) >>> 0;
    }
    digest ^= digest << 3 >>> 0;
    digest = digest + (digest >>> 5) >>> 0;
    digest ^= digest << 4 >>> 0;
    digest = digest + (digest >>> 17) >>> 0;
    digest ^= digest << 25 >>> 0;
    digest = digest + (digest >>> 6) >>> 0;
    return (digest | 0) >>> 0;
}
/**
 * Creates Super Fast Hash 32 bit checksum.
 *
 * @param message - Message to hash
 * @returns `number`
 */
function _SFH(message) {
    return SuperFastHash(formatMessage(message));
}
/**
 * Static class of all Super Fast Hash functions and classes
 */
class SFH {
    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST() {
        return [
            "SFH"
        ];
    }
}
exports.SFH = SFH;
SFH.SFH = _SFH;
//# sourceMappingURL=SFH.js.map