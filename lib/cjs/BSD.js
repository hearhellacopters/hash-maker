"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BSD = exports.Bsd = void 0;
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
    if (message instanceof Uint8Array || Buffer.isBuffer(message)) {
        return message;
    }
    throw new Error('input is invalid type');
}
/**
 * Create Berkeley Software Distribution (BSD) a 16 bit checksum of the message.
 *
 * @param {InputData} message - Message to hash
 * @param {number?} seed - starting value
 * @returns `number
 */
function Bsd(message, seed = 0) {
    message = formatMessage(message);
    var checksum = seed; /* The checksum mod 2^16. */
    for (let ch = 0; ch < message.length; ch++) {
        checksum = (checksum >> 1) + ((checksum & 1) << 15);
        checksum += ch;
        checksum &= 0xffff; /* Keep it within bounds. */
    }
    return checksum;
}
exports.Bsd = Bsd;
/**
 * Static class of all BSD functions
 */
class BSD {
    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST() {
        return [
            "BSD"
        ];
    }
}
exports.BSD = BSD;
BSD.BSD = Bsd;
//# sourceMappingURL=BSD.js.map