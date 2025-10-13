"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.LCR = exports.Lcr = void 0;
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
 * Creates Longitudinal Redundancy Checksum as an 8 bit number of the message.
 *
 * @param {InputData} message - Message to hash
 * @param {number?} seed - starting value
 * @returns `number`
 */
function Lcr(message, seed = 0) {
    message = formatMessage(message);
    let lrc = seed & 0xFF;
    for (let i = 0; i < message.length; i++) {
        const b = message[i];
        lrc = (lrc + b) & 0xFF;
    }
    lrc = (((lrc ^ 0xFF) + 1) & 0xFF);
    return lrc;
}
exports.Lcr = Lcr;
/**
 * Static class of all LCR functions
 */
class LCR {
    /**
     * List of all hashes in class
     */
    static get FUNCTION_LIST() {
        return [
            "LCR"
        ];
    }
}
exports.LCR = LCR;
LCR.LCR = Lcr;
;
//# sourceMappingURL=LCR.js.map