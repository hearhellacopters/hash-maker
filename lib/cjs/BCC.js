"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BCC = exports.bcc = void 0;
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
 * Creates Block Check Character 8 bit number of the message.
 *
 * @param {InputData} message - Message to hash
 * @param {numer?} seed - starting value
 * @returns `number`
 */
function bcc(message, seed = 0) {
    message = formatMessage(message);
    let number = seed;
    for (let i = 0; i < message.length; i++) {
        number ^= message[i];
    }
    return number;
}
exports.bcc = bcc;
;
/**
* Static class of all BCC functions
*/
class BCC {
    /**
     * List of all hashes in class
     */
    static get FUNCTION_LIST() {
        return [
            "BCC"
        ];
    }
}
exports.BCC = BCC;
BCC.BCC = bcc;
;
//# sourceMappingURL=BCC.js.map