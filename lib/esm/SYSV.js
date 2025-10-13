"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SYSV = exports.Sysv = void 0;
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
;
/**
 * System V (SYSV) 16 bit number of the message.
 *
 * @param {InputData} message - Message to check
 * @param {number?} seed - starting value
 * @returns `number`
 */
function Sysv(message, seed = 0) {
    message = formatMessage(message);
    const MOD_16 = BigInt(1 << 16);
    const MOD_32 = BigInt(1 << 32);
    let s = BigInt(seed);
    for (let byte of message) {
        s = BigInt.asUintN(64, s + BigInt(byte));
    }
    const r = (s % MOD_16) + ((s % MOD_32) / MOD_16);
    const cksum = (r % MOD_16) + (r / MOD_16);
    return Number(cksum);
}
exports.Sysv = Sysv;
;
/**
 * Static class of all SYSV functions and classes
 */
class SYSV {
    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST() {
        return [
            "SYSV"
        ];
    }
}
exports.SYSV = SYSV;
SYSV.SYSV = Sysv;
//# sourceMappingURL=SYSV.js.map