"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CRC16 = exports.CRC3 = exports.CRC32 = void 0;
/**
 * Cyclic Redundancy Check 32
 * @param {string|Uint8Array|Buffer} message - Message as string, Uint8Array or Buffer
 * @returns number
 */
function CRC32(message, options) {
    var bytes;
    if (typeof message == "string") {
        bytes = stringToBytes(message);
    }
    else if (arraybuffcheck(message)) {
        bytes = message;
    }
    else {
        throw new Error("Message must be either String, Buffer or Uint8Array");
    }
    const divisor = 0xEDB88320;
    let crc = 0xFFFFFFFF;
    for (const byte of bytes) {
        crc = (crc ^ byte);
        for (let i = 0; i < 8; i++) {
            if (crc & 1) {
                crc = (crc >>> 1) ^ divisor;
            }
            else {
                crc = crc >>> 1;
            }
        }
    }
    crc = toUnsignedInt32(crc ^ 0xFFFFFFFF);
    if (options && options.asBuffer) {
        const buff = Buffer.alloc(4);
        buff[0] = (crc >> 24) & 0xFF;
        buff[1] = (crc >> 16) & 0xFF;
        buff[2] = (crc >> 8) & 0xFF;
        buff[3] = crc & 0xFF;
        return buff;
    }
    else if (options && options.asArray) {
        const buff = new Uint8Array(4);
        buff[0] = (crc >> 24) & 0xFF;
        buff[1] = (crc >> 16) & 0xFF;
        buff[2] = (crc >> 8) & 0xFF;
        buff[3] = crc & 0xFF;
        return buff;
    }
    else if (options && options.asHex) {
        const buff = new Uint8Array(4);
        buff[0] = (crc >> 24) & 0xFF;
        buff[1] = (crc >> 16) & 0xFF;
        buff[2] = (crc >> 8) & 0xFF;
        buff[3] = crc & 0xFF;
        return bytesToHex(buff);
    }
    return crc;
}
exports.CRC32 = CRC32;
/**
 * Cyclic Redundancy Check 3
 * @param {string|Uint8Array|Buffer} message - Message as string, Uint8Array or Buffer
 * @returns number
 */
function CRC3(message, options) {
    var bytes;
    if (typeof message == "string") {
        bytes = stringToBytes(message);
    }
    else if (arraybuffcheck(message)) {
        bytes = message;
    }
    else {
        throw new Error("Message must be either String, Buffer or Uint8Array");
    }
    const divisor = 0b111;
    let crc = 0b000;
    for (const byte of bytes) {
        let reminder = byte;
        for (let i = 0; i < 8; i++) {
            if (reminder & 1) {
                reminder = (reminder >>> 1) ^ divisor;
            }
            else {
                reminder = reminder >>> 1;
            }
        }
        // final division
        crc = crc ^ reminder;
    }
    if (options && options.asBuffer) {
        const buff = Buffer.alloc(1);
        buff[0] = crc & 0xFF;
    }
    else if (options && options.asArray) {
        const buff = new Uint8Array(1);
        buff[0] = crc & 0xFF;
        return buff;
    }
    else if (options && options.asHex) {
        const buff = new Uint8Array(1);
        buff[0] = crc & 0xFF;
        return bytesToHex(buff);
    }
    return crc;
}
exports.CRC3 = CRC3;
/**
 * Cyclic Redundancy Check 16
 * @param {string|Uint8Array|Buffer} message - Message as string, Uint8Array or Buffer
 * @returns number
 */
function CRC16(message, options) {
    var bytes;
    const crc_tab16 = new Uint16Array(256);
    if (typeof message == "string") {
        bytes = stringToBytes(message);
    }
    else if (arraybuffcheck(message)) {
        bytes = message;
    }
    else {
        throw new Error("Message must be either String, Buffer or Uint8Array");
    }
    var crc = new Uint16Array(1);
    const c = new Uint16Array(1);
    for (var i = 0; i < 256; i++) {
        crc[0] = 0;
        c[0] = i;
        for (var j = 0; j < 8; j++) {
            if ((crc[0] ^ c[0]) & 0x0001)
                crc[0] = (crc[0] >> 1) ^ 0xA001;
            else
                crc[0] = crc[0] >> 1;
            c[0] = c[0] >> 1;
        }
        crc_tab16[i] = crc[0];
    }
    var num_bytes = bytes.length;
    crc[0] = 0x0000;
    var ptr = 0;
    for (var a = 0; a < num_bytes; a++) {
        crc[0] = (crc[0] >> 8) ^ crc_tab16[(crc[0] ^ bytes[ptr]) & 0x00FF];
        ptr++;
    }
    if (options && options.asBuffer) {
        const buff = Buffer.alloc(2);
        buff[0] = (crc[0] >> 8) & 0xFF;
        buff[1] = crc[0] & 0xFF;
    }
    else if (options && options.asArray) {
        const buff = new Uint8Array(2);
        buff[0] = (crc[0] >> 8) & 0xFF;
        buff[1] = crc[0] & 0xFF;
        return buff;
    }
    else if (options && options.asHex) {
        const buff = new Uint8Array(2);
        buff[0] = (crc[0] >> 8) & 0xFF;
        buff[1] = crc[0] & 0xFF;
        return bytesToHex(buff);
    }
    return crc[0];
}
exports.CRC16 = CRC16;
function bytesToHex(bytes) {
    for (var hex = [], i = 0; i < bytes.length; i++) {
        hex.push((bytes[i] >>> 4).toString(16));
        hex.push((bytes[i] & 0xF).toString(16));
    }
    return hex.join("");
}
function toUnsignedInt32(n) {
    if (n >= 0) {
        return n;
    }
    return 0xFFFFFFFF - (n * -1) + 1;
}
function stringToBytes(str) {
    for (var bytes = [], i = 0; i < str.length; i++) {
        bytes.push(str.charCodeAt(i) & 0xFF);
    }
    return bytes;
}
function isBuffer(obj) {
    return (typeof Buffer !== 'undefined' && obj instanceof Buffer);
}
function arraybuffcheck(obj) {
    return obj instanceof Uint8Array || isBuffer(obj);
}
//# sourceMappingURL=CRC32.js.map