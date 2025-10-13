// Input types
type InputData = string | Uint8Array | Buffer;

// Output formats
type OutputFormat = 'hex' | 'array' | 'buffer';

function strToUint8Array(str: string): Uint8Array {
    // Check if the browser supports TextDecoder API
    try {
        const encoder = new TextEncoder();

        // Encode the string and return as a Uint8Array
        return encoder.encode(str);
    } catch (e) { }

    // Fallback for older systems without TextDecoder support
    let result = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
        const codePoint = str.charCodeAt(i);
        if (codePoint <= 255) {
            result[i] = codePoint;
        } else {
            result.set([codePoint >> 8, codePoint & 0xFF], i * 2);
        }
    }
    return result;
};

function formatMessage(message: InputData): Uint8Array {
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
};

function arraycopy(
    src: ArrayBufferView,
    srcPos: number = 0,
    dst: ArrayBufferView,
    destPos: number = 0,
    length: number) {
    // Validate inputs
    const srcbyteLength = src.byteLength;
    if (srcPos + length > src.byteLength) {
        throw new Error(`memcpy${length}: Source buffer too small, ${srcbyteLength} of ${srcPos + length}`);
    }
    const dstbyteLength = dst.byteLength;
    if (destPos + length > dstbyteLength) {
        throw new Error(`memcpy${length}: Destination buffer too small, ${dstbyteLength} of ${destPos + length}`);
    }

    const dstView = new Uint8Array(dst.buffer, dst.byteOffset + destPos, length);
    const srcView = new Uint8Array(src.buffer, src.byteOffset + srcPos, length);

    dstView.set(srcView);
};

function arrayConvert(
    src: ArrayBufferView,
    type: Int8ArrayConstructor | Uint8ArrayConstructor | Uint8ClampedArrayConstructor | Int16ArrayConstructor | Uint16ArrayConstructor | Int32ArrayConstructor | Uint32ArrayConstructor | Float32ArrayConstructor | Float64ArrayConstructor | BigInt64ArrayConstructor | BigUint64ArrayConstructor,
    byteLength: number) {
    const array = new Uint8Array(byteLength);
    const input = new Uint8Array(src.buffer);
    for (let i = 0; i < input.length; i++) {
        array[i] = input[i];
    }
    return new type(array.buffer, 0, byteLength / type.BYTES_PER_ELEMENT);
}

function tcp_sum_calc(
    buff: Uint8Array,
    src_addr: Uint8Array  /*4 bytes*/,
    dest_addr: Uint8Array /*4 bytes*/,

) {
    const prot_tcp: number = 6;
    let sum: number = 0;
    let len_tcp = buff.byteLength;

    // Sum 16-bit words from buff (with pad if needed, without modifying buff)
    for (let i = 0; i < len_tcp; i += 2) {
        const high: number = (i < len_tcp) ? buff[i] : 0;
        const low: number = (i + 1 < len_tcp) ? buff[i + 1] : 0;
        const word16: number = (high << 8) + low;
        sum += word16;
    }

    // Sum source address (two 16-bit words)
    for (let i = 0; i < 4; i += 2) {
        const word16: number = (src_addr[i] << 8) + src_addr[i + 1];
        sum += word16;
    }

    // Sum destination address (two 16-bit words)
    for (let i = 0; i < 4; i += 2) {
        const word16: number = (dest_addr[i] << 8) + dest_addr[i + 1];
        sum += word16;
    }

    // Add protocol and TCP length
    sum += prot_tcp + len_tcp;

    // Fold the sum (add carries)
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // One's complement
    sum = (~sum) & 0xFFFF;

    return sum;
};

/**
 * TCP checksum
 * 
 * @param {InputData} message - Message to check
 * @param {InputData} srcAddr - 4 byte source IP address
 * @param {InputData} destAddr - 4 byte destnation IP address
 * @returns `number`
 */
export function SUM_TCP(message: InputData, srcAddr: InputData, destAddr: InputData) {
    message = formatMessage(message);
    srcAddr = formatMessage(srcAddr);
    destAddr = formatMessage(destAddr);
    var len_tcp = message.byteLength;
    if (len_tcp % 2) {
        const buffer = new Uint8Array(len_tcp + 1);
        arraycopy(message, 0, buffer, 0, len_tcp + 1);
        message = buffer;
        len_tcp++;
    }

    if (srcAddr.byteLength != 4) {
        const buffer2 = new Uint8Array(4);
        arraycopy(srcAddr, 0, buffer2, 0, 4);
        srcAddr = buffer2;
    }

    if (destAddr.byteLength != 4) {
        const buffer3 = new Uint8Array(4);
        arraycopy(destAddr, 0, buffer3, 0, 4);
        destAddr = buffer3;
    }

    return tcp_sum_calc(message, srcAddr, destAddr);
}

// #region Math Sum

/**
 * Sum of the message as 8 bits
 * 
 * @param {InputData} message - Message to check
 * @returns `number`
 */
export function SUM8(message: InputData): number {
    message = formatMessage(message);
    const sum = new Uint8Array(1);
    for (let i = 0; i < message.length; i++) {
        sum[0] += message[i];
    }
    return sum[0];
};

/**
 * Sum of the message as 16 bits
 * 
 * @param {InputData} message - Message to check
 * @returns `number`
 */
export function SUM16(message: InputData): number {
    message = formatMessage(message);
    var buf = arrayConvert(message, Uint16Array, message.byteLength + message.byteLength % 2);
    const sum = new Uint16Array(1);
    for (let i = 0; i < buf.length; i++) {
        sum[0] += buf[i] as number;
    }
    return sum[0];
};

/**
 * Sum of the message as 16 bits
 * 
 * @param {InputData} message - Message to check
 * @returns `number`
 */
export function SUM24(message: InputData) {
    message = formatMessage(message);
    let hash = 0;
    for (let i = 0; i < message.length; i++) {
        hash = (message[i] + hash) % 16777216;
    }
    // Limit to 24 bits (0xFFFFFF)
    return hash & 0xFFFFFF;
};

/**
 * Sum of the message as 32 bits
 * 
 * @param {InputData} message - Message to check
 * @returns `number`
 */
export function SUM32(message: InputData): number {
    message = formatMessage(message);
    var buf = arrayConvert(message, Uint32Array, message.byteLength + message.byteLength % 2);
    const sum = new Uint32Array(1);
    for (let i = 0; i < buf.length; i++) {
        sum[0] += buf[i] as number;
    }
    return sum[0];
};

// #region Math Xor

/**
 * XOR of the message as 8 bits
 * 
 * @param {InputData} message - Message to check
 * @returns `number`
 */
export function XOR8(message: InputData): number {
    message = formatMessage(message);
    const sum = new Uint8Array(1);
    for (let i = 0; i < message.length; i++) {
        sum[0] ^= message[i];
    }
    return sum[0];
};

/**
 * XOR of the message as 16 bits
 * 
 * @param {InputData} message - Message to check
 * @returns `number`
 */
export function XOR16(message: InputData): number {
    message = formatMessage(message);
    var buf = arrayConvert(message, Uint16Array, message.byteLength + message.byteLength % 2);
    const sum = new Uint16Array(1);
    for (let i = 0; i < buf.length; i++) {
        sum[0] ^= buf[i] as number;
    }
    return sum[0];
};

/**
 * XOR of the message as 24 bits
 * 
 * @param {InputData} message - Message to check
 * @returns `number`
 */
export function XOR24(message: InputData) {
    message = formatMessage(message);
    let hash = 0;
    for (let i = 0; i < message.length; i++) {
        hash = (message[i] ^ hash) % 16777216;
    }
    // Limit to 24 bits (0xFFFFFF)
    return hash & 0xFFFFFF;
}

/**
 * XOR of the message as 32 bits
 * 
 * @param {InputData} message - Message to check
 * @returns `number`
 */
export function XOR32(message: InputData): number {
    message = formatMessage(message);
    var buf = arrayConvert(message, Uint32Array, message.byteLength + message.byteLength % 2);
    const sum = new Uint32Array(1);
    for (let i = 0; i < buf.length; i++) {
        sum[0] ^= buf[i] as number;
    }
    return sum[0];
};

/**
 * Static class of all Math like functions and classes
 */
export class MATH{
    static SUM8    = SUM8;
    static SUM16   = SUM16;
    static SUM24   = SUM24;
    static SUM32   = SUM32;
    static SUM_TCP = SUM_TCP;

    static XOR8  = XOR8;
    static XOR16 = XOR16;
    static XOR24 = XOR24;
    static XOR32 = XOR32;

    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST(){
        return [
            "SUM8",
            "SUM16",
            "SUM24",
            "SUM32",
            "SUM_TCP",

            "XOR8",
            "XOR16",
            "XOR24",
            "XOR32",
        ];
    }
}