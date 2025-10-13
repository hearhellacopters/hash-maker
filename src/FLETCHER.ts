export function fletcher16(data:Buffer|Uint8Array, sum1:number = 0, sum2:number = 0) {
    const len = data.length;
    for (let index = 0; index < len; ++index ){
        sum1 = (sum1 + data[index]) % 0xFF;
        sum2 = (sum2 + sum1) % 0xFF;
    }
    return (sum2 << 8) | sum1;
}

export function fletcher32(data:Buffer|Uint8Array, sum1 = 0, sum2 = 0) {
    const len = data.length;
    for (let index = 0; index < len; ++index ){
        sum1 = (sum1 + data[index]) % 0xFFFF;
        sum2 = (sum2 + sum1) % 0xFFFF;
    }
	return (sum1 << 16 | sum2);
}

export function fletcher64(data:Buffer|Uint8Array, sum1 = BigInt(0), sum2 = BigInt(0)) {
    const len = data.length;
    for (let index = 0; index < len; ++index ){
        sum1 = (sum1 + BigInt(data[index])) % BigInt(0xFFFFFFFF);
        sum2 = (sum2 + sum1) % BigInt(0xFFFFFFFF);
    }
	return (sum2 << BigInt(32)) | sum1;
}

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
}

function formatMessage(message: InputData): Uint8Array|Buffer {
    if (message === undefined) {
        return new Uint8Array(0);
    }

    if (typeof message === 'string') {
        return strToUint8Array(message);
    }

    if (message instanceof Uint8Array || Buffer.isBuffer(message)) {
        return message as Uint8Array;
    }

    throw new Error('input is invalid type');
}

// Input types
type InputData = string | Uint8Array | Buffer;

/**
 * Creates an Fletcher16 number of the message.
 * 
 * @param {InputData} message - Message to hash
 * @param {number?} seed - starting 16 bit number
 * @returns `number`
 */
export function FLETCHER16(message: InputData, seed:number = 0): number{
    var sum1 = (seed >> 8) & 0xFF;
    var sum2 = seed & 0xFF;
    return fletcher16(formatMessage(message), sum1, sum2);
};

/**
 * Creates an Fletcher32 number of the message.
 * 
 * @param {InputData} message - Message to hash
 * @param {number?} seed - starting 32 bit number
 * @returns `number`
 */
export function FLETCHER32(message: InputData, seed:number = 0): number{
    var sum1 = (seed >> 16) & 0xFFFF;
    var sum2 = seed & 0xFFFF;
    return fletcher32(formatMessage(message), sum1, sum2);
};

/**
 * Creates an Fletcher64 bigint of the message.
 * 
 * @param {InputData} message - Message to hash
 * @param {bigint?} seed - starting 64 bit number
 * @returns `bigint`
 */
export function FLETCHER64(message: InputData, seed:bigint = BigInt(0)): bigint{
    const sum1 = (seed >> BigInt(32));
    const sum2 = seed & BigInt(0xffffffff);
    return fletcher64(formatMessage(message),sum1,sum2);
};

/**
 * Static class of all FLECTHER functions
 */
export class FLETCHER {
    static FLETCHER16 = FLETCHER16;
    static FLETCHER32 = FLETCHER32;
    static FLETCHER64 = FLETCHER64;
    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST() {
        return [
            "FLETCHER16",
            "FLETCHER32",
            "FLETCHER64",
        ]
    }
}