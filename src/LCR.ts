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
}

function formatMessage(message: InputData): Uint8Array|Buffer {
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
export function Lcr(message: InputData, seed:number = 0): number {
    message = formatMessage(message);
    let lrc = seed & 0xFF;
    for (let i = 0; i < message.length; i++) {
        const b = message[i];
        lrc = (lrc + b) & 0xFF;
    }
    lrc = (((lrc ^ 0xFF) + 1) & 0xFF);
    return lrc;
}

/**
 * Static class of all LCR functions
 */
export class LCR {
    static LCR = Lcr;
    /**
     * List of all hashes in class
     */
    static get FUNCTION_LIST() {
        return [
            "LCR"
        ]
    }
};
