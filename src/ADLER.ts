function adler(buf:Buffer|Uint8Array, sum:number = 1){
    var BASE = 65521;
    var NMAX = 5552;
	if (sum == undefined || sum == null)
		sum = 1;

	var a = sum & 0xFFFF,
		b = (sum >>> 16) & 0xFFFF,
		i = 0,
		max = buf.length,
		n;

	while (i < max)
	{
		n = Math.min(NMAX, max - i);

		do
		{
			a += buf[i++]<<0;
			b += a;
		}
		while (--n);

		a %= BASE;
		b %= BASE;
	}

	return ((b << 16) | a) >>> 0;
};

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

// Input types
type InputData = string | Uint8Array | Buffer;

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

/**
 * Creates an Adler32 number of the message.
 * 
 * @param {InputData} message - Message to hash
 * @param {number?} seed - starting value
 * @returns `number`
 */
export function _ADLER32(message: InputData, seed: number = 1): number{
    message = formatMessage(message);
    return adler(message, seed);
}

/**
 * Static class of all ADLER functions
 */
export class ADLER {
    static ADLER32 = _ADLER32;
    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST() {
        return [
            "ADLER32"
        ]
    }
};