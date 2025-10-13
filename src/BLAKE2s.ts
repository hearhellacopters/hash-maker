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

function formatMessage(message?: InputData): Uint8Array | Buffer {
    if (message === undefined) {
        throw new Uint8Array(0);
    }

    if (typeof message === 'string') {
        return strToUint8Array(message);
    }

    if (message instanceof Uint8Array || Buffer.isBuffer(message)) {
        return message;
    }

    throw new Error('input is invalid type');
}

function B2S_GET32(v: Uint8Array, i: number) {
    return v[i] ^ (v[i + 1] << 8) ^ (v[i + 2] << 16) ^ (v[i + 3] << 24);
}

function B2S_G(a: number, b: number, c: number, d: number, x: number, y: number) {
    v[a] = v[a] + v[b] + x;
    v[d] = ROTR32(v[d] ^ v[a], 16);
    v[c] = v[c] + v[d];
    v[b] = ROTR32(v[b] ^ v[c], 12);
    v[a] = v[a] + v[b] + y;
    v[d] = ROTR32(v[d] ^ v[a], 8);
    v[c] = v[c] + v[d];
    v[b] = ROTR32(v[b] ^ v[c], 7);
}

function ROTR32(x: number, y: number) {
    return (x >>> y) ^ (x << (32 - y));
}

var BLAKE2S_IV: Uint32Array;

var SIGMA: Uint8Array;

var v: Uint32Array;
var m: Uint32Array;

var inited = false;

/**
 * Static class of all Blake2s functions
 */
export class Blake2s {
    h: Uint32Array;
    b: Uint8Array;
    c: number;
    t: number;
    outlen: number;
    constructor(outlen: number, key?: InputData) {
        if (!inited) {
            BLAKE2S_IV = new Uint32Array([
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
            ]);
            SIGMA = new Uint8Array([
                 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
                14, 10,  4,  8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
                11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
                7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
                9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
                2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
                12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
                13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
                6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
                10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0
            ]);
            v = new Uint32Array(16);
            m = new Uint32Array(16);
            inited = true;
        }
        if (key) {
            key = formatMessage(key);
        }
        if (!(outlen > 0 && outlen <= 32)) {
            throw new Error('Incorrect output length, should be in [1, 32]');
        }
        const keylen = key ? key.length : 0;
        if (key && !(keylen > 0 && keylen <= 32)) {
            throw new Error('Incorrect key length, should be in [1, 32]');
        }

        this.h = new Uint32Array(BLAKE2S_IV),
            this.b = new Uint8Array(64),
            this.c = 0,
            this.t = 0,
            this.outlen = outlen
        this.h[0] ^= 0x01010000 ^ (keylen << 8) ^ outlen;

        if (keylen > 0) {
            this.blake2sUpdate(key as Buffer | Uint8Array);
            this.c = 64;
        }

        return this;
    }

    blake2sUpdate(input: Uint8Array | Buffer) {
        for (let i = 0; i < input.length; i++) {
            if (this.c === 64) {
                this.t += this.c;
                this.blake2sCompress(false);
                this.c = 0;
            }
            this.b[this.c++] = input[i];
        }
    }

    blake2sCompress(last: boolean) {
        let i = 0
        for (i = 0; i < 8; i++) {
            v[i] = this.h[i];
            v[i + 8] = BLAKE2S_IV[i];
        }

        v[12] ^= this.t;
        v[13] ^= this.t / 0x100000000;
        if (last) {
            v[14] = ~v[14];
        }

        for (i = 0; i < 16; i++) {

            m[i] = B2S_GET32(this.b, 4 * i);
        }

        for (i = 0; i < 10; i++) {
            B2S_G(0, 4, 8, 12, m[SIGMA[i * 16 + 0]], m[SIGMA[i * 16 + 1]]);
            B2S_G(1, 5, 9, 13, m[SIGMA[i * 16 + 2]], m[SIGMA[i * 16 + 3]]);
            B2S_G(2, 6, 10, 14, m[SIGMA[i * 16 + 4]], m[SIGMA[i * 16 + 5]]);
            B2S_G(3, 7, 11, 15, m[SIGMA[i * 16 + 6]], m[SIGMA[i * 16 + 7]]);
            B2S_G(0, 5, 10, 15, m[SIGMA[i * 16 + 8]], m[SIGMA[i * 16 + 9]]);
            B2S_G(1, 6, 11, 12, m[SIGMA[i * 16 + 10]], m[SIGMA[i * 16 + 11]]);
            B2S_G(2, 7, 8, 13, m[SIGMA[i * 16 + 12]], m[SIGMA[i * 16 + 13]]);
            B2S_G(3, 4, 9, 14, m[SIGMA[i * 16 + 14]], m[SIGMA[i * 16 + 15]]);
        }

        for (i = 0; i < 8; i++) {
            this.h[i] ^= v[i] ^ v[i + 8];
        }
    }

    blake2sFinal() {
        this.t += this.c;
        while (this.c < 64) {
            this.b[this.c++] = 0;
        }
        this.blake2sCompress(true);

        const out = new Uint8Array(this.outlen);
        for (let i = 0; i < this.outlen; i++) {
            out[i] = (this.h[i >> 2] >> (8 * (i & 3))) & 0xff;
        }
        return out;
    }
}

function blake2sHex(output: Uint8Array) {
    return Array.from(output)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

function arrayType():OutputFormat{
	if (typeof window !== 'undefined') {
		return "array" as OutputFormat;
	} else {
    return "buffer" as OutputFormat;
	}
};

/**
 * Creates a vary length BLAKE2s of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {InputData?} key - key for hash
 * @param {number?} bitLen - length of hash (default 32 bytes)
 * @returns `string|Uint8Array|Buffer`
 */
export function BLAKE2s(message: InputData, format: OutputFormat = arrayType(), key?: InputData, bitLen: 256| 224 = 256): string | Uint8Array | Buffer {
    message = formatMessage(message);
    const len = bitLen ? bitLen / 8 : 256;
    const hash = new Blake2s(len, key);
    hash.blake2sUpdate(message);
    const digestbytes = hash.blake2sFinal();
    if(format == "hex"){
         return blake2sHex(digestbytes);
    } else if(format == "buffer"){
        return Buffer.from(digestbytes);
    }
    return digestbytes;
}

/**
 * Creates a 32 byte BLAKE2s of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {InputData?} key - key for hash
 * @returns `string|Uint8Array|Buffer`
 */
export function BLAKE2s256(message: InputData, format: OutputFormat = arrayType(), key?: InputData): string | Uint8Array | Buffer {
    return BLAKE2s(message, format, key, 256);
}

/**
 * Creates a 32 byte keyed BLAKE2s of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - key for hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function BLAKE2s256_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType()): string | Uint8Array | Buffer {
    return BLAKE2s(message, format, key, 256);
}

/**
 * Creates a 28 byte BLAKE2s of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {InputData?} key - key for hash
 * @returns `string|Uint8Array|Buffer`
 */
export function BLAKE2s224(message: InputData, format: OutputFormat = arrayType(), key?: InputData): string | Uint8Array | Buffer {
    return BLAKE2s(message, format, key, 224);
}

/**
 * Creates a 28 byte keyed BLAKE2s of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - key for hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function BLAKE2s224_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType()): string | Uint8Array | Buffer {
    return BLAKE2s(message, format, key, 224);
}

/**
 * Creates a very length keyed BLAKE2s of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - key for hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {number?} bitLen - length of hash (default 256 bits or 32 bytes)
 * @returns `string|Uint8Array|Buffer`
 */
export function BLAKE2s_HMAC(message: InputData, key?: InputData, format: OutputFormat = arrayType(), bitLen: 224 | 256 = 256) {
    message = formatMessage(message);
    const len = bitLen ? bitLen / 8 : 32;
    const hash = new Blake2s(len, key);
    hash.blake2sUpdate(message);
    const digestbytes = hash.blake2sFinal();
    if(format == "hex"){
         return blake2sHex(digestbytes);
    } else if(format == "buffer"){
        return Buffer.from(digestbytes);
    }
    return digestbytes;
}