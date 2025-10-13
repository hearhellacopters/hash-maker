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

// Output formats
type OutputFormat = 'hex' | 'array' | 'buffer';

interface Options {
    type: string,
    rounds: number
}

interface state {
    message: Uint8Array,
    length: number,
    hash: number[];
}

function arrayType():OutputFormat{
	if (typeof window !== 'undefined') {
		return "array" as OutputFormat;
	} else {
    	return "buffer" as OutputFormat;
	}
};

/**
 * Base hasher class
 * @interface
 */
class Hasher {
    unitSize: number;
    unitOrder: number;
    blockSize: number;
    blockSizeInBytes: number;
    options: Options;
    state: state = { message: new Uint8Array(), length: 0, hash: [] };
    /**
     * @param {Object} options
     * @constructor
     */
    constructor(options: Options = {type:"",rounds:10}) {
        /**
         * Size of unit in bytes (4 = 32 bits)
         * @type {number}
         */
        this.unitSize = 4;
        /**
         * Bytes order in unit
         *   0 - normal
         *   1 - reverse
         * @type {number}
         */
        this.unitOrder = 0;
        /**
         * Size of block in units
         * @type {number}
         */
        this.blockSize = 16;
        /**
         * Size of block in bytes
         * @type {number}
         */
        this.blockSizeInBytes = this.blockSize * this.unitSize;

        this.options = options;

        this.reset();
    }

    /**
     * Reset hasher to initial state
     */
    reset() {
        /**
         * All algorithm variables that changed during process
         * @protected
         * @type {Object}
         * @property {Uint8Array} state.message - Unprocessed Message
         * @property {number} state.length - Length of message in bytes
         */
        this.state.message = new Uint8Array(0);
        this.state.length = 0;
        this.state.hash = [];
    }

    /**
     * Return current state
     *
     * @returns {Object}
     */
    getState(): object {
        return JSON.parse(JSON.stringify({
            message: Array.from(this.state.message),
            length: this.state.length
        }));
    }

    /**
     * Set current state
     *
     * @param {Object} state
     */
    setState(state: state) {
        this.state = {
            message: new Uint8Array(state.message || []),
            length: state.length || 0,
            hash: []
        };
    }

    /**
     * Update message from binary data
     *
     * @param {InputData} message
     */
    update(message: InputData) {
        // Convert various input types to Uint8Array
        const data = Hasher.convertToUint8Array(message);

        // Append to existing message
        const newMessage = new Uint8Array(this.state.message.length + data.length);
        newMessage.set(this.state.message);
        newMessage.set(data, this.state.message.length);

        this.state.message = newMessage;
        this.state.length += data.length;
        this.process();
    }

    /**
     * Convert various input types to Uint8Array
     *
     * @private
     * @param {InputData?} data
     * @returns {Uint8Array}
     */
    static convertToUint8Array(data?: InputData): Uint8Array {
        if (data == undefined) {
            return new Uint8Array(0);
        }

        if (Buffer.isBuffer(data)) {
            return new Uint8Array(data);
        }

        if (data instanceof Uint8Array) {
            return data;
        }

        if (typeof data === 'string') {
            return strToUint8Array(data);
        }

        throw new Error('Unsupported input type for hash update');
    }

    /**
     * Process ready blocks
     *
     * @protected
     */
    process() {
    }

    /**
     * Finalize hash and return result
     *
     * @returns {Uint8Array}
     */
    finalize(): Uint8Array {
        return new Uint8Array(0);
    }

    /**
     * Get hash from state
     *
     * @protected
     * @param {number} [size=this.state.hash.length] - Limit hash size (in chunks)
     * @returns {Uint8Array}
     */
    getStateHash(size?: number): Uint8Array {
        return new Uint8Array(0);
    }

    /**
     * Add PKCS7 padding to message
     * Pad with bytes all of the same value as the number of padding bytes
     *
     * @protected
     * @param {number} length
     */
    addPaddingPKCS7(length: number) {
        const padding = new Uint8Array(length);
        padding.fill(length);
        this.state.message = this.concatUint8Arrays(this.state.message, padding);
    }

    /**
     * Add ISO7816-4 padding to message
     * Pad with 0x80 followed by zero bytes
     *
     * @protected
     * @param {number} length
     */
    addPaddingISO7816(length: number) {
        const padding = new Uint8Array(length);
        padding[0] = 0x80;
        this.state.message = this.concatUint8Arrays(this.state.message, padding);
    }

    /**
     * Add zero padding to message
     * Pad with 0x00 characters
     *
     * @protected
     * @param {number} length
     */
    addPaddingZero(length: number) {
        const padding = new Uint8Array(length);
        this.state.message = this.concatUint8Arrays(this.state.message, padding);
    }

    /**
     * Concatenate two Uint8Arrays
     *
     * @private
     * @param {Uint8Array} a
     * @param {Uint8Array} b
     * @returns {Uint8Array}
     */
    concatUint8Arrays(a: Uint8Array, b: Uint8Array): Uint8Array {
        const result = new Uint8Array(a.length + b.length);
        result.set(a);
        result.set(b, a.length);
        return result;
    }
}

/**
 * Hasher for 32 bit big endian blocks
 * @interface
 */
class Hasher32be extends Hasher {
    blockUnits: number[];
    /**
     * @param {Object} [options]
     */
    constructor(options?: Options) {
        super(options);

        /**
         * Reverse order of bytes
         * @type {number}
         */
        this.unitOrder = 1;
        /**
         * Current block (only for speed optimization)
         * @private
         * @type {number[]}
         */
        this.blockUnits = [];
    }

    /**
     * Process ready blocks
     *
     * @protected
     */
    process() {
        while (this.state.message.length >= this.blockSizeInBytes) {
            this.blockUnits = [];
            for (let b = 0; b < this.blockSizeInBytes; b += 4) {
                // Read 4 bytes in little-endian order
                this.blockUnits.push(
                    this.state.message[b] << 24 |
                    this.state.message[b + 1] << 16 |
                    this.state.message[b + 2] << 8 |
                    this.state.message[b + 3]
                );
            }
            // Remove processed block from message
            this.state.message = this.state.message.subarray(this.blockSizeInBytes);
            this.processBlock(this.blockUnits);
        }
    }

    /**
     * Process ready blocks
     *
     * @protected
     * @param {number[]} M
     */
    processBlock(M: number[]) {
    }

    /**
     * Get hash from state
     *
     * @protected
     * @param {number} [size=this.state.hash.length] - Limit hash size (in chunks)
     * @returns {Uint8Array}
     */
    getStateHash(size?: number): Uint8Array {
        size = size || this.state.hash.length;
        const hash = new Uint8Array(size * 4);
        for (let i = 0; i < size; i++) {
            const word = this.state.hash[i];
            hash[i * 4] = (word >> 24) & 0xff;
            hash[i * 4 + 1] = (word >> 16) & 0xff;
            hash[i * 4 + 2] = (word >> 8) & 0xff;
            hash[i * 4 + 3] = word & 0xff;
        }
        return hash;
    }

    /**
     * Add to message cumulative size of message in bits
     *
     * @protected
     */
    addLengthBits() {
        // Calculate length in bits (64-bit)
        const bitLength = BigInt(this.state.length) * BigInt(8);

        // Convert to 8 bytes (little-endian)
        const lengthBytes = new Uint8Array(8);
        lengthBytes[0] = Number((bitLength >> BigInt(56)) & BigInt(0xff));
        lengthBytes[1] = Number((bitLength >> BigInt(48)) & BigInt(0xff));
        lengthBytes[2] = Number((bitLength >> BigInt(40)) & BigInt(0xff));
        lengthBytes[3] = Number((bitLength >> BigInt(32)) & BigInt(0xff));
        lengthBytes[4] = Number((bitLength >> BigInt(24)) & BigInt(0xff));
        lengthBytes[5] = Number((bitLength >> BigInt(16)) & BigInt(0xff));
        lengthBytes[6] = Number((bitLength >> BigInt(8)) & BigInt(0xff));
        lengthBytes[7] = Number(bitLength & BigInt(0xff));

        this.state.message = this.concatUint8Arrays(this.state.message, lengthBytes);
    }
}

/**
 * Rotate 64bit to n bits right and return hi
 *
 * @param {number} hi
 * @param {number} lo
 * @param {number} n
 * @returns {number}
 */
function rotateRight64hi(hi: number, lo: number, n: number): number {
    if (n === 32) {
        return lo;
    }
    if (n > 32) {
        return rotateRight64hi(lo, hi, n - 32);
    }
    return ((hi >>> n) | (lo << (32 - n))) & (0xFFFFFFFF);
}

/**
 * Rotate 64bit to n bits right and return lo
 *
 * @param {number} hi
 * @param {number} lo
 * @param {number} n
 * @returns {number}
 */
function rotateRight64lo(hi: number, lo: number, n: number): number {
    if (n === 32) {
        return hi;
    }
    if (n > 32) {
        return rotateRight64lo(lo, hi, n - 32);
    }
    return ((lo >>> n) | (hi << (32 - n))) & (0xFFFFFFFF);
}

/** @type {number[]} */
const SBOX = new Array(256);
/** @type {number[]} */
const SBOX0 = [
    0x68, 0xd0, 0xeb, 0x2b, 0x48, 0x9d, 0x6a, 0xe4, 0xe3, 0xa3, 0x56, 0x81,
    0x7d, 0xf1, 0x85, 0x9e, 0x2c, 0x8e, 0x78, 0xca, 0x17, 0xa9, 0x61, 0xd5,
    0x5d, 0x0b, 0x8c, 0x3c, 0x77, 0x51, 0x22, 0x42, 0x3f, 0x54, 0x41, 0x80,
    0xcc, 0x86, 0xb3, 0x18, 0x2e, 0x57, 0x06, 0x62, 0xf4, 0x36, 0xd1, 0x6b,
    0x1b, 0x65, 0x75, 0x10, 0xda, 0x49, 0x26, 0xf9, 0xcb, 0x66, 0xe7, 0xba,
    0xae, 0x50, 0x52, 0xab, 0x05, 0xf0, 0x0d, 0x73, 0x3b, 0x04, 0x20, 0xfe,
    0xdd, 0xf5, 0xb4, 0x5f, 0x0a, 0xb5, 0xc0, 0xa0, 0x71, 0xa5, 0x2d, 0x60,
    0x72, 0x93, 0x39, 0x08, 0x83, 0x21, 0x5c, 0x87, 0xb1, 0xe0, 0x00, 0xc3,
    0x12, 0x91, 0x8a, 0x02, 0x1c, 0xe6, 0x45, 0xc2, 0xc4, 0xfd, 0xbf, 0x44,
    0xa1, 0x4c, 0x33, 0xc5, 0x84, 0x23, 0x7c, 0xb0, 0x25, 0x15, 0x35, 0x69,
    0xff, 0x94, 0x4d, 0x70, 0xa2, 0xaf, 0xcd, 0xd6, 0x6c, 0xb7, 0xf8, 0x09,
    0xf3, 0x67, 0xa4, 0xea, 0xec, 0xb6, 0xd4, 0xd2, 0x14, 0x1e, 0xe1, 0x24,
    0x38, 0xc6, 0xdb, 0x4b, 0x7a, 0x3a, 0xde, 0x5e, 0xdf, 0x95, 0xfc, 0xaa,
    0xd7, 0xce, 0x07, 0x0f, 0x3d, 0x58, 0x9a, 0x98, 0x9c, 0xf2, 0xa7, 0x11,
    0x7e, 0x8b, 0x43, 0x03, 0xe2, 0xdc, 0xe5, 0xb2, 0x4e, 0xc7, 0x6d, 0xe9,
    0x27, 0x40, 0xd8, 0x37, 0x92, 0x8f, 0x01, 0x1d, 0x53, 0x3e, 0x59, 0xc1,
    0x4f, 0x32, 0x16, 0xfa, 0x74, 0xfb, 0x63, 0x9f, 0x34, 0x1a, 0x2a, 0x5a,
    0x8d, 0xc9, 0xcf, 0xf6, 0x90, 0x28, 0x88, 0x9b, 0x31, 0x0e, 0xbd, 0x4a,
    0xe8, 0x96, 0xa6, 0x0c, 0xc8, 0x79, 0xbc, 0xbe, 0xef, 0x6e, 0x46, 0x97,
    0x5b, 0xed, 0x19, 0xd9, 0xac, 0x99, 0xa8, 0x29, 0x64, 0x1f, 0xad, 0x55,
    0x13, 0xbb, 0xf7, 0x6f, 0xb9, 0x47, 0x2f, 0xee, 0xb8, 0x7b, 0x89, 0x30,
    0xd3, 0x7f, 0x76, 0x82
];
/** @type {number[]} */
const eBOX = [
    0x1, 0xb, 0x9, 0xc, 0xd, 0x6, 0xf, 0x3,
    0xe, 0x8, 0x7, 0x4, 0xa, 0x2, 0x5, 0x0
];
/** @type {number[]} */
const rBOX = [
    0x7, 0xc, 0xb, 0xd, 0xe, 0x4, 0x9, 0xf,
    0x6, 0x3, 0x8, 0xa, 0x2, 0x5, 0x1, 0x0
];
/** @type {number[]} */
const iBOX = new Array(16);
/** @type {number[]} */
const theta = [1, 1, 4, 1, 8, 5, 2, 9];
/** @type {number[]} */
const theta0 = [1, 1, 3, 1, 5, 8, 9, 5];
/** @type {Array[]} */
let C = new Array(512);
/** @type {number[]} */
let RC = new Array(22);
/** @type {Array[]} */
let C0 = new Array(512);
/** @type {number[]} */
let RC0 = new Array(22);
/** @type {Array[]} */
let CT = new Array(512);
/** @type {number[]} */
let RCT = new Array(22);

/**
 * Calculates SBOX from eBOX & rBOX
 *
 * @private
 * @returns {void}
 */
function calculateSBOX() {
    for (let i = 0; i < 16; i++) {
        iBOX[eBOX[i]] = i | 0;
    }
    for (let i = 0; i < 256; i++) {
        let left = eBOX[i >> 4];
        let right = iBOX[i & 0xf];
        let temp = rBOX[left ^ right];
        SBOX[i] = (eBOX[left ^ temp] << 4) | iBOX[right ^ temp];
    }
}

/**
 * Calculates C* & RC* transform tables
 *
 * @private
 * @param {number[]} SBOX
 * @param {number[]} theta
 * @returns {[Array[], number[]]}
 */
function calculateRC(SBOX: number[], theta: number[]): [Array<any>[], number[]] {
    /** @type {Array[]} */
    const C = new Array(512);
    /** @type {number[]} */
    const RC = new Array(22);

    for (let t = 0; t < 8; t++) {
        C[t] = [];
    }
    for (let i = 0; i < 256; i++) {
        let V = new Array(10);
        V[1] = SBOX[i];
        V[2] = V[1] << 1;
        if (V[2] >= 0x100) {
            V[2] ^= 0x11d;
        }
        V[3] = V[2] ^ V[1];
        V[4] = V[2] << 1;
        if (V[4] >= 0x100) {
            V[4] ^= 0x11d;
        }
        V[5] = V[4] ^ V[1];
        V[8] = V[4] << 1;
        if (V[8] >= 0x100) {
            V[8] ^= 0x11d;
        }
        V[9] = V[8] ^ V[1];

        // build the circulant table C[0][x] = S[x].[1, 1, 4, 1, 8, 5, 2, 9] | S[x].[1, 1, 3, 1, 5, 8, 9, 5]
        C[0][i * 2] = (V[theta[0]] << 24) | (V[theta[1]] << 16) | (V[theta[2]] << 8) | V[theta[3]];
        C[0][i * 2 + 1] = (V[theta[4]] << 24) | (V[theta[5]] << 16) | (V[theta[6]] << 8) | V[theta[7]];

        // build the remaining circulant tables C[t][x] = C[0][x] rotr t
        for (let t = 1; t < 8; t++) {
            C[t][i * 2] = rotateRight64lo(C[0][i * 2 + 1], C[0][i * 2], t << 3);
            C[t][i * 2 + 1] = rotateRight64hi(C[0][i * 2 + 1], C[0][i * 2], t << 3);
        }
    }
    // build the round constants
    RC[0] = 0;
    RC[1] = 0;
    for (let i = 1; i <= 10; i++) {
        RC[i * 2] = (C[0][16 * i - 16] & 0xff000000) ^
            (C[1][16 * i - 14] & 0x00ff0000) ^
            (C[2][16 * i - 12] & 0x0000ff00) ^
            (C[3][16 * i - 10] & 0x000000ff);
        RC[i * 2 + 1] = (C[4][16 * i - 7] & 0xff000000) ^
            (C[5][16 * i - 5] & 0x00ff0000) ^
            (C[6][16 * i - 3] & 0x0000ff00) ^
            (C[7][16 * i - 1] & 0x000000ff);
    }

    return [C, RC];
}

var init = false;

// Build transform tables
function WhirlpoolInit() {
    calculateSBOX();

    // whirlpool-0
    let x = calculateRC(SBOX0, theta0);
    C0 = x[0];
    RC0 = x[1];
    // whirlpool-t
    x = calculateRC(SBOX, theta0);
    CT = x[0];
    RCT = x[1];
    // whirlpool
    x = calculateRC(SBOX, theta);
    C = x[0];
    RC = x[1];
};

/**
 * Calculates [WHIRLPOOL (WHIRLPOOL-0, WHIRLPOOL-T)](http://www.larc.usp.br/~pbarreto/WhirlpoolPage.html) hash
 */
export class Whirlpool extends Hasher32be {
    C: number[];
    RC: number[];
    /**
     * @param {Object} [options]
     * @param {number} [options.rounds=10] - Number of rounds (Can be from 1 to 10)
     * @param {string} [options.type] - Algorithm type
     *
     * | Hash type   | Type      |
     * |-------------|-----------|
     * | whirlpool-0 | '0'       |
     * | whirlpool-t | 't'       |
     * | whirlpool   | undefined |
     */
    constructor(options: Options = {type:"",rounds:10}) {
        if (!init) {
            WhirlpoolInit();
            init = true;
        }
        options = options || {};
        options.type = options.type || '';
        options.rounds = options.rounds || 10;
        super(options);

        switch (this.options.type) {
            case '0':
            // @ts-ignore
            case 0:
                this.C = C0;
                this.RC = RC0;
                break;
            case 't':
                this.C = CT;
                this.RC = RCT;
                break;
            default:
                this.C = C;
                this.RC = RC;
        }
    }

    /**
     * Reset hasher to initial state
     */
    reset() {
        super.reset();
        this.state.hash = new Array(16);
        for (let i = 0; i < 16; i++) {
            this.state.hash[i] = 0 | 0;
        }
    }

    /**
     * Process ready blocks
     *
     * @protected
     * @ignore
     * @param {number[]} block - Block
     */
    processBlock(block:number[]) {
        // compute and apply K^0 to the cipher state
        let K:number[] = new Array(16);
        let state:number[] = [];
        for (let i = 0; i < 16; i++) {
            state[i] = block[i] ^ (K[i] = this.state.hash[i]) | 0;
        }

        // iterate over all rounds
        let L:number[] = [];
        for (let r = 1; r <= this.options.rounds; r++) {
            // compute K^r from K^{r-1}
            for (let i = 0; i < 8; i++) {
                L[i * 2] = 0;
                L[i * 2 + 1] = 0;
                for (let t = 0, s = 56, j = 0; t < 8; t++, s -= 8, j = s < 32 ? 1 : 0) {
                    // @ts-ignore
                    L[i * 2] ^= this.C[t][((K[((i - t) & 7) * 2 + j] >>> (s % 32)) & 0xff) * 2];
                    // @ts-ignore
                    L[i * 2 + 1] ^= this.C[t][((K[((i - t) & 7) * 2 + j] >>> (s % 32)) & 0xff) * 2 + 1];
                }
            }
            for (let i = 0; i < 16; i++) {
                K[i] = L[i];
            }
            K[0] ^= this.RC[r * 2];
            K[1] ^= this.RC[r * 2 + 1];

            // apply the r-th round transformation
            for (let i = 0; i < 8; i++) {
                L[i * 2] = K[i * 2];
                L[i * 2 + 1] = K[i * 2 + 1];
                for (let t = 0, s = 56, j = 0; t < 8; t++, s -= 8, j = s < 32 ? 1 : 0) {
                    // @ts-ignore
                    L[i * 2] ^= this.C[t][((state[((i - t) & 7) * 2 + j] >>> (s % 32)) & 0xff) * 2];
                    // @ts-ignore
                    L[i * 2 + 1] ^= this.C[t][((state[((i - t) & 7) * 2 + j] >>> (s % 32)) & 0xff) * 2 + 1];
                }
            }
            for (let i = 0; i < 16; i++) {
                state[i] = L[i];
            }
        }
        // apply the Miyaguchi-Preneel compression function
        for (let i = 0; i < 16; i++) {
            this.state.hash[i] ^= state[i] ^ block[i];
        }
    }

    /**
     * Finalize hash and return result
     *
     * @returns {Uint8Array}
     */
    finalize(): Uint8Array {
        this.addPaddingISO7816(
            this.state.message.length < 32 ?
                (56 - this.state.message.length) | 0 :
                (120 - this.state.message.length) | 0);
        this.addLengthBits();
        this.process();
        return this.getStateHash();
    }
}

function bytesToHex(bytes: number[] | Uint8Array): string {
    for (var hex: string[] = [], i = 0; i < bytes.length; i++) {
        hex.push((bytes[i] >>> 4).toString(16));
        hex.push((bytes[i] & 0xF).toString(16));
    }
    return hex.join("");
}


/**
 * Creates a 64 byte WHIRLPOOL hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function _WHIRLPOOL(message: InputData, format: OutputFormat = arrayType()): string | Uint8Array | Buffer {
    const hash = new Whirlpool();
    hash.update(message);
    var digestbytes = hash.finalize();
    if(format == "buffer"){
        return Buffer.from(digestbytes);
    } else if(format == "hex"){
        return bytesToHex(digestbytes);
    }
    return digestbytes;
};

/**
 * Creates a 64 byte keyed WHIRLPOOL hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function WHIRLPOOL_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType()): string | Uint8Array | Buffer {
    const key_length = 64;
    const hash_len = 64;
    key = Hasher.convertToUint8Array(key);
    message = Hasher.convertToUint8Array(message);
    if (key.length > key_length) {
        key = _WHIRLPOOL(key, "array") as Uint8Array;
    }

    if (key.length < key_length) {
        const tmp = new Uint8Array(key_length);
        tmp.set(key, 0);
        key = tmp;
    }

    // Generate inner and outer keys
    var innerKey = new Uint8Array(key_length);
    var outerKey = new Uint8Array(key_length);
    for (var i = 0; i < key_length; i++) {
        innerKey[i] = 0x36 ^ key[i];
        outerKey[i] = 0x5c ^ key[i];
    }

    // Append the innerKey
    var msg = new Uint8Array(message.length + key_length);
    msg.set(innerKey, 0);
    msg.set(message, key_length);

    // Hash the previous message and append the outerKey
    var result = new Uint8Array(key_length + hash_len);
    result.set(outerKey, 0);
    result.set(_WHIRLPOOL(msg, "array") as Uint8Array, key_length);

    var digestbytes = _WHIRLPOOL(result, "array") as Uint8Array;
    if(format == "buffer"){
        return Buffer.from(digestbytes);
    } else if(format == "hex"){
        return bytesToHex(digestbytes);
    }
    return digestbytes;
};

/**
 * Creates a 64 byte WHIRLPOOL0 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function WHIRLPOOL0(message: InputData,  format: OutputFormat = arrayType()): string | Uint8Array | Buffer {
    const hash = new Whirlpool({type:"0", rounds: 10});
    hash.update(message);
    var digestbytes = hash.finalize();
    if(format == "buffer"){
        return Buffer.from(digestbytes);
    } else if(format == "hex"){
        return bytesToHex(digestbytes);
    }
    return digestbytes;
}

/**
 * Creates a 64 byte keyed WHIRLPOOL0 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function WHIRLPOOL0_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType()): string | Uint8Array | Buffer {
    const key_length = 64;
    const hash_len = 64;
    key = Hasher.convertToUint8Array(key);
    message = Hasher.convertToUint8Array(message);
    if (key.length > key_length) {
        key = WHIRLPOOL0(key, "array") as Uint8Array;
    }

    if (key.length < key_length) {
        const tmp = new Uint8Array(key_length);
        tmp.set(key, 0);
        key = tmp;
    }

    // Generate inner and outer keys
    var innerKey = new Uint8Array(key_length);
    var outerKey = new Uint8Array(key_length);
    for (var i = 0; i < key_length; i++) {
        innerKey[i] = 0x36 ^ key[i];
        outerKey[i] = 0x5c ^ key[i];
    }

    // Append the innerKey
    var msg = new Uint8Array(message.length + key_length);
    msg.set(innerKey, 0);
    msg.set(message, key_length);

    // Hash the previous message and append the outerKey
    var result = new Uint8Array(key_length + hash_len);
    result.set(outerKey, 0);
    result.set(WHIRLPOOL0(msg, "array") as Uint8Array, key_length);

    var digestbytes = WHIRLPOOL0(result, "array") as Uint8Array;
    if(format == "buffer"){
        return Buffer.from(digestbytes);
    } else if(format == "hex"){
        return bytesToHex(digestbytes);
    }
    return digestbytes;
}

/**
 * Creates a 64 byte WHIRLPOOLT hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function WHIRLPOOLT(message: InputData, format: OutputFormat = arrayType()): string | Uint8Array | Buffer {
    const hash = new Whirlpool({type:"t", rounds: 10});
    hash.update(message);
    var digestbytes = hash.finalize();
    if(format == "buffer"){
        return Buffer.from(digestbytes);
    } else if(format == "hex"){
        return bytesToHex(digestbytes);
    }
    return digestbytes;
};

/**
 * Creates a 64 byte keyed WHIRLPOOLT hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function WHIRLPOOLT_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType()): string | Uint8Array | Buffer {
    const key_length = 64;
    const hash_len = 64;
    key = Hasher.convertToUint8Array(key);
    message = Hasher.convertToUint8Array(message);
    if (key.length > key_length) {
        key = WHIRLPOOLT(key, "array") as Uint8Array;
    }

    if (key.length < key_length) {
        const tmp = new Uint8Array(key_length);
        tmp.set(key, 0);
        key = tmp;
    }

    // Generate inner and outer keys
    var innerKey = new Uint8Array(key_length);
    var outerKey = new Uint8Array(key_length);
    for (var i = 0; i < key_length; i++) {
        innerKey[i] = 0x36 ^ key[i];
        outerKey[i] = 0x5c ^ key[i];
    }

    // Append the innerKey
    var msg = new Uint8Array(message.length + key_length);
    msg.set(innerKey, 0);
    msg.set(message, key_length);

    // Hash the previous message and append the outerKey
    var result = new Uint8Array(key_length + hash_len);
    result.set(outerKey, 0);
    result.set(WHIRLPOOLT(msg, "array") as Uint8Array, key_length);

    var digestbytes = WHIRLPOOLT(result, "array") as Uint8Array;
    if(format == "buffer"){
        return Buffer.from(digestbytes);
    } else if(format == "hex"){
        return bytesToHex(digestbytes);
    }
    return digestbytes;
};

/**
 * Static class of all WHIRLPOOL functions and classes
 */
export class WHIRLPOOL {
    static Whirlpool = Whirlpool;
    static WHIRLPOOL = _WHIRLPOOL;
    static WHIRLPOOL_HMAC = WHIRLPOOL_HMAC;
    static WHIRLPOOL0 = WHIRLPOOL0;
    static WHIRLPOOL0_HMAC = WHIRLPOOL0_HMAC;
    static WHIRLPOOLT = WHIRLPOOLT;
    static WHIRLPOOLT_HMAC = WHIRLPOOLT_HMAC;
    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST() {
        return [
            "WHIRLPOOL",
            "WHIRLPOOL_HMAC",
            "WHIRLPOOL0",
            "WHIRLPOOL0_HMAC",
            "WHIRLPOOLT",
            "WHIRLPOOLT_HMAC"
        ]
    }
};