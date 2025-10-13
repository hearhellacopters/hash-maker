function arrayType():OutputFormat{
	if (typeof window !== 'undefined') {
		return "array" as OutputFormat;
	} else {
    return "buffer" as OutputFormat;
	}
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
        return message as Uint8Array;
    }

    throw new Error('input is invalid type');
}

// Input types
type InputData = string | Uint8Array | Buffer;

// Output formats
type OutputFormat = 'hex' | 'array' | 'buffer';

interface Options {
    length?: number
}

interface state {
    message: Uint8Array,
    length: number,
    hash: number[];
}

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
    constructor(options: Options = {}) {
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

        this.options = options || {};

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
        const data = this.convertToUint8Array(message);

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
    convertToUint8Array(data?: InputData): Uint8Array {
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
 * Hasher for 32 bit little endian blocks
 * @interface
 */
class Hasher32le extends Hasher {
    blockUnits: number[];
    /**
     * @param {Object} [options]
     */
    constructor(options?: Options) {
        super(options);

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
                    this.state.message[b] |
                    this.state.message[b + 1] << 8 |
                    this.state.message[b + 2] << 16 |
                    this.state.message[b + 3] << 24
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
            hash[i * 4] = word & 0xff;
            hash[i * 4 + 1] = (word >> 8) & 0xff;
            hash[i * 4 + 2] = (word >> 16) & 0xff;
            hash[i * 4 + 3] = (word >> 24) & 0xff;
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
        lengthBytes[0] = Number(bitLength & BigInt(0xff));
        lengthBytes[1] = Number((bitLength >> BigInt(8)) & BigInt(0xff));
        lengthBytes[2] = Number((bitLength >> BigInt(16)) & BigInt(0xff));
        lengthBytes[3] = Number((bitLength >> BigInt(24)) & BigInt(0xff));
        lengthBytes[4] = Number((bitLength >> BigInt(32)) & BigInt(0xff));
        lengthBytes[5] = Number((bitLength >> BigInt(40)) & BigInt(0xff));
        lengthBytes[6] = Number((bitLength >> BigInt(48)) & BigInt(0xff));
        lengthBytes[7] = Number((bitLength >> BigInt(56)) & BigInt(0xff));

        this.state.message = this.concatUint8Arrays(this.state.message, lengthBytes);
    }
}

function rotateLeft(x: number, n: number) {
    return ((x << n) | (x >>> (32 - n))) | 0;
}

/** @type {number[]} */
const ZL = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
];
/** @type {number[]} */
const ZR = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
];
/** @type {number[]} */
const SL = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
];
/** @type {number[]} */
const SR = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
];

/**
 * Calculates [RIPEMD-160 (RIPEMD-128, RIPEMD-256, RIPEMD-320)](http://homes.esat.kuleuven.be/~bosselae/ripemd160.html) hash
 */
export class Ripemd extends Hasher32le {
    /**
     * @param {Object} [options]
     * @param {number} [options.length=160] - Length of hash result
     *
     * | Hash type | Length |
     * |-----------|--------|
     * | ripemd128 | 128    |
     * | ripemd160 | 160    |
     * | ripemd256 | 256    |
     * | ripemd320 | 320    |
     */
    constructor(options?: Options) {
        options = options || {};
        options.length = options.length || 160;
        super(options);
    }

    /**
     * Reset hasher to initial state
     */
    reset() {
        super.reset();
        switch (this.options.length) {
            case 128:
                this.state.hash = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
                /**
                 * Process ready blocks
                 *
                 * @protected
                 * @ignore
                 * @method processBlock
                 * @param {number[]} block - Block
                 */
                this.processBlock = this.processBlock128;
                break;
            case 256:
                this.state.hash = [
                    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476,
                    0x76543210, 0xfedcba98, 0x89abcdef, 0x01234567
                ];
                this.processBlock = this.processBlock256;
                break;
            case 320:
                this.state.hash = [
                    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0,
                    0x76543210, 0xfedcba98, 0x89abcdef, 0x01234567, 0x3c2d1e0f
                ];
                this.processBlock = this.processBlock320;
                break;
            default: // 160
                this.state.hash = [
                    0x67452301,
                    0xefcdab89,
                    0x98badcfe,
                    0x10325476,
                    0xc3d2e1f0
                ];
                this.processBlock = this.processBlock160;
        }
    }

    /**
     * @private
     * @ignore
     * @param {number} x
     * @param {number} y
     * @param {number} z
     * @returns {number}
     */
    static F(x: number, y: number, z: number): number {
        return x ^ y ^ z;
    }

    /**
     * @private
     * @ignore
     * @param {number} x
     * @param {number} y
     * @param {number} z
     * @returns {number}
     */
    static G(x: number, y: number, z: number): number {
        return (x & y) | ((~x) & z);
    }

    /**
     * @private
     * @ignore
     * @param {number} x
     * @param {number} y
     * @param {number} z
     * @returns {number}
     */
    static H(x: number, y: number, z: number): number {
        return (x | (~y)) ^ z;
    }

    /**
     * @private
     * @ignore
     * @param {number} x
     * @param {number} y
     * @param {number} z
     * @returns {number}
     */
    static I(x: number, y: number, z: number): number {
        return (x & z) | (y & (~z));
    }

    /**
     * @private
     * @ignore
     * @param {number} x
     * @param {number} y
     * @param {number} z
     * @returns {number}
     */
    static J(x: number, y: number, z: number): number {
        return x ^ (y | (~z));
    }

    /**
     * @private
     * @ignore
     * @param {number} i
     * @param {number} bl
     * @param {number} cl
     * @param {number} dl
     * @returns {number}
     */
    static T(i: number, bl: number, cl: number, dl: number): number {
        if (i < 16) {
            return this.F(bl, cl, dl);
        }
        if (i < 32) {
            return (this.G(bl, cl, dl) + 0x5a827999) | 0;
        }
        if (i < 48) {
            return (this.H(bl, cl, dl) + 0x6ed9eba1) | 0;
        }
        if (i < 64) {
            return (this.I(bl, cl, dl) + 0x8f1bbcdc) | 0;
        }
        return (this.J(bl, cl, dl) + 0xa953fd4e) | 0;
    }

    /**
     * @private
     * @ignore
     * @param {number} i
     * @param {number} br
     * @param {number} cr
     * @param {number} dr
     * @returns {number}
     */
    static T64(i: number, br: number, cr: number, dr: number): number {
        if (i < 16) {
            return (this.I(br, cr, dr) + 0x50a28be6) | 0;
        }
        if (i < 32) {
            return (this.H(br, cr, dr) + 0x5c4dd124) | 0;
        }
        if (i < 48) {
            return (this.G(br, cr, dr) + 0x6d703ef3) | 0;
        }
        return this.F(br, cr, dr);
    }

    /**
     * @private
     * @ignore
     * @param {number} i
     * @param {number} br
     * @param {number} cr
     * @param {number} dr
     * @returns {number}
     */
    static T80(i: number, br: number, cr: number, dr: number): number {
        if (i < 16) {
            return (this.J(br, cr, dr) + 0x50a28be6) | 0;
        }
        if (i < 32) {
            return (this.I(br, cr, dr) + 0x5c4dd124) | 0;
        }
        if (i < 48) {
            return (this.H(br, cr, dr) + 0x6d703ef3) | 0;
        }
        if (i < 64) {
            return (this.G(br, cr, dr) + 0x7a6d76e9) | 0;
        }
        return this.F(br, cr, dr);
    }

    /**
     * Process ready blocks
     *
     * @protected
     * @ignore
     * @param {number[]} block - Block
     */
    processBlock128(block: number[]) {
        // Working variables
        let al = this.state.hash[0] | 0;
        let bl = this.state.hash[1] | 0;
        let cl = this.state.hash[2] | 0;
        let dl = this.state.hash[3] | 0;
        let ar = al;
        let br = bl;
        let cr = cl;
        let dr = dl;

        for (let i = 0; i < 64; i++) {
            let t = (al + block[ZL[i]]) | 0;
            t = (t + Ripemd.T(i, bl, cl, dl)) | 0;
            t = rotateLeft(t, SL[i]);
            al = dl;
            dl = cl;
            cl = bl;
            bl = t;

            t = (ar + block[ZR[i]]) | 0;
            t = (t + Ripemd.T64(i, br, cr, dr)) | 0;
            t = rotateLeft(t, SR[i]);
            ar = dr;
            dr = cr;
            cr = br;
            br = t;
        }
        let t = (this.state.hash[1] + cl + dr) | 0;
        this.state.hash[1] = (this.state.hash[2] + dl + ar) | 0;
        this.state.hash[2] = (this.state.hash[3] + al + br) | 0;
        this.state.hash[3] = (this.state.hash[0] + bl + cr) | 0;
        this.state.hash[0] = t;
    }

    /**
     * Process ready blocks
     *
     * @protected
     * @ignore
     * @param {number[]} block - Block
     */
    processBlock160(block: number[]) {
        // Working variables
        let al = this.state.hash[0] | 0;
        let bl = this.state.hash[1] | 0;
        let cl = this.state.hash[2] | 0;
        let dl = this.state.hash[3] | 0;
        let el = this.state.hash[4] | 0;
        let ar = al;
        let br = bl;
        let cr = cl;
        let dr = dl;
        let er = el;

        for (let i = 0; i < 80; i++) {
            let t = (al + block[ZL[i]]) | 0;
            t = (t + Ripemd.T(i, bl, cl, dl)) | 0;
            t = rotateLeft(t, SL[i]);
            t = (t + el) | 0;
            al = el;
            el = dl;
            dl = rotateLeft(cl, 10);
            cl = bl;
            bl = t;

            t = (ar + block[ZR[i]]) | 0;
            t = (t + Ripemd.T80(i, br, cr, dr)) | 0;
            t = rotateLeft(t, SR[i]);
            t = (t + er) | 0;
            ar = er;
            er = dr;
            dr = rotateLeft(cr, 10);
            cr = br;
            br = t;
        }
        let t = (this.state.hash[1] + cl + dr) | 0;
        this.state.hash[1] = (this.state.hash[2] + dl + er) | 0;
        this.state.hash[2] = (this.state.hash[3] + el + ar) | 0;
        this.state.hash[3] = (this.state.hash[4] + al + br) | 0;
        this.state.hash[4] = (this.state.hash[0] + bl + cr) | 0;
        this.state.hash[0] = t;
    }

    /**
     * Process ready blocks
     *
     * @protected
     * @ignore
     * @param {number[]} block - Block
     */
    processBlock256(block: number[]) {
        // Working variables
        let al = this.state.hash[0] | 0;
        let bl = this.state.hash[1] | 0;
        let cl = this.state.hash[2] | 0;
        let dl = this.state.hash[3] | 0;
        let ar = this.state.hash[4] | 0;
        let br = this.state.hash[5] | 0;
        let cr = this.state.hash[6] | 0;
        let dr = this.state.hash[7] | 0;

        for (let i = 0; i < 64; i += 1) {
            let t = (al + block[ZL[i]]) | 0;
            t = (t + Ripemd.T(i, bl, cl, dl)) | 0;
            t = rotateLeft(t, SL[i]);
            al = dl;
            dl = cl;
            cl = bl;
            bl = t;

            t = (ar + block[ZR[i]]) | 0;
            t = (t + Ripemd.T64(i, br, cr, dr)) | 0;
            t = rotateLeft(t, SR[i]);
            ar = dr;
            dr = cr;
            cr = br;
            br = t;
            switch (i) {
                case 15:
                    t = al;
                    al = ar;
                    ar = t;
                    break;
                case 31:
                    t = bl;
                    bl = br;
                    br = t;
                    break;
                case 47:
                    t = cl;
                    cl = cr;
                    cr = t;
                    break;
                case 63:
                    t = dl;
                    dl = dr;
                    dr = t;
                    break;
            }
        }
        this.state.hash[0] = (this.state.hash[0] + al) | 0;
        this.state.hash[1] = (this.state.hash[1] + bl) | 0;
        this.state.hash[2] = (this.state.hash[2] + cl) | 0;
        this.state.hash[3] = (this.state.hash[3] + dl) | 0;
        this.state.hash[4] = (this.state.hash[4] + ar) | 0;
        this.state.hash[5] = (this.state.hash[5] + br) | 0;
        this.state.hash[6] = (this.state.hash[6] + cr) | 0;
        this.state.hash[7] = (this.state.hash[7] + dr) | 0;
    }

    /**
     * Process ready blocks
     *
     * @protected
     * @ignore
     * @param {number[]} block - Block
     */
    processBlock320(block: number[]) {
        // Working variables
        let al = this.state.hash[0] | 0;
        let bl = this.state.hash[1] | 0;
        let cl = this.state.hash[2] | 0;
        let dl = this.state.hash[3] | 0;
        let el = this.state.hash[4] | 0;
        let ar = this.state.hash[5] | 0;
        let br = this.state.hash[6] | 0;
        let cr = this.state.hash[7] | 0;
        let dr = this.state.hash[8] | 0;
        let er = this.state.hash[9] | 0;

        for (let i = 0; i < 80; i += 1) {
            let t = (al + block[ZL[i]]) | 0;
            t = (t + Ripemd.T(i, bl, cl, dl)) | 0;
            t = rotateLeft(t, SL[i]);
            t = (t + el) | 0;
            al = el;
            el = dl;
            dl = rotateLeft(cl, 10);
            cl = bl;
            bl = t;

            t = (ar + block[ZR[i]]) | 0;
            t = (t + Ripemd.T80(i, br, cr, dr)) | 0;
            t = rotateLeft(t, SR[i]);
            t = (t + er) | 0;
            ar = er;
            er = dr;
            dr = rotateLeft(cr, 10);
            cr = br;
            br = t;
            switch (i) {
                case 15:
                    t = bl;
                    bl = br;
                    br = t;
                    break;
                case 31:
                    t = dl;
                    dl = dr;
                    dr = t;
                    break;
                case 47:
                    t = al;
                    al = ar;
                    ar = t;
                    break;
                case 63:
                    t = cl;
                    cl = cr;
                    cr = t;
                    break;
                case 79:
                    t = el;
                    el = er;
                    er = t;
                    break;
            }
        }
        this.state.hash[0] = (this.state.hash[0] + al) | 0;
        this.state.hash[1] = (this.state.hash[1] + bl) | 0;
        this.state.hash[2] = (this.state.hash[2] + cl) | 0;
        this.state.hash[3] = (this.state.hash[3] + dl) | 0;
        this.state.hash[4] = (this.state.hash[4] + el) | 0;
        this.state.hash[5] = (this.state.hash[5] + ar) | 0;
        this.state.hash[6] = (this.state.hash[6] + br) | 0;
        this.state.hash[7] = (this.state.hash[7] + cr) | 0;
        this.state.hash[8] = (this.state.hash[8] + dr) | 0;
        this.state.hash[9] = (this.state.hash[9] + er) | 0;
    }

    /**
     * Finalize hash and return result
     *
     * @returns {Uint8Array}
     */
    finalize(): Uint8Array {
        // Calculate padding length
        let paddingLength = this.state.message.length < 56 ?
            56 - this.state.message.length :
            120 - this.state.message.length;

        this.addPaddingISO7816(paddingLength);
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
 * Creates a 16 byte RIPEMD128 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function RIPEMD128(message: InputData, format: OutputFormat = arrayType()): string | Uint8Array | Buffer {
    const hash = new Ripemd({ length: 128 });
    hash.update(message);
    var digestbytes = hash.finalize();
    if(format == "hex"){
        return bytesToHex(digestbytes);
    } else if(format == "buffer"){
        return Buffer.from(digestbytes);
    }
    return digestbytes;
};

/**
 * Creates a 16 byte keyed RIPEMD128 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function RIPEMD128_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType()): string | Uint8Array | Buffer {
    const key_length = 64;
    const hash_len = 16;
    key = formatMessage(key);
    message = formatMessage(message);
    if (key.length > key_length) {
        key = RIPEMD128(key, "array") as Uint8Array;
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
    result.set(RIPEMD128(msg, "array") as Uint8Array, key_length);

    var digestbytes = RIPEMD128(result, "array") as Uint8Array;
    if(format == "hex"){
        return bytesToHex(digestbytes);
    } else if(format == "buffer"){
        return Buffer.from(digestbytes);
    }
    return digestbytes;
};

/**
 * Creates a 20 byte RIPEMD160 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function RIPEMD160(message: InputData, format: OutputFormat = arrayType()): string | Uint8Array | Buffer {
    const hash = new Ripemd({ length: 160 });
    hash.update(message);
    var digestbytes = hash.finalize();
    if(format == "hex"){
        return bytesToHex(digestbytes);
    } else if(format == "buffer"){
        return Buffer.from(digestbytes);
    }
    return digestbytes;
};

/**
 * Creates a 20 byte keyed RIPEMD160 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function RIPEMD160_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType()): string | Uint8Array | Buffer {
    const key_length = 64;
    const hash_len = 20;
    key = formatMessage(key);
    message = formatMessage(message);
    if (key.length > key_length) {
        key = RIPEMD160(key, "array") as Uint8Array;
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
    result.set(RIPEMD160(msg, "array") as Uint8Array, key_length);

    var digestbytes = RIPEMD160(result, "array") as Uint8Array;
    if(format == "hex"){
        return bytesToHex(digestbytes);
    } else if(format == "buffer"){
        return Buffer.from(digestbytes);
    }
    return digestbytes;
};

/**
 * Creates a 32 byte RIPEMD256 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function RIPEMD256(message: InputData, format: OutputFormat = arrayType()): string | Uint8Array | Buffer {
    const hash = new Ripemd({ length: 256 });
    hash.update(message);
    var digestbytes = hash.finalize();
    if(format == "hex"){
        return bytesToHex(digestbytes);
    } else if(format == "buffer"){
        return Buffer.from(digestbytes);
    }
    return digestbytes;
};

/**
 * Creates a 32 byte keyed RIPEMD256 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function RIPEMD256_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType()): string | Uint8Array | Buffer {
    const key_length = 64;
    const hash_len = 32;
    key = formatMessage(key);
    message = formatMessage(message);
    if (key.length > key_length) {
        key = RIPEMD256(key, "array") as Uint8Array;
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
    result.set(RIPEMD256(msg, "array") as Uint8Array, key_length);

    var digestbytes = RIPEMD256(result, "array") as Uint8Array;
    if(format == "hex"){
        return bytesToHex(digestbytes);
    } else if(format == "buffer"){
        return Buffer.from(digestbytes);
    }
    return digestbytes;
};

/**
 * Creates a 40 byte RIPEMD256 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function RIPEMD320(message: InputData, format: OutputFormat = arrayType()): string | Uint8Array | Buffer {
    const hash = new Ripemd({ length: 320 });
    hash.update(message);
    var digestbytes = hash.finalize();
    if(format == "hex"){
        return bytesToHex(digestbytes);
    } else if(format == "buffer"){
        return Buffer.from(digestbytes);
    }
    return digestbytes;
};

/**
 * Creates a 40 byte keyed RIPEMD256 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function RIPEMD320_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType()): string | Uint8Array | Buffer {
    const key_length = 64;
    const hash_len = 40;
    key = formatMessage(key);
    message = formatMessage(message);
    if (key.length > key_length) {
        key = RIPEMD320(key, "array") as Uint8Array;
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
    result.set(RIPEMD320(msg, "array") as Uint8Array, key_length);

    var digestbytes = RIPEMD320(result, "array") as Uint8Array;
    if(format == "hex"){
        return bytesToHex(digestbytes);
    } else if(format == "buffer"){
        return Buffer.from(digestbytes);
    }
    return digestbytes;
};

/**
 * Creates a vary bit length RIPEMD hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @param {number} bits = bit length of hash
 * @returns `string|Uint8Array|Buffer`
 */
export function _RIPEMD(message: InputData, bits: number = 128, format: OutputFormat = arrayType()): string | Uint8Array | Buffer {
    const hash = new Ripemd({ length: bits });
    hash.update(message);
    var digestbytes = hash.finalize();
    if(format == "hex"){
        return bytesToHex(digestbytes);
    } else if(format == "buffer"){
        return Buffer.from(digestbytes);
    }
    return digestbytes;
};

/**
 * Creates a vary bit length keyed RIPEMD hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @param {number} bits = bit length of hash
 * @returns `string|Uint8Array|Buffer`
 */
export function RIPEMD_HMAC(message: InputData, key: InputData, bits: number = 128, format: OutputFormat = arrayType()): string | Uint8Array | Buffer {
    const key_length = 64;
    const hash_len = bits / 8;
    key = formatMessage(key);
    message = formatMessage(message);
    if (key.length > key_length) {
        key = _RIPEMD(key, bits, "array") as Uint8Array;
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
    result.set(_RIPEMD(msg, bits, "array") as Uint8Array, key_length);

    var digestbytes = _RIPEMD(result, bits, "array") as Uint8Array;
    if(format == "hex"){
        return bytesToHex(digestbytes);
    } else if(format == "buffer"){
        return Buffer.from(digestbytes);
    }
    return digestbytes;
};

/**
 * Static class of all RIPEMD functions
 */
export class RIPEMD {
    static Ripemd = Ripemd;
    static RIPEMD = _RIPEMD;
    static RIPEMD128 = RIPEMD128;
    static RIPEMD128_HMAC = RIPEMD128_HMAC;
    static RIPEMD160 = RIPEMD160;
    static RIPEMD160_HMAC = RIPEMD160_HMAC;
    static RIPEMD256 = RIPEMD256;
    static RIPEMD256_HMAC = RIPEMD256_HMAC;
    static RIPEMD320 = RIPEMD320;
    static RIPEMD320_HMAC = RIPEMD320_HMAC;
    static RIPEMD_HMAC = RIPEMD_HMAC;
    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST() {
        return [
            "RIPEMD",
            "RIPEMD128",
            "RIPEMD128_HMAC",
            "RIPEMD160",
            "RIPEMD160_HMAC",
            "RIPEMD256",
            "RIPEMD256_HMAC",
            "RIPEMD320",
            "RIPEMD320_HMAC",
            "RIPEMD_HMAC"
        ];
    }
};