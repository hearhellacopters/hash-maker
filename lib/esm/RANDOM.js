"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RandomBytes = exports.RANDOMXORSHIFT = void 0;
/**
 * Random Xor Shift RNG. Can seed with number, a Uint8Array or Buffer of 4 bytes
 * ```javascript
 * const {RANDOMXORSHIFT} = require('hash-maker');
 * const seed; //number, Uint8Array or Buffer of 4 bytes
 * const rxs = new RANDOMXORSHIFT(seed);
 * const random_int = rxs.random_int();
 * ```
 * @param {number|Uint8Array|Buffer} seed - Can seeded with a number or a Uint8Array or Buffer of 4 bytes
 */
class RANDOMXORSHIFT {
    constructor(seed) {
        var s;
        const mt = new Uint32Array(5); //[0, 0, 0, 0];
        if (seed == undefined) {
            seed = new Date().getTime();
        }
        if (typeof Buffer !== 'undefined' && seed instanceof Buffer) {
            if (seed.length < 4) {
                throw new Error("Must be a seed Buffer of 4 bytes");
            }
            mt[0] = seed.readUInt32LE() >>> 0;
        }
        else if (seed instanceof Uint8Array) {
            if (seed.length < 4) {
                throw new Error("Must be a seed Uint8Array of 4 bytes");
            }
            mt[0] = ((seed[3] << 24) | (seed[2] << 16) | (seed[1] << 8) | seed[0]);
        }
        else if (typeof seed == "number") {
            mt[0] = seed >>> 0;
        }
        for (var i = 1; i < 5; i++) {
            s = mt[i - 1] ^ (mt[i - 1] >>> 30);
            mt[i] = (((((s & 0xffff0000) >>> 16) * 1812433253) << 16) + (s & 0x0000ffff) * 1812433253) + (i - 1);
            mt[i] >>>= 0;
        }
        this.mt = mt.subarray(1);
    }
    /**
     * Generate a random unsigned 32 bit integer
     * @returns number
     */
    random_int() {
        let v1 = this.mt[0];
        let v4 = this.mt[3];
        let comp_1 = (v4 ^ (v4 >>> 19) ^ v1 ^ (v1 << 11) ^ ((v1 ^ (v1 << 11)) >>> 8)) >>> 0;
        for (let i = 0; i < 4; i++) {
            this.mt[i] = this.mt[i + 1];
        }
        this.mt[3] = comp_1;
        console.log(this.mt);
        return comp_1;
    }
}
exports.RANDOMXORSHIFT = RANDOMXORSHIFT;
function bytesToHex(bytes) {
    for (var hex = [], i = 0; i < bytes.length; i++) {
        hex.push((bytes[i] >>> 4).toString(16));
        hex.push((bytes[i] & 0xF).toString(16));
    }
    return hex.join("");
}
function arrayType() {
    if (typeof window !== 'undefined') {
        return "array";
    }
    else {
        return "buffer";
    }
}
;
/**
 * Generate random bytes as a hex string, Uint8Array, Buffer
 *
 * @param {number|Uint8Array|Buffer} number number bytes to create
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function RandomBytes(number, format = arrayType()) {
    if (number == undefined || !(typeof number == "number")) {
        throw new Error("Must supply number of bytes to generate.");
    }
    const mt = new RANDOMXORSHIFT();
    var array;
    if (format == "buffer") {
        array = Buffer.alloc(number);
    }
    else {
        array = new Uint8Array(number);
    }
    for (let i = 0; i < number; i++) {
        array[i] = mt.random_int();
    }
    if (format == "hex") {
        return bytesToHex(array);
    }
    return array;
}
exports.RandomBytes = RandomBytes;
//# sourceMappingURL=RANDOM.js.map