"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.randomBytes = void 0;
class RANDOMXORSHIFT {
    constructor(seed) {
        var s;
        const mt = [0, 0, 0, 0];
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
            mt[i] =
                (((((s & 0xffff0000) >>> 16) * 1812433253) << 16) + (s & 0x0000ffff) * 1812433253) + (i - 1);
            mt[i] >>>= 0;
        }
        mt.shift();
        var result = new Uint8Array(16);
        mt.forEach((e, i) => {
            result[(i * 4)] = e & 0xFF;
            result[(i * 4) + 1] = (e >> 8) & 0xFF;
            result[(i * 4) + 2] = (e >> 16) & 0xFF;
            result[(i * 4) + 3] = (e >> 24) & 0xFF;
        });
        this.mt = result;
    }
    /**
     * Generate a random unsigned 32 bit integer
     * @returns number
     */
    random_int() {
        let v1 = ((this.mt[3] << 24) | (this.mt[2] << 16) | (this.mt[1] << 8) | this.mt[0]);
        let v4 = ((this.mt[15] << 24) | (this.mt[14] << 16) | (this.mt[13] << 8) | this.mt[12]);
        let comp_1 = (v4 ^ (v4 >>> 19) ^ v1 ^ (v1 << 11) ^ ((v1 ^ (v1 << 11)) >>> 8)) >>> 0;
        let new_value = new Uint8Array(4);
        new_value[0] = comp_1 & 0xFF;
        new_value[1] = (comp_1 >> 8) & 0xFF;
        new_value[2] = (comp_1 >> 16) & 0xFF;
        new_value[3] = (comp_1 >> 24) & 0xFF;
        const shift = this.mt.subarray(4, 16);
        var newBuffer = new Uint8Array([...shift, ...new_value]);
        this.mt = newBuffer;
        return comp_1;
    }
}
/**
 * Generate random bytes as Uint8Array or Buffer
 *
 * @param {number} number number bytes to create
 * @param {boolean} asBuffer - returns a Buffer else returns a Uint8Array
 * @returns Uint8Array or Buffer
 */
function randomBytes(number, asBuffer) {
    if (number == undefined || !(typeof number == "number")) {
        throw new Error("Must supply number of bytes to generate.");
    }
    const mt = new RANDOMXORSHIFT();
    var array;
    if (asBuffer) {
        array = Buffer.alloc(number);
    }
    else {
        array = new Uint8Array(number);
    }
    for (let i = 0; i < number; i++) {
        array[i] = mt.random_int();
    }
    return array;
}
exports.randomBytes = randomBytes;
//# sourceMappingURL=randomBytes.js.map