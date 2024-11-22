"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MERSENNETWISTER = void 0;
/**
 * Random number generator. Can be seeded with number or Uint32Array
 * ```javascript
 * const {MERSENNETWISTER} = require('hash-maker');
 * const seed; // number or Uint32Array
 * const mt = new MERSENNETWISTER(seed);
 * const unsignedInt = mt.genrand_int32() // or mt.RandTwisterUnsigned() mt.random_int()
 * const signedInt = mt.genrand_int32i() // or mt.RandTwisterSigned()
 * const unsigned31Int = mt.genrand_int3i()
 * const double = mt.genrand_real1() // or mt.RandTwisterDouble()
 * const float1 = mt.genrand_real2() // generates a random number on [0,1)-real-interval
 * const float2 = mt.genrand_real3() // generates a random number on (0,1)-real-interval
 * const float3 = mt.genrand_res53() // generates a random number on [0,1) with 53-bit resolution
 * ```
 * @param {number|Uint32Array} seed - can be seeded with a number or Uint32Array
 */
class MERSENNETWISTER {
    constructor(seed) {
        this.N = 624;
        this.M = 397;
        this.MATRIX_A = 0x9908b0df;
        this.UPPER_MASK = 0x80000000;
        this.LOWER_MASK = 0x7fffffff;
        this.UCHAR_MAX = 255;
        this.mt = new Uint32Array(624);
        this.mti = 625;
        if (seed && typeof seed == "number") {
            this.init_genrand(seed >>> 0);
        }
        else if (seed && (seed instanceof Uint32Array)) {
            this.init_by_array(seed, seed.length);
        }
        else if (seed == undefined) {
            this.init_genrand(this.CreateTwisterSeed());
        }
    }
    CreateTwisterSeed() {
        var differ = 0;
        var t = new Date().getTime();
        var p = new Uint8Array(4);
        var h1 = 0;
        p[0] = t & 0xFF;
        p[1] = (t >> 8) & 0xFF;
        p[2] = (t >> 16) & 0xFF;
        p[3] = (t >> 24) & 0xFF;
        for (var i = 0; i < 4; ++i) {
            h1 *= this.UCHAR_MAX + 2;
            h1 += p[i];
        }
        return h1 + differ++;
    }
    init_genrand(s) {
        this.mt[0] = s >>> 0;
        for (this.mti = 1; this.mti < this.N; this.mti++) {
            this.mt[this.mti] = (1812433253 * (this.mt[this.mti - 1] ^ (this.mt[this.mti - 1] >> 30)) + this.mti);
            this.mt[this.mti] >>>= 0;
        }
    }
    init_by_array(init_key, key_length) {
        var i, j, k;
        this.init_genrand(19650218);
        i = 1;
        j = 0;
        k = (this.N > key_length ? this.N : key_length);
        for (; k; k--) {
            this.mt[i] = (this.mt[i] ^ ((this.mt[i - 1] ^ (this.mt[i - 1] >> 30)) * 1664525)) + init_key[j] + j;
            this.mt[i] >>>= 0;
            i++;
            j++;
            if (i >= this.N) {
                this.mt[0] = this.mt[this.N - 1];
                i = 1;
            }
            if (j >= key_length)
                j = 0;
        }
        for (k = this.N - 1; k; k--) {
            this.mt[i] = (this.mt[i] ^ ((this.mt[i - 1] ^ (this.mt[i - 1] >> 30)) * 1566083941)) - i;
            this.mt[i] &= 0xffffffff;
            i++;
            if (i >= this.N) {
                this.mt[0] = this.mt[this.N - 1];
                i = 1;
            }
        }
        this.mt[0] = 0x80000000;
    }
    /**
     * generates a random number on [0,0xffffffff]-interval (unsigned)
     * @returns number
     */
    genrand_int32() {
        var y = new Uint32Array(1);
        var mag01 = new Uint32Array([0x0, this.MATRIX_A]);
        if (this.mti >= this.N) {
            var kk;
            if (this.mti == this.N + 1) {
                this.init_genrand(5489);
            }
            for (kk = 0; kk < this.N - this.M; kk++) {
                y[0] = (this.mt[kk] & this.UPPER_MASK) | (this.mt[kk + 1] & this.LOWER_MASK);
                this.mt[kk] = this.mt[kk + this.M] ^ (y[0] >> 1) ^ mag01[y[0] & 0x1];
            }
            for (; kk < this.N - 1; kk++) {
                y[0] = (this.mt[kk] & this.UPPER_MASK) | (this.mt[kk + 1] & this.LOWER_MASK);
                this.mt[kk] = this.mt[kk + (this.M - this.N)] ^ (y[0] >> 1) ^ mag01[y[0] & 0x1];
            }
            y[0] = (this.mt[this.N - 1] & this.UPPER_MASK) | (this.mt[0] & this.LOWER_MASK);
            this.mt[this.N - 1] = this.mt[this.M - 1] ^ (y[0] >> 1) ^ mag01[y[0] & 0x1];
            this.mti = 0;
        }
        y[0] = this.mt[this.mti++];
        /* Tempering */
        y[0] ^= (y[0] >> 11);
        y[0] ^= (y[0] << 7) & 0x9d2c5680;
        y[0] ^= (y[0] << 15) & 0xefc60000;
        y[0] ^= (y[0] >> 18);
        return y[0];
    }
    /**
     * generates a random number on [-2147483648,2147483647]-interval (unsigned)
     * @returns number
     */
    genrand_int32i() {
        var y = new Int32Array(1);
        var mag01 = new Uint32Array([0x0, this.MATRIX_A]);
        if (this.mti >= this.N) {
            var kk;
            if (this.mti == this.N + 1) {
                this.init_genrand(5489);
            }
            for (kk = 0; kk < this.N - this.M; kk++) {
                y[0] = (this.mt[kk] & this.UPPER_MASK) | (this.mt[kk + 1] & this.LOWER_MASK);
                this.mt[kk] = this.mt[kk + this.M] ^ (y[0] >> 1) ^ mag01[y[0] & 0x1];
            }
            for (; kk < this.N - 1; kk++) {
                y[0] = (this.mt[kk] & this.UPPER_MASK) | (this.mt[kk + 1] & this.LOWER_MASK);
                this.mt[kk] = this.mt[kk + (this.M - this.N)] ^ (y[0] >> 1) ^ mag01[y[0] & 0x1];
            }
            y[0] = (this.mt[this.N - 1] & this.UPPER_MASK) | (this.mt[0] & this.LOWER_MASK);
            this.mt[this.N - 1] = this.mt[this.M - 1] ^ (y[0] >> 1) ^ mag01[y[0] & 0x1];
            this.mti = 0;
        }
        y[0] = this.mt[this.mti++];
        return y[0];
    }
    /**
     * generates a random number on [0,0x7fffffff]-interval (signed)
     * @returns number
     */
    genrand_int31() {
        return (this.genrand_int32() >> 1);
    }
    /**
     * generates a random number on [0,1]-real-interval
     * @returns number
     */
    genrand_real1() {
        return this.genrand_int32() * (1.0 / 4294967295.0);
    }
    /**
     * generates a random number on [0,1)-real-interval
     * @returns number
     */
    genrand_real2() {
        return this.genrand_int32() * (1.0 / 4294967296.0);
    }
    /**
     * generates a random number on (0,1)-real-interval
     * @returns number
     */
    genrand_real3() {
        return (this.genrand_int32() + 0.5) * (1.0 / 4294967296.0);
    }
    /**
     * generates a random number on [0,1) with 53-bit resolution
     * @returns number
     */
    genrand_res53() {
        var a = this.genrand_int32() >>> 5, b = this.genrand_int32() >>> 6;
        return (a * 67108864.0 + b) * (1.0 / 9007199254740992.0);
    }
    /**
     * generates a random number on [0,1]-real-interval
     * @returns number
     */
    RandTwisterDouble() {
        return this.genrand_real1();
    }
    /**
     * generates a random number on [0,0xffffffff]-interval (unsigned)
     * @returns number
     */
    RandTwisterUnsigned() {
        return this.genrand_int32();
    }
    /**
     * generates a random number on [-2147483648,2147483647]-interval (signed)
     * @returns number
     */
    RandTwisterSigned() {
        return this.genrand_int32i();
    }
    /**
     * generates a random number on [0,0xffffffff]-interval (unsigned)
     * @returns number
     */
    random_int() {
        return this.genrand_int32();
    }
}
exports.MERSENNETWISTER = MERSENNETWISTER;
//# sourceMappingURL=MERSENNETWISTER.js.map