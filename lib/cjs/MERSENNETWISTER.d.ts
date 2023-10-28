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
export declare class MERSENNETWISTER {
    private N;
    private M;
    private MATRIX_A;
    private UPPER_MASK;
    private LOWER_MASK;
    private UCHAR_MAX;
    private mt;
    private mti;
    constructor(seed?: number | Uint32Array);
    private CreateTwisterSeed;
    private init_genrand;
    private init_by_array;
    /**
     * generates a random number on [0,0xffffffff]-interval (unsigned)
     * @returns number
     */
    genrand_int32(): number;
    /**
     * generates a random number on [-2147483648,2147483647]-interval (unsigned)
     * @returns number
     */
    genrand_int32i(): number;
    /**
     * generates a random number on [0,0x7fffffff]-interval (signed)
     * @returns number
     */
    genrand_int31(): number;
    /**
     * generates a random number on [0,1]-real-interval
     * @returns number
     */
    genrand_real1(): number;
    /**
     * generates a random number on [0,1)-real-interval
     * @returns number
     */
    genrand_real2(): number;
    /**
     * generates a random number on (0,1)-real-interval
     * @returns number
     */
    genrand_real3(): number;
    /**
     * generates a random number on [0,1) with 53-bit resolution
     * @returns number
     */
    genrand_res53(): number;
    /**
     * generates a random number on [0,1]-real-interval
     * @returns number
     */
    RandTwisterDouble(): number;
    /**
     * generates a random number on [0,0xffffffff]-interval (unsigned)
     * @returns number
     */
    RandTwisterUnsigned(): number;
    /**
     * generates a random number on [-2147483648,2147483647]-interval (signed)
     * @returns number
     */
    RandTwisterSigned(): number;
    /**
     * generates a random number on [0,0xffffffff]-interval (unsigned)
     * @returns number
     */
    random_int(): number;
}
//# sourceMappingURL=MERSENNETWISTER.d.ts.map