/// <reference types="node" resolution-mode="require"/>
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
export declare class RANDOMXORSHIFT {
    private mt;
    constructor(seed?: number | Uint8Array | Buffer);
    /**
     * Generate a random unsigned 32 bit integer
     * @returns number
     */
    random_int(): number;
}
//# sourceMappingURL=RANDOMXORSHIFT.d.ts.map