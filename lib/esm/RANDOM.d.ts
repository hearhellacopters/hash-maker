/// <reference types="node" />
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
type OutputFormat = 'hex' | 'array' | 'buffer';
/**
 * Generate random bytes as a hex string, Uint8Array, Buffer
 *
 * @param {number|Uint8Array|Buffer} number number bytes to create
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export declare function RandomBytes(number: number, format?: OutputFormat): string | Uint8Array | Buffer;
export {};
//# sourceMappingURL=RANDOM.d.ts.map