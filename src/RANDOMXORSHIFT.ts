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
export class RANDOMXORSHIFT {
  private mt: Uint32Array;
  constructor(seed?: number | Uint8Array | Buffer) {
    var s: number;
    const mt = new Uint32Array(5); //[0, 0, 0, 0];
    if (seed == undefined) {
      seed = new Date().getTime();
    }
    if (typeof Buffer !== 'undefined' && seed instanceof Buffer) {
      if (seed.length < 4) {
        throw new Error("Must be a seed Buffer of 4 bytes")
      }
      mt[0] = seed.readUInt32LE() >>> 0;
    } else
      if (seed instanceof Uint8Array) {
        if (seed.length < 4) {
          throw new Error("Must be a seed Uint8Array of 4 bytes")
        }
        mt[0] = ((seed[3] << 24) | (seed[2] << 16) | (seed[1] << 8) | seed[0]);
      } else
        if (typeof seed == "number") {
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
  random_int(): number {
    let v1 = this.mt[0];
    let v4 = this.mt[3];
    let comp_1 = (v4 ^ (v4 >>> 19) ^ v1 ^ (v1 << 11) ^ ((v1 ^ (v1 << 11)) >>> 8)) >>> 0;
    for (let i = 0; i < 4; i++) {
      this.mt[i] = this.mt[i + 1];
    }
    this.mt[3] = comp_1;
    console.log(this.mt)
    return comp_1;
  }
}
