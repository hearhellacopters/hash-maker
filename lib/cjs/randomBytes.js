"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.randomBytes = void 0;
const MERSENNETWISTER_1 = require("./MERSENNETWISTER");
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
    const mt = new MERSENNETWISTER_1.MERSENNETWISTER();
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