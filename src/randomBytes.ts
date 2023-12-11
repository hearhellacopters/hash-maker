import {MERSENNETWISTER} from './MERSENNETWISTER.js'

/**
 * Generate random bytes as Uint8Array or Buffer
 * 
 * @param {number} number number bytes to create
 * @param {boolean} asBuffer - returns a Buffer else returns a Uint8Array
 * @returns Uint8Array or Buffer
 */
export function randomBytes(number:number, asBuffer?:boolean) {
    if(number == undefined || !(typeof number == "number")){
        throw new Error("Must supply number of bytes to generate.")
    }
    const mt = new MERSENNETWISTER();
    var array:Buffer|Uint8Array;
    if(asBuffer){
        array = Buffer.alloc(number)
    } else {
        array = new Uint8Array(number)
    }
    for (let i = 0; i < number ; i++) {
        array[i] = mt.random_int()
    }
    return array
}