/// <reference types="node" />
type InputData = string | Uint8Array | Buffer;
/**
 * Creates an Adler32 number of the message.
 *
 * @param {InputData} message - Message to hash
 * @param {number?} seed - starting value
 * @returns `number`
 */
export declare function _ADLER32(message: InputData, seed?: number): number;
/**
 * Static class of all ADLER functions
 */
export declare class ADLER {
    static ADLER32: typeof _ADLER32;
    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST(): string[];
}
export {};
//# sourceMappingURL=ADLER.d.ts.map