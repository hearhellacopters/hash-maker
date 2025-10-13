/// <reference types="node" />
type InputData = string | Uint8Array | Buffer;
/**
 * Creates Longitudinal Redundancy Checksum as an 8 bit number of the message.
 *
 * @param {InputData} message - Message to hash
 * @param {number?} seed - starting value
 * @returns `number`
 */
export declare function Lcr(message: InputData, seed?: number): number;
/**
 * Static class of all LCR functions
 */
export declare class LCR {
    static LCR: typeof Lcr;
    /**
     * List of all hashes in class
     */
    static get FUNCTION_LIST(): string[];
}
export {};
//# sourceMappingURL=LCR.d.ts.map