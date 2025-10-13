/// <reference types="node" />
type InputData = string | Uint8Array | Buffer;
/**
 * System V (SYSV) 16 bit number of the message.
 *
 * @param {InputData} message - Message to check
 * @param {number?} seed - starting value
 * @returns `number`
 */
export declare function Sysv(message: InputData, seed?: number): number;
/**
 * Static class of all SYSV functions and classes
 */
export declare class SYSV {
    static SYSV: typeof Sysv;
    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST(): string[];
}
export {};
//# sourceMappingURL=SYSV.d.ts.map