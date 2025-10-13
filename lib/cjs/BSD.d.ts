/// <reference types="node" />
type InputData = string | Uint8Array | Buffer;
/**
 * Create Berkeley Software Distribution (BSD) a 16 bit checksum of the message.
 *
 * @param {InputData} message - Message to hash
 * @param {number?} seed - starting value
 * @returns `number
 */
export declare function Bsd(message: InputData, seed?: number): number;
/**
 * Static class of all BSD functions
 */
export declare class BSD {
    static BSD: typeof Bsd;
    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST(): string[];
}
export {};
//# sourceMappingURL=BSD.d.ts.map