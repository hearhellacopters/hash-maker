/// <reference types="node" />
type InputData = string | Uint8Array | Buffer;
/**
 * Creates Super Fast Hash 32 bit checksum.
 *
 * @param message - Message to hash
 * @returns `number`
 */
declare function _SFH(message: InputData): number;
/**
 * Static class of all Super Fast Hash functions and classes
 */
export declare class SFH {
    static SFH: typeof _SFH;
    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST(): string[];
}
export {};
//# sourceMappingURL=SFH.d.ts.map