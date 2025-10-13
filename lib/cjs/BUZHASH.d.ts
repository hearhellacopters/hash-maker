/// <reference types="node" />
type InputData = string | Uint8Array | Buffer;
declare class BuzHash {
    static bytehash: Uint8Array;
    /**uint32_t */
    state: number;
    buf: Uint8Array;
    /**uint32_t */
    n: number;
    /**int */
    bshiftn: number;
    /**int */
    bshiftm: number;
    /**uint32_t */
    bufpos: number;
    /**int */
    overflow: boolean;
    constructor(seed?: number);
    init(n: number): void;
    reset(): void;
    hash_byte(b: number): number;
    update(message?: InputData): number;
    digest(): number;
}
/**
 * Creates a 32 bit BuzHash of the message.
 *
 * @param {InputData} message - Message to hash
 * @param {number?} seed - starting value
 * @returns `number`
 */
export declare function _BUZHASH(message: InputData, seed?: number): number;
/**
 * Static class of all BuzHash functions and classes
 */
export declare class BUZHASH {
    static BuzHash: typeof BuzHash;
    static BUZHASH: typeof _BUZHASH;
    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST(): string[];
}
export {};
//# sourceMappingURL=BUZHASH.d.ts.map