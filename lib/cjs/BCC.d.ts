/// <reference types="node" />
type InputData = string | Uint8Array | Buffer;
/**
 * Creates Block Check Character 8 bit number of the message.
 *
 * @param {InputData} message - Message to hash
 * @param {numer?} seed - starting value
 * @returns `number`
 */
export declare function bcc(message: InputData, seed?: number): number;
/**
* Static class of all BCC functions
*/
export declare class BCC {
    static BCC: typeof bcc;
    /**
     * List of all hashes in class
     */
    static get FUNCTION_LIST(): string[];
}
export {};
//# sourceMappingURL=BCC.d.ts.map