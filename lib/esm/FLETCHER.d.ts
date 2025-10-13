/// <reference types="node" />
export declare function fletcher16(data: Buffer | Uint8Array, sum1?: number, sum2?: number): number;
export declare function fletcher32(data: Buffer | Uint8Array, sum1?: number, sum2?: number): number;
export declare function fletcher64(data: Buffer | Uint8Array, sum1?: bigint, sum2?: bigint): bigint;
type InputData = string | Uint8Array | Buffer;
/**
 * Creates an Fletcher16 number of the message.
 *
 * @param {InputData} message - Message to hash
 * @param {number?} seed - starting 16 bit number
 * @returns `number`
 */
export declare function FLETCHER16(message: InputData, seed?: number): number;
/**
 * Creates an Fletcher32 number of the message.
 *
 * @param {InputData} message - Message to hash
 * @param {number?} seed - starting 32 bit number
 * @returns `number`
 */
export declare function FLETCHER32(message: InputData, seed?: number): number;
/**
 * Creates an Fletcher64 bigint of the message.
 *
 * @param {InputData} message - Message to hash
 * @param {bigint?} seed - starting 64 bit number
 * @returns `bigint`
 */
export declare function FLETCHER64(message: InputData, seed?: bigint): bigint;
/**
 * Static class of all FLECTHER functions
 */
export declare class FLETCHER {
    static FLETCHER16: typeof FLETCHER16;
    static FLETCHER32: typeof FLETCHER32;
    static FLETCHER64: typeof FLETCHER64;
    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST(): string[];
}
export {};
//# sourceMappingURL=FLETCHER.d.ts.map