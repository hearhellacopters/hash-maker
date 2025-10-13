/// <reference types="node" />
type InputData = string | Uint8Array | Buffer;
/**
 * TCP checksum
 *
 * @param {InputData} message - Message to check
 * @param {InputData} srcAddr - 4 byte source IP address
 * @param {InputData} destAddr - 4 byte destnation IP address
 * @returns `number`
 */
export declare function SUM_TCP(message: InputData, srcAddr: InputData, destAddr: InputData): number;
/**
 * Sum of the message as 8 bits
 *
 * @param {InputData} message - Message to check
 * @returns `number`
 */
export declare function SUM8(message: InputData): number;
/**
 * Sum of the message as 16 bits
 *
 * @param {InputData} message - Message to check
 * @returns `number`
 */
export declare function SUM16(message: InputData): number;
/**
 * Sum of the message as 16 bits
 *
 * @param {InputData} message - Message to check
 * @returns `number`
 */
export declare function SUM24(message: InputData): number;
/**
 * Sum of the message as 32 bits
 *
 * @param {InputData} message - Message to check
 * @returns `number`
 */
export declare function SUM32(message: InputData): number;
/**
 * XOR of the message as 8 bits
 *
 * @param {InputData} message - Message to check
 * @returns `number`
 */
export declare function XOR8(message: InputData): number;
/**
 * XOR of the message as 16 bits
 *
 * @param {InputData} message - Message to check
 * @returns `number`
 */
export declare function XOR16(message: InputData): number;
/**
 * XOR of the message as 24 bits
 *
 * @param {InputData} message - Message to check
 * @returns `number`
 */
export declare function XOR24(message: InputData): number;
/**
 * XOR of the message as 32 bits
 *
 * @param {InputData} message - Message to check
 * @returns `number`
 */
export declare function XOR32(message: InputData): number;
/**
 * Static class of all Math like functions and classes
 */
export declare class MATH {
    static SUM8: typeof SUM8;
    static SUM16: typeof SUM16;
    static SUM24: typeof SUM24;
    static SUM32: typeof SUM32;
    static SUM_TCP: typeof SUM_TCP;
    static XOR8: typeof XOR8;
    static XOR16: typeof XOR16;
    static XOR24: typeof XOR24;
    static XOR32: typeof XOR32;
    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST(): string[];
}
export {};
//# sourceMappingURL=MATH.d.ts.map