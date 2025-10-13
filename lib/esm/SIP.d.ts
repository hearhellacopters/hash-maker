/// <reference types="node" />
type InputData = string | Uint8Array | Buffer;
type OutputFormat = 'hex' | 'array' | 'buffer';
/**
 * Creates a vary byte keyed SipHash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData?} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {32 | 64 | 128} bitLen - output bit length (default 128 AKA 16 bytes)
 * @param {number?} cROUNDS - Primary rounds (default 2)
 * @param {number?} dROUNDS - Secondary rounds (default 4)
 */
export declare function _SIP(message: InputData, key?: InputData, format?: OutputFormat, bitLen?: 32 | 64 | 128, cROUNDS?: number, dROUNDS?: number): string | Uint8Array | Buffer;
/**
 * Creates a 4 byte keyed SipHash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData?} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {number} cROUNDS - Primary rounds (default 2)
 * @param {number} dROUNDS - Secondary rounds (default 4)
 */
export declare function SIP32(message: InputData, key?: InputData, format?: OutputFormat, cROUNDS?: number, dROUNDS?: number): string | Uint8Array | Buffer;
/**
 * Creates a 8 byte keyed SipHash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData?} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {number} cROUNDS - Primary rounds
 * @param {number} dROUNDS - Secondary rounds
 */
export declare function SIP64(message: InputData, key?: InputData, format?: OutputFormat, cROUNDS?: number, dROUNDS?: number): string | Uint8Array | Buffer;
/**
 * Creates a 16 byte keyed SipHash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData?} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {number} cROUNDS - Primary rounds
 * @param {number} dROUNDS - Secondary rounds
 */
export declare function SIP128(message: InputData, key?: InputData, format?: OutputFormat, cROUNDS?: number, dROUNDS?: number): string | Uint8Array | Buffer;
/**
 * Static class of all SIP functions and classes
 */
export declare class SIP {
    static SIP: typeof _SIP;
    static SIP32: typeof SIP32;
    static SIP64: typeof SIP64;
    static SIP128: typeof SIP128;
    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST(): string[];
}
export {};
//# sourceMappingURL=SIP.d.ts.map