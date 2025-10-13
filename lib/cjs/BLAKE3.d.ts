/// <reference types="node" />
interface blake3_chunk_state {
    /**
     * uint32_t[8]
     */
    cv: Uint32Array;
    chunk_counter: bigint;
    /**
     * uint8_t[BLAKE3_BLOCK_LEN]
     */
    buf: Uint8Array;
    buf_len: number;
    blocks_compressed: number;
    flags: number;
}
interface blake3_hasher {
    /**
     * uint32_t[8]
     */
    key: Uint32Array;
    chunk: blake3_chunk_state;
    cv_stack_len: number;
    /**
     * uint8_t[(BLAKE3_MAX_DEPTH + 1) * BLAKE3_OUT_LEN]
     *
     * The stack size is MAX_DEPTH + 1 because we do lazy merging. For example,
     * with 7 chunks, we have 3 entries in the stack. Adding an 8th chunk
     * requires a 4th entry, rather than merging everything down to 1, because we
     * don't know whether more input is coming. This is different from how the
     * reference implementation does things.
     */
    cv_stack: Uint8Array;
}
type InputData = string | Uint8Array | Buffer;
type OutputFormat = 'hex' | 'array' | 'buffer';
/**
 * Static class of all Blake3 functions
 */
export declare class Blake3 {
    key: InputData | undefined;
    hasher: blake3_hasher;
    constructor(key?: InputData, flags?: number);
    init(): void;
    init_derive_key(): void;
    update(message?: InputData): void;
    final(digestBytes: number): Uint8Array;
}
/**
 * Creates a vary length BLAKE3 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {number?} outLen - length of hash (default 32 bytes)
 * @returns `string|Uint8Array|Buffer`
 */
export declare function BLAKE3(message: InputData, format?: OutputFormat, outLen?: number): string | Uint8Array | Buffer;
/**
 * Creates a vary length keyed BLAKE3 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - key for hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {number?} outLen - length of hash (default 32 bytes)
 * @returns `string|Uint8Array|Buffer`
 */
export declare function BLAKE3_HMAC(message: InputData, key: InputData, format?: OutputFormat, outLen?: number): string | Uint8Array | Buffer;
/**
 * Creates a 32 byte BLAKE3 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData?} message - context salt
 * @param {InputData?} key - starting key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {number?} outLen - length of hash (default 32 bytes)
 * @returns `string|Uint8Array|Buffer`
 */
export declare function BLAKE3_DeriveKey(message?: InputData, key?: InputData, format?: OutputFormat, outLen?: number): string | Uint8Array | Buffer;
export {};
//# sourceMappingURL=BLAKE3.d.ts.map