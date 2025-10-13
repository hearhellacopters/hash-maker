/// <reference types="node" />
type InputData = string | Uint8Array | Buffer;
type OutputFormat = 'hex' | 'array' | 'buffer';
/**
 * SHA3 of vary byte size hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {224 | 256 | 384 | 512} bits - hash output size (default 256)
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export declare function SHA3(message: InputData, bits?: 224 | 256 | 384 | 512, format?: OutputFormat): string | Buffer | Uint8Array;
/**
 * SHA3 of vary byte size keyed hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {224 | 256 | 384 | 512} bits - hash output size (default 256)
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export declare function SHA3_HMAC(message: InputData, key: InputData, bits?: 224 | 256 | 384 | 512, format?: OutputFormat): string | Buffer | Uint8Array;
/**
 * SHA3 28 byte hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export declare function SHA3_224(message: InputData, format?: OutputFormat): string | Buffer | Uint8Array;
/**
 * SHA3 28 keyed byte hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export declare function SHA3_224_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Buffer | Uint8Array;
/**
 * SHA3 32 byte hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export declare function SHA3_256(message: InputData, format?: OutputFormat): string | Buffer | Uint8Array;
/**
 * SHA3 32 byte keyed hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export declare function SHA3_256_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Buffer | Uint8Array;
/**
 * SHA3 48 byte hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export declare function SHA3_384(message: InputData, format?: OutputFormat): string | Buffer | Uint8Array;
/**
 * SHA3 48 byte keyed hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export declare function SHA3_384_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Buffer | Uint8Array;
/**
 * SHA3 64 byte hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export declare function SHA3_512(message: InputData, format?: OutputFormat): string | Buffer | Uint8Array;
/**
 * SHA3 64 byte keyed hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export declare function SHA3_512_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Buffer | Uint8Array;
/**
 * Keccak of vary byte size hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {224 | 256 | 384 | 512} bits - hash output size (default 256)
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export declare function _KECCAK(message: InputData, bits?: 224 | 256 | 384 | 512, format?: OutputFormat): string | Buffer | Uint8Array;
/**
 * Keccak of vary byte size keyed hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {224 | 256 | 384 | 512} bits - hash output size (default 256)
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export declare function KECCAK_HMAC(message: InputData, key: InputData, bits?: 224 | 256 | 384 | 512, format?: OutputFormat): string | Buffer | Uint8Array;
/**
 * Keccak 28 byte hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export declare function KECCAK224(message: InputData, format?: OutputFormat): string | Buffer | Uint8Array;
/**
 * Keccak 28 byte keyed hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export declare function KECCAK224_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Buffer | Uint8Array;
/**
 * Keccak 32 byte hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export declare function KECCAK256(message: InputData, format?: OutputFormat): string | Buffer | Uint8Array;
/**
 * Keccak 32 byte keyed hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export declare function KECCAK256_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Buffer | Uint8Array;
/**
 * Keccak 48 byte hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export declare function KECCAK384(message: InputData, format?: OutputFormat): string | Buffer | Uint8Array;
/**
 * Keccak 48 byte keyed hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export declare function KECCAK384_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Buffer | Uint8Array;
/**
 * Keccak 64 byte hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export declare function KECCAK512(message: InputData, format?: OutputFormat): string | Buffer | Uint8Array;
/**
 * Keccak 64 byte keyed hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export declare function KECCAK512_HMAC(message: InputData, key: InputData, format?: OutputFormat): string | Buffer | Uint8Array;
/**
 * Custom Shake a vary byte hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {128 | 256} bits - hash size (default 256)
 * @param {number} outputBits - output hash size
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export declare function _SHAKE(message: InputData, bits: 128 | 256 | undefined, outputBits: number, format?: OutputFormat): string | Buffer | Uint8Array;
/**
 * Shake 128 with vary byte hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {number} outputBits - output size
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export declare function SHAKE128(message: InputData, outputBits?: number, format?: OutputFormat): string | Buffer | Uint8Array;
/**
 * Shake 256 with vary byte hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {number} outputBits - output size
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export declare function SHAKE256(message: InputData, outputBits?: number, format?: OutputFormat): string | Buffer | Uint8Array;
/**
 * KMac vary input bits with vary byte hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - Message key
 * @param {128 | 256 } inputBits - input bits (default 256)
 * @param {number} outputBits - output size
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @param {InputData?} secret - salt after key
 * @returns `string | Buffer | Uint8Array`
 */
export declare function _KMAC(message: InputData, key: InputData, inputBits: 128 | 256 | undefined, outputBits: number | undefined, format: OutputFormat | undefined, secret: InputData): string | Buffer | Uint8Array;
/**
 * KMac 128 with vary byte hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - Message key
 * @param {number} outputBits - output size
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @param {InputData?} secret - salt after key
 * @returns `string | Buffer | Uint8Array`
 */
export declare function KMAC128(message: InputData, key: InputData, outputBits: number | undefined, format: OutputFormat | undefined, secret: InputData): string | Buffer | Uint8Array;
/**
 * KMac 256 with vary byte hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - Message key
 * @param {number} outputBits - output size
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @param {InputData?} secret - salt after key
 * @returns `string | Buffer | Uint8Array`
 */
export declare function KMAC256(message: InputData, key: InputData, outputBits: number | undefined, format: OutputFormat | undefined, secret: InputData): string | Buffer | Uint8Array;
/**
 * cSHAKE 128 with vary byte hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {number} inputBits - input bits
 * @param {number} outputBits - output hash size
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @param {InputData?} name - input name
 * @param {InputData?} secret - salt for hash
 * @returns `string | Buffer | Uint8Array`
 */
export declare function _cSHAKE(message: InputData, inputBits: 128 | 256 | undefined, outputBits: number, format: OutputFormat | undefined, name: InputData, secret: InputData): string | Buffer | Uint8Array;
/**
 * cSHAKE 128 with vary byte hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {number} outputBits - output hash size
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @param {InputData?} name - input name
 * @param {InputData?} secret - salt for hash
 * @returns `string | Buffer | Uint8Array`
 */
export declare function cSHAKE128(message: InputData, outputBits: number, format: OutputFormat | undefined, name: InputData, secret: InputData): string | Buffer | Uint8Array;
/**
 * cSHAKE 256 with vary byte hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {number} outputBits - output hash size
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @param {InputData?} name - input name
 * @param {InputData?} secret - salt for hash
 * @returns `string | Buffer | Uint8Array`
 */
export declare function cSHAKE256(message: InputData, outputBits: number, format: OutputFormat | undefined, name: InputData, secret: InputData): string | Buffer | Uint8Array;
export {};
//# sourceMappingURL=SHA3.d.ts.map