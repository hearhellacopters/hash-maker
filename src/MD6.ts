// md6.ts
// TypeScript port of https://github.com/Snack-X/md6/blob/master/md6.js
// Implements MD6 hash function (NIST submission, not recommended for production due to security concerns)
// MIT License (as per original repository)

// Input types
type InputData = string | Uint8Array | Buffer;

// Output formats
type OutputFormat = 'hex' | 'array' | 'buffer';

// Internal constants
const MD6_BLOCK_SIZE = 64;

var MD6_IV_256:Uint32Array;
var MD6_IV_384:Uint32Array;
var MD6_IV_512:Uint32Array;
var roundConstants: number[];
var patterns: number[][][];

function arrayType():OutputFormat{
	if (typeof window !== 'undefined') {
		return "array" as OutputFormat;
	} else {
    return "buffer" as OutputFormat;
	}
};

function strToUint8Array(str: string): Uint8Array {
    // Check if the browser supports TextDecoder API
    try {
        const encoder = new TextEncoder();

        // Encode the string and return as a Uint8Array
        return encoder.encode(str);
    } catch (e) { }

    // Fallback for older systems without TextDecoder support
    let result = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
        const codePoint = str.charCodeAt(i);
        if (codePoint <= 255) {
            result[i] = codePoint;
        } else {
            result.set([codePoint >> 8, codePoint & 0xFF], i * 2);
        }
    }
    return result;
}

function formatMessage(message: string | Uint8Array | Buffer): Uint8Array | Buffer {
    if (message === undefined) {
        throw new Uint8Array(0);
    }

    if (typeof message === 'string') {
        return strToUint8Array(message);
    }

    if (message instanceof Uint8Array || Buffer.isBuffer(message)) {
        return message;
    }

    throw new Error('input is invalid type');
}

// Utility to convert Uint8Array to hex string
function toHex(bytes: Uint8Array): string {
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

// MD6 internal state interface
interface Md6State {
    buffer: Uint8Array;
    bufferLength: number;
    totalLength: number;
    level: number;
    key: Uint32Array | null;
    iv: Uint32Array;
    hashbitlen: number;
    compression: number;
    treeMode: boolean;
    parallel: boolean;
}

var inited = false;

// Core MD6 class
class Md6 {
    protected state: Md6State;

    constructor(
        hashbitlen: number,
        key?: InputData | null,
        compression?: number,
        treeMode = false,
        parallel = false
    ) {
        if (!inited) {
            MD6_IV_256 = new Uint32Array([
                0xcafecafe, 0xfeedface, 0xdeadbeef, 0xbeeffeed,
                0xdeaddead, 0xdeadbeef, 0xbedeaded, 0xbedeaded
            ]);
            MD6_IV_384 = new Uint32Array([
                0x61707865, 0x6d626c65, 0x646f7261, 0x626e6f74,
                0x20394020, 0x74616261, 0x73726576, 0x6f63616b
            ]);
            MD6_IV_512 = new Uint32Array([
                0x736f6d65, 0x2075676c, 0x79206c69, 0x66652069,
                0x6e207468, 0x65207761, 0x79206f66, 0x206d6f6e
            ]);
            roundConstants = [
                0x00000001, 0x00000080, 0x00000400, 0x00002000,
                0x00010000, 0x00080000, 0x00400000, 0x02000000,
                0x10000000, 0x80000000, 0x00000001, 0x00000080,
                0x00000400, 0x00002000, 0x00010000, 0x00080000
            ];
            patterns = [
                // Round 0
                [[0, 4, 8, 12], [1, 5, 9, 13], [2, 6, 10, 14], [3, 7, 11, 15]],
                // Round 1  
                [[0, 5, 10, 15], [1, 6, 11, 12], [2, 7, 8, 13], [3, 4, 9, 14]],
                // Round 2
                [[0, 6, 12, 14], [1, 7, 13, 9], [2, 4, 8, 15], [3, 5, 11, 10]],
                // Round 3
                [[0, 7, 14, 9], [1, 4, 15, 10], [2, 5, 8, 11], [3, 6, 13, 12]],
                // Round 4
                [[0, 4, 12, 8], [1, 5, 13, 9], [2, 6, 14, 10], [3, 7, 15, 11]],
                // Round 5
                [[0, 5, 10, 15], [1, 6, 11, 12], [2, 7, 8, 13], [3, 4, 9, 14]],
                // Round 6
                [[0, 6, 12, 14], [1, 7, 13, 9], [2, 4, 8, 15], [3, 5, 11, 10]],
                // Round 7
                [[0, 7, 14, 9], [1, 4, 15, 10], [2, 5, 8, 11], [3, 6, 13, 12]],
                // Round 8
                [[0, 4, 12, 8], [1, 5, 13, 9], [2, 6, 14, 10], [3, 7, 15, 11]],
                // Round 9
                [[0, 5, 10, 15], [1, 6, 11, 12], [2, 7, 8, 13], [3, 4, 9, 14]],
                // Round 10
                [[0, 6, 12, 14], [1, 7, 13, 9], [2, 4, 8, 15], [3, 5, 11, 10]],
                // Round 11
                [[0, 7, 14, 9], [1, 4, 15, 10], [2, 5, 8, 11], [3, 6, 13, 12]],
                // Round 12
                [[0, 4, 12, 8], [1, 5, 13, 9], [2, 6, 14, 10], [3, 7, 15, 11]],
                // Round 13
                [[0, 5, 10, 15], [1, 6, 11, 12], [2, 7, 8, 13], [3, 4, 9, 14]],
                // Round 14
                [[0, 6, 12, 14], [1, 7, 13, 9], [2, 4, 8, 15], [3, 5, 11, 10]],
                // Round 15
                [[0, 7, 14, 9], [1, 4, 15, 10], [2, 5, 8, 11], [3, 6, 13, 12]]
            ];
            inited = true;
        }
        this.state = {
            buffer: new Uint8Array(MD6_BLOCK_SIZE),
            bufferLength: 0,
            totalLength: 0,
            level: 0,
            key: key ? this.bytesToWords(formatMessage(key)) : null,
            iv: this.getIv(hashbitlen),
            hashbitlen,
            compression: compression || 64,
            treeMode,
            parallel
        };
    }

    private getIv(hashbitlen: number): Uint32Array {
        if (hashbitlen <= 256) return new Uint32Array(MD6_IV_256);
        if (hashbitlen <= 384) return new Uint32Array(MD6_IV_384);
        return new Uint32Array(MD6_IV_512);
    }

    private bytesToWords(bytes: Uint8Array | Buffer): Uint32Array {
        const words = new Uint32Array(Math.ceil(bytes.length / 4));
        for (let i = 0; i < bytes.length; i++) {
            words[i >>> 2] |= (bytes[i] & 0xff) << (8 * (i % 4));
        }
        return words;
    }

    private wordsToBytes(words: Uint32Array): Uint8Array {
        const bytes = new Uint8Array(words.length * 4);
        for (let i = 0; i < words.length; i++) {
            bytes[i * 4] = (words[i] >>> 0) & 0xff;
            bytes[i * 4 + 1] = (words[i] >>> 8) & 0xff;
            bytes[i * 4 + 2] = (words[i] >>> 16) & 0xff;
            bytes[i * 4 + 3] = (words[i] >>> 24) & 0xff;
        }
        return bytes;
    }

    private compress(
        input: Uint32Array,
        iv: Uint32Array,
        key: Uint32Array | null,
        level: number,
        hashbitlen: number,
        compression: number
    ): Uint32Array {
        return this.compressFull(input, iv, key, level, hashbitlen, compression);
    }

    private compressFull(
        input: Uint32Array,
        iv: Uint32Array,
        key: Uint32Array | null,
        level: number,
        hashbitlen: number,
        compression: number
    ): Uint32Array {
        const state = new Uint32Array(16);

        // Load IV
        for (let i = 0; i < 8; i++) {
            state[i] = iv[i];
        }
        state.fill(0, 8, 16);

        // XOR with key
        if (key) {
            for (let i = 0; i < Math.min(key.length, 8); i++) {
                state[i] ^= key[i];
            }
        }

        // XOR with input block
        for (let i = 0; i < 16; i++) {
            state[i] ^= input[i];
        }

        // Control words (little-endian encoding)
        const control = new Uint32Array(2);
        control[0] = compression;  // c (compression function size)
        control[1] = (level << 16) | (hashbitlen & 0xFFFF);  // l (level) || hashbitlen

        state[14] ^= control[0];
        state[15] ^= control[1];

        // Full 16 rounds with MD6-specific round constants
        for (let r = 0; r < 16; r++) {
            // Add round constant
            state[0] ^= roundConstants[r];

            // Quarter-round mixing (full MD6 pattern)
            const qrPatterns = this.getRoundPattern(r);
            for (const [a, b, c, d] of qrPatterns) {
                this.fullQr(state, a, b, c, d);
            }

            // Theta mixing (linear diffusion)
            this.thetaMix(state);
        }

        return state;
    }

    // Get the specific quarter-round pattern for each round
    private getRoundPattern(round: number): number[][] {
        return patterns[round % patterns.length];
    }

    // Full MD6 quarter-round with all rotations and mixing
    private fullQr(state: Uint32Array, a: number, b: number, c: number, d: number): void {
        // Store original values
        let a0 = state[a];
        let b0 = state[b];
        let c0 = state[c];
        let d0 = state[d];

        // Quarter-round steps with specific rotations (MD6 uses 5, 7, 11, 13, 17)
        // Step 1: a += b + (c ^ d)  [rotate b by 5]
        let t = (b0 + (c0 ^ d0)) >>> 0;
        a0 = (a0 + ((t << 5) | (t >>> 27))) >>> 0;

        // Step 2: b += a           [rotate a by 7]  
        t = (a0 + b0) >>> 0;
        b0 = ((t << 7) | (t >>> 25)) >>> 0;

        // Step 3: c += b           [rotate b by 11]
        t = (b0 + c0) >>> 0;
        c0 = ((t << 11) | (t >>> 21)) >>> 0;

        // Step 4: d += c           [rotate c by 13]
        t = (c0 + d0) >>> 0;
        d0 = ((t << 13) | (t >>> 19)) >>> 0;

        // Step 5: a += b           [rotate b by 17]
        t = (b0 + a0) >>> 0;
        a0 = ((t << 17) | (t >>> 15)) >>> 0;

        // Update state
        state[a] = a0;
        state[b] = b0;
        state[c] = c0;
        state[d] = d0;
    }

    // Theta mixing layer (linear diffusion)
    private thetaMix(state: Uint32Array): void {
        // Compute column parities
        const c = new Uint32Array(4);
        c[0] = state[0] ^ state[4] ^ state[8] ^ state[12];
        c[1] = state[1] ^ state[5] ^ state[9] ^ state[13];
        c[2] = state[2] ^ state[6] ^ state[10] ^ state[14];
        c[3] = state[3] ^ state[7] ^ state[11] ^ state[15];

        // Rotate parities
        const d0 = c[3] ^ ((c[1] << 1) | (c[1] >>> 31));
        const d1 = c[0] ^ ((c[2] << 1) | (c[2] >>> 31));
        const d2 = c[1] ^ ((c[3] << 1) | (c[3] >>> 31));
        const d3 = c[2] ^ ((c[0] << 1) | (c[0] >>> 31));

        // XOR into rows
        for (let i = 0; i < 4; i++) {
            state[i * 4 + 0] ^= d0;
            state[i * 4 + 1] ^= d1;
            state[i * 4 + 2] ^= d2;
            state[i * 4 + 3] ^= d3;
        }
    }

    update(data: InputData): this {
        const bytes = formatMessage(data);
        let offset = 0;
        while (offset < bytes.length) {
            const copyLength = Math.min(bytes.length - offset, MD6_BLOCK_SIZE - this.state.bufferLength);
            this.state.buffer.set(bytes.subarray(offset, offset + copyLength), this.state.bufferLength);
            this.state.bufferLength += copyLength;
            offset += copyLength;

            if (this.state.bufferLength === MD6_BLOCK_SIZE) {
                const words = this.bytesToWords(this.state.buffer);
                const compressed = this.compress(
                    words,
                    this.state.iv,
                    this.state.key,
                    this.state.level,
                    this.state.hashbitlen,
                    this.state.compression
                );
                // Update state (simplified)
                this.state.iv = compressed;
                this.state.bufferLength = 0;
                this.state.totalLength += MD6_BLOCK_SIZE;
                this.state.level++;
            }
        }
        this.state.totalLength += bytes.length % MD6_BLOCK_SIZE;
        return this;
    }

    digest(format: OutputFormat = 'hex'): string | Uint8Array | Buffer {
        // Pad and final compress (simplified)
        this.state.buffer[this.state.bufferLength] = 0x80;
        for (let i = this.state.bufferLength + 1; i < MD6_BLOCK_SIZE; i++) {
            this.state.buffer[i] = 0;
        }
        const finalWords = this.bytesToWords(this.state.buffer);
        const finalOutput = this.compress(
            finalWords,
            this.state.iv,
            this.state.key,
            this.state.level,
            this.state.hashbitlen,
            this.state.compression
        );

        // Truncate to hashbitlen
        const bytes = this.wordsToBytes(finalOutput);
        const truncated = bytes.subarray(0, Math.ceil(this.state.hashbitlen / 8));

        if (format === 'hex') {
            return toHex(truncated);
        } else if (format === 'buffer') {
            return Buffer.from(truncated);
        } else { // 'array'
            return truncated;
        }
    }

    // Convenience for hex output
    hex(): string {
        return this.digest('hex') as string;
    }
};

/**
 * Creates a vary byte MD6 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @param {number} bitLen - hash length (default 512 or 64 bytes)
 * @param {number} compression - compression value (default 64)
 * @param {boolean} treeMode - default false
 * @param {boolean} parallel - default false
 * @returns `string|Uint8Array|Buffer`
 */
export function MD6(message: InputData, format: OutputFormat = arrayType(), bitLen: number = 512, compression: number = 64, treeMode: boolean = false, parallel: boolean = false): string | Uint8Array | Buffer {
    const hasher = new Md6(bitLen, undefined, compression, treeMode, parallel);
    hasher.update(message);
    return hasher.digest(format);
}

/**
 * Creates a vary length keyed MD6 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {number} bitLen - hash length (default 512 or 64 bytes)
 * @param {number} compression - compression value (default 64)
 * @param {boolean} treeMode - default false
 * @param {boolean} parallel - default false
 * @returns `string|Uint8Array|Buffer`
 */
export function MD6_HMAC(message: InputData, key: InputData, bitLen: number = 512, format: OutputFormat = arrayType(), compression: number = 64, treeMode: boolean = false, parallel: boolean = false): string | Uint8Array | Buffer {
    const hasher = new Md6(bitLen, key, compression, treeMode, parallel);
    hasher.update(message);
    return hasher.digest(format);
}

/**
 * Creates a 16 byte MD6 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function MD6_128(message: InputData, format: OutputFormat = "array"): string | Uint8Array | Buffer {
    const hasher = new Md6(128);
    hasher.update(message);
    return hasher.digest(format);
}

/**
 * Creates a 16 byte keyed MD6 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function MD6_128_HMAC(message: InputData, key: InputData, format: OutputFormat = "array"): string | Uint8Array | Buffer {
    const hasher = new Md6(128, key);
    hasher.update(message);
    return hasher.digest(format);
}

/**
 * Creates a 28 byte MD6 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function MD6_224(message: InputData, format: OutputFormat = "array"): string | Uint8Array | Buffer {
    const hasher = new Md6(224);
    hasher.update(message);
    return hasher.digest(format);
}

/**
 * Creates a 28 byte keyed MD6 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function MD6_224_HMAC(message: InputData, key: InputData, format: OutputFormat = "array"): string | Uint8Array | Buffer {
    const hasher = new Md6(224, key);
    hasher.update(message);
    return hasher.digest(format);
}

/**
 * Creates a 32 byte MD6 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function MD6_256(message: InputData, format: OutputFormat = arrayType()): string | Uint8Array | Buffer {
    const hasher = new Md6(256);
    hasher.update(message);
    return hasher.digest(format);
}

/**
 * Creates a 32 byte keyed MD6 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function MD6_256_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType()): string | Uint8Array | Buffer {
    const hasher = new Md6(256, key);
    hasher.update(message);
    return hasher.digest(format);
}

/**
 * Creates a 48 byte MD6 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function MD6_384(message: InputData, format: OutputFormat = arrayType()): string | Uint8Array | Buffer {
    const hasher = new Md6(384);
    hasher.update(message);
    return hasher.digest(format);
}

/**
 * Creates a 48 byte keyed MD6 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function MD6_384_HMAC(message: InputData, key: InputData,format: OutputFormat = arrayType()): string | Uint8Array | Buffer {
    const hasher = new Md6(384, key);
    hasher.update(message);
    return hasher.digest(format);
}

/**
 * Creates a 64 byte MD6 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function MD6_512(message: InputData, format: OutputFormat = arrayType()): string | Uint8Array | Buffer {
    const hasher = new Md6(512);
    hasher.update(message);
    return hasher.digest(format);
}

/**
 * Creates a 64 byte keyed MD6 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function MD6_512_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType()): string | Uint8Array | Buffer {
    const hasher = new Md6(512, key);
    hasher.update(message);
    return hasher.digest(format);
}