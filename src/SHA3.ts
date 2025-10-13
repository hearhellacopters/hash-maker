var SHIFT = [0, 8, 16, 24];
var RC: number[];
var HEX_CHARS = '0123456789abcdef'.split('');

function arrayType():OutputFormat{
	if (typeof window !== 'undefined') {
		return "array" as OutputFormat;
	} else {
    return "buffer" as OutputFormat;
	}
};

var inited = false;

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

function formatMessage(message?: InputData): Buffer | Uint8Array {
    if (message === undefined) {
        return new Uint8Array(0);
    }

    if (typeof message === 'string') {
        return strToUint8Array(message);
    }

    if (Buffer.isBuffer(message)) {
        return message;
    }

    if (message instanceof Uint8Array) {
        return message;
    }

    throw new Error('input is invalid type');
}

// Input types
type InputData = string | Uint8Array | Buffer;

// Output types for hash results
type OutputFormat = 'hex' | 'array' | 'buffer';


function cloneArray(array: any[]) {
    var newArray = [];
    for (var i = 0; i < array.length; ++i) {
        newArray[i] = array[i];
    }
    return newArray;
}

function f(s: number[]) {
    var h, l, n, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9,
        b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15, b16, b17,
        b18, b19, b20, b21, b22, b23, b24, b25, b26, b27, b28, b29, b30, b31, b32, b33,
        b34, b35, b36, b37, b38, b39, b40, b41, b42, b43, b44, b45, b46, b47, b48, b49;
    for (n = 0; n < 48; n += 2) {
        c0 = s[0] ^ s[10] ^ s[20] ^ s[30] ^ s[40];
        c1 = s[1] ^ s[11] ^ s[21] ^ s[31] ^ s[41];
        c2 = s[2] ^ s[12] ^ s[22] ^ s[32] ^ s[42];
        c3 = s[3] ^ s[13] ^ s[23] ^ s[33] ^ s[43];
        c4 = s[4] ^ s[14] ^ s[24] ^ s[34] ^ s[44];
        c5 = s[5] ^ s[15] ^ s[25] ^ s[35] ^ s[45];
        c6 = s[6] ^ s[16] ^ s[26] ^ s[36] ^ s[46];
        c7 = s[7] ^ s[17] ^ s[27] ^ s[37] ^ s[47];
        c8 = s[8] ^ s[18] ^ s[28] ^ s[38] ^ s[48];
        c9 = s[9] ^ s[19] ^ s[29] ^ s[39] ^ s[49];

        h = c8 ^ ((c2 << 1) | (c3 >>> 31));
        l = c9 ^ ((c3 << 1) | (c2 >>> 31));
        s[0] ^= h;
        s[1] ^= l;
        s[10] ^= h;
        s[11] ^= l;
        s[20] ^= h;
        s[21] ^= l;
        s[30] ^= h;
        s[31] ^= l;
        s[40] ^= h;
        s[41] ^= l;
        h = c0 ^ ((c4 << 1) | (c5 >>> 31));
        l = c1 ^ ((c5 << 1) | (c4 >>> 31));
        s[2] ^= h;
        s[3] ^= l;
        s[12] ^= h;
        s[13] ^= l;
        s[22] ^= h;
        s[23] ^= l;
        s[32] ^= h;
        s[33] ^= l;
        s[42] ^= h;
        s[43] ^= l;
        h = c2 ^ ((c6 << 1) | (c7 >>> 31));
        l = c3 ^ ((c7 << 1) | (c6 >>> 31));
        s[4] ^= h;
        s[5] ^= l;
        s[14] ^= h;
        s[15] ^= l;
        s[24] ^= h;
        s[25] ^= l;
        s[34] ^= h;
        s[35] ^= l;
        s[44] ^= h;
        s[45] ^= l;
        h = c4 ^ ((c8 << 1) | (c9 >>> 31));
        l = c5 ^ ((c9 << 1) | (c8 >>> 31));
        s[6] ^= h;
        s[7] ^= l;
        s[16] ^= h;
        s[17] ^= l;
        s[26] ^= h;
        s[27] ^= l;
        s[36] ^= h;
        s[37] ^= l;
        s[46] ^= h;
        s[47] ^= l;
        h = c6 ^ ((c0 << 1) | (c1 >>> 31));
        l = c7 ^ ((c1 << 1) | (c0 >>> 31));
        s[8] ^= h;
        s[9] ^= l;
        s[18] ^= h;
        s[19] ^= l;
        s[28] ^= h;
        s[29] ^= l;
        s[38] ^= h;
        s[39] ^= l;
        s[48] ^= h;
        s[49] ^= l;

        b0 = s[0];
        b1 = s[1];
        b32 = (s[11] << 4) | (s[10] >>> 28);
        b33 = (s[10] << 4) | (s[11] >>> 28);
        b14 = (s[20] << 3) | (s[21] >>> 29);
        b15 = (s[21] << 3) | (s[20] >>> 29);
        b46 = (s[31] << 9) | (s[30] >>> 23);
        b47 = (s[30] << 9) | (s[31] >>> 23);
        b28 = (s[40] << 18) | (s[41] >>> 14);
        b29 = (s[41] << 18) | (s[40] >>> 14);
        b20 = (s[2] << 1) | (s[3] >>> 31);
        b21 = (s[3] << 1) | (s[2] >>> 31);
        b2 = (s[13] << 12) | (s[12] >>> 20);
        b3 = (s[12] << 12) | (s[13] >>> 20);
        b34 = (s[22] << 10) | (s[23] >>> 22);
        b35 = (s[23] << 10) | (s[22] >>> 22);
        b16 = (s[33] << 13) | (s[32] >>> 19);
        b17 = (s[32] << 13) | (s[33] >>> 19);
        b48 = (s[42] << 2) | (s[43] >>> 30);
        b49 = (s[43] << 2) | (s[42] >>> 30);
        b40 = (s[5] << 30) | (s[4] >>> 2);
        b41 = (s[4] << 30) | (s[5] >>> 2);
        b22 = (s[14] << 6) | (s[15] >>> 26);
        b23 = (s[15] << 6) | (s[14] >>> 26);
        b4 = (s[25] << 11) | (s[24] >>> 21);
        b5 = (s[24] << 11) | (s[25] >>> 21);
        b36 = (s[34] << 15) | (s[35] >>> 17);
        b37 = (s[35] << 15) | (s[34] >>> 17);
        b18 = (s[45] << 29) | (s[44] >>> 3);
        b19 = (s[44] << 29) | (s[45] >>> 3);
        b10 = (s[6] << 28) | (s[7] >>> 4);
        b11 = (s[7] << 28) | (s[6] >>> 4);
        b42 = (s[17] << 23) | (s[16] >>> 9);
        b43 = (s[16] << 23) | (s[17] >>> 9);
        b24 = (s[26] << 25) | (s[27] >>> 7);
        b25 = (s[27] << 25) | (s[26] >>> 7);
        b6 = (s[36] << 21) | (s[37] >>> 11);
        b7 = (s[37] << 21) | (s[36] >>> 11);
        b38 = (s[47] << 24) | (s[46] >>> 8);
        b39 = (s[46] << 24) | (s[47] >>> 8);
        b30 = (s[8] << 27) | (s[9] >>> 5);
        b31 = (s[9] << 27) | (s[8] >>> 5);
        b12 = (s[18] << 20) | (s[19] >>> 12);
        b13 = (s[19] << 20) | (s[18] >>> 12);
        b44 = (s[29] << 7) | (s[28] >>> 25);
        b45 = (s[28] << 7) | (s[29] >>> 25);
        b26 = (s[38] << 8) | (s[39] >>> 24);
        b27 = (s[39] << 8) | (s[38] >>> 24);
        b8 = (s[48] << 14) | (s[49] >>> 18);
        b9 = (s[49] << 14) | (s[48] >>> 18);

        s[0] = b0 ^ (~b2 & b4);
        s[1] = b1 ^ (~b3 & b5);
        s[10] = b10 ^ (~b12 & b14);
        s[11] = b11 ^ (~b13 & b15);
        s[20] = b20 ^ (~b22 & b24);
        s[21] = b21 ^ (~b23 & b25);
        s[30] = b30 ^ (~b32 & b34);
        s[31] = b31 ^ (~b33 & b35);
        s[40] = b40 ^ (~b42 & b44);
        s[41] = b41 ^ (~b43 & b45);
        s[2] = b2 ^ (~b4 & b6);
        s[3] = b3 ^ (~b5 & b7);
        s[12] = b12 ^ (~b14 & b16);
        s[13] = b13 ^ (~b15 & b17);
        s[22] = b22 ^ (~b24 & b26);
        s[23] = b23 ^ (~b25 & b27);
        s[32] = b32 ^ (~b34 & b36);
        s[33] = b33 ^ (~b35 & b37);
        s[42] = b42 ^ (~b44 & b46);
        s[43] = b43 ^ (~b45 & b47);
        s[4] = b4 ^ (~b6 & b8);
        s[5] = b5 ^ (~b7 & b9);
        s[14] = b14 ^ (~b16 & b18);
        s[15] = b15 ^ (~b17 & b19);
        s[24] = b24 ^ (~b26 & b28);
        s[25] = b25 ^ (~b27 & b29);
        s[34] = b34 ^ (~b36 & b38);
        s[35] = b35 ^ (~b37 & b39);
        s[44] = b44 ^ (~b46 & b48);
        s[45] = b45 ^ (~b47 & b49);
        s[6] = b6 ^ (~b8 & b0);
        s[7] = b7 ^ (~b9 & b1);
        s[16] = b16 ^ (~b18 & b10);
        s[17] = b17 ^ (~b19 & b11);
        s[26] = b26 ^ (~b28 & b20);
        s[27] = b27 ^ (~b29 & b21);
        s[36] = b36 ^ (~b38 & b30);
        s[37] = b37 ^ (~b39 & b31);
        s[46] = b46 ^ (~b48 & b40);
        s[47] = b47 ^ (~b49 & b41);
        s[8] = b8 ^ (~b0 & b2);
        s[9] = b9 ^ (~b1 & b3);
        s[18] = b18 ^ (~b10 & b12);
        s[19] = b19 ^ (~b11 & b13);
        s[28] = b28 ^ (~b20 & b22);
        s[29] = b29 ^ (~b21 & b23);
        s[38] = b38 ^ (~b30 & b32);
        s[39] = b39 ^ (~b31 & b33);
        s[48] = b48 ^ (~b40 & b42);
        s[49] = b49 ^ (~b41 & b43);

        s[0] ^= RC[n];
        s[1] ^= RC[n + 1];
    }
};

class Keccak {
    blocks: number[];
    s: number[];
    padding: number[];
    outputBits: number;
    reset: boolean;
    finalized: boolean;
    block: number;
    start: number;
    blockCount: number;
    byteCount: number;
    outputBlocks: number;
    extraBytes: number;
    lastByteIndex: number = 0;
    constructor(bits: number, padding: number[], outputBits: number) {
        if (!inited) {
            RC = [1, 0, 32898, 0, 32906, 2147483648, 2147516416, 2147483648, 32907, 0, 2147483649,
                0, 2147516545, 2147483648, 32777, 2147483648, 138, 0, 136, 0, 2147516425, 0,
                2147483658, 0, 2147516555, 0, 139, 2147483648, 32905, 2147483648, 32771,
                2147483648, 32770, 2147483648, 128, 2147483648, 32778, 0, 2147483658, 2147483648,
                2147516545, 2147483648, 32896, 2147483648, 2147483649, 0, 2147516424, 2147483648];
            inited = true;
        }
        this.blocks = [];
        this.s = [];
        this.padding = padding;
        this.outputBits = outputBits;
        this.reset = true;
        this.finalized = false;
        this.block = 0;
        this.start = 0;
        this.blockCount = (1600 - (bits << 1)) >> 5;
        this.byteCount = this.blockCount << 2;
        this.outputBlocks = outputBits >> 5;
        this.extraBytes = (outputBits & 31) >> 3;

        for (var i = 0; i < 50; ++i) {
            this.s[i] = 0;
        }
    }
    update(message: string | Uint8Array | Buffer) {
        if (this.finalized) {
            throw new Error('finalize already called');
        }
        message = formatMessage(message);
        var blocks = this.blocks, byteCount = this.byteCount, length = message.length, blockCount = this.blockCount, index = 0, s = this.s, i;

        while (index < length) {
            if (this.reset) {
                this.reset = false;
                blocks[0] = this.block;
                for (i = 1; i < blockCount + 1; ++i) {
                    blocks[i] = 0;
                }
            }
            message = message as Uint8Array;
            for (i = this.start; index < length && i < byteCount; ++index) {
                blocks[i >> 2] |= message[index] << SHIFT[i++ & 3];
            }
            this.lastByteIndex = i;
            if (i >= byteCount) {
                this.start = i - byteCount;
                this.block = blocks[blockCount];
                for (i = 0; i < blockCount; ++i) {
                    s[i] ^= blocks[i];
                }
                f(s);
                this.reset = true;
            } else {
                this.start = i;
            }
        }
        return this;
    }
    encode(x: number, right?: boolean) {
        var o = x & 255, n = 1;
        var bytes = [o];
        x = x >> 8;
        o = x & 255;
        while (o > 0) {
            bytes.unshift(o);
            x = x >> 8;
            o = x & 255;
            ++n;
        }
        if (right) {
            bytes.push(n);
        } else {
            bytes.unshift(n);
        }
        this.update(new Uint8Array(bytes));
        return bytes.length;
    }
    encodeString(str?: InputData) {
        str = formatMessage(str);
        var bytes = 0, length = str.length;
        bytes = length;
        bytes += this.encode(bytes * 8);
        this.update(str);
        return bytes;
    }
    bytepad(strs: InputData[], w: number) {
        var bytes = this.encode(w);
        for (var i = 0; i < strs.length; ++i) {
            bytes += this.encodeString(strs[i]);
        }
        var paddingBytes = (w - bytes % w) % w;
        var zeros = new Uint8Array(paddingBytes);
        //zeros.length = paddingBytes;
        this.update(zeros);
        return this;
    }
    finalize() {
        if (this.finalized) {
            return;
        }
        this.finalized = true;
        var blocks = this.blocks, i = this.lastByteIndex, blockCount = this.blockCount, s = this.s;
        blocks[i >> 2] |= this.padding[i & 3];
        if (this.lastByteIndex === this.byteCount) {
            blocks[0] = blocks[blockCount];
            for (i = 1; i < blockCount + 1; ++i) {
                blocks[i] = 0;
            }
        }
        blocks[blockCount - 1] |= 0x80000000;
        for (i = 0; i < blockCount; ++i) {
            s[i] ^= blocks[i];
        }
        f(s);
    }
    hex(): string {
        this.finalize();

        var blockCount = this.blockCount, s = this.s, outputBlocks = this.outputBlocks, extraBytes = this.extraBytes, i = 0, j = 0;
        var hex = '', block;
        while (j < outputBlocks) {
            for (i = 0; i < blockCount && j < outputBlocks; ++i, ++j) {
                block = s[i];
                hex += HEX_CHARS[(block >> 4) & 0x0F] + HEX_CHARS[block & 0x0F] +
                    HEX_CHARS[(block >> 12) & 0x0F] + HEX_CHARS[(block >> 8) & 0x0F] +
                    HEX_CHARS[(block >> 20) & 0x0F] + HEX_CHARS[(block >> 16) & 0x0F] +
                    HEX_CHARS[(block >> 28) & 0x0F] + HEX_CHARS[(block >> 24) & 0x0F];
            }
            if (j % blockCount === 0) {
                s = cloneArray(s);
                f(s);
                i = 0;
            }
        }
        if (extraBytes) {
            block = s[i];
            hex += HEX_CHARS[(block >> 4) & 0x0F] + HEX_CHARS[block & 0x0F];
            if (extraBytes > 1) {
                hex += HEX_CHARS[(block >> 12) & 0x0F] + HEX_CHARS[(block >> 8) & 0x0F];
            }
            if (extraBytes > 2) {
                hex += HEX_CHARS[(block >> 20) & 0x0F] + HEX_CHARS[(block >> 16) & 0x0F];
            }
        }
        return hex;
    }
    toString(): string {
        return this.hex();
    }
    arrayBuffer(asBuffer: boolean): Uint8Array | Buffer {
        this.finalize();

        var blockCount = this.blockCount, s = this.s, outputBlocks = this.outputBlocks, extraBytes = this.extraBytes, i = 0, j = 0;
        var bytes = this.outputBits >> 3;
        var buffer;
        if (extraBytes) {
            buffer = new ArrayBuffer((outputBlocks + 1) << 2);
        } else {
            buffer = new ArrayBuffer(bytes);
        }
        var array = new Uint32Array(buffer);
        while (j < outputBlocks) {
            for (i = 0; i < blockCount && j < outputBlocks; ++i, ++j) {
                array[j] = s[i];
            }
            if (j % blockCount === 0) {
                s = cloneArray(s);
                f(s);
            }
        }
        if (extraBytes) {
            array[j] = s[i];
            buffer = buffer.slice(0, bytes);
        }
        return asBuffer ? Buffer.from(buffer) : new Uint8Array(buffer);
    }
    buffer(): Buffer {
        return this.arrayBuffer(true) as Buffer;
    }
    array(): Uint8Array {
        return this.arrayBuffer(false) as Uint8Array;
    }
}

class Kmac extends Keccak {
    constructor(bits: number, padding: number[], outputBits: number) {
        super(bits, padding, outputBits);
    }
    finalize(): void {
        this.encode(this.outputBits, true);
        return this.finalize();
    }
}

function createKeccak(bits: 224 | 256 | 384 | 512) {
    var KECCAK_PADDING = [1, 256, 65536, 16777216];
    return new Keccak(bits, KECCAK_PADDING, bits);
}

function createSha3(bits: 224 | 256 | 384 | 512) {
    var PADDING = [6, 1536, 393216, 100663296];
    return new Keccak(bits, PADDING, bits);
}

function createShake(bits: 128 | 256, outputBits: number) {
    var SHAKE_PADDING = [31, 7936, 2031616, 520093696];
    return new Keccak(bits, SHAKE_PADDING, outputBits);
}

function createCShake(bits: 128 | 256, outputBits: number, name?: InputData, secret?: InputData) {
    name = formatMessage(name);
    secret = formatMessage(secret);
    var CSHAKE_PADDING = [4, 1024, 262144, 67108864];
    var CSHAKE_BYTEPAD = {
        '128': 168,
        '256': 136
    };
    var w = CSHAKE_BYTEPAD[bits];
    return new Keccak(bits, CSHAKE_PADDING, outputBits).bytepad([name, secret], w);
}

function createKmac(bits: 128 | 256, outputBits: number, key?: InputData, secret?: InputData) {
    key = formatMessage(key);
    secret = formatMessage(secret);
    var CSHAKE_PADDING = [4, 1024, 262144, 67108864];
    var CSHAKE_BYTEPAD = {
        '128': 168,
        '256': 136
    };
    var w = CSHAKE_BYTEPAD[bits];
    return new Kmac(bits, CSHAKE_PADDING, outputBits).bytepad(['KMAC', secret], w).bytepad([key], w);
}

/**
 * SHA3 of vary byte size hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {224 | 256 | 384 | 512} bits - hash output size (default 256)
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export function SHA3(message: InputData, bits: 224 | 256 | 384 | 512 = 256, format: OutputFormat = "hex"): string | Buffer | Uint8Array {
    const hash = createSha3(bits);
    hash.update(message);
    if (format == "hex") {
        return hash.hex() ;
    } else if (format == "buffer") {
        return hash.buffer();
    }
    return hash.array();
}

/**
 * SHA3 of vary byte size keyed hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {224 | 256 | 384 | 512} bits - hash output size (default 256)
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export function SHA3_HMAC(message: InputData, key: InputData, bits: 224 | 256 | 384 | 512 = 256, format: OutputFormat = "hex"): string | Buffer | Uint8Array {
    switch (bits){
        case 224:
            return SHA3_224_HMAC(message, key, format);
            break;
        case 256:
            return SHA3_256_HMAC(message, key, format);
            break;
        case 384:
            return SHA3_384_HMAC(message, key, format);
            break;
        case 512:
            return SHA3_512_HMAC(message, key, format);
            break;
        default:
            return SHA3_256_HMAC(message, key, format);
            break;
    }
}

/**
 * SHA3 28 byte hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export function SHA3_224(message: InputData, format: OutputFormat = arrayType()): string | Buffer | Uint8Array {
    const hash = createSha3(224);
    hash.update(message);
    if (format == "hex") {
        return hash.hex() ;
    } else if (format == "buffer") {
        return hash.buffer();
    }
    return hash.array();
}

/**
 * SHA3 28 keyed byte hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export function SHA3_224_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType()): string | Buffer | Uint8Array {
    const key_length = 144;
    const hash_length = 28;
    key = formatMessage(key);
    message = formatMessage(message);
    if (key.length > key_length) {
        key = SHA3_224(key, "array") as Uint8Array;
    }

    if (key.length < key_length) {
        const tmp = new Uint8Array(key_length);
        tmp.set(key, 0);
        key = tmp;
    }

    // Generate inner and outer keys
    var innerKey = new Uint8Array(key_length);
    var outerKey = new Uint8Array(key_length);
    for (var i = 0; i < key_length; i++) {
        innerKey[i] = 0x36 ^ key[i];
        outerKey[i] = 0x5c ^ key[i];
    }

    // Append the innerKey
    var msg = new Uint8Array(message.length + key_length);
    msg.set(innerKey, 0);
    msg.set(message, 64);

    // Hash the previous message and append the outerKey
    var result = new Uint8Array(key_length + hash_length);
    result.set(outerKey, 0);
    result.set(SHA3_224(msg, "array") as Uint8Array, key_length);

    return SHA3_224(result, format);
}

/**
 * SHA3 32 byte hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export function SHA3_256(message: InputData, format: OutputFormat = arrayType()): string | Buffer | Uint8Array {
    const hash = createSha3(256);
    hash.update(message);
    if (format == "hex") {
        return hash.hex() ;
    } else if (format == "buffer") {
        return hash.buffer();
    }
    return hash.array();
}

/**
 * SHA3 32 byte keyed hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export function SHA3_256_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType()): string | Buffer | Uint8Array {
    const key_length = 136;
    const hash_length = 32;
    key = formatMessage(key);
    message = formatMessage(message);
    if (key.length > key_length) {
        key = SHA3_256(key, "array") as Uint8Array;
    }

    if (key.length < key_length) {
        const tmp = new Uint8Array(key_length);
        tmp.set(key, 0);
        key = tmp;
    }

    // Generate inner and outer keys
    var innerKey = new Uint8Array(key_length);
    var outerKey = new Uint8Array(key_length);
    for (var i = 0; i < key_length; i++) {
        innerKey[i] = 0x36 ^ key[i];
        outerKey[i] = 0x5c ^ key[i];
    }

    // Append the innerKey
    var msg = new Uint8Array(message.length + key_length);
    msg.set(innerKey, 0);
    msg.set(message, 64);

    // Hash the previous message and append the outerKey
    var result = new Uint8Array(key_length + hash_length);
    result.set(outerKey, 0);
    result.set(SHA3_256(msg, "array") as Uint8Array, key_length);

    return SHA3_256(result, format);
}

/**
 * SHA3 48 byte hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export function SHA3_384(message: InputData, format: OutputFormat = arrayType()): string | Buffer | Uint8Array {
    const hash = createSha3(384);
    hash.update(message);
    if (format == "hex") {
        return hash.hex() ;
    } else if (format == "buffer") {
        return hash.buffer();
    }
    return hash.array();
}

/**
 * SHA3 48 byte keyed hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export function SHA3_384_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType()): string | Buffer | Uint8Array {
    const key_length = 104;
    const hash_length = 48;
    key = formatMessage(key);
    message = formatMessage(message);
    if (key.length > key_length) {
        key = SHA3_384(key, "array") as Uint8Array;
    }

    if (key.length < key_length) {
        const tmp = new Uint8Array(key_length);
        tmp.set(key, 0);
        key = tmp;
    }

    // Generate inner and outer keys
    var innerKey = new Uint8Array(key_length);
    var outerKey = new Uint8Array(key_length);
    for (var i = 0; i < key_length; i++) {
        innerKey[i] = 0x36 ^ key[i];
        outerKey[i] = 0x5c ^ key[i];
    }

    // Append the innerKey
    var msg = new Uint8Array(message.length + key_length);
    msg.set(innerKey, 0);
    msg.set(message, 64);

    // Hash the previous message and append the outerKey
    var result = new Uint8Array(key_length + hash_length);
    result.set(outerKey, 0);
    result.set(SHA3_384(msg, "array") as Uint8Array, key_length);

    return SHA3_384(result, format);
}

/**
 * SHA3 64 byte hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export function SHA3_512(message: InputData, format: OutputFormat = arrayType()): string | Buffer | Uint8Array {
    const hash = createSha3(512);
    hash.update(message);
    if (format == "hex") {
        return hash.hex() ;
    } else if (format == "buffer") {
        return hash.buffer();
    }
    return hash.array();
}

/**
 * SHA3 64 byte keyed hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export function SHA3_512_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType()): string | Buffer | Uint8Array {
    const key_length = 72;
    const hash_length = 64;
    key = formatMessage(key);
    message = formatMessage(message);
    if (key.length > key_length) {
        key = SHA3_512(key, "array") as Uint8Array;
    }

    if (key.length < key_length) {
        const tmp = new Uint8Array(key_length);
        tmp.set(key, 0);
        key = tmp;
    }

    // Generate inner and outer keys
    var innerKey = new Uint8Array(key_length);
    var outerKey = new Uint8Array(key_length);
    for (var i = 0; i < key_length; i++) {
        innerKey[i] = 0x36 ^ key[i];
        outerKey[i] = 0x5c ^ key[i];
    }

    // Append the innerKey
    var msg = new Uint8Array(message.length + key_length);
    msg.set(innerKey, 0);
    msg.set(message, 64);

    // Hash the previous message and append the outerKey
    var result = new Uint8Array(key_length + hash_length);
    result.set(outerKey, 0);
    result.set(SHA3_512(msg, "array") as Uint8Array, key_length);

    return SHA3_512(result, format);
}

/**
 * Keccak of vary byte size hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {224 | 256 | 384 | 512} bits - hash output size (default 256)
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export function _KECCAK(message: InputData, bits: 224 | 256 | 384 | 512 = 256, format: OutputFormat = "hex"): string | Buffer | Uint8Array {
    const hash = createKeccak(bits);
    hash.update(message);
    if (format == "hex") {
        return hash.hex() ;
    } else if (format == "buffer") {
        return hash.buffer();
    }
    return hash.array();
}

/**
 * Keccak of vary byte size keyed hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {224 | 256 | 384 | 512} bits - hash output size (default 256)
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export function KECCAK_HMAC(message: InputData, key: InputData, bits: 224 | 256 | 384 | 512 = 256, format: OutputFormat = "hex"): string | Buffer | Uint8Array {
    switch (bits){
        case 224:
            return KECCAK224_HMAC(message, key, format);
            break;
        case 256:
            return KECCAK256_HMAC(message, key, format);
            break;
        case 384:
            return KECCAK384_HMAC(message, key, format);
            break;
        case 512:
            return KECCAK512_HMAC(message, key, format);
            break;
        default:
            return KECCAK256_HMAC(message, key, format);
            break;
    }
}

/**
 * Keccak 28 byte hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export function KECCAK224(message: InputData, format: OutputFormat = arrayType()): string | Buffer | Uint8Array {
    const hash = createKeccak(224);
    hash.update(message);
    if (format == "hex") {
        return hash.hex() ;
    } else if (format == "buffer") {
        return hash.buffer();
    }
    return hash.array();
}

/**
 * Keccak 28 byte keyed hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export function KECCAK224_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType()): string | Buffer | Uint8Array {
    const hash_len = 28;
    const key_length = 200 - 2 * hash_len;
    key = formatMessage(key);
    message = formatMessage(message);
    if (key.length > key_length) {
        key = KECCAK224(key, "array") as Uint8Array;
    }

    if (key.length < key_length) {
        const tmp = new Uint8Array(key_length);
        tmp.set(key, 0);
        key = tmp;
    }

    // Generate inner and outer keys
    var innerKey = new Uint8Array(key_length);
    var outerKey = new Uint8Array(key_length);
    for (var i = 0; i < key_length; i++) {
        innerKey[i] = 0x36 ^ key[i];
        outerKey[i] = 0x5c ^ key[i];
    }

    // Append the innerKey
    var msg = new Uint8Array(message.length + key_length);
    msg.set(innerKey, 0);
    msg.set(message, key_length);

    // Hash the previous message and append the outerKey
    var result = new Uint8Array(key_length + hash_len);
    result.set(outerKey, 0);
    result.set(KECCAK224(msg, "array") as Uint8Array, key_length);

    return KECCAK224(result, format);
}

/**
 * Keccak 32 byte hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export function KECCAK256(message: InputData, format: OutputFormat = arrayType()): string | Buffer | Uint8Array {
    const hash = createKeccak(256);
    hash.update(message);
    if (format == "hex") {
        return hash.hex() ;
    } else if (format == "buffer") {
        return hash.buffer();
    }
    return hash.array();
}

/**
 * Keccak 32 byte keyed hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export function KECCAK256_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType()): string | Buffer | Uint8Array {
    const hash_len = 32;
    const key_length = 200 - 2 * hash_len;
    key = formatMessage(key);
    message = formatMessage(message);
    if (key.length > key_length) {
        key = KECCAK256(key, "array") as Uint8Array;
    }

    if (key.length < key_length) {
        const tmp = new Uint8Array(key_length);
        tmp.set(key, 0);
        key = tmp;
    }

    // Generate inner and outer keys
    var innerKey = new Uint8Array(key_length);
    var outerKey = new Uint8Array(key_length);
    for (var i = 0; i < key_length; i++) {
        innerKey[i] = 0x36 ^ key[i];
        outerKey[i] = 0x5c ^ key[i];
    }

    // Append the innerKey
    var msg = new Uint8Array(message.length + key_length);
    msg.set(innerKey, 0);
    msg.set(message, key_length);

    // Hash the previous message and append the outerKey
    var result = new Uint8Array(key_length + hash_len);
    result.set(outerKey, 0);
    result.set(KECCAK256(msg, "array") as Uint8Array, key_length);

    return KECCAK256(result, format);
}

/**
 * Keccak 48 byte hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export function KECCAK384(message: InputData, format: OutputFormat = arrayType()): string | Buffer | Uint8Array {
    const hash = createKeccak(384);
    hash.update(message);
    if (format == "hex") {
        return hash.hex() ;
    } else if (format == "buffer") {
        return hash.buffer();
    }
    return hash.array();
}

/**
 * Keccak 48 byte keyed hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export function KECCAK384_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType()): string | Buffer | Uint8Array {
    const hash_len = 48;
    const key_length = 200 - 2 * hash_len;
    key = formatMessage(key);
    message = formatMessage(message);
    if (key.length > key_length) {
        key = KECCAK384(key, "array") as Uint8Array;
    }

    if (key.length < key_length) {
        const tmp = new Uint8Array(key_length);
        tmp.set(key, 0);
        key = tmp;
    }

    // Generate inner and outer keys
    var innerKey = new Uint8Array(key_length);
    var outerKey = new Uint8Array(key_length);
    for (var i = 0; i < key_length; i++) {
        innerKey[i] = 0x36 ^ key[i];
        outerKey[i] = 0x5c ^ key[i];
    }

    // Append the innerKey
    var msg = new Uint8Array(message.length + key_length);
    msg.set(innerKey, 0);
    msg.set(message, key_length);

    // Hash the previous message and append the outerKey
    var result = new Uint8Array(key_length + hash_len);
    result.set(outerKey, 0);
    result.set(KECCAK384(msg, "array") as Uint8Array, key_length);

    return KECCAK384(result, format);
}

/**
 * Keccak 64 byte hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export function KECCAK512(message: InputData, format: OutputFormat = arrayType()): string | Buffer | Uint8Array {
    const hash = createKeccak(512);
    hash.update(message);
    if (format == "hex") {
        return hash.hex() ;
    } else if (format == "buffer") {
        return hash.buffer();
    }
    return hash.array();
}

/**
 * Keccak 64 byte keyed hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export function KECCAK512_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType()): string | Buffer | Uint8Array {
    const hash_len = 64;
    const key_length = 200 - 2 * hash_len;
    key = formatMessage(key);
    message = formatMessage(message);
    if (key.length > key_length) {
        key = KECCAK512(key, "array") as Uint8Array;
    }

    if (key.length < key_length) {
        const tmp = new Uint8Array(key_length);
        tmp.set(key, 0);
        key = tmp;
    }

    // Generate inner and outer keys
    var innerKey = new Uint8Array(key_length);
    var outerKey = new Uint8Array(key_length);
    for (var i = 0; i < key_length; i++) {
        innerKey[i] = 0x36 ^ key[i];
        outerKey[i] = 0x5c ^ key[i];
    }

    // Append the innerKey
    var msg = new Uint8Array(message.length + key_length);
    msg.set(innerKey, 0);
    msg.set(message, key_length);

    // Hash the previous message and append the outerKey
    var result = new Uint8Array(key_length + hash_len);
    result.set(outerKey, 0);
    result.set(KECCAK512(msg, "array") as Uint8Array, key_length);

    return KECCAK512(result, format);
}

/**
 * Custom Shake a vary byte hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {128 | 256} bits - hash size (default 256)
 * @param {number} outputBits - output hash size
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export function _SHAKE(message: InputData, bits: 128 | 256 = 256, outputBits: number, format: OutputFormat = arrayType()): string | Buffer | Uint8Array {
    const hash = createShake(bits, outputBits);
    hash.update(message);
    if (format == "hex") {
        return hash.hex() ;
    } else if (format == "buffer") {
        return hash.buffer();
    }
    return hash.array();
}

/**
 * Shake 128 with vary byte hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {number} outputBits - output size
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export function SHAKE128(message: InputData, outputBits: number = 256, format: OutputFormat = arrayType()): string | Buffer | Uint8Array {
    const hash = createShake(128, outputBits);
    hash.update(message);
    if (format == "hex") {
        return hash.hex() ;
    } else if (format == "buffer") {
        return hash.buffer();
    }
    return hash.array();
}

/**
 * Shake 256 with vary byte hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {number} outputBits - output size
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Buffer | Uint8Array`
 */
export function SHAKE256(message: InputData, outputBits: number = 256, format: OutputFormat = arrayType()): string | Buffer | Uint8Array {
    const hash = createShake(256, outputBits);
    hash.update(message);
    if (format == "hex") {
        return hash.hex() ;
    } else if (format == "buffer") {
        return hash.buffer();
    }
    return hash.array();
}

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
export function _KMAC(message: InputData, key: InputData, inputBits: 128 | 256 = 256,  outputBits: number = 256, format: OutputFormat = arrayType(), secret: InputData): string | Buffer | Uint8Array {
    const hash = createKmac(inputBits, outputBits, key, secret);
    hash.update(message);
    if (format == "hex") {
        return hash.hex() ;
    } else if (format == "buffer") {
        return hash.buffer();
    }
    return hash.array();
}

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
export function KMAC128(message: InputData, key: InputData, outputBits: number = 256, format: OutputFormat = arrayType(), secret: InputData): string | Buffer | Uint8Array {
    const hash = createKmac(128, outputBits, key, secret);
    hash.update(message);
    if (format == "hex") {
        return hash.hex() ;
    } else if (format == "buffer") {
        return hash.buffer();
    }
    return hash.array();
}

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
export function KMAC256(message: InputData, key: InputData, outputBits: number = 256, format: OutputFormat = arrayType(), secret: InputData): string | Buffer | Uint8Array {
    const hash = createKmac(256, outputBits, key, secret);
    hash.update(message);
    if (format == "hex") {
        return hash.hex() ;
    } else if (format == "buffer") {
        return hash.buffer();
    }
    return hash.array();
}

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
export function _cSHAKE(message: InputData, inputBits: 128 | 256 = 256, outputBits: number, format: OutputFormat = arrayType(), name: InputData, secret: InputData): string | Buffer | Uint8Array {
    const hash = createCShake(inputBits, outputBits, name, secret);
    hash.update(message);
    if (format == "hex") {
        return hash.hex() ;
    } else if (format == "buffer") {
        return hash.buffer();
    }
    return hash.array();
}

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
export function cSHAKE128(message: InputData, outputBits: number, format: OutputFormat = arrayType(), name: InputData, secret: InputData): string | Buffer | Uint8Array {
    const hash = createCShake(128, outputBits, name, secret);
    hash.update(message);
    if (format == "hex") {
        return hash.hex() ;
    } else if (format == "buffer") {
        return hash.buffer();
    }
    return hash.array();
}

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
export function cSHAKE256(message: InputData, outputBits: number, format: OutputFormat = arrayType(), name: InputData, secret: InputData): string | Buffer | Uint8Array {
    const hash = createCShake(256, outputBits, name, secret);
    hash.update(message);
    if (format == "hex") {
        return hash.hex() ;
    } else if (format == "buffer") {
        return hash.buffer();
    }
    return hash.array();
}