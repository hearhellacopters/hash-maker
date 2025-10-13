// General Purpose Hash

// Input types
type InputData = string | Uint8Array | Buffer;

// Output formats
type OutputFormat = 'hex' | 'array' | 'buffer';

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
};

function formatMessage(message?: InputData): Uint8Array {
    if (message === undefined) {
        return new Uint8Array(0);
    }

    if (typeof message === 'string') {
        return strToUint8Array(message);
    }

    if (Buffer.isBuffer(message)) {
        return new Uint8Array(message);
    }

    if (message instanceof Uint8Array) {
        return message as Uint8Array;
    }

    throw new Error('input is invalid type');
};

/**
 * Robert Sedgwicks hash as a 32 bit number.
 * 
 * @param {InputData} message - Message to hash
 * @param {number?} seed - starting value
 * @returns `number`
 */
export function RSHash(message: InputData, seed: number = 0) {
    message = formatMessage(message);
    const length = message.length;
    const b = BigInt(378551);
    const a = new BigUint64Array(1); a[0] = BigInt(63689);
    const hash = new BigUint64Array(1); hash[0] = BigInt(seed);
    for (let i = 0; i < length; ++i) {
        hash[0] = BigInt.asUintN(32, (BigInt.asUintN(32, hash[0] * a[0]) + BigInt(message[i])));
        a[0] = BigInt.asUintN(32, (a[0] * b));
    }

    return Number(hash[0]);
};

/**
 * Justin Sobel hash as a 32bit number. (can't be seeded)
 * 
 * @param {InputData} message - Message to hash
 * @returns `number`
 */
export function JSHash(message: InputData) {
    message = formatMessage(message);
    const length = message.length;
    const hash = new Uint32Array(1); hash[0] = 0x4E67C6A7;

    for (let i = 0; i < length; ++i) {
        hash[0] ^= ((hash[0] << 5) + (message[i]) + (hash[0] >>> 2));
    }

    return hash[0];
};

/**
 * Peter J. Weinberger hash as a 32 bit number.
 * 
 * @param {InputData} message - Message to hash
 * @param {number?} seed - starting value
 * @returns `number`
 */
export function PJWHash(message: InputData, seed: number = 0) {
    message = formatMessage(message);
    const BitsInUnsignedInt = (4 * 8);
    const ThreeQuarters = ((BitsInUnsignedInt * 3) / 4);
    const OneEighth = (BitsInUnsignedInt / 8);
    const HighBits = (4294967295 << (BitsInUnsignedInt - OneEighth)) >>> 0;
    var hash = new Uint32Array(1);
    hash[0] = seed >>> 0;
    var test = 0;

    for (let i = 0; i < message.length; i++) {
        hash[0] = (hash[0] << OneEighth) + message[i];
        test = hash[0] & HighBits;
        if (test != 0) {
            hash[0] = (hash[0] ^ ((test >> ThreeQuarters) & 0xFF)) & (~HighBits);
        }
    }

    return hash[0];
};

/**
 * Executable and Linkable Format (ELF file format) hash as a 32 bit number. (PJW based, widley used on UNIX systems) 
 * 
 * @param {InputData} message - Message to hash
 * @param {number?} seed - starting value
 * @returns `number`
 */
export function ELFHash(message: InputData, seed: number = 0) {
    message = formatMessage(message);
    var h = new Uint32Array(1);
    h[0] = seed >>> 0;
    var g = 0;
    for (let i = 0; i < message.length; i++) {
        h[0] = (h[0] << 4) + message[i];
        g = (h[0] & 0xF0000000) >>> 0;
        if (g) {
            h[0] ^= (g >> 24) & 0xFF;
        }
        h[0] &= ~g;
    }
    return h[0];
};

/**
 * Brian Kernighan and Dennis Ritchie hash as a 32 bit number.
 *  
 * @param {InputData} message - Message to hash
 * @param {number?} seed - starting value
 * @returns `number`
 */
export function BKDRHash(message: InputData, seed: number = 0) {
    message = formatMessage(message);
    const length = message.length;

    const s = 131; /* 31 131 1313 13131 131313 etc.. */
    const hash = new Uint32Array(1); hash[0] = seed;

    for (let i = 0; i < length; ++i) {
        hash[0] = (hash[0] * s) + (message[i]);
    }

    return hash[0];
};

/**
 * Simple Database Management hash as a 32 bit number (a public-domain reimplementation of ndbm)
 * 
 * @param {InputData} message - Message to hash
 * @param {number?} seed - starting value
 * @returns `number`
 */
export function SDBMHash(message: InputData, seed: number = 0) {
    message = formatMessage(message);
    const length = message.length;
    const hash = new Uint32Array(1); hash[0] = seed;

    for (let i = 0; i < length; ++i) {
        hash[0] = (message[i]) + (hash[0] << 6) + (hash[0] << 16) - hash[0];
    }

    return hash[0];
};

/**
 * Daniel J. Bernstein hash as a 32 bit number. (can't be seeded)
 * 
 * @param {InputData} message - Message to hash
 * @returns `number`
 */
export function DJBHash(message: InputData) {
    message = formatMessage(message);
    const length = message.length;
    const hash = new Uint32Array(1); hash[0] = 5381;

    for (let i = 0; i < length; ++i) {
        hash[0] = ((hash[0] << 5) + hash[0]) + (message[i]);
    }

    return hash[0];
};

/**
 * Donald E. Knuth Hash as a 32 bit number. (can't be seeded)
 * 
 * @param {InputData} message - Message to hash
 * @returns `number`
 */
export function DEKHash(message: InputData) {
    message = formatMessage(message);
    const length = message.length;
    const hash = new Uint32Array(1);
    hash[0] = length;

    for (let i = 0; i < length; i++) {
        hash[0] = ((hash[0] << 5) ^ (hash[0] >>> 27)) ^ (message[i]);
    }

    return hash[0];
};

/**
 * Benjamin Pritchard Hash as a 32 bit number.
 * 
 * @param {InputData} message - Message to hash
 * @param {number?} seed - starting value
 * @returns `number`
 */
export function BPHash(message: InputData, seed: number = 0) {
    message = formatMessage(message);
    const length = message.length;
    const hash = new Uint32Array(1);
    hash[0] = seed;
    for (let i = 0; i < length; i++) {
        hash[0] = hash[0] << 7 ^ message[i];
    }

    return hash[0];
};

/**
 * Anchor-based Probability Hash as a 32 bit number.
 * 
 * @param {InputData} message - Message to hash
 * @param {number?} seed - starting value
 * @returns `number`
 */
export function APHash(message: InputData, seed: number = 0xAAAAAAAA) {
    message = formatMessage(message);
    const hash = new Uint32Array(1);
    hash[0] = seed;
    for (let i = 0; i < message.length; i++) {
        if ((i & 1) == 0) {
            hash[0] ^= ((hash[0] << 7) ^ message[i] * (hash[0] >>> 3));
        } else {
            hash[0] ^= (~((hash[0] << 11) + (message[i] ^ (hash[0] >>> 5))));
        }
    }
    return hash[0];
};

/**
 * Daniel J. Bernstein 2 hash as a 32 bit number. (can't be seeded)
 * 
 * @param {InputData} message - Message to hash
 * @returns `number`
 */
export function DJB2Hash(message: InputData) {
    message = formatMessage(message);
    const hash = new Uint32Array(1); hash[0] = 5381;
    for (let i = 0; i < message.length; i++) {
        hash[0] = ((hash[0] << 5) + hash[0]) + message[i];
    }
    return hash[0];
};

/**
 * Fowler/Noll/Vo Hash as a 32 bit number.
 * 
 * @param {InputData} message - Message to hash
 * @param {number?} seed - starting value
 * @returns `number`
 */
export function FNVHash(message: InputData, seed: number = 0) {
    message = formatMessage(message);
    const length = message.length;
    const fnv_prime = BigInt(0x811C9DC5 >>> 0);
    const hash = new BigUint64Array(1); hash[0] = BigInt(seed);
    for (let i = 0; i < length; i++) {
        hash[0] = BigInt.asUintN(32, (hash[0] * fnv_prime));
        hash[0] ^= BigInt(message[i]);
    }

    return Number(hash[0]);
};

/**
 * Zilong Tan Fast Hash as a 32 bit number.
 * 
 * @param {InputData} message - Message to hash
 * @param {number|bigint} seed - starting value
 * @returns `number`
 */
export function Fast32Hash(message: InputData, seed: number|bigint = 0) {
    message = formatMessage(message);
    const len = message.length;
    const rounds = Math.floor(len / 8);

    const m = BigInt("0x880355f21e6d1965");
    const h = new BigUint64Array(1);
    h[0] = BigInt(seed) ^ (BigInt(len) * m);
    
    function read64(buf: Uint8Array, off: number) {
        let value = BigInt(0);
        let endian = "little";
        let unsigned: boolean = false;
        if (endian == "little") {
            for (let i = 0; i < 8; i++) {
                value = value | BigInt(buf[off]) << BigInt(8 * i);
                off++;
            }
            // @ts-ignore
            if (unsigned == false) {
                if (value & (BigInt(1) << BigInt(63))) {
                    value -= BigInt(1) << BigInt(64);
                }
            }
        }
        else {
            for (let i = 0; i < 8; i++) {
                value = (value << BigInt(8)) | BigInt(buf[off]);
                off++;
            }
            // @ts-ignore
            if (unsigned == false) {
                if (value & (BigInt(1) << BigInt(63))) {
                    value -= BigInt(1) << BigInt(64);
                }
            }
        }
        return value;
    }

    function mix(h: bigint) {
        const t = new BigUint64Array([h]);
        t[0] ^= t[0] >> BigInt(23);
        t[0] *= BigInt("0x2127599bf4325c37");
        t[0] ^= t[0] >> BigInt(47);
        return t[0];
    }

    for (let i = 0; i < rounds; i++) {
        h[0] ^= mix(read64(message, i*8));
        h[0] *= m;
        message.subarray(i * 8, h.length);
    }
    var v = BigInt(0);

    switch (len & 7) {
        // @ts-ignore
        case 7: v ^= BigInt(message[6]) << BigInt(48);
        // @ts-ignore
        case 6: v ^= BigInt(message[5]) << BigInt(40);
        // @ts-ignore
        case 5: v ^= BigInt(message[4]) << BigInt(32);
        // @ts-ignore
        case 4: v ^= BigInt(message[3]) << BigInt(24);
        // @ts-ignore
        case 3: v ^= BigInt(message[2]) << BigInt(16);
        // @ts-ignore
        case 2: v ^= BigInt(message[1]) << BigInt(8 );
        case 1: v ^= BigInt(message[0]);
            h[0] ^= mix(v);
            h[0] *= m;
    }

    const final = mix(h[0]);

    return Number(final - (final >> BigInt(32)));
}

/**
 * Zilong Tan Fast Hash as a 64 bit bigint.
 * 
 * @param {InputData} message - Message to hash
 * @param {number|bigint} seed - starting value
 * @returns `bigint`
 */
export function Fast64Hash(message: InputData, seed: number = 0) {
    message = formatMessage(message);
    const len = message.length;
    const rounds = Math.floor(len / 8);

    const m = BigInt("0x880355f21e6d1965");
    const h = new BigUint64Array(1);
    h[0] = BigInt(seed) ^ (BigInt(len) * m);
    
    function read64(buf: Uint8Array, off: number) {
        let value = BigInt(0);
        let endian = "little";
        let unsigned: boolean = false;
        if (endian == "little") {
            for (let i = 0; i < 8; i++) {
                value = value | BigInt(buf[off]) << BigInt(8 * i);
                off++;
            }
            // @ts-ignore
            if (unsigned == false) {
                if (value & (BigInt(1) << BigInt(63))) {
                    value -= BigInt(1) << BigInt(64);
                }
            }
        }
        else {
            for (let i = 0; i < 8; i++) {
                value = (value << BigInt(8)) | BigInt(buf[off]);
                off++;
            }
            // @ts-ignore
            if (unsigned == false) {
                if (value & (BigInt(1) << BigInt(63))) {
                    value -= BigInt(1) << BigInt(64);
                }
            }
        }
        return value;
    }

    function mix(h: bigint) {
        const t = new BigUint64Array([h]);
        t[0] ^= t[0] >> BigInt(23);
        t[0] *= BigInt("0x2127599bf4325c37");
        t[0] ^= t[0] >> BigInt(47);
        return t[0];
    }

    for (let i = 0; i < rounds; i++) {
        h[0] ^= mix(read64(message, i*8));
        h[0] *= m;
        message.subarray(i * 8, h.length);
    }
    var v = BigInt(0);

    switch (len & 7) {
        // @ts-ignore
        case 7: v ^= BigInt(message[6]) << BigInt(48);
        // @ts-ignore
        case 6: v ^= BigInt(message[5]) << BigInt(40);
        // @ts-ignore
        case 5: v ^= BigInt(message[4]) << BigInt(32);
        // @ts-ignore
        case 4: v ^= BigInt(message[3]) << BigInt(24);
        // @ts-ignore
        case 3: v ^= BigInt(message[2]) << BigInt(16);
        // @ts-ignore
        case 2: v ^= BigInt(message[1]) << BigInt(8 );
        case 1: v ^= BigInt(message[0]);
            h[0] ^= mix(v);
            h[0] *= m;
    }

    const final = mix(h[0]);

    return final;
}

/**
 * Static class of all General Purpose Hash functions
 */
export class GPH {
    static RSHash = RSHash;
    static JSHash = JSHash;
    static PJWHash = PJWHash;
    static ELFHash = ELFHash;
    static BKDRHash = BKDRHash;
    static SDBMHash = SDBMHash;
    static DJBHash = DJBHash;
    static DEKHash = DEKHash;
    static BPHash = BPHash;
    static APHash = APHash;
    static DJB2Hash = DJB2Hash;
    static FNVHash = FNVHash;
    static Fast32Hash = Fast32Hash;
    static Fast64Hash = Fast64Hash;

    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST() {
        return [
            "RSHash",
            "JSHash",
            "PJWHash",
            "ELFHash",
            "BKDRHash",
            "SDBMHash",
            "DJBHash",
            "DEKHash",
            "BPHash",
            "APHash",
            "DJB2Hash",
            "FNVHash",
            "Fast32Hash",
            "Fast64Hash"
        ]
    }
}