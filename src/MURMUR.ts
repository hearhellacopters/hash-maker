import {MURMUR3_X64_128, MURMUR3_X86_32, MURMUR3_X86_128} from './MURMUR3';

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
}

function rotateRight64(value: bigint, shift: number): bigint {
  const BITS = BigInt(64);
  const MASK = (BigInt(1) << BITS) - BigInt(1);
  value = value & MASK;
  let k = BigInt(shift) % BITS;
  if (k === BigInt(0)) return value;
  return (value >> k) | ((value << (BITS - k)) & MASK);
}

function m64(a:number, b:number){
    return Number(BigInt(a) * BigInt(b) & BigInt(0xFFFFFFFF));
}

/**
 * Decode a 32-bit little-endian word from the array {@code buf}
 * at offset {@code off}.
 *
 * @param buf   the source buffer
 * @param off   the source offset
 * @return  the decoded value
 */
function decodeLEInt(buf:Uint8Array,  off: number)
{
    return ((buf[off + 3] & 0xFF) << 24)
        | ((buf[off + 2] & 0xFF) << 16)
        | ((buf[off + 1] & 0xFF) << 8)
        | (buf[off + 0] & 0xFF);
}

/**
 * Decode a 32-bit big-endian word from the array {@code buf}
 * at offset {@code off}.
 *
 * @param buf   the source buffer
 * @param off   the source offset
 * @return  the decoded value
 */
function decodeBEInt(buf:Uint8Array,  off: number)
{
    return ((buf[off + 0] & 0xFF) << 24)
        | ((buf[off + 1] & 0xFF) << 16)
        | ((buf[off + 2] & 0xFF) << 8)
        | (buf[off + 3] & 0xFF);
}

/**
 * Decode a 64-bit little-endian word from the array {@code buf}
 * at offset {@code off}.
 *
 * @param buf   the source buffer
 * @param off   the source offset
 * @return  the decoded value
 */
function decodeLELong(buf: Uint8Array, off: number) {
    let value = BigInt(0);
    let endian = "little";
    let unsigned: boolean = true;
    // @ts-ignore
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

function toInt64(high:number, low:number) {
  const highU = BigInt(high) & BigInt(0xffffffff);
  const lowU = BigInt(low) & BigInt(0xffffffff);
  const u64 = (highU << BigInt(32)) | lowU;
  const SIGN_BIT = BigInt(1) << BigInt(63);
  if ((u64 & SIGN_BIT) !== BigInt(0)) {
    return u64 - (BigInt(1) << BigInt(64));
  } else {
    return u64;
  }
}

// Input types
type InputData = string | Uint8Array | Buffer;

// Output formats
type OutputFormat = 'hex' | 'array' | 'buffer';

/**
 * MurMur1 hash as 32 bit number
 * 
 * @param {InputData} message - Message to hash
 * @param {number?} seed - starting value
 * @returns 
 */
export function MURMUR1(message: InputData, seed:number = 0) {
    var key = formatMessage(message);
    var len = message.length;
    const m = -962287725;
    const r = 16;
    const h = new Int32Array(1);
    h[0] = seed ^ m64(len, m);
    const k = new Int32Array(1);
    while(len >= 4){
        k[0] = decodeLEInt(key, 0);
        h[0] += k[0];
        h[0] = m64(h[0], m);
        h[0] ^= h[0] >>> 16;
        len -= 4;
        key = key.subarray(4,key.length);
    }

    switch(len){
        // @ts-ignore
    case 3:
        h[0] += key[2] << 16;
        // @ts-ignore
    case 2:
        h[0] += key[1] << 8;
    case 1:
        h[0] += key[0];
        h[0] =  m64(h[0], m);
        h[0] ^= h[0] >>> r;
    };

    h[0] =  m64(h[0], m);
    h[0] ^= h[0] >>> 10;
    h[0] =  m64(h[0], m);
    h[0] ^= h[0] >>> 17;
    
    return h[0] >>> 0;
}

/**
 * MurMur2 hash as a 32 bit number.
 * 
 * @param {InputData} message - Message to hash
 * @param {number?} seed - starting value
 * @returns `number`
 */
export function MURMUR2_32(message: InputData, seed: number = 0) {
    var data = formatMessage(message);
    var
        l = data.length,
        h = seed ^ l,
        i = 0,
        k;

    while (l >= 4) {
        k =
            ((data[i] & 0xff)) |
            ((data[++i] & 0xff) << 8) |
            ((data[++i] & 0xff) << 16) |
            ((data[++i] & 0xff) << 24);

        k = (((k & 0xffff) * 0x5bd1e995) + ((((k >>> 16) * 0x5bd1e995) & 0xffff) << 16));
        k ^= k >>> 24;
        k = (((k & 0xffff) * 0x5bd1e995) + ((((k >>> 16) * 0x5bd1e995) & 0xffff) << 16));

        h = (((h & 0xffff) * 0x5bd1e995) + ((((h >>> 16) * 0x5bd1e995) & 0xffff) << 16)) ^ k;

        l -= 4;
        ++i;
    }

    switch (l) {
        //@ts-ignore
        case 3: h ^= (data[i + 2] & 0xff) << 16;
        //@ts-ignore
        case 2: h ^= (data[i + 1] & 0xff) << 8;
        case 1: h ^= (data[i] & 0xff);
            h = (((h & 0xffff) * 0x5bd1e995) + ((((h >>> 16) * 0x5bd1e995) & 0xffff) << 16));
    }

    h ^= h >>> 13;
    h = (((h & 0xffff) * 0x5bd1e995) + ((((h >>> 16) * 0x5bd1e995) & 0xffff) << 16));
    h ^= h >>> 15;

    return h >>> 0;
}

/**
 * MurMur2A hash as a 32 bit number.
 * 
 * @param {InputData} message - Message to hash
 * @param {number?} seed - starting value
 * @returns `number`
 */
export function MURMUR2A_32(message: InputData, seed: number = 0) {
    var data = formatMessage(message);
    var len = data.length;
    const l = new Uint32Array(1);
    l[0] = len;
    const m = 0x5bd1e995;
    const r = 24;
    const h = new Uint32Array(1);
    const k = new Uint32Array(1);
    h[0] = seed;
    while(len >= 4){
        k[0] =
            ((data[0] & 0xff)) |
            ((data[1] & 0xff) << 8) |
            ((data[2] & 0xff) << 16) |
            ((data[3] & 0xff) << 24);
        k[0]  = m64(k[0], m);
        k[0] ^= k[0] >>> r;
        k[0]  = m64(k[0], m);
        h[0]  = m64(h[0], m);
        h[0] ^= k[0];

        data = data.subarray(4, data.length);
        len -= 4;
    }

    var t = new Uint32Array(1);

    switch(len) {
    // @ts-ignore
    case 3: t[0] ^= data[2] << 16;
    // @ts-ignore
    case 2: t[0] ^= data[1] << 8;
    // @ts-ignore
    case 1: t[0] ^= data[0];
    };

    t[0]  = m64(t[0], m);
    t[0] ^= t[0] >>> r;
    t[0]  = m64(t[0], m);
    h[0]  = m64(h[0], m);
    h[0] ^= t[0];

    l[0]  = m64(l[0], m);
    l[0] ^= l[0] >>> r;
    l[0]  = m64(l[0], m);
    h[0]  = m64(h[0], m);
    h[0] ^= l[0];

    h[0] ^= h[0] >>> 13;
    h[0]  = m64(h[0], m);
    h[0] ^= h[0] >>> 15;

    return h[0];
}

/**
 * Murmur2A hash as a 64 bit bigint.
 * 
 * @param {InputData} message - Message to hash
 * @param {bigint?} seed - starting value
 * @returns `bigint`
 */
export function MURMUR2A_64(message:InputData, seed:bigint = BigInt(0)) {
    var data = formatMessage(message);
    const m = BigInt("0xc6a4a7935bd1e995");
    var len = data.length;
    const r = BigInt(47);
    const h = new BigUint64Array(1);
    h[0] = seed ^ (BigInt(len) * m);
    const k = new BigUint64Array(1);
    while(len >= 8){
        k[0] = decodeLELong(data, 0);

        k[0] *= m; 
        k[0] ^= k[0] >> r; 
        k[0] *= m; 
        
        h[0] ^= k[0];
        h[0] *= m; 
        data = data.subarray(0, data.length);
        len -= 8;
    }

    switch(len)
    {
     // @ts-ignore
    case 7: h[0] ^= BigInt(data[6]) << BigInt(48);
    // @ts-ignore
    case 6: h[0] ^= BigInt(data[5]) << BigInt(40);
    // @ts-ignore
    case 5: h[0] ^= BigInt(data[4]) << BigInt(32);
    // @ts-ignore
    case 4: h[0] ^= BigInt(data[3]) << BigInt(24);
    // @ts-ignore
    case 3: h[0] ^= BigInt(data[2]) << BigInt(16);
    // @ts-ignore
    case 2: h[0] ^= BigInt(data[1]) << BigInt(8 );
    // @ts-ignore
    case 1: h[0] ^= BigInt(data[0]);
            h[0] *= m;
    };
    
    h[0] ^= h[0] >> r;
    h[0] *= m;
    h[0] ^= h[0] >> r;

    return h[0];
}

/**
 * Murmur2B hash as a 64 bit bigint.
 * 
 * @param {InputData} message - Message to hash
 * @param {bigint?} seed - starting value
 * @returns `bigint`
 */
export function MURMUR2B_64(message:InputData, seed:bigint = BigInt(0)) {
    var data = formatMessage(message);
    var len = data.length;
    const m = 0x5bd1e995 >>> 0;
    const r = 24;
    const k = new Int32Array(3);
    const h = new Int32Array(3);
    h[1] = Number(seed & BigInt(0xFFFFFFFF)) ^ len;
    h[2] = Number(seed >> BigInt(32));

    while(len >= 8)
    {
        k[1] = ((data[0] & 0xff)) |
            ((data[1] & 0xff) << 8) |
            ((data[2] & 0xff) << 16) |
            ((data[3] & 0xff) << 24);
        k[1]  = m64(k[1], m); 
        k[1] ^= k[1] >>> r; 
        k[1]  = m64(k[1], m); 
        h[1]  = m64(h[1], m);  
        h[1] ^= k[1];
        len -= 4;
        data = data.subarray(4, data.length);
        k[2] = ((data[0] & 0xff)) |
            ((data[1] & 0xff) << 8) |
            ((data[2] & 0xff) << 16) |
            ((data[3] & 0xff) << 24);
        k[2]  = m64(k[2], m); 
        k[2] ^= k[2] >>> r; 
        k[2]  = m64(k[2], m); 
        h[2]  = m64(h[2], m); 
        h[2] ^= k[2];
        len -= 4;
        data = data.subarray(4, data.length);
    }
    
    
    if(len >= 4)
    {
        k[1] = ((data[0] & 0xff)) |
            ((data[1] & 0xff) << 8) |
            ((data[2] & 0xff) << 16) |
            ((data[3] & 0xff) << 24);
        k[1]  = m64(k[1], m); 
        k[1] ^= k[1] >>> r; 
        k[1]  = m64(k[1], m); 
        h[1]  = m64(h[1], m);  
        h[1] ^= k[1];
        len -= 4;
        data = data.subarray(4, data.length);
    }
    
    switch(len)
    {
    // @ts-ignore
    case 3: h[2] ^= data[2] << 16;
    // @ts-ignore
    case 2: h[2] ^= data[1] << 8 ;
    // @ts-ignore
    case 1: h[2] ^= data[0];
        h[2]  = m64(h[2], m);
    };

    h[1] ^= h[2] >>> 18; 
    h[1]  = m64(h[1], m);
    h[2] ^= h[1] >>> 22; 
    h[2]  = m64(h[2], m);
    h[1] ^= h[2] >>> 17; 
    h[1]  = m64(h[1], m);
    h[2] ^= h[1] >>> 19; 
    h[2]  = m64(h[2], m);

    return toInt64(h[1], h[2]);
}

/**
 * Static class of all MurMur functions and classes
 */
export class MURMUR{
    static MURMUR1 = MURMUR1;
    static MURMUR2_32 = MURMUR2_32;
    static MURMUR2A_32 = MURMUR2A_32;
    static MURMUR2A_64 = MURMUR2A_64;
    static MURMUR2B_64 = MURMUR2B_64;
    static MURMUR3_X86_32 = MURMUR3_X86_32;
    static MURMUR3_X86_128 = MURMUR3_X86_128;
    static MURMUR3_X64_128 = MURMUR3_X64_128;
    /**
     * List of all hashes in class
     */
  	static get FUNCTION_LIST() {
    	return [
            "MURMUR1",
            "MURMUR2_32",
            "MURMUR2A_32",
            "MURMUR2A_64",
            "MURMUR2B_64",
            "MURMUR3_X86_32 ",
            "MURMUR3_X86_128",
            "MURMUR3_X64_128"
        ]
    }
}