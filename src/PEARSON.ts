function arrayType():OutputFormat{
	if (typeof window !== 'undefined') {
		return "array" as OutputFormat;
	} else {
    return "buffer" as OutputFormat;
	}
};

/**
 * This interface documents the API for a hash function. This
 * interface somewhat mimics the standard java.security.MessageDigest class. We do not extend that class in order to provide compatibility with reduced Java implementations such as J2ME. Implementing a java.security.Provider compatible with Sun's JCA ought to be easy.
 *
 * A Digest object maintains a running state for a hash function computation. Data is inserted with update() calls; the result is obtained from a digest() method (where some final data can be inserted as well). When a digest output has been produced, the object is automatically reset, and can be used immediately for another digest operation. The state of a computation can be cloned with the copy() method; this can be used to get a partial hash result without interrupting the complete computation.
 *
 * Digest objects are stateful and hence not thread-safe; however, distinct Digest objects can be accessed concurrently without any problem.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 * 
 * @version $Revision: 232 $
 * @author Thomas Pornin <thomas.pornin@cryptolog.com>
 */
interface Digest {
    /**
     * Insert one more input data byte.
     *
     * @param input the input byte (0-255)
     */
    update(input: number): void;

    /**
     * Insert some more bytes.
     *
     * @param input the data bytes
     */
    update(input: Uint8Array): void;

    /**
     * Insert some more bytes.
     *
     * @param input the data buffer
     * @param off the data offset in input
     * @param len the data length (in bytes)
     */
    update(input: Uint8Array, off: number, len: number): void;

    /**
     * Finalize the current hash computation and return the hash value
     * in a newly-allocated Uint8Array. The object is reset.
     *
     * @return the hash output
     */
    digest(): Uint8Array;

    /**
     * Input some bytes, then finalize the current hash computation
     * and return the hash value in a newly-allocated Uint8Array. The object
     * is reset.
     *
     * @param inbuf the input data
     * @return the hash output
     */
    digest(inbuf: Uint8Array): Uint8Array;

    /**
     * Finalize the current hash computation and store the hash value
     * in the provided output buffer. The len parameter
     * contains the maximum number of bytes that should be written;
     * no more bytes than the natural hash function output length will
     * be produced. If len is smaller than the natural
     * hash output length, the hash output is truncated to its first
     * len bytes. The object is reset.
     *
     * @param outbuf the output buffer
     * @param off the output offset within outbuf
     * @param len the requested hash output length (in bytes)
     * @return the number of bytes actually written in outbuf
     */
    digest(outbuf: Uint8Array, off: number, len: number): number;

    /**
     * Get the natural hash function output length (in bytes).
     *
     * @return the digest output length (in bytes)
     */
    getDigestLength(): number;

    /**
     * Reset the object: this makes it suitable for a new hash computation.
     * The current computation, if any, is discarded.
     */
    reset(): void;

    /**
     * Clone the current state. The returned object evolves independently
     * of this object.
     *
     * @return the clone
     */
    copy(): Digest;

    /**
     * Get the "block length", which is the hash function internal block
     * length, in bytes. The block length is used by some protocols, such as HMAC.
     *
     * @return the internal block length (in bytes), or 0 if it is not defined by the algorithm
     */
    getBlockLength(): number;

    /**
     * Return a string description of this object.
     *
     * @return the string description
     */
    toString(): string;
}

/**
 * This class is a template which can be used to implement hash
 * functions. It takes care of some of the API, and also provides an
 * internal data buffer whose length is equal to the hash function
 * internal block length.
 *
 * Classes which use this template MUST provide a working getBlockLength
 * method even before initialization (alternatively, they may define a custom
 * getInternalBlockLength which does not call getBlockLength. The getDigestLength should
 * also be operational from the beginning, but it is acceptable that it
 * returns 0 while the doInit method has not been called yet.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 * 
 * @version   $Revision: 229 $
 * @author    Thomas Pornin <thomas.pornin@cryptolog.com>
 */
abstract class DigestEngine implements Digest {

    protected abstract engineReset(): void;

    protected abstract processBlock(data: Uint8Array): void;

    protected abstract doPadding(buf: Uint8Array, off: number): void;

    protected abstract doInit(): void;

    digestLen: number; blockLen: number; inputLen: number;

    inputBuf: Uint8Array; outputBuf: Uint8Array;

    blockCount: bigint;  // Using BigInt as per ES6 requirements for large integer values

    constructor() {
        this.doInit();
        this.digestLen = this.getDigestLength();
        this.blockLen = this.getInternalBlockLength();
        this.inputBuf = new Uint8Array(this.blockLen);
        this.outputBuf = new Uint8Array(this.digestLen);
        this.inputLen = 0;
        this.blockCount = BigInt(0);
    }

    private adjustDigestLen(): void {
        if (this.digestLen == undefined || this.digestLen === 0) {
            this.digestLen = this.getDigestLength();
            this.outputBuf = new Uint8Array(this.digestLen);
        }
    }

    digest(): Uint8Array;
    digest(input: Uint8Array): Uint8Array;
    digest(input: Uint8Array, offset: number, len: number): number;
    digest(input?: Uint8Array, offset?: number, len?: number): Uint8Array | number {
        if (input === undefined) {
            this.adjustDigestLen();
            const result = new Uint8Array(this.digestLen);
            this.digest(result, 0, this.digestLen);
            return result;
        } else if (offset === undefined || len === undefined) {
            this.update(input, 0, input.length);
            return this.digest();
        } else {
            this.adjustDigestLen();
            if (len >= this.digestLen) {
                this.doPadding(input, offset);
                this.reset();
                return this.digestLen;
            } else {
                this.doPadding(this.outputBuf, 0);
                arraycopy(this.outputBuf, 0, input, offset, len);
                this.reset();
                return len;
            }
        }
    }

    reset(): void {
        this.engineReset();
        this.inputLen = 0;
        this.blockCount = BigInt(0);
    }

    update(input: number): void;
    update(input: Uint8Array): void;
    update(input: Uint8Array, offset: number, len: number): void;
    update(input: number | Uint8Array, offset?: number, len?: number): void {
        if (typeof input === 'number') {
            this.inputBuf[this.inputLen++] = input;
            if (this.inputLen === this.blockLen) {
                this.processBlock(this.inputBuf);
                this.blockCount++;
                this.inputLen = 0;
            }
        } else if (offset === undefined || len === undefined) {
            this.update(input, 0, input.length);
        } else {
            while (len > 0) {
                var copyLen = this.blockLen - this.inputLen;
                if (copyLen > len) {
                    copyLen = len;
                }
                arraycopy(input, offset, this.inputBuf, this.inputLen, copyLen);
                offset += copyLen;
                this.inputLen += copyLen;
                len -= copyLen;
                if (this.inputLen == this.blockLen) {
                    this.processBlock(this.inputBuf);
                    this.blockCount++;
                    this.inputLen = 0;
                }
            }
        }
    }

    protected getInternalBlockLength(): number {
        return this.getBlockLength();
    }

    protected flush(): number {
        return this.inputLen;
    }

    getBlockBuffer() {
        return this.inputBuf;
    }

    getBlockCount() {
        return this.blockCount;
    }

    protected copyState<T>(dest: DigestEngine): T {
        dest.inputLen = this.inputLen;
        dest.blockCount = this.blockCount;
        arraycopy(this.inputBuf, 0, dest.inputBuf, 0, this.inputBuf.length);
        this.adjustDigestLen();
        dest.adjustDigestLen();
        arraycopy(this.outputBuf, 0, dest.outputBuf, 0, this.outputBuf.length);
        return dest as T;
    }

    getDigestLength(): number {
        throw new Error('Method not implemented.');
    }
    copy(): Digest {
        throw new Error('Method not implemented.');
    }
    getBlockLength(): number {
        throw new Error('Method not implemented.');
    }
    toString(): string {
        throw new Error('Method not implemented.');
    }
}

function arraycopy(
    src: Uint8Array | Uint16Array | Uint32Array | Float32Array | Uint8ClampedArray,
    srcPos: number = 0,
    dst: Uint8Array | Uint16Array | Uint32Array | Float32Array | Uint8ClampedArray,
    destPos: number = 0,
    length: number) {
    // Validate inputs
    const srcbyteLength = src.byteLength;
    if (srcPos + length > src.byteLength) {
        throw new Error(`memcpy${length}: Source buffer too small, ${srcbyteLength} of ${srcPos + length}`);
    }
    const dstbyteLength = dst.byteLength;
    if (destPos + length > dstbyteLength) {
        throw new Error(`memcpy${length}: Destination buffer too small, ${dstbyteLength} of ${destPos + length}`);
    }

    const dstView = new Uint8Array(dst.buffer, dst.byteOffset + destPos, length);
    const srcView = new Uint8Array(src.buffer, src.byteOffset + srcPos, length);

    dstView.set(srcView);
};

/**
 * Implementation of the multi-byte Pearson hash function.
 * Based on the approach described in the repository summary: using exclusive-or for index modification to create effective different permutations for each output byte.
 * This allows streaming computation without multiple tables.
 * Initial hash for each byte is 0, and for each data byte d, for each position i: h[i] = T[(h[i] ^ d) ^ i]
 * The table T is the same permutation as in the 8-bit version.
 * Output is the concatenation of the 8-bit hashes in order (big-endian within each byte, but since 8-bit, N/A).
 * For HMAC, block length set to 64 * outputBytes or something, but kept 64 for simplicity.
 */

export class Pearson extends DigestEngine {

    private static readonly T: Uint8Array = new Uint8Array([
        1, 87, 49, 12, 176, 178, 102, 166, 121, 193, 6, 84, 249, 230, 44, 163,
        14, 197, 213, 181, 161, 85, 218, 80, 64, 239, 24, 226, 236, 142, 38, 200,
        110, 177, 104, 103, 141, 253, 255, 50, 77, 101, 81, 18, 45, 96, 31, 222,
        25, 107, 190, 70, 86, 237, 240, 34, 72, 242, 20, 214, 244, 227, 149, 235,
        97, 234, 57, 22, 60, 250, 82, 175, 208, 5, 127, 199, 111, 62, 135, 248,
        174, 169, 211, 58, 66, 154, 106, 195, 245, 171, 17, 187, 182, 179, 0, 243,
        132, 56, 148, 75, 128, 133, 158, 100, 130, 126, 91, 13, 153, 246, 216, 219,
        119, 68, 223, 78, 83, 88, 201, 99, 122, 11, 92, 32, 136, 114, 52, 10,
        138, 30, 48, 183, 156, 35, 61, 26, 143, 74, 251, 94, 129, 162, 63, 152,
        170, 7, 115, 167, 241, 206, 3, 150, 55, 59, 151, 220, 90, 53, 23, 131,
        125, 173, 15, 238, 79, 95, 89, 16, 105, 137, 225, 224, 217, 160, 37, 123,
        118, 73, 2, 157, 46, 116, 9, 145, 134, 228, 207, 212, 202, 215, 69, 229,
        27, 188, 67, 124, 168, 252, 42, 4, 29, 108, 21, 247, 19, 205, 39, 203,
        233, 40, 186, 147, 198, 192, 155, 33, 164, 191, 98, 204, 165, 180, 117, 76,
        140, 36, 210, 172, 41, 54, 159, 8, 185, 232, 113, 196, 231, 231, 47, 146,
        120, 51, 65, 28, 144, 254, 221, 93, 189, 194, 139, 112, 43, 71, 109, 184,
        209
    ]);

    private outputBytes: number;

    private hash!: number[];

    constructor(outputBytes: number = 1) {
        super();
        this.outputBytes = outputBytes;
    }

    protected doInit(): void {
        this.hash = new Array(this.outputBytes).fill(0);
    }

    protected engineReset(): void {
        this.hash.fill(0);
    }

    protected processBlock(data: Uint8Array): void {
        for (let j = 0; j < data.length; j++) {
            const d = data[j];
            for (let i = 0; i < this.outputBytes; i++) {
                const idx = (this.hash[i] ^ d) ^ i;
                this.hash[i] = Pearson.T[idx & 0xFF];
            }
        }
    }

    protected doPadding(buf: Uint8Array, off: number): void {
        for (let i = 0; i < this.outputBytes; i++) {
            buf[off + i] = this.hash[i] & 0xFF;
        }
    }

    getDigestLength(): number {
        return this.outputBytes;
    }

    getBlockLength(): number {
        return 64;
    }

    protected getInternalBlockLength(): number {
        return 1;//this.getBlockLength();
    }

    protected dup(): DigestEngine {
        const x = new Pearson(this.outputBytes);
        x.hash = this.hash.slice();
        return x;
    }

    getAlgorithmName(): string {
        return `Pearson-${this.getDigestLength() * 8}`;
    }
}

class HMAC extends DigestEngine {

    private dig!: Digest;
    private kipad!: Uint8Array
    private kopad!: Uint8Array;
    private outputLength!: number;
    private tmpOut!: Uint8Array;
    private onlyThis = 0;
    private static zeroPad = new Uint8Array(64);

    /**
     * Build the object. The provided digest algorithm will be used
     * internally; it MUST NOT be directly accessed afterwards. The
     * {@code key} array holds the MAC key; the key is copied
     * internally, which means that the caller may modify the {@code
     * key} array afterwards.
     *
     * @param dig   the underlying hash function
     * @param key   the MAC key
     * @param outputLength   the HMAC output length (in bytes)
     */
    constructor(dig: Digest, key: Uint8Array, outputLength?: number) {
        super();
        dig.reset();
        this.dig = dig;
        var B = dig.getBlockLength();
        if (B < 0) {
            /*
             * Virtual block length: inferred from the key
             * length, with rounding (used for Fugue-xxx).
             */
            let n = -B;
            B = n * ((key.length + (n - 1)) / n);
        }
        const keyB = new Uint8Array(B);
        var len = key.length;
        if (len > B) {
            key = dig.digest(key);
            len = key.length;
            if (len > B) {
                len = B;
            }
        }
        arraycopy(key, 0, keyB, 0, len);
        /*
         * Newly created arrays are guaranteed filled with zeroes,
         * hence the key padding is already done.
         */
        this.processKey(keyB);

        this.outputLength = -1;
        this.tmpOut = new Uint8Array(dig.getDigestLength());
        this.reset();
        if (outputLength && outputLength < dig.getDigestLength()) {
            this.outputLength = outputLength;
        }
    }

    /**
     * Internal constructor, used for cloning. The key is referenced,
     * not copied.
     *
     * @param dig            the digest
     * @param kipad          the (internal) ipad key
     * @param kopad          the (internal) opad key
     * @param outputLength   the output length, or -1
     */
    private _HMAC(dig: Digest, kipad: Uint8Array, kopad: Uint8Array, outputLength: number) {
        this.dig = dig;
        this.kipad = kipad;
        this.kopad = kopad;
        this.outputLength = outputLength;
        this.tmpOut = new Uint8Array(dig.getDigestLength());
        return this;
    }

    private processKey(keyB: Uint8Array) {
        var B = keyB.length;
        this.kipad = new Uint8Array(B);
        this.kopad = new Uint8Array(B);
        for (let i = 0; i < B; i++) {
            var x = keyB[i];
            this.kipad[i] = (x ^ 0x36);
            this.kopad[i] = (x ^ 0x5C);
        }
    }

    /** @see Digest */
    public copy(): Digest {
        const h = this._HMAC(this.dig.copy(), this.kipad, this.kopad, this.outputLength);
        return this.copyState(h);
    }

    /** @see Digest */
    public getDigestLength(): number {
        /*
         * At construction time, outputLength is first set to 0,
         * which means that this method will return 0, which is
         * appropriate since at that time "dig" has not yet been
         * set.
         */
        return this.outputLength < 0 ? this.dig.getDigestLength() : this.outputLength;
    }

    /** @see Digest */
    public getBlockLength(): number {
        /*
         * Internal block length is not defined for HMAC, which
         * is not, stricto-sensu, an iterated hash function.
         * The value 64 should provide correct buffering. Do NOT
         * change this value without checking doPadding().
         */
        return 64;
    }

    /** @see DigestEngine */
    protected engineReset() {
        this.dig.reset();
        this.dig.update(this.kipad);
    }

    /** @see DigestEngine */
    protected processBlock(data: Uint8Array) {
        if (this.onlyThis > 0) {
            this.dig.update(data, 0, this.onlyThis);
            this.onlyThis = 0;
        } else {
            this.dig.update(data);
        }
    }

    /** @see DigestEngine */
    protected doPadding(output: Uint8Array, outputOffset: number) {
        /*
         * This is slightly ugly... we need to get the still
         * buffered data, but the only way to get it from
         * DigestEngine is to input some more bytes and wait
         * for the processBlock() call. We set a variable
         * with the count of actual data bytes, so that
         * processBlock() knows what to do.
         */
        this.onlyThis = this.flush();
        if (this.onlyThis > 0) {
            this.update(HMAC.zeroPad, 0, 64 - this.onlyThis);
        }
        var olen = this.tmpOut.length;
        this.dig.digest(this.tmpOut, 0, olen);
        this.dig.update(this.kopad);
        this.dig.update(this.tmpOut);
        this.dig.digest(this.tmpOut, 0, olen);
        if (this.outputLength >= 0) {
            olen = this.outputLength;
        }
        arraycopy(this.tmpOut, 0, output, outputOffset, olen);
    }

    /** @see DigestEngine */
    protected doInit() {
        /*
         * Empty: we do not want to do anything here because
         * it would prevent correct cloning. The initialization
         * job is done in the constructor.
         */
    }

    /** @see Digest */
    public toString(): string {
        return "HMAC/" + this.dig.toString();
    }
}

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

function toHex(bytes: Uint8Array): string {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
};

/**
 * Creates vary byte Pearson hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {number} outputBytes - byte length of the returned hash (default 4 or 32 bit)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function _PEARSON(message: InputData, outputBytes: number = 1, format: OutputFormat = arrayType()) {
    const hash = new Pearson(outputBytes);
    hash.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(hash.digest());
    } else if (format == 'hex') {
        return toHex(hash.digest());
    }
    return hash.digest();
}

/**
 * Creates a 4 byte Pearson hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function PEARSON32(message: InputData, format: OutputFormat = arrayType()) {
    const hash = new Pearson(4);
    hash.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(hash.digest());
    } else if (format == 'hex') {
        return toHex(hash.digest());
    }
    return hash.digest();
};

/**
 * Creates a 4 byte keyed Pearson hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function PEARSON32_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType()) {
    const hash = new Pearson(4);
    const mac = new HMAC(hash, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    } else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
};

/**
 * Creates a 8 byte Pearson hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function PEARSON64(message: InputData, format: OutputFormat = arrayType()) {
    const hash = new Pearson(8);
    hash.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(hash.digest());
    } else if (format == 'hex') {
        return toHex(hash.digest());
    }
    return hash.digest();
};

/**
 * Creates a 8 byte keyed Pearson hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function PEARSON64_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType()) {
    const hash = new Pearson(8);
    const mac = new HMAC(hash, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    } else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
};

/**
 * Creates a 16 byte Pearson hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function PEARSON128(message: InputData, format: OutputFormat = arrayType()) {
    const hash = new Pearson(16);
    hash.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(hash.digest());
    } else if (format == 'hex') {
        return toHex(hash.digest());
    }
    return hash.digest();
};

/**
 * Creates a 16 byte keyed Pearson hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function PEARSON128_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType()) {
    const hash = new Pearson(16);
    const mac = new HMAC(hash, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    } else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
};

/**
 * Creates a 32 byte Pearson hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function PEARSON256(message: InputData, format: OutputFormat = arrayType()) {
    const hash = new Pearson(32);
    hash.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(hash.digest());
    } else if (format == 'hex') {
        return toHex(hash.digest());
    }
    return hash.digest();
};

/**
 * Creates a 32 byte keyed Pearson hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function PEARSON256_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType()) {
    const hash = new Pearson(32);
    const mac = new HMAC(hash, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    } else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
};

/**
 * Creates vary byte keyed Pearson hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {number} outputBytes - byte length of the returned hash (default 4 or 32 bit)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function PEARSON_HMAC(message: InputData, key: InputData, outputBytes: number = 1, format: OutputFormat = arrayType()) {
    const hash = new Pearson(outputBytes);
    const mac = new HMAC(hash, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    } else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
}

/**
 * Static class of all RNG functions and classes
 */
export class PEARSON {
    static Pearson         = Pearson;
    static PEARSON         = _PEARSON;
    
    static PEARSON32       = PEARSON32;
    static PEARSON32_HMAC  = PEARSON32_HMAC;

    static PEARSON64       = PEARSON64;
    static PEARSON64_HMAC  = PEARSON64_HMAC;

    static PEARSON128      = PEARSON128;
    static PEARSON128_HMAC = PEARSON128_HMAC;

    static PEARSON256      = PEARSON256;
    static PEARSON256_HMAC = PEARSON256_HMAC;

    static PEARSON_HMAC = PEARSON_HMAC;
    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST(){
        return [
            "PEARSON",
            "PEARSON32",
            "PEARSON32_HMAC",

            "PEARSON64",
            "PEARSON64_HMAC",

            "PEARSON128",
            "PEARSON128_HMAC",

            "PEARSON256",
            "PEARSON256_HMAC",

            "PEARSON_HMAC"
        ]
    }
}