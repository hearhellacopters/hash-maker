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
};

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
};

/**
 * <p>This class implements the HMAC message authentication algorithm,
 * under the {@link Digest} API, using the {@link DigestEngine} class.
 * HMAC is defined in RFC 2104 (also FIPS 198a). This implementation
 * uses an underlying digest algorithm, provided as parameter to the
 * constructor.</p>
 *
 * <pre>
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
 * </pre>
 *
 * @version   $Revision: 214 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

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
};

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
        return message;
    }

    throw new Error('input is invalid type');
};

function toHex(bytes: Uint8Array): string {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
};

/**
 * Implementation of the 32-bit FNV-0 hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 * FNV-0 is historic and deprecated, equivalent to FNV-1 with initial hash = 0.
 *
 * The repository provides utilities and library for FNV hashes, but the core algorithm is standard and implemented here faithfully.
 *
 * For HMAC compatibility, block length is set to 64 bytes (as per FNV standard recommendation).
 */

export class Fnv0_32 extends DigestEngine {

    private static readonly PRIME: bigint = BigInt(0x01000193);

    private static readonly INIT: bigint = BigInt(0);

    private static readonly MASK: bigint = BigInt(0xFFFFFFFF);

    private hash!: bigint;

    protected doInit(): void {
        this.engineReset();
    }

    protected engineReset(): void {
        this.hash = Fnv0_32.INIT;
    }

    protected processBlock(data: Uint8Array): void {
        for (let i = 0; i < data.length; i++) {
            this.hash = (this.hash * Fnv0_32.PRIME) & Fnv0_32.MASK;
            this.hash = (this.hash ^ BigInt(data[i])) & Fnv0_32.MASK;
        }
    }

    protected doPadding(buf: Uint8Array, off: number): void {
        let h = this.hash;
        buf[off] = Number((h >> BigInt(24)) & BigInt(0xFF));
        buf[off + 1] = Number((h >> BigInt(16)) & BigInt(0xFF));
        buf[off + 2] = Number((h >> BigInt(8)) & BigInt(0xFF));
        buf[off + 3] = Number(h & BigInt(0xFF));
    }

    getDigestLength(): number {
        return 4;
    }

    getBlockLength(): number {
        return 64;
    }

    protected getInternalBlockLength(): number {
        return 1; //this.getBlockLength();
    }

    protected dup(): DigestEngine {
        const x = new Fnv0_32();
        x.hash = this.hash;
        return x;
    }

    getAlgorithmName(): string {
        return "FNV0-32";
    }
}

/**
 * Implementation of the 64-bit FNV-0 hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 * FNV-0 is historic and deprecated, equivalent to FNV-1 with initial hash = 0.
 *
 * The repository provides utilities and library for FNV hashes, but the core algorithm is standard and implemented here faithfully.
 * For HMAC compatibility, block length is set to 128 bytes (as per FNV standard recommendation).
 */

export class Fnv0_64 extends DigestEngine {

    private static readonly PRIME: bigint = BigInt("0x100000001b3");

    private static readonly INIT: bigint = BigInt(0);

    private static readonly MASK: bigint = BigInt("0xFFFFFFFFFFFFFFFF");

    private hash!: bigint;

    protected doInit(): void {
        this.engineReset();
    }

    protected engineReset(): void {
        this.hash = Fnv0_64.INIT;
    }

    protected processBlock(data: Uint8Array): void {
        for (let i = 0; i < data.length; i++) {
            this.hash = (this.hash * Fnv0_64.PRIME) & Fnv0_64.MASK;
            this.hash = (this.hash ^ BigInt(data[i])) & Fnv0_64.MASK;
        }
    }

    protected doPadding(buf: Uint8Array, off: number): void {
        let h = this.hash;
        for (let i = 7; i >= 0; i--) {
            buf[off + i] = Number((h >> BigInt(i * 8)) & BigInt(0xFF));
        }
    }

    getDigestLength(): number {
        return 8;
    }

    getBlockLength(): number {
        return 128;
    }

    protected getInternalBlockLength(): number {
        return 1; //this.getBlockLength();
    }

    protected dup(): DigestEngine {
        const x = new Fnv0_64();
        x.hash = this.hash;
        return x;
    }

    getAlgorithmName(): string {
        return "FNV0-64";
    }
};

/**
 * Implementation of the 128-bit FNV-0 hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 * FNV-0 is historic and deprecated, equivalent to FNV-1 with initial hash = 0.
 *
 * Parameters from http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
 *
 * For HMAC compatibility, block length is set to 256 bytes (scaled from smaller variants).
 */

export class Fnv0_128 extends DigestEngine {

    private static readonly PRIME: bigint = BigInt("0x1000000000000000000013B");

    private static readonly INIT: bigint = BigInt(0);

    private static readonly MASK: bigint = (BigInt(1) << BigInt(128)) - BigInt(1);

    private hash!: bigint;

    protected doInit(): void {
        this.engineReset();
    }

    protected engineReset(): void {
        this.hash = Fnv0_128.INIT;
    }

    protected processBlock(data: Uint8Array): void {
        for (let i = 0; i < data.length; i++) {
            this.hash = ((this.hash * Fnv0_128.PRIME) ^ BigInt(data[i])) & Fnv0_128.MASK;
        }
    }

    protected doPadding(buf: Uint8Array, off: number): void {
        let h = this.hash;
        for (let i = 15; i >= 0; i--) {
            buf[off + (15 - i)] = Number((h >> BigInt(i * 8)) & BigInt(0xFF));
        }
    }

    getDigestLength(): number {
        return 16;
    }

    getBlockLength(): number {
        return 256;
    }

    protected getInternalBlockLength(): number {
        return 1; //this.getBlockLength();
    }

    protected dup(): DigestEngine {
        const x = new Fnv0_128();
        x.hash = this.hash;
        return x;
    }

    getAlgorithmName(): string {
        return "FNV0-128";
    }
};

/**
 * Implementation of the 256-bit FNV-0 hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 * FNV-0 is historic and deprecated, equivalent to FNV-1 with initial hash = 0.
 *
 * Parameters from http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
 *
 * For HMAC compatibility, block length is set to 512 bytes (scaled from smaller variants).
 */

export class Fnv0_256 extends DigestEngine {

    private static readonly PRIME: bigint = BigInt("0x1000000000000000000000B3");

    private static readonly INIT: bigint = BigInt(0);

    private static readonly MASK: bigint = (BigInt(1) << BigInt(256)) - BigInt(1);

    private hash!: bigint;

    protected doInit(): void {
        this.engineReset()
    }

    protected engineReset(): void {
        this.hash = Fnv0_256.INIT;
    }

    protected processBlock(data: Uint8Array): void {
        for (let i = 0; i < data.length; i++) {
            this.hash = ((this.hash * Fnv0_256.PRIME) ^ BigInt(data[i])) & Fnv0_256.MASK;
        }
    }

    protected doPadding(buf: Uint8Array, off: number): void {
        let h = this.hash;
        for (let i = 31; i >= 0; i--) {
            buf[off + (31 - i)] = Number((h >> BigInt(i * 8)) & BigInt(0xFF));
        }
    }

    getDigestLength(): number {
        return 32;
    }

    getBlockLength(): number {
        return 512;
    }

    protected getInternalBlockLength(): number {
        return 1; //this.getBlockLength();
    }

    protected dup(): DigestEngine {
        const x = new Fnv0_256();
        x.hash = this.hash;
        return x;
    }

    getAlgorithmName(): string {
        return "FNV0-256";
    }
};

/**
 * Implementation of the 512-bit FNV-0 hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 * FNV-0 is historic and deprecated, equivalent to FNV-1 with initial hash = 0.
 *
 * Parameters from http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
 *
 * For HMAC compatibility, block length is set to 1024 bytes (scaled from smaller variants).
 */

export class Fnv0_512 extends DigestEngine {

    private static readonly PRIME: bigint = BigInt("0x1000000000000000000000000000000B5");

    private static readonly INIT: bigint = BigInt(0);

    private static readonly MASK: bigint = (BigInt(1) << BigInt(512)) - BigInt(1);

    private hash!: bigint;

    protected doInit(): void {
        this.engineReset();
    }

    protected engineReset(): void {
        this.hash = Fnv0_512.INIT;
    }

    protected processBlock(data: Uint8Array): void {
        for (let i = 0; i < data.length; i++) {
            this.hash = ((this.hash * Fnv0_512.PRIME) ^ BigInt(data[i])) & Fnv0_512.MASK;
        }
    }

    protected doPadding(buf: Uint8Array, off: number): void {
        let h = this.hash;
        for (let i = 63; i >= 0; i--) {
            buf[off + (63 - i)] = Number((h >> BigInt(i * 8)) & BigInt(0xFF));
        }
    }

    getDigestLength(): number {
        return 64;
    }

    getBlockLength(): number {
        return 1024;
    }

    protected getInternalBlockLength(): number {
        return 1; // this.getBlockLength();
    }

    protected dup(): DigestEngine {
        const x = new Fnv0_512();
        x.hash = this.hash;
        return x;
    }

    getAlgorithmName(): string {
        return "FNV0-512";
    }
};

/**
 * Implementation of the 1024-bit FNV-0 hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 * FNV-0 is historic and deprecated, equivalent to FNV-1 with initial hash = 0.
 *
 * Parameters from http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
 *
 * For HMAC compatibility, block length is set to 2048 bytes (scaled from smaller variants).
 */

export class Fnv0_1024 extends DigestEngine {

    private static readonly PRIME: bigint = BigInt("0x1000000000000000000000000000000000000000000000000B7");

    private static readonly INIT: bigint = BigInt(0);

    private static readonly MASK: bigint = (BigInt(1) << BigInt(1024)) - BigInt(1);

    private hash!: bigint;

    protected doInit(): void {
        this.engineReset();
    }

    protected engineReset(): void {
        this.hash = Fnv0_1024.INIT;
    }

    protected processBlock(data: Uint8Array): void {
        for (let i = 0; i < data.length; i++) {
            this.hash = ((this.hash * Fnv0_1024.PRIME) ^ BigInt(data[i])) & Fnv0_1024.MASK;
        }
    }

    protected doPadding(buf: Uint8Array, off: number): void {
        let h = this.hash;
        for (let i = 127; i >= 0; i--) {
            buf[off + (127 - i)] = Number((h >> BigInt(i * 8)) & BigInt(0xFF));
        }
    }

    getDigestLength(): number {
        return 128;
    }

    getBlockLength(): number {
        return 2048;
    }

    protected getInternalBlockLength(): number {
        return 1; // this.getBlockLength();
    }

    protected dup(): DigestEngine {
        const x = new Fnv0_1024();
        x.hash = this.hash;
        return x;
    }

    getAlgorithmName(): string {
        return "FNV0-1024";
    }
};

/**
 * Implementation of the 32-bit FNV-1 hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 *
 * The repository provides utilities and library for FNV hashes, but the core algorithm is standard and implemented here faithfully.
 * For HMAC compatibility, block length is set to 64 bytes.
 */

export class Fnv1_32 extends DigestEngine {

    private static readonly PRIME: bigint = BigInt(0x01000193);

    private static readonly INIT: bigint = BigInt(0x811c9dc5);

    private static readonly MASK: bigint = BigInt(0xFFFFFFFF);

    private hash!: bigint;

    protected doInit(): void {
        this.engineReset();
    }

    protected engineReset(): void {
        this.hash = Fnv1_32.INIT;
    }

    protected processBlock(data: Uint8Array): void {
        for (let i = 0; i < data.length; i++) {
            this.hash = (this.hash * Fnv1_32.PRIME) & Fnv1_32.MASK;
            this.hash = (this.hash ^ BigInt(data[i])) & Fnv1_32.MASK;
        }
    }

    protected doPadding(buf: Uint8Array, off: number): void {
        let h = this.hash;
        buf[off] = Number((h >> BigInt(24)) & BigInt(0xFF));
        buf[off + 1] = Number((h >> BigInt(16)) & BigInt(0xFF));
        buf[off + 2] = Number((h >> BigInt(8)) & BigInt(0xFF));
        buf[off + 3] = Number(h & BigInt(0xFF));
    }

    getDigestLength(): number {
        return 4;
    }

    getBlockLength(): number {
        return 64;
    }

    protected getInternalBlockLength(): number {
        return 1; //this.getBlockLength();
    }

    protected dup(): DigestEngine {
        const x = new Fnv1_32();
        x.hash = this.hash;
        return x;
    }

    getAlgorithmName(): string {
        return "FNV1-32";
    }
}

/**
 * Implementation of the 64-bit FNV-1 hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 *
 * The repository provides utilities and library for FNV hashes, but the core algorithm is standard and implemented here faithfully.
 * For HMAC compatibility, block length is set to 128 bytes.
 */

export class Fnv1_64 extends DigestEngine {

    private static readonly PRIME: bigint = BigInt("0x100000001b3");

    private static readonly INIT: bigint = BigInt("0xcbf29ce484222325");

    private static readonly MASK: bigint = BigInt("0xFFFFFFFFFFFFFFFF");

    private hash!: bigint;

    protected doInit(): void {
        this.engineReset();
    }

    protected engineReset(): void {
        this.hash = Fnv1_64.INIT;
    }

    protected processBlock(data: Uint8Array): void {
        for (let i = 0; i < data.length; i++) {
            this.hash = (this.hash * Fnv1_64.PRIME) & Fnv1_64.MASK;
            this.hash = (this.hash ^ BigInt(data[i])) & Fnv1_64.MASK;
        }
    }

    protected doPadding(buf: Uint8Array, off: number): void {
        let h = this.hash;
        for (let i = 7; i >= 0; i--) {
            buf[off + i] = Number((h >> BigInt(i * 8)) & BigInt(0xFF));
        }
    }

    getDigestLength(): number {
        return 8;
    }

    getBlockLength(): number {
        return 128;
    }

    protected getInternalBlockLength(): number {
        return 1; //this.getBlockLength();
    }

    protected dup(): DigestEngine {
        const x = new Fnv1_64();
        x.hash = this.hash;
        return x;
    }

    getAlgorithmName(): string {
        return "FNV1-64";
    }
};

/**
 * Implementation of the 128-bit FNV-1 hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 *
 * Parameters from http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
 *
 * For HMAC compatibility, block length is set to 256 bytes (scaled from smaller variants).
 */

export class Fnv1_128 extends DigestEngine {

    private static readonly PRIME: bigint = BigInt("0x1000000000000000000013B");

    private static readonly INIT: bigint = BigInt("0x6c62272e07bb014262b821756295c58d");

    private static readonly MASK: bigint = (BigInt(1) << BigInt(128)) - BigInt(1);

    private hash!: bigint;

    protected doInit(): void {
        this.engineReset();
    }

    protected engineReset(): void {
        this.hash = Fnv1_128.INIT;
    }

    protected processBlock(data: Uint8Array): void {
        for (let i = 0; i < data.length; i++) {
            this.hash = ((this.hash * Fnv1_128.PRIME) ^ BigInt(data[i])) & Fnv1_128.MASK;
        }
    }

    protected doPadding(buf: Uint8Array, off: number): void {
        let h = this.hash;
        for (let i = 15; i >= 0; i--) {
            buf[off + (15 - i)] = Number((h >> BigInt(i * 8)) & BigInt(0xFF));
        }
    }

    getDigestLength(): number {
        return 16;
    }

    getBlockLength(): number {
        return 256;
    }

    protected getInternalBlockLength(): number {
        return 1; //this.getBlockLength();
    }

    protected dup(): DigestEngine {
        const x = new Fnv1_128();
        x.hash = this.hash;
        return x;
    }

    getAlgorithmName(): string {
        return "FNV1-128";
    }
};

/**
 * Implementation of the 256-bit FNV-1 hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 *
 * Parameters from http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
 *
 * For HMAC compatibility, block length is set to 512 bytes (scaled from smaller variants).
 */

export class Fnv1_256 extends DigestEngine {

    private static readonly PRIME: bigint = BigInt("0x1000000000000000000000B3");

    private static readonly INIT: bigint = BigInt("0xdd268dbcaac550362d98c384c4e576cc");

    private static readonly MASK: bigint = (BigInt(1) << BigInt(256)) - BigInt(1);

    private hash!: bigint;

    protected doInit(): void {
        this.engineReset()
    }

    protected engineReset(): void {
        this.hash = Fnv1_256.INIT;
    }

    protected processBlock(data: Uint8Array): void {
        for (let i = 0; i < data.length; i++) {
            this.hash = ((this.hash * Fnv1_256.PRIME) ^ BigInt(data[i])) & Fnv1_256.MASK;
        }
    }

    protected doPadding(buf: Uint8Array, off: number): void {
        let h = this.hash;
        for (let i = 31; i >= 0; i--) {
            buf[off + (31 - i)] = Number((h >> BigInt(i * 8)) & BigInt(0xFF));
        }
    }

    getDigestLength(): number {
        return 32;
    }

    getBlockLength(): number {
        return 512;
    }

    protected getInternalBlockLength(): number {
        return 1; //this.getBlockLength();
    }

    protected dup(): DigestEngine {
        const x = new Fnv1_256();
        x.hash = this.hash;
        return x;
    }

    getAlgorithmName(): string {
        return "FNV1-256";
    }
};

/**
 * Implementation of the 512-bit FNV-1 hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 *
 * Parameters from http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
 *
 * For HMAC compatibility, block length is set to 1024 bytes (scaled from smaller variants).
 */

export class Fnv1_512 extends DigestEngine {

    private static readonly PRIME: bigint = BigInt("0x1000000000000000000000000000000B5");

    private static readonly INIT: bigint = BigInt("0xb86db0b1171f4416dca1e50f309990ac");

    private static readonly MASK: bigint = (BigInt(1) << BigInt(512)) - BigInt(1);

    private hash!: bigint;

    protected doInit(): void {
        this.engineReset();
    }

    protected engineReset(): void {
        this.hash = Fnv1_512.INIT;
    }

    protected processBlock(data: Uint8Array): void {
        for (let i = 0; i < data.length; i++) {
            this.hash = ((this.hash * Fnv1_512.PRIME) ^ BigInt(data[i])) & Fnv1_512.MASK;
        }
    }

    protected doPadding(buf: Uint8Array, off: number): void {
        let h = this.hash;
        for (let i = 63; i >= 0; i--) {
            buf[off + (63 - i)] = Number((h >> BigInt(i * 8)) & BigInt(0xFF));
        }
    }

    getDigestLength(): number {
        return 64;
    }

    getBlockLength(): number {
        return 1024;
    }

    protected getInternalBlockLength(): number {
        return 1;//this.getBlockLength();
    }

    protected dup(): DigestEngine {
        const x = new Fnv1_512();
        x.hash = this.hash;
        return x;
    }

    getAlgorithmName(): string {
        return "FNV1-512";
    }
};

/**
 * Implementation of the 1024-bit FNV-1 hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 *
 * Parameters from http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
 *
 * For HMAC compatibility, block length is set to 2048 bytes (scaled from smaller variants).
 */

export class Fnv1_1024 extends DigestEngine {

    private static readonly PRIME: bigint = BigInt("0x1000000000000000000000000000000000000000000000000B7");

    private static readonly INIT: bigint = BigInt("0x0707d8d4a74da77c3b54d6f3c21b9a6f");

    private static readonly MASK: bigint = (BigInt(1) << BigInt(1024)) - BigInt(1);

    private hash!: bigint;

    protected doInit(): void {
        this.engineReset();
    }

    protected engineReset(): void {
        this.hash = Fnv1_1024.INIT;
    }

    protected processBlock(data: Uint8Array): void {
        for (let i = 0; i < data.length; i++) {
            this.hash = ((this.hash * Fnv1_1024.PRIME) ^ BigInt(data[i])) & Fnv1_1024.MASK;
        }
    }

    protected doPadding(buf: Uint8Array, off: number): void {
        let h = this.hash;
        for (let i = 127; i >= 0; i--) {
            buf[off + (127 - i)] = Number((h >> BigInt(i * 8)) & BigInt(0xFF));
        }
    }

    getDigestLength(): number {
        return 128;
    }

    getBlockLength(): number {
        return 2048;
    }

    protected getInternalBlockLength(): number {
        return 1; //this.getBlockLength();
    }

    protected dup(): DigestEngine {
        const x = new Fnv1_1024();
        x.hash = this.hash;
        return x;
    }

    getAlgorithmName(): string {
        return "FNV1-1024";
    }
};

/**
 * Implementation of the 32-bit FNV-1a hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 * FNV-1a is the recommended variant for better hash distribution.
 *
 * The repository provides utilities and library for FNV hashes, but the core algorithm is standard and implemented here faithfully.
 * For HMAC compatibility, block length is set to 64 bytes.
 */

export class Fnv1a_32 extends DigestEngine {

    private static readonly PRIME: bigint = BigInt(0x01000193);

    private static readonly INIT: bigint = BigInt(0x811c9dc5);

    private static readonly MASK: bigint = BigInt(0xFFFFFFFF);

    private hash!: bigint;

    protected doInit(): void {
        this.engineReset();
    }

    protected engineReset(): void {
        this.hash = Fnv1a_32.INIT;
    }

    protected processBlock(data: Uint8Array): void {
        for (let i = 0; i < data.length; i++) {
            this.hash = (this.hash ^ BigInt(data[i])) & Fnv1a_32.MASK;
            this.hash = (this.hash * Fnv1a_32.PRIME) & Fnv1a_32.MASK;
        }
    }

    protected doPadding(buf: Uint8Array, off: number): void {
        let h = this.hash;
        buf[off] = Number(h & BigInt(0xFF));
        buf[off + 1] = Number((h >> BigInt(8)) & BigInt(0xFF));
        buf[off + 2] = Number((h >> BigInt(16)) & BigInt(0xFF));
        buf[off + 3] = Number((h >> BigInt(24)) & BigInt(0xFF));
    }

    getDigestLength(): number {
        return 4;
    }

    getBlockLength(): number {
        return 64;
    }

    protected getInternalBlockLength(): number {
        return 1; //this.getBlockLength();
    }

    protected dup(): DigestEngine {
        const x = new Fnv1a_32();
        x.hash = this.hash;
        return x;
    }

    getAlgorithmName(): string {
        return "FNV1a-32";
    }
};

/**
 * Implementation of the 64-bit FNV-1a hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 * FNV-1a is the recommended variant for better hash distribution.
 *
 * The repository provides utilities and library for FNV hashes, but the core algorithm is standard and implemented here faithfully.
 * For HMAC compatibility, block length is set to 128 bytes.
 */

export class Fnv1a_64 extends DigestEngine {

    private static readonly PRIME: bigint = BigInt("0x100000001b3");

    private static readonly INIT: bigint = BigInt("0xcbf29ce484222325");

    private static readonly MASK: bigint = BigInt("0xFFFFFFFFFFFFFFFF");

    private hash!: bigint;

    protected doInit(): void {
        this.engineReset();
    }

    protected engineReset(): void {
        this.hash = Fnv1a_64.INIT;
    }

    protected processBlock(data: Uint8Array): void {
        for (let i = 0; i < data.length; i++) {
            this.hash = (this.hash ^ BigInt(data[i])) & Fnv1a_64.MASK;
            this.hash = (this.hash * Fnv1a_64.PRIME) & Fnv1a_64.MASK;
        }
    }

    protected doPadding(buf: Uint8Array, off: number): void {
        let h = this.hash;
        for (let i = 7; i >= 0; i--) {
            buf[off + i] = Number((h >> BigInt(i * 8)) & BigInt(0xFF));
        }
    }

    getDigestLength(): number {
        return 8;
    }

    getBlockLength(): number {
        return 128;
    }

    protected getInternalBlockLength(): number {
        return 1; //this.getBlockLength();
    }

    protected dup(): DigestEngine {
        const x = new Fnv1a_64();
        x.hash = this.hash;
        return x;
    }

    getAlgorithmName(): string {
        return "FNV1a-64";
    }
};

/**
 * Implementation of the 128-bit FNV-1a hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 * FNV-1a is the recommended variant for better hash distribution.
 *
 * Parameters from http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
 *
 * For HMAC compatibility, block length is set to 256 bytes (scaled from smaller variants).
 */

export class Fnv1a_128 extends DigestEngine {

    private static readonly PRIME: bigint = BigInt("0x1000000000000000000013B");

    private static readonly INIT: bigint = BigInt("0x6c62272e07bb014262b821756295c58d");

    private static readonly MASK: bigint = (BigInt(1) << BigInt(128)) - BigInt(1);

    private hash!: bigint;

    protected doInit(): void {
        this.engineReset();
    }

    protected engineReset(): void {
        this.hash = Fnv1a_128.INIT;
    }

    protected processBlock(data: Uint8Array): void {
        for (let i = 0; i < data.length; i++) {
            this.hash = ((this.hash ^ BigInt(data[i])) * Fnv1a_128.PRIME) & Fnv1a_128.MASK;
        }
    }

    protected doPadding(buf: Uint8Array, off: number): void {
        let h = this.hash;
        for (let i = 15; i >= 0; i--) {
            buf[off + (15 - i)] = Number((h >> BigInt(i * 8)) & BigInt(0xFF));
        }
    }

    getDigestLength(): number {
        return 16;
    }

    getBlockLength(): number {
        return 256;
    }

    protected getInternalBlockLength(): number {
        return 1; //this.getBlockLength();
    }

    protected dup(): DigestEngine {
        const x = new Fnv1a_128();
        x.hash = this.hash;
        return x;
    }

    getAlgorithmName(): string {
        return "FNV1a-128";
    }
};

/**
 * Implementation of the 256-bit FNV-1a hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 * FNV-1a is the recommended variant for better hash distribution.
 *
 * Parameters from http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
 *
 * For HMAC compatibility, block length is set to 512 bytes (scaled from smaller variants).
 */

export class Fnv1a_256 extends DigestEngine {

    private static readonly PRIME: bigint = BigInt("0x1000000000000000000000B3");

    private static readonly INIT: bigint = BigInt("0xdd268dbcaac550362d98c384c4e576cc");

    private static readonly MASK: bigint = (BigInt(1) << BigInt(256)) - BigInt(1);

    private hash!: bigint;

    protected doInit(): void {
        this.engineReset();
    }

    protected engineReset(): void {
        this.hash = Fnv1a_256.INIT;
    }

    protected processBlock(data: Uint8Array): void {
        for (let i = 0; i < data.length; i++) {
            this.hash = ((this.hash ^ BigInt(data[i])) * Fnv1a_256.PRIME) & Fnv1a_256.MASK;
        }
    }

    protected doPadding(buf: Uint8Array, off: number): void {
        let h = this.hash;
        for (let i = 31; i >= 0; i--) {
            buf[off + (31 - i)] = Number((h >> BigInt(i * 8)) & BigInt(0xFF));
        }
    }

    getDigestLength(): number {
        return 32;
    }

    getBlockLength(): number {
        return 512;
    }

    protected getInternalBlockLength(): number {
        return 1; //this.getBlockLength();
    }

    protected dup(): DigestEngine {
        const x = new Fnv1a_256();
        x.hash = this.hash;
        return x;
    }

    getAlgorithmName(): string {
        return "FNV1a-256";
    }
};

/**
 * Implementation of the 512-bit FNV-1a hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 * FNV-1a is the recommended variant for better hash distribution.
 *
 * Parameters from http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
 *
 * For HMAC compatibility, block length is set to 1024 bytes (scaled from smaller variants).
 */

export class Fnv1a_512 extends DigestEngine {

    private static readonly PRIME: bigint = BigInt("0x1000000000000000000000000000000B5");

    private static readonly INIT: bigint = BigInt("0xb86db0b1171f4416dca1e50f309990ac");

    private static readonly MASK: bigint = (BigInt(1) << BigInt(512)) - BigInt(1);

    private hash!: bigint;

    protected doInit(): void {
        this.engineReset();
    }

    protected engineReset(): void {
        this.hash = Fnv1a_512.INIT;
    }

    protected processBlock(data: Uint8Array): void {
        for (let i = 0; i < data.length; i++) {
            this.hash = ((this.hash ^ BigInt(data[i])) * Fnv1a_512.PRIME) & Fnv1a_512.MASK;
        }
    }

    protected doPadding(buf: Uint8Array, off: number): void {
        let h = this.hash;
        for (let i = 63; i >= 0; i--) {
            buf[off + (63 - i)] = Number((h >> BigInt(i * 8)) & BigInt(0xFF));
        }
    }

    getDigestLength(): number {
        return 64;
    }

    getBlockLength(): number {
        return 1024;
    }

    protected getInternalBlockLength(): number {
        return 1; //this.getBlockLength();
    }

    protected dup(): DigestEngine {
        const x = new Fnv1a_512();
        x.hash = this.hash;
        return x;
    }

    getAlgorithmName(): string {
        return "FNV1a-512";
    }
};

/**
 * Implementation of the 1024-bit FNV-1a hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 * FNV-1a is the recommended variant for better hash distribution.
 *
 * Parameters from http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
 *
 * For HMAC compatibility, block length is set to 2048 bytes (scaled from smaller variants).
 */

export class Fnv1a_1024 extends DigestEngine {

    private static readonly PRIME: bigint = BigInt("0x1000000000000000000000000000000000000000000000000B7");

    private static readonly INIT: bigint = BigInt("0x0707d8d4a74da77c3b54d6f3c21b9a6f");

    private static readonly MASK: bigint = (BigInt(1) << BigInt(1024)) - BigInt(1);

    private hash!: bigint;

    protected doInit(): void {
        this.engineReset();
    }

    protected engineReset(): void {
        this.hash = Fnv1a_1024.INIT;
    }

    protected processBlock(data: Uint8Array): void {
        for (let i = 0; i < data.length; i++) {
            this.hash = ((this.hash ^ BigInt(data[i])) * Fnv1a_1024.PRIME) & Fnv1a_1024.MASK;
        }
    }

    protected doPadding(buf: Uint8Array, off: number): void {
        let h = this.hash;
        for (let i = 127; i >= 0; i--) {
            buf[off + (127 - i)] = Number((h >> BigInt(i * 8)) & BigInt(0xFF));
        }
    }

    getDigestLength(): number {
        return 128;
    }

    getBlockLength(): number {
        return 2048;
    }

    protected getInternalBlockLength(): number {
        return 1;//this.getBlockLength();
    }

    protected dup(): DigestEngine {
        const x = new Fnv1a_1024();
        x.hash = this.hash;
        return x;
    }

    getAlgorithmName(): string {
        return "FNV1a-1024";
    }
}

class Fnv {
    class!: 
    Fnv0_32 |
    Fnv0_64 | 
    Fnv0_128 | 
    Fnv0_256 | 
    Fnv0_512 | 
    Fnv0_1024 | 

    Fnv1_32 | 
    Fnv1_64 | 
    Fnv1_128 | 
    Fnv1_256 | 
    Fnv1_512 | 
    Fnv1_1024 | 

    Fnv1a_32 |
    Fnv1a_64 | 
    Fnv1a_128 | 
    Fnv1a_256 | 
    Fnv1a_512 | 
    Fnv1a_1024;
    constructor(type:
        "FNV0_32" |
        "FNV0_64" | 
        "FNV0_128" | 
        "FNV0_256" | 
        "FNV0_512" | 
        "FNV0_1024" | 

        "FNV1_32" | 
        "FNV1_64" | 
        "FNV1_128" | 
        "FNV1_256" | 
        "FNV1_512" | 
        "FNV1_1024" | 

        "FNV1A_32" |
        "FNV1A_64" | 
        "FNV1A_128" | 
        "FNV1A_256" | 
        "FNV1A_512" | 
        "FNV1A_1024" 
         = 
        "FNV1A_64") {
        switch (type) {
            case "FNV0_32":
                this.class = new Fnv0_32();
                break;
            case "FNV0_64":
                this.class = new Fnv0_64();
                break;
            case "FNV0_128":
                this.class = new Fnv0_128();
                break;
            case "FNV0_256":
                this.class = new Fnv0_256();
                break;
            case "FNV0_512":
                this.class = new Fnv0_512();
                break;
            case "FNV0_1024":
                this.class = new Fnv0_1024();
                break;

            case "FNV1_32":
                this.class = new Fnv1_32();
                break;
            case "FNV1_64":
                this.class = new Fnv1_64();
                break;
            case "FNV1_128":
                this.class = new Fnv1_128();
                break;
            case "FNV1_256":
                this.class = new Fnv1_256();
                break;
            case "FNV1_512":
                this.class = new Fnv1_512();
                break;
            case "FNV1_1024":
                this.class = new Fnv1_1024();
                break;

            case "FNV1A_32":
                this.class = new Fnv1a_32();
                break;
            case "FNV1A_64":
                this.class = new Fnv1a_64();
                break;
            case "FNV1A_128":
                this.class = new Fnv1a_128();
                break;
            case "FNV1A_256":
                this.class = new Fnv1a_256();
                break;
            case "FNV1A_512":
                this.class = new Fnv1a_512();
                break;
            case "FNV1A_1024":
                this.class = new Fnv1a_1024();
                break;

            default:
                this.class = new Fnv1a_32();
                break;
        }
    }

    update(message: InputData) {
        message = formatMessage(message);
        this.class.update(message);
    }

    digest(format: OutputFormat) {
        if (format == "hex") {
            return toHex(this.class.digest());
        } else if (format == "buffer") {
            return Buffer.from(this.class.digest());
        }
        return this.class.digest();
    }
}

/**
 * Creates a FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param message - Message to hash
 * @param {32|64|128|256|512|1024} bitLen - Hash length (default 64 or 8 bytes)
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV0(message: InputData, bitLen: 32|64|128|256|512|1024 = 64, format: OutputFormat = arrayType()) {
    const hash = new Fnv(`FNV0_${bitLen}`);
    hash.update(message);
    return hash.digest(format);
};

/**
 * Creates a keyed FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {32|64|128|256|512|1024} bitLen - Hash length (default 64 or 8 bytes)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV0_HMAC(message: InputData, key?: InputData, bitLen: 32|64|128|256|512|1024 = 64, format: OutputFormat = arrayType()) {
    const hash = new Fnv(`FNV0_${bitLen}`);
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    } else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
};

/**
 * Creates a 4 byte FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV0_32(message: InputData, format: OutputFormat = arrayType()) {
    const hash = new Fnv("FNV0_32");
    hash.update(message);
    return hash.digest(format);
};

/**
 * Creates a 4 byte keyed FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV0_32_HMAC(message: InputData, key?: InputData, format: OutputFormat = arrayType()) {
    const hash = new Fnv("FNV0_32");
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    } else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
};

/**
 * Creates a 8 byte FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV0_64(message: InputData, format: OutputFormat = arrayType()) {
    const hash = new Fnv("FNV0_64");
    hash.update(message);
    return hash.digest(format);
};

/**
 * Creates a 8 byte keyed FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV0_64_HMAC(message: InputData, key?: InputData, format: OutputFormat = arrayType()) {
    const hash = new Fnv("FNV0_64");
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    } else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
};

/**
 * Creates a 16 byte FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV0_128(message: InputData, format: OutputFormat = arrayType()) {
    const hash = new Fnv("FNV0_128");
    hash.update(message);
    return hash.digest(format);
};

/**
 * Creates a 16 byte keyed FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV0_128_HMAC(message: InputData, key?: InputData, format: OutputFormat = arrayType()) {
    const hash = new Fnv("FNV0_128");
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    } else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
};

/**
 * Creates a 32 byte FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV0_256(message: InputData, format: OutputFormat = arrayType()) {
    const hash = new Fnv("FNV0_256");
    hash.update(message);
    return hash.digest(format);
};

/**
 * Creates a 32 byte keyed FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV0_256_HMAC(message: InputData, key?: InputData, format: OutputFormat = arrayType()) {
    const hash = new Fnv("FNV0_256");
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    } else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
};

/**
 * Creates a 64 byte FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV0_512(message: InputData, format: OutputFormat = arrayType()) {
    const hash = new Fnv("FNV0_512");
    hash.update(message);
    return hash.digest(format);
};

/**
 * Creates a 64 byte keyed FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV0_512_HMAC(message: InputData, key?: InputData, format: OutputFormat = arrayType()) {
    const hash = new Fnv("FNV0_512");
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    } else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
};

/**
 * Creates a 128 byte FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV0_1024(message: InputData, format: OutputFormat = arrayType()) {
    const hash = new Fnv("FNV0_512");
    hash.update(message);
    return hash.digest(format);
};

/**
 * Creates a 128 byte keyed FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV0_1024_HMAC(message: InputData, key?: InputData, format: OutputFormat = arrayType()) {
    const hash = new Fnv("FNV0_512");
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    } else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
};

/**
 * Creates a FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param message - Message to hash
 * @param {32|64|128|256|512|1024} bitLen - Hash length (default 64 or 8 bytes)
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV1(message: InputData, bitLen: 32|64|128|256|512|1024 = 64, format: OutputFormat = arrayType()) {
    const hash = new Fnv(`FNV1_${bitLen}`);
    hash.update(message);
    return hash.digest(format);
};

/**
 * Creates a keyed FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {32|64|128|256|512|1024} bitLen - Hash length (default 64 or 8 bytes)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV1_HMAC(message: InputData, key?: InputData, bitLen: 32|64|128|256|512|1024 = 64, format: OutputFormat = arrayType()) {
    const hash = new Fnv(`FNV1_${bitLen}`);
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    } else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
};

/**
 * Creates a 4 byte FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV1_32(message: InputData, format: OutputFormat = arrayType()) {
    const hash = new Fnv("FNV1_32");
    hash.update(message);
    return hash.digest(format);
};

/**
 * Creates a 4 byte keyed FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV1_32_HMAC(message: InputData, key?: InputData, format: OutputFormat = arrayType()) {
    const hash = new Fnv("FNV1_32");
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    } else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
};

/**
 * Creates a 8 byte FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV1_64(message: InputData, format: OutputFormat = arrayType()) {
    const hash = new Fnv("FNV1_64");
    hash.update(message);
    return hash.digest(format);
};

/**
 * Creates a 8 byte keyed FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV1_64_HMAC(message: InputData, key?: InputData, format: OutputFormat = arrayType()) {
    const hash = new Fnv("FNV1_64");
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    } else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
};

/**
 * Creates a 16 byte FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV1_128(message: InputData, format: OutputFormat = arrayType()) {
    const hash = new Fnv("FNV1_128");
    hash.update(message);
    return hash.digest(format);
};

/**
 * Creates a 16 byte keyed FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV1_128_HMAC(message: InputData, key?: InputData, format: OutputFormat = arrayType()) {
    const hash = new Fnv("FNV1_128");
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    } else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
};

/**
 * Creates a 32 byte FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV1_256(message: InputData, format: OutputFormat = arrayType()) {
    const hash = new Fnv("FNV1_256");
    hash.update(message);
    return hash.digest(format);
};

/**
 * Creates a 32 byte keyed FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV1_256_HMAC(message: InputData, key?: InputData, format: OutputFormat = arrayType()) {
    const hash = new Fnv("FNV1_256");
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    } else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
};

/**
 * Creates a 64 byte FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV1_512(message: InputData, format: OutputFormat = arrayType()) {
    const hash = new Fnv("FNV1_512");
    hash.update(message);
    return hash.digest(format);
};

/**
 * Creates a 64 byte keyed FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV1_512_HMAC(message: InputData, key?: InputData, format: OutputFormat = arrayType()) {
    const hash = new Fnv("FNV1_512");
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    } else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
};

/**
 * Creates a 128 byte FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV1_1024(message: InputData, format: OutputFormat = arrayType()) {
    const hash = new Fnv("FNV1_1024");
    hash.update(message);
    return hash.digest(format);
};

/**
 * Creates a 128 byte keyed FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV1_1024_HMAC(message: InputData, key?: InputData, format: OutputFormat = arrayType()) {
    const hash = new Fnv("FNV1_1024");
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    } else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
};

/**
 * Creates a FNV1A of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param message - Message to hash
 * @param {32|64|128|256|512|1024} bitLen - Hash length (default 64 or 8 bytes)
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV1A(message: InputData, bitLen: 32|64|128|256|512|1024 = 64, format: OutputFormat = arrayType()) {
    const hash = new Fnv(`FNV1A_${bitLen}`);
    hash.update(message);
    return hash.digest(format);
};

/**
 * Creates a keyed FNV1A of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {32|64|128|256|512|1024} bitLen - Hash length (default 64 or 8 bytes)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV1A_HMAC(message: InputData, key?: InputData, bitLen: 32|64|128|256|512|1024 = 64, format: OutputFormat = arrayType()) {
    const hash = new Fnv(`FNV1A_${bitLen}`);
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    } else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
};

/**
 * Creates a 4 byte FNV1a of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV1A_32(message: InputData, format: OutputFormat = arrayType()) {
    const hash = new Fnv("FNV1A_32");
    hash.update(message);
    return hash.digest(format);
};

/**
 * Creates a 4 byte keyed FNV1a of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV1A_32_HMAC(message: InputData, key?: InputData, format: OutputFormat = arrayType()) {
    const hash = new Fnv("FNV1A_32");
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    } else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
};

/**
 * Creates a 8 byte FNV1a of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV1A_64(message: InputData, format: OutputFormat = arrayType()) {
    const hash = new Fnv("FNV1A_64");
    hash.update(message);
    return hash.digest(format);
};

/**
 * Creates a 8 byte keyed FNV1a of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV1A_64_HMAC(message: InputData, key?: InputData, format: OutputFormat = arrayType()) {
    const hash = new Fnv("FNV1A_64");
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    } else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
};

/**
 * Creates a 16 byte FNV1a of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV1A_128(message: InputData, format: OutputFormat = arrayType()) {
    const hash = new Fnv("FNV1A_128");
    hash.update(message);
    return hash.digest(format);
};

/**
 * Creates a 16 byte keyed FNV1a of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV1A_128_HMAC(message: InputData, key?: InputData, format: OutputFormat = arrayType()) {
    const hash = new Fnv("FNV1A_128");
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    } else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
};

/**
 * Creates a 32 byte FNV1a of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV1A_256(message: InputData, format: OutputFormat = arrayType()) {
    const hash = new Fnv("FNV1A_256");
    hash.update(message);
    return hash.digest(format);
};

/**
 * Creates a 32 byte keyed FNV1a of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV1A_256_HMAC(message: InputData, key?: InputData, format: OutputFormat = arrayType()) {
    const hash = new Fnv("FNV1A_256");
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    } else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
};

/**
 * Creates a 64 byte FNV1a of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV1A_512(message: InputData, format: OutputFormat = arrayType()) {
    const hash = new Fnv("FNV1A_512");
    hash.update(message);
    return hash.digest(format);
};

/**
 * Creates a 64 byte keyed FNV1a of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV1A_512_HMAC(message: InputData, key?: InputData, format: OutputFormat = arrayType()) {
    const hash = new Fnv("FNV1A_512");
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    } else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
};

/**
 * Creates a 128 byte FNV1a of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV1A_1024(message: InputData, format: OutputFormat = arrayType()) {
    const hash = new Fnv("FNV1A_1024");
    hash.update(message);
    return hash.digest(format);
};

/**
 * Creates a 128 byte keyed FNV1a of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV1A_1024_HMAC(message: InputData, key?: InputData, format: OutputFormat = arrayType()) {
    const hash = new Fnv("FNV1A_1024");
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    } else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
};

/**
 * Creates a FNV hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {0 | "0" | 1 | "1" | "1A"} type - FNV type (default 1A)
 * @param {32|64|128|256|512|1024} bitLen - Hash length (default 64 or 8 bytes)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function _FNV(message: InputData, type: 0 | "0" | 1 | "1" | "1A"  = "1A", bitLen: 32|64|128|256|512|1024 = 64, format: OutputFormat = arrayType()){
    const hash = new Fnv(`FNV${type}_${bitLen}`);
    hash.update(message);
    return hash.digest(format);
};

/**
 * Creates a keyed FNV hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {0 | "0" | 1 | "1" | "1A"} type - FNV type (default 1A)
 * @param {32|64|128|256|512|1024} bitLen - Hash length (default 64 or 8 bytes)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function FNV_HMAC(message: InputData, key?: InputData, type: 0 | "0" | 1 | "1" | "1A"  = "1A", bitLen: 32|64|128|256|512|1024 = 64, format: OutputFormat = arrayType()) {
    const hash = new Fnv(`FNV${type}_${bitLen}`);
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    } else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
}

/**
 * Static class of all Fowler/Noll/Vo FNV functions and classes
 */
export class FNV {
    static Fnv = Fnv;
    static FNV = _FNV;

    static FNV0            = FNV0;
    static FNV0_HMAC       = FNV0_HMAC;
    static FNV0_32_HMAC    = FNV0_32_HMAC;
    static FNV0_32         = FNV0_32;
    static FNV0_64_HMAC    = FNV0_64_HMAC;
    static FNV0_64         = FNV0_64;
    static FNV0_128_HMAC   = FNV0_128_HMAC;
    static FNV0_128        = FNV0_128;
    static FNV0_256_HMAC   = FNV0_256_HMAC;
    static FNV0_256        = FNV0_256;
    static FNV0_512_HMAC   = FNV0_512_HMAC;
    static FNV0_512        = FNV0_512;
    static FNV0_1024_HMAC  = FNV0_1024_HMAC;
    static FNV0_1024       = FNV0_1024;
    
    static FNV1            = FNV1;
    static FNV1_HMAC       = FNV1_HMAC;
    static FNV1_32_HMAC    = FNV1_32_HMAC;
    static FNV1_32         = FNV1_32;
    static FNV1_64_HMAC    = FNV1_64_HMAC;
    static FNV1_64         = FNV1_64;
    static FNV1_128_HMAC   = FNV1_128_HMAC;
    static FNV1_128        = FNV1_128;
    static FNV1_256_HMAC   = FNV1_256_HMAC;
    static FNV1_256        = FNV1_256;
    static FNV1_512_HMAC   = FNV1_512_HMAC;
    static FNV1_512        = FNV1_512;
    static FNV1_1024_HMAC  = FNV1_1024_HMAC;
    static FNV1_1024       = FNV1_1024;

    static FNV1A           = FNV1A;
    static FNV1A_HMAC      = FNV1A_HMAC;
    static FNV1A_32_HMAC   = FNV1A_32_HMAC;
    static FNV1A_32        = FNV1A_32;
    static FNV1A_64_HMAC   = FNV1A_64_HMAC;
    static FNV1A_64        = FNV1A_64;
    static FNV1A_128_HMAC  = FNV1A_128_HMAC;
    static FNV1A_128       = FNV1A_128;
    static FNV1A_256_HMAC  = FNV1A_256_HMAC;
    static FNV1A_256       = FNV1A_256;
    static FNV1A_512_HMAC  = FNV1A_512_HMAC;
    static FNV1A_512       = FNV1A_512;
    static FNV1A_1024_HMAC = FNV1A_1024_HMAC;
    static FNV1A_1024      = FNV1A_1024;

    static FNV_HMAC = FNV_HMAC;

    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST(){
        return [
            "FNV",

            "FNV0",
            "FNV0_HMAC",
            "FNV0_32",
            "FNV0_32_HMAC",
            "FNV0_64",
            "FNV0_64_HMAC",
            "FNV0_128",
            "FNV0_128_HMAC",
            "FNV0_256",
            "FNV0_256_HMAC",
            "FNV0_512",
            "FNV0_512_HMAC",
            "FNV0_1024",
            "FNV0_1024_HMAC",

            "FNV1",
            "FNV1_HMAC",
            "FNV1_32",
            "FNV1_32_HMAC",
            "FNV1_64",
            "FNV1_64_HMAC",
            "FNV1_128",
            "FNV1_128_HMAC",
            "FNV1_256",
            "FNV1_256_HMAC",
            "FNV1_512",
            "FNV1_512_HMAC",
            "FNV1_1024",
            "FNV1_1024_HMAC",

            "FNV1A",
            "FNV1A_HMAC",
            "FNV1A_32",
            "FNV1A_32_HMAC",
            "FNV1A_64",
            "FNV1A_64_HMAC",
            "FNV1A_128",
            "FNV1A_128_HMAC",
            "FNV1A_256",
            "FNV1A_256_HMAC",
            "FNV1A_512",
            "FNV1A_512_HMAC",
            "FNV1A_1024",
            "FNV1A_1024_HMAC",
        ]
    }
};