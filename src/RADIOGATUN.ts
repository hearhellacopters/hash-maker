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

    protected copyState<T>(dest: DigestEngine):T {
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
    src: BigInt64Array | Uint8Array | Uint16Array | Int32Array | Uint32Array | Float32Array | Uint8ClampedArray,
    srcPos: number = 0,
    dst: BigInt64Array | Uint8Array | Uint16Array | Int32Array | Uint32Array | Float32Array | Uint8ClampedArray,
    destPos: number = 0,
    length: number) {
    const src2 = [];
    for (let i = 0; i < length; i++) {
        src2.push(src[srcPos + i]);
    }
    for (let i = 0; i < length; i++) {
        dst[destPos + i] = src2[i];
    }
};

function lshr(x:bigint, n:number) {
  return (x >> BigInt(n)) & ((BigInt(1) << (BigInt(64) - BigInt(n))) - BigInt(1));
}

/**
 * <p>This class implements the RadioGatun[32] digest algorithm under the
 * {@link Digest} API.</p>
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
 * @version   $Revision: 232 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

export class RadioGatun32 extends DigestEngine {

	private a!:Int32Array;
    private b!:Int32Array;

	/**
	 * Build the object.
	 */
	constructor()
	{
		super();
	}

	/** @see Digest */
	public copy(): Digest
	{
		const d = new RadioGatun32();
		arraycopy(this.a, 0, d.a, 0, this.a.length);
		arraycopy(this.b, 0, d.b, 0, this.b.length);
		return this.copyState(d);
	}

	/** @see Digest */
	public getDigestLength()
	{
		return 32;
	}

	/** @see DigestEngine */
	protected getInternalBlockLength()
	{
		return 156;
	}

	/** @see Digest */
	public getBlockLength()
	{
		return -12;
	}

	/** @see DigestEngine */
	protected engineReset()
	{
		for (let i = 0; i < this.a.length; i ++){
			this.a[i] = 0;
        }
		for (let i = 0; i < this.b.length; i ++){
			this.b[i] = 0;
        }
	}

	/** @see DigestEngine */
	protected doPadding(output:Uint8Array, outputOffset:number)
	{
		var ptr = this.flush();
		var buf = this.getBlockBuffer();
		buf[ptr++] = 0x01;
		for (var i = ptr; i < 156; i ++){
			buf[i] = 0;
        }
		this.processBlock(buf);
		var num = 20;
		for (;;) {
			ptr += 12;
			if (ptr > 156){
				break;
            }
			num--;
		}
		this.blank(num, output, outputOffset);
	}

	/** @see DigestEngine */
	protected doInit()
	{
		this.a = new Int32Array(19);
		this.b = new Int32Array(39);
		this.engineReset();
	}

	/**
	 * Encode the 32-bit word {@code val} into the array
	 * {@code buf} at offset {@code off}, in little-endian
	 * convention (least significant byte first).
	 *
	 * @param val   the value to encode
	 * @param buf   the destination buffer
	 * @param off   the destination offset
	 */
	private encodeLEInt(val:number, buf: Uint8Array, off: number)
	{
		buf[off + 0] = val;
		buf[off + 1] = (val >>> 8);
		buf[off + 2] = (val >>> 16);
		buf[off + 3] = (val >>> 24);
	}

	/**
	 * Decode a 32-bit little-endian word from the array {@code buf}
	 * at offset {@code off}.
	 *
	 * @param buf   the source buffer
	 * @param off   the source offset
	 * @return  the decoded value
	 */
	private decodeLEInt(buf:Uint8Array,  off: number)
	{
		return ((buf[off + 3] & 0xFF) << 24)
			| ((buf[off + 2] & 0xFF) << 16)
			| ((buf[off + 1] & 0xFF) << 8)
			| (buf[off + 0] & 0xFF);
	}

	/** @see DigestEngine */
	protected processBlock(data:Uint8Array)
	{
        const a = new Int32Array(19);
		a[0] = this.a[ 0];
		a[1] = this.a[ 1];
		a[2] = this.a[ 2];
		a[3] = this.a[ 3];
		a[4] = this.a[ 4];
		a[5] = this.a[ 5];
		a[6] = this.a[ 6];
		a[7] = this.a[ 7];
		a[8] = this.a[ 8];
		a[9] = this.a[ 9];
		a[10] = this.a[10];
		a[11] = this.a[11];
		a[12] = this.a[12];
		a[13] = this.a[13];
		a[14] = this.a[14];
		a[15] = this.a[15];
		a[16] = this.a[16];
		a[17] = this.a[17];
		a[18] = this.a[18];

		var dp = 0;
        const p = new Int32Array(3);
        const t = new Int32Array(19);
		for (let mk = 12; mk >= 0; mk--) {
			p[0] = this.decodeLEInt(data, dp + 0);
			p[1] = this.decodeLEInt(data, dp + 4);
			p[2] = this.decodeLEInt(data, dp + 8);
			dp += 12;
			var bj = (mk == 12) ? 0 : 3 * (mk + 1);
			this.b[bj + 0] ^= p[0];
			this.b[bj + 1] ^= p[1];
			this.b[bj + 2] ^= p[2];
			a[16] ^= p[0];
			a[17] ^= p[1];
			a[18] ^= p[2];

			bj = mk * 3;
			if ((bj += 3) == 39){
				bj = 0;
            }
			this.b[bj + 0] ^= a[ 1];
			if ((bj += 3) == 39){
				bj = 0;
            }
			this.b[bj + 1] ^= a[ 2];
			if ((bj += 3) == 39){
				bj = 0;
            }
			this.b[bj + 2] ^= a[ 3];
			if ((bj += 3) == 39){
				bj = 0;
            }
			this.b[bj + 0] ^= a[ 4];
			if ((bj += 3) == 39){
				bj = 0;
            }
			this.b[bj + 1] ^= a[ 5];
			if ((bj += 3) == 39){
				bj = 0;
            }
			this.b[bj + 2] ^= a[ 6];
			if ((bj += 3) == 39)
				bj = 0;
			this.b[bj + 0] ^= a[ 7];
			if ((bj += 3) == 39){
				bj = 0;
            }
			this.b[bj + 1] ^= a[ 8];
			if ((bj += 3) == 39){
				bj = 0;
            }
			this.b[bj + 2] ^= a[ 9];
			if ((bj += 3) == 39){
				bj = 0;
            }
			this.b[bj + 0] ^= a[10];
			if ((bj += 3) == 39){
				bj = 0;
            }
			this.b[bj + 1] ^= a[11];
			if ((bj += 3) == 39){
				bj = 0;
            }
			this.b[bj + 2] ^= a[12];

			t[ 0] = a[ 0] ^ (a[ 1] | ~a[ 2]);
			t[ 1] = a[ 1] ^ (a[ 2] | ~a[ 3]);
			t[ 2] = a[ 2] ^ (a[ 3] | ~a[ 4]);
			t[ 3] = a[ 3] ^ (a[ 4] | ~a[ 5]);
			t[ 4] = a[ 4] ^ (a[ 5] | ~a[ 6]);
			t[ 5] = a[ 5] ^ (a[ 6] | ~a[ 7]);
			t[ 6] = a[ 6] ^ (a[ 7] | ~a[ 8]);
			t[ 7] = a[ 7] ^ (a[ 8] | ~a[ 9]);
			t[ 8] = a[ 8] ^ (a[ 9] | ~a[10]);
			t[ 9] = a[ 9] ^ (a[10] | ~a[11]);
			t[10] = a[10] ^ (a[11] | ~a[12]);
			t[11] = a[11] ^ (a[12] | ~a[13]);
			t[12] = a[12] ^ (a[13] | ~a[14]);
			t[13] = a[13] ^ (a[14] | ~a[15]);
			t[14] = a[14] ^ (a[15] | ~a[16]);
			t[15] = a[15] ^ (a[16] | ~a[17]);
			t[16] = a[16] ^ (a[17] | ~a[18]);
			t[17] = a[17] ^ (a[18] | ~a[ 0]);
			t[18] = a[18] ^ (a[ 0] | ~a[ 1]);

			a[0] = t[0];
			a[ 1] = (t[ 7] << 31) | (t[ 7] >>>  1);
			a[ 2] = (t[14] << 29) | (t[14] >>>  3);
			a[ 3] = (t[ 2] << 26) | (t[ 2] >>>  6);
			a[ 4] = (t[ 9] << 22) | (t[ 9] >>> 10);
			a[ 5] = (t[16] << 17) | (t[16] >>> 15);
			a[ 6] = (t[ 4] << 11) | (t[ 4] >>> 21);
			a[ 7] = (t[11] <<  4) | (t[11] >>> 28);
			a[ 8] = (t[18] << 28) | (t[18] >>>  4);
			a[ 9] = (t[ 6] << 19) | (t[ 6] >>> 13);
			a[10] = (t[13] <<  9) | (t[13] >>> 23);
			a[11] = (t[ 1] << 30) | (t[ 1] >>>  2);
			a[12] = (t[ 8] << 18) | (t[ 8] >>> 14);
			a[13] = (t[15] <<  5) | (t[15] >>> 27);
			a[14] = (t[ 3] << 23) | (t[ 3] >>>  9);
			a[15] = (t[10] <<  8) | (t[10] >>> 24);
			a[16] = (t[17] << 24) | (t[17] >>>  8);
			a[17] = (t[ 5] <<  7) | (t[ 5] >>> 25);
			a[18] = (t[12] << 21) | (t[12] >>> 11);

			t[ 0] = a[ 0] ^ a[ 1] ^ a[ 4];
			t[ 1] = a[ 1] ^ a[ 2] ^ a[ 5];
			t[ 2] = a[ 2] ^ a[ 3] ^ a[ 6];
			t[ 3] = a[ 3] ^ a[ 4] ^ a[ 7];
			t[ 4] = a[ 4] ^ a[ 5] ^ a[ 8];
			t[ 5] = a[ 5] ^ a[ 6] ^ a[ 9];
			t[ 6] = a[ 6] ^ a[ 7] ^ a[10];
			t[ 7] = a[ 7] ^ a[ 8] ^ a[11];
			t[ 8] = a[ 8] ^ a[ 9] ^ a[12];
			t[ 9] = a[ 9] ^ a[10] ^ a[13];
			t[10] = a[10] ^ a[11] ^ a[14];
			t[11] = a[11] ^ a[12] ^ a[15];
			t[12] = a[12] ^ a[13] ^ a[16];
			t[13] = a[13] ^ a[14] ^ a[17];
			t[14] = a[14] ^ a[15] ^ a[18];
			t[15] = a[15] ^ a[16] ^ a[ 0];
			t[16] = a[16] ^ a[17] ^ a[ 1];
			t[17] = a[17] ^ a[18] ^ a[ 2];
			t[18] = a[18] ^ a[ 0] ^ a[ 3];

			a[ 0] = t[ 0] ^ 1;
			a[ 1] = t[ 1];
			a[ 2] = t[ 2];
			a[ 3] = t[ 3];
			a[ 4] = t[ 4];
			a[ 5] = t[ 5];
			a[ 6] = t[ 6];
			a[ 7] = t[ 7];
			a[ 8] = t[ 8];
			a[ 9] = t[ 9];
			a[10] = t[10];
			a[11] = t[11];
			a[12] = t[12];
			a[13] = t[13];
			a[14] = t[14];
			a[15] = t[15];
			a[16] = t[16];
			a[17] = t[17];
			a[18] = t[18];

			bj = mk * 3;
			a[13] ^= this.b[bj + 0];
			a[14] ^= this.b[bj + 1];
			a[15] ^= this.b[bj + 2];
		}

		this.a[ 0] = a[ 0];
		this.a[ 1] = a[ 1];
		this.a[ 2] = a[ 2];
		this.a[ 3] = a[ 3];
		this.a[ 4] = a[ 4];
		this.a[ 5] = a[ 5];
		this.a[ 6] = a[ 6];
		this.a[ 7] = a[ 7];
		this.a[ 8] = a[ 8];
		this.a[ 9] = a[ 9];
		this.a[10] = a[10];
		this.a[11] = a[11];
		this.a[12] = a[12];
		this.a[13] = a[13];
		this.a[14] = a[14];
		this.a[15] = a[15];
		this.a[16] = a[16];
		this.a[17] = a[17];
		this.a[18] = a[18];
	}

	/**
	 * Run {@code num} blank rounds. For the last four rounds,
	 * {@code a[1]} and {@code a[2]} are written out in {@code out},
	 * beginning at offset {@code off}. This method does not write
	 * back all the state; thus, it must be the final operation in a
	 * given hash function computation.
	 *
	 * @param num   the number of blank rounds
	 * @param out   the output buffer
	 * @param off   the output offset
	 */
	private blank(num:number, out:Uint8Array, off:number)
	{
		const a = new Int32Array(19);
		a[ 0] = this.a[ 0];
		a[ 1] = this.a[ 1];
		a[ 2] = this.a[ 2];
		a[ 3] = this.a[ 3];
		a[ 4] = this.a[ 4];
		a[ 5] = this.a[ 5];
		a[ 6] = this.a[ 6];
		a[ 7] = this.a[ 7];
		a[ 8] = this.a[ 8];
		a[ 9] = this.a[ 9];
		a[10] = this.a[10];
		a[11] = this.a[11];
		a[12] = this.a[12];
		a[13] = this.a[13];
		a[14] = this.a[14];
		a[15] = this.a[15];
		a[16] = this.a[16];
		a[17] = this.a[17];
		a[18] = this.a[18];

		const t = new Int32Array(19);
		const bt = new Int32Array(3);
		while (num -- > 0) {
			this.b[ 0] ^= a[ 1];
			this.b[ 4] ^= a[ 2];
			this.b[ 8] ^= a[ 3];
			this.b[ 9] ^= a[ 4];
			this.b[13] ^= a[ 5];
			this.b[17] ^= a[ 6];
			this.b[18] ^= a[ 7];
			this.b[22] ^= a[ 8];
			this.b[26] ^= a[ 9];
			this.b[27] ^= a[10];
			this.b[31] ^= a[11];
			this.b[35] ^= a[12];

			t[ 0] = a[ 0] ^ (a[ 1] | ~a[ 2]);
			t[ 1] = a[ 1] ^ (a[ 2] | ~a[ 3]);
			t[ 2] = a[ 2] ^ (a[ 3] | ~a[ 4]);
			t[ 3] = a[ 3] ^ (a[ 4] | ~a[ 5]);
			t[ 4] = a[ 4] ^ (a[ 5] | ~a[ 6]);
			t[ 5] = a[ 5] ^ (a[ 6] | ~a[ 7]);
			t[ 6] = a[ 6] ^ (a[ 7] | ~a[ 8]);
			t[ 7] = a[ 7] ^ (a[ 8] | ~a[ 9]);
			t[ 8] = a[ 8] ^ (a[ 9] | ~a[10]);
			t[ 9] = a[ 9] ^ (a[10] | ~a[11]);
			t[10] = a[10] ^ (a[11] | ~a[12]);
			t[11] = a[11] ^ (a[12] | ~a[13]);
			t[12] = a[12] ^ (a[13] | ~a[14]);
			t[13] = a[13] ^ (a[14] | ~a[15]);
			t[14] = a[14] ^ (a[15] | ~a[16]);
			t[15] = a[15] ^ (a[16] | ~a[17]);
			t[16] = a[16] ^ (a[17] | ~a[18]);
			t[17] = a[17] ^ (a[18] | ~a[ 0]);
			t[18] = a[18] ^ (a[ 0] | ~a[ 1]);

			a[ 0] = t[ 0];
			a[ 1] = (t[ 7] << 31) | (t[ 7] >>>  1);
			a[ 2] = (t[14] << 29) | (t[14] >>>  3);
			a[ 3] = (t[ 2] << 26) | (t[ 2] >>>  6);
			a[ 4] = (t[ 9] << 22) | (t[ 9] >>> 10);
			a[ 5] = (t[16] << 17) | (t[16] >>> 15);
			a[ 6] = (t[ 4] << 11) | (t[ 4] >>> 21);
			a[ 7] = (t[11] <<  4) | (t[11] >>> 28);
			a[ 8] = (t[18] << 28) | (t[18] >>>  4);
			a[ 9] = (t[ 6] << 19) | (t[ 6] >>> 13);
			a[10] = (t[13] <<  9) | (t[13] >>> 23);
			a[11] = (t[ 1] << 30) | (t[ 1] >>>  2);
			a[12] = (t[ 8] << 18) | (t[ 8] >>> 14);
			a[13] = (t[15] <<  5) | (t[15] >>> 27);
			a[14] = (t[ 3] << 23) | (t[ 3] >>>  9);
			a[15] = (t[10] <<  8) | (t[10] >>> 24);
			a[16] = (t[17] << 24) | (t[17] >>>  8);
			a[17] = (t[ 5] <<  7) | (t[ 5] >>> 25);
			a[18] = (t[12] << 21) | (t[12] >>> 11);

			t[ 0] = a[ 0] ^ a[ 1] ^ a[ 4];
			t[ 1] = a[ 1] ^ a[ 2] ^ a[ 5];
			t[ 2] = a[ 2] ^ a[ 3] ^ a[ 6];
			t[ 3] = a[ 3] ^ a[ 4] ^ a[ 7];
			t[ 4] = a[ 4] ^ a[ 5] ^ a[ 8];
			t[ 5] = a[ 5] ^ a[ 6] ^ a[ 9];
			t[ 6] = a[ 6] ^ a[ 7] ^ a[10];
			t[ 7] = a[ 7] ^ a[ 8] ^ a[11];
			t[ 8] = a[ 8] ^ a[ 9] ^ a[12];
			t[ 9] = a[ 9] ^ a[10] ^ a[13];
			t[10] = a[10] ^ a[11] ^ a[14];
			t[11] = a[11] ^ a[12] ^ a[15];
			t[12] = a[12] ^ a[13] ^ a[16];
			t[13] = a[13] ^ a[14] ^ a[17];
			t[14] = a[14] ^ a[15] ^ a[18];
			t[15] = a[15] ^ a[16] ^ a[ 0];
			t[16] = a[16] ^ a[17] ^ a[ 1];
			t[17] = a[17] ^ a[18] ^ a[ 2];
			t[18] = a[18] ^ a[ 0] ^ a[ 3];

			a[ 0] = t[ 0] ^ 1;
			a[ 1] = t[ 1];
			a[ 2] = t[ 2];
			a[ 3] = t[ 3];
			a[ 4] = t[ 4];
			a[ 5] = t[ 5];
			a[ 6] = t[ 6];
			a[ 7] = t[ 7];
			a[ 8] = t[ 8];
			a[ 9] = t[ 9];
			a[10] = t[10];
			a[11] = t[11];
			a[12] = t[12];
			a[13] = t[13];
			a[14] = t[14];
			a[15] = t[15];
			a[16] = t[16];
			a[17] = t[17];
			a[18] = t[18];

			bt[0] = this.b[36];
			bt[1] = this.b[37];
			bt[2] = this.b[38];
			a[13] ^= bt[0];
			a[14] ^= bt[1];
			a[15] ^= bt[2];
			arraycopy(this.b, 0, this.b, 3, 36);
			this.b[0] = bt[0];
			this.b[1] = bt[1];
			this.b[2] = bt[2];
			if (num < 4) {
				this.encodeLEInt(a[ 1], out, off + 0);
				this.encodeLEInt(a[ 2], out, off + 4);
				off += 8;
			}
		}
	}

	/** @see Digest */
	public toString()
	{
		return "RadioGatun[32]";
	}
}

/**
 * <p>This class implements the RadioGatun[64] digest algorithm under the
 * {@link Digest} API.</p>
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
 * @version   $Revision: 232 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

export class RadioGatun64 extends DigestEngine {

	private a!:BigInt64Array;
    private b!:BigInt64Array;

	/**
	 * Build the object.
	 */
	constructor()
	{
		super();
	}

	/** @see Digest */
	public copy(): Digest
	{
		const d = new RadioGatun64();
		arraycopy(this.a, 0, d.a, 0, this.a.length);
		arraycopy(this.b, 0, d.b, 0, this.b.length);
		return this.copyState(d);
	}

	/** @see Digest */
	public getDigestLength()
	{
		return 32;
	}

	/** @see DigestEngine */
	protected getInternalBlockLength()
	{
		return 312;
	}

	/** @see Digest */
	public getBlockLength()
	{
		return -24;
	}

	/** @see DigestEngine */
	protected engineReset()
	{
		for (let i = 0; i < this.a.length; i ++){
			this.a[i] = BigInt(0);
		}
		for (let i = 0; i < this.b.length; i ++){
			this.b[i] = BigInt(0);
		}
	}

	/** @see DigestEngine */
	protected doPadding(output:Uint8Array, outputOffset:number)
	{
		var ptr = this.flush();
		var buf = this.getBlockBuffer();
		buf[ptr++] = 0x01;
		for (let i = ptr; i < 312; i ++){
			buf[i] = 0;
		}
		this.processBlock(buf);
		var num = 18;
		for (;;) {
			ptr += 24;
			if (ptr > 312){
				break;
			}
			num--;
		}
		this.blank(num, output, outputOffset);
	}

	/** @see DigestEngine */
	protected doInit()
	{
		this.a = new BigInt64Array(19);
		this.b = new BigInt64Array(39);
		this.engineReset();
	}

	/**
	 * Encode the 64-bit word {@code val} into the array
	 * {@code buf} at offset {@code off}, in little-endian
	 * convention (least significant byte first).
	 *
	 * @param val   the value to encode
	 * @param buf   the destination buffer
	 * @param off   the destination offset
	 */
	private encodeLELong(val:bigint, buf:Uint8Array, off:number)
	{
		let endian = "little";
        let unsigned: boolean = false;
        const bigIntArray = new BigInt64Array(1);
        bigIntArray[0] = BigInt(val);
        // Use two 32-bit views to write the Int64
        const int32Array = new Int32Array(bigIntArray.buffer);
        for (let i = 0; i < 2; i++) {
            if (endian == "little") {
                if (unsigned == false) {
                    buf[off + i * 4 + 0] = int32Array[i];
                    buf[off + i * 4 + 1] = (int32Array[i] >> 8);
                    buf[off + i * 4 + 2] = (int32Array[i] >> 16);
                    buf[off + i * 4 + 3] = (int32Array[i] >> 24);
                } else {
                    buf[off + i * 4 + 0] = int32Array[i] & 0xFF;
                    buf[off + i * 4 + 1] = (int32Array[i] >> 8) & 0xFF;
                    buf[off + i * 4 + 2] = (int32Array[i] >> 16) & 0xFF;
                    buf[off + i * 4 + 3] = (int32Array[i] >> 24) & 0xFF;
                }
            } else {
                if (unsigned == undefined || unsigned == false) {
                    buf[off + (1 - i) * 4 + 3] = int32Array[i];
                    buf[off + (1 - i) * 4 + 2] = (int32Array[i] >> 8);
                    buf[off + (1 - i) * 4 + 1] = (int32Array[i] >> 16);
                    buf[off + (1 - i) * 4 + 0] = (int32Array[i] >> 24);
                } else {
                    buf[off + (1 - i) * 4 + 3] = int32Array[i] & 0xFF;
                    buf[off + (1 - i) * 4 + 2] = (int32Array[i] >> 8) & 0xFF;
                    buf[off + (1 - i) * 4 + 1] = (int32Array[i] >> 16) & 0xFF;
                    buf[off + (1 - i) * 4 + 0] = (int32Array[i] >> 24) & 0xFF;
                }
            }
        }
	}

	/**
	 * Decode a 64-bit little-endian word from the array {@code buf}
	 * at offset {@code off}.
	 *
	 * @param buf   the source buffer
	 * @param off   the source offset
	 * @return  the decoded value
	 */
	private decodeLELong(buf:Uint8Array, off:number)
	{
		let value = BigInt(0);
        let endian = "little";
        let unsigned: boolean = false;
        if (endian == "little") {
            for (let i = 0; i < 8; i++) {
                value = value | BigInt(buf[off]) << BigInt(8 * i);
                off++;
            }
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
            if (unsigned == false) {
                if (value & (BigInt(1) << BigInt(63))) {
                    value -= BigInt(1) << BigInt(64);
                }
            }
        }
        return value;
	}

	/** @see DigestEngine */
	protected processBlock( data:Uint8Array)
	{
		const a = new BigInt64Array(19);
		a[ 0] = BigInt(this.a[ 0]);
		a[ 1] = BigInt(this.a[ 1]);
		a[ 2] = BigInt(this.a[ 2]);
		a[ 3] = BigInt(this.a[ 3]);
		a[ 4] = BigInt(this.a[ 4]);
		a[ 5] = BigInt(this.a[ 5]);
		a[ 6] = BigInt(this.a[ 6]);
		a[ 7] = BigInt(this.a[ 7]);
		a[ 8] = BigInt(this.a[ 8]);
		a[ 9] = BigInt(this.a[ 9]);
		a[10] = BigInt(this.a[10]);
		a[11] = BigInt(this.a[11]);
		a[12] = BigInt(this.a[12]);
		a[13] = BigInt(this.a[13]);
		a[14] = BigInt(this.a[14]);
		a[15] = BigInt(this.a[15]);
		a[16] = BigInt(this.a[16]);
		a[17] = BigInt(this.a[17]);
		a[18] = BigInt(this.a[18]);

		var dp = 0;

		const p = new BigInt64Array(3);
		const t = new BigInt64Array(19);
		for (let mk = 12; mk >= 0; mk--) {
			p[0] = this.decodeLELong(data, dp + 0);
			p[1] = this.decodeLELong(data, dp + 8);
			p[2] = this.decodeLELong(data, dp + 16);
			dp += 24;
			var bj = (mk == 12) ? 0 : 3 * (mk + 1);
			this.b[bj + 0] ^= p[0];
			this.b[bj + 1] ^= p[1];
			this.b[bj + 2] ^= p[2];
			a[16] ^= p[0];
			a[17] ^= p[1];
			a[18] ^= p[2];

			bj = mk * 3;
			if ((bj += 3) == 39){
				bj = 0;
			}
			this.b[bj + 0] ^= a[ 1];
			if ((bj += 3) == 39){
				bj = 0;
			}
			this.b[bj + 1] ^= a[ 2];
			if ((bj += 3) == 39){
				bj = 0;
			}
			this.b[bj + 2] ^= a[ 3];
			if ((bj += 3) == 39){
				bj = 0;
			}
			this.b[bj + 0] ^= a[ 4];
			if ((bj += 3) == 39){
				bj = 0;
			}
			this.b[bj + 1] ^= a[ 5];
			if ((bj += 3) == 39){
				bj = 0;
			}
			this.b[bj + 2] ^= a[ 6];
			if ((bj += 3) == 39){
				bj = 0;
			}
			this.b[bj + 0] ^= a[ 7];
			if ((bj += 3) == 39){
				bj = 0;
			}
			this.b[bj + 1] ^= a[ 8];
			if ((bj += 3) == 39){
				bj = 0;
			}
			this.b[bj + 2] ^= a[ 9];
			if ((bj += 3) == 39){
				bj = 0;
			}
			this.b[bj + 0] ^= a[10];
			if ((bj += 3) == 39){
				bj = 0;
			}
			this.b[bj + 1] ^= a[11];
			if ((bj += 3) == 39){
				bj = 0;
			}
			this.b[bj + 2] ^= a[12];

			t[ 0] = a[ 0] ^ (a[ 1] | ~a[ 2]);
			t[ 1] = a[ 1] ^ (a[ 2] | ~a[ 3]);
			t[ 2] = a[ 2] ^ (a[ 3] | ~a[ 4]);
			t[ 3] = a[ 3] ^ (a[ 4] | ~a[ 5]);
			t[ 4] = a[ 4] ^ (a[ 5] | ~a[ 6]);
			t[ 5] = a[ 5] ^ (a[ 6] | ~a[ 7]);
			t[ 6] = a[ 6] ^ (a[ 7] | ~a[ 8]);
			t[ 7] = a[ 7] ^ (a[ 8] | ~a[ 9]);
			t[ 8] = a[ 8] ^ (a[ 9] | ~a[10]);
			t[ 9] = a[ 9] ^ (a[10] | ~a[11]);
			t[10] = a[10] ^ (a[11] | ~a[12]);
			t[11] = a[11] ^ (a[12] | ~a[13]);
			t[12] = a[12] ^ (a[13] | ~a[14]);
			t[13] = a[13] ^ (a[14] | ~a[15]);
			t[14] = a[14] ^ (a[15] | ~a[16]);
			t[15] = a[15] ^ (a[16] | ~a[17]);
			t[16] = a[16] ^ (a[17] | ~a[18]);
			t[17] = a[17] ^ (a[18] | ~a[ 0]);
			t[18] = a[18] ^ (a[ 0] | ~a[ 1]);
			a[ 0] = t[ 0];
			a[ 1] = (t[ 7] << BigInt(63)) | lshr(t[ 7],  1);
			a[ 2] = (t[14] << BigInt(61)) | lshr(t[14],  3);
			a[ 3] = (t[ 2] << BigInt(58)) | lshr(t[ 2],  6);
			a[ 4] = (t[ 9] << BigInt(54)) | lshr(t[ 9], 10);
			a[ 5] = (t[16] << BigInt(49)) | lshr(t[16], 15);
			a[ 6] = (t[ 4] << BigInt(43)) | lshr(t[ 4], 21);
			a[ 7] = (t[11] << BigInt(36)) | lshr(t[11], 28);
			a[ 8] = (t[18] << BigInt(28)) | lshr(t[18], 36);
			a[ 9] = (t[ 6] << BigInt(19)) | lshr(t[ 6], 45);
			a[10] = (t[13] << BigInt( 9)) | lshr(t[13], 55);
			a[11] = (t[ 1] << BigInt(62)) | lshr(t[ 1],  2);
			a[12] = (t[ 8] << BigInt(50)) | lshr(t[ 8], 14);
			a[13] = (t[15] << BigInt(37)) | lshr(t[15], 27);
			a[14] = (t[ 3] << BigInt(23)) | lshr(t[ 3], 41);
			a[15] = (t[10] << BigInt( 8)) | lshr(t[10], 56);
			a[16] = (t[17] << BigInt(56)) | lshr(t[17],  8);
			a[17] = (t[ 5] << BigInt(39)) | lshr(t[ 5], 25);
			a[18] = (t[12] << BigInt(21)) | lshr(t[12], 43);

			t[ 0] = a[ 0] ^ a[ 1] ^ a[ 4];
			t[ 1] = a[ 1] ^ a[ 2] ^ a[ 5];
			t[ 2] = a[ 2] ^ a[ 3] ^ a[ 6];
			t[ 3] = a[ 3] ^ a[ 4] ^ a[ 7];
			t[ 4] = a[ 4] ^ a[ 5] ^ a[ 8];
			t[ 5] = a[ 5] ^ a[ 6] ^ a[ 9];
			t[ 6] = a[ 6] ^ a[ 7] ^ a[10];
			t[ 7] = a[ 7] ^ a[ 8] ^ a[11];
			t[ 8] = a[ 8] ^ a[ 9] ^ a[12];
			t[ 9] = a[ 9] ^ a[10] ^ a[13];
			t[10] = a[10] ^ a[11] ^ a[14];
			t[11] = a[11] ^ a[12] ^ a[15];
			t[12] = a[12] ^ a[13] ^ a[16];
			t[13] = a[13] ^ a[14] ^ a[17];
			t[14] = a[14] ^ a[15] ^ a[18];
			t[15] = a[15] ^ a[16] ^ a[ 0];
			t[16] = a[16] ^ a[17] ^ a[ 1];
			t[17] = a[17] ^ a[18] ^ a[ 2];
			t[18] = a[18] ^ a[ 0] ^ a[ 3];

			a[ 0] = t[ 0] ^ BigInt(1);
			a[ 1] = t[ 1];
			a[ 2] = t[ 2];
			a[ 3] = t[ 3];
			a[ 4] = t[ 4];
			a[ 5] = t[ 5];
			a[ 6] = t[ 6];
			a[ 7] = t[ 7];
			a[ 8] = t[ 8];
			a[ 9] = t[ 9];
			a[10] = t[10];
			a[11] = t[11];
			a[12] = t[12];
			a[13] = t[13];
			a[14] = t[14];
			a[15] = t[15];
			a[16] = t[16];
			a[17] = t[17];
			a[18] = t[18];

			bj = mk * 3;
			a[13] ^= this.b[bj + 0];
			a[14] ^= this.b[bj + 1];
			a[15] ^= this.b[bj + 2];
		}
		
		this.a[ 0] = a[ 0];
		this.a[ 1] = a[ 1];
		this.a[ 2] = a[ 2];
		this.a[ 3] = a[ 3];
		this.a[ 4] = a[ 4];
		this.a[ 5] = a[ 5];
		this.a[ 6] = a[ 6];
		this.a[ 7] = a[ 7];
		this.a[ 8] = a[ 8];
		this.a[ 9] = a[ 9];
		this.a[10] = a[10];
		this.a[11] = a[11];
		this.a[12] = a[12];
		this.a[13] = a[13];
		this.a[14] = a[14];
		this.a[15] = a[15];
		this.a[16] = a[16];
		this.a[17] = a[17];
		this.a[18] = a[18];
	}

	/**
	 * Run {@code num} blank rounds. For the last four rounds,
	 * {@code a[1]} and {@code a[2]} are written out in {@code out},
	 * beginning at offset {@code off}. This method does not write
	 * back all the state; thus, it must be the final operation in a
	 * given hash function computation.
	 *
	 * @param num   the number of blank rounds
	 * @param out   the output buffer
	 * @param off   the output offset
	 */
	private blank(num:number, out:Uint8Array, off:number)
	{
		const a = new BigInt64Array(19);
		a[ 0] = this.a[ 0];
		a[ 1] = this.a[ 1];
		a[ 2] = this.a[ 2];
		a[ 3] = this.a[ 3];
		a[ 4] = this.a[ 4];
		a[ 5] = this.a[ 5];
		a[ 6] = this.a[ 6];
		a[ 7] = this.a[ 7];
		a[ 8] = this.a[ 8];
		a[ 9] = this.a[ 9];
		a[10] = this.a[10];
		a[11] = this.a[11];
		a[12] = this.a[12];
		a[13] = this.a[13];
		a[14] = this.a[14];
		a[15] = this.a[15];
		a[16] = this.a[16];
		a[17] = this.a[17];
		a[18] = this.a[18];

		const t = new BigInt64Array(19);
		const bt = new BigInt64Array(3);
		while (num -- > 0) {
			this.b[ 0] ^= a[ 1];
			this.b[ 4] ^= a[ 2];
			this.b[ 8] ^= a[ 3];
			this.b[ 9] ^= a[ 4];
			this.b[13] ^= a[ 5];
			this.b[17] ^= a[ 6];
			this.b[18] ^= a[ 7];
			this.b[22] ^= a[ 8];
			this.b[26] ^= a[ 9];
			this.b[27] ^= a[10];
			this.b[31] ^= a[11];
			this.b[35] ^= a[12];

			t[ 0] = a[ 0] ^ (a[ 1] | ~a[ 2]);
			t[ 1] = a[ 1] ^ (a[ 2] | ~a[ 3]);
			t[ 2] = a[ 2] ^ (a[ 3] | ~a[ 4]);
			t[ 3] = a[ 3] ^ (a[ 4] | ~a[ 5]);
			t[ 4] = a[ 4] ^ (a[ 5] | ~a[ 6]);
			t[ 5] = a[ 5] ^ (a[ 6] | ~a[ 7]);
			t[ 6] = a[ 6] ^ (a[ 7] | ~a[ 8]);
			t[ 7] = a[ 7] ^ (a[ 8] | ~a[ 9]);
			t[ 8] = a[ 8] ^ (a[ 9] | ~a[10]);
			t[ 9] = a[ 9] ^ (a[10] | ~a[11]);
			t[10] = a[10] ^ (a[11] | ~a[12]);
			t[11] = a[11] ^ (a[12] | ~a[13]);
			t[12] = a[12] ^ (a[13] | ~a[14]);
			t[13] = a[13] ^ (a[14] | ~a[15]);
			t[14] = a[14] ^ (a[15] | ~a[16]);
			t[15] = a[15] ^ (a[16] | ~a[17]);
			t[16] = a[16] ^ (a[17] | ~a[18]);
			t[17] = a[17] ^ (a[18] | ~a[ 0]);
			t[18] = a[18] ^ (a[ 0] | ~a[ 1]);

			a[ 0] = t[ 0];
			a[ 1] = (t[ 7] << BigInt(63)) | lshr(t[ 7],  1);
			a[ 2] = (t[14] << BigInt(61)) | lshr(t[14],  3);
			a[ 3] = (t[ 2] << BigInt(58)) | lshr(t[ 2],  6);
			a[ 4] = (t[ 9] << BigInt(54)) | lshr(t[ 9], 10);
			a[ 5] = (t[16] << BigInt(49)) | lshr(t[16], 15);
			a[ 6] = (t[ 4] << BigInt(43)) | lshr(t[ 4], 21);
			a[ 7] = (t[11] << BigInt(36)) | lshr(t[11], 28);
			a[ 8] = (t[18] << BigInt(28)) | lshr(t[18], 36);
			a[ 9] = (t[ 6] << BigInt(19)) | lshr(t[ 6], 45);
			a[10] = (t[13] << BigInt( 9)) | lshr(t[13], 55);
			a[11] = (t[ 1] << BigInt(62)) | lshr(t[ 1],  2);
			a[12] = (t[ 8] << BigInt(50)) | lshr(t[ 8], 14);
			a[13] = (t[15] << BigInt(37)) | lshr(t[15], 27);
			a[14] = (t[ 3] << BigInt(23)) | lshr(t[ 3], 41);
			a[15] = (t[10] << BigInt( 8)) | lshr(t[10], 56);
			a[16] = (t[17] << BigInt(56)) | lshr(t[17],  8);
			a[17] = (t[ 5] << BigInt(39)) | lshr(t[ 5], 25);
			a[18] = (t[12] << BigInt(21)) | lshr(t[12], 43);

			t[ 0] = a[ 0] ^ a[ 1] ^ a[ 4];
			t[ 1] = a[ 1] ^ a[ 2] ^ a[ 5];
			t[ 2] = a[ 2] ^ a[ 3] ^ a[ 6];
			t[ 3] = a[ 3] ^ a[ 4] ^ a[ 7];
			t[ 4] = a[ 4] ^ a[ 5] ^ a[ 8];
			t[ 5] = a[ 5] ^ a[ 6] ^ a[ 9];
			t[ 6] = a[ 6] ^ a[ 7] ^ a[10];
			t[ 7] = a[ 7] ^ a[ 8] ^ a[11];
			t[ 8] = a[ 8] ^ a[ 9] ^ a[12];
			t[ 9] = a[ 9] ^ a[10] ^ a[13];
			t[10] = a[10] ^ a[11] ^ a[14];
			t[11] = a[11] ^ a[12] ^ a[15];
			t[12] = a[12] ^ a[13] ^ a[16];
			t[13] = a[13] ^ a[14] ^ a[17];
			t[14] = a[14] ^ a[15] ^ a[18];
			t[15] = a[15] ^ a[16] ^ a[ 0];
			t[16] = a[16] ^ a[17] ^ a[ 1];
			t[17] = a[17] ^ a[18] ^ a[ 2];
			t[18] = a[18] ^ a[ 0] ^ a[ 3];

			a[ 0] = t[ 0] ^ BigInt(1);
			a[ 1] = t[ 1];
			a[ 2] = t[ 2];
			a[ 3] = t[ 3];
			a[ 4] = t[ 4];
			a[ 5] = t[ 5];
			a[ 6] = t[ 6];
			a[ 7] = t[ 7];
			a[ 8] = t[ 8];
			a[ 9] = t[ 9];
			a[10] = t[10];
			a[11] = t[11];
			a[12] = t[12];
			a[13] = t[13];
			a[14] = t[14];
			a[15] = t[15];
			a[16] = t[16];
			a[17] = t[17];
			a[18] = t[18];

			bt[0] = this.b[36];
			bt[1] = this.b[37];
			bt[2] = this.b[38];
			a[13] ^= bt[0];
			a[14] ^= bt[1];
			a[15] ^= bt[2];
			arraycopy(this.b, 0, this.b, 3, 36);
			this.b[0] = bt[0];
			this.b[1] = bt[1];
			this.b[2] = bt[2];
			if (num < 2) {
				this.encodeLELong(a[ 1], out, off + 0);
				this.encodeLELong(a[ 2], out, off + 8);
				off += 16;
			}
		}

	}

	/** @see Digest */
	public toString()
	{
		return "RadioGatun[64]";
	}
}

function toHex(bytes: Uint8Array): string {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
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

// Input types
type InputData = string | Uint8Array | Buffer;

// Output formats
type OutputFormat = 'hex' | 'array' | 'buffer';

/**
 * Creates a 32 byte RadioGatún32 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function RADIOGATUN32(message: InputData,format: OutputFormat = arrayType()){
	const hash = new RadioGatun32();
	hash.update(formatMessage(message));
	var digestbytes = hash.digest();
	if (format == "hex") {
        return toHex(digestbytes);
    } else if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    return digestbytes;
}

/**
 * Creates a 32 byte RadioGatún64 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function RADIOGATUN64(message: InputData, format: OutputFormat = arrayType()){
	const hash = new RadioGatun64();
	hash.update(formatMessage(message));
	var digestbytes = hash.digest();
	if (format == "hex") {
        return toHex(digestbytes);
    } else if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    return digestbytes;
}

/**
 * Static class of all RadioGatún functions and classes
 */
export class RADIOGATUN{
    static RadioGatun32 = RadioGatun32;
    static RADIOGATUN32 = RADIOGATUN32;
    static RadioGatun64 = RadioGatun64;
    static RADIOGATUN64 = RADIOGATUN64;
    /**
     * List of all hashes in class
     */
    static get FUNCTION_LIST() {
        return [
            "RADIOGATUN32",
            "RADIOGATUN64"
        ]
    }
}