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
 * This class implements the core operations for the CubeHash digest
 * algorithm.
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
 * @version   $Revision: 232 $
 * @author    Thomas Pornin <thomas.pornin@cryptolog.com>
 */

export abstract class CubeHashCore extends DigestEngine {

    private x!: Uint32Array;

    private inputBlock(data: Uint8Array): void {
        this.x[0] ^= this.decodeLEInt(data,  0);
        this.x[1] ^= this.decodeLEInt(data,  4);
        this.x[2] ^= this.decodeLEInt(data,  8);
        this.x[3] ^= this.decodeLEInt(data, 12);
        this.x[4] ^= this.decodeLEInt(data, 16);
        this.x[5] ^= this.decodeLEInt(data, 20);
        this.x[6] ^= this.decodeLEInt(data, 24);
        this.x[7] ^= this.decodeLEInt(data, 28);
    }

    private sixteenRounds(): void {
        const a = 10; const b = 11; const c = 12;
        const d = 13; const e = 14; const f = 15;
        const g = 16; const h = 17; const i = 18;
        const j = 19; const k = 20; const l = 21;
        const m = 22; const n = 23; const o = 24;
        const p = 25; const q = 26; const r = 27;
        const s = 28; const t = 29; const u = 30;
        const v = 31;
        for (let x = 0; x < 8; x++) {
            this.x[g] = this.x[0] + this.x[g];
            this.x[0] = (this.x[0] << 7) | (this.x[0] >>> (32 - 7));
            this.x[h] = this.x[1] + this.x[h];
            this.x[1] = (this.x[1] << 7) | (this.x[1] >>> (32 - 7));
            this.x[i] = this.x[2] + this.x[i];
            this.x[2] = (this.x[2] << 7) | (this.x[2] >>> (32 - 7));
            this.x[j] = this.x[3] + this.x[j];
            this.x[3] = (this.x[3] << 7) | (this.x[3] >>> (32 - 7));
            this.x[k] = this.x[4] + this.x[k];
            this.x[4] = (this.x[4] << 7) | (this.x[4] >>> (32 - 7));
            this.x[l] = this.x[5] + this.x[l];
            this.x[5] = (this.x[5] << 7) | (this.x[5] >>> (32 - 7));
            this.x[m] = this.x[6] + this.x[m];
            this.x[6] = (this.x[6] << 7) | (this.x[6] >>> (32 - 7));
            this.x[n] = this.x[7] + this.x[n];
            this.x[7] = (this.x[7] << 7) | (this.x[7] >>> (32 - 7));
            this.x[o] = this.x[8] + this.x[o];
            this.x[8] = (this.x[8] << 7) | (this.x[8] >>> (32 - 7));
            this.x[p] = this.x[9] + this.x[p];
            this.x[9] = (this.x[9] << 7) | (this.x[9] >>> (32 - 7));
            this.x[q] = this.x[a] + this.x[q];
            this.x[a] = (this.x[a] << 7) | (this.x[a] >>> (32 - 7));
            this.x[r] = this.x[b] + this.x[r];
            this.x[b] = (this.x[b] << 7) | (this.x[b] >>> (32 - 7));
            this.x[s] = this.x[c] + this.x[s];
            this.x[c] = (this.x[c] << 7) | (this.x[c] >>> (32 - 7));
            this.x[t] = this.x[d] + this.x[t];
            this.x[d] = (this.x[d] << 7) | (this.x[d] >>> (32 - 7));
            this.x[u] = this.x[e] + this.x[u];
            this.x[e] = (this.x[e] << 7) | (this.x[e] >>> (32 - 7));
            this.x[v] = this.x[f] + this.x[v];
            this.x[f] = (this.x[f] << 7) | (this.x[f] >>> (32 - 7));
            this.x[8] ^= this.x[g];
            this.x[9] ^= this.x[h];
            this.x[a] ^= this.x[i];
            this.x[b] ^= this.x[j];
            this.x[c] ^= this.x[k];
            this.x[d] ^= this.x[l];
            this.x[e] ^= this.x[m];
            this.x[f] ^= this.x[n];
            this.x[0] ^= this.x[o];
            this.x[1] ^= this.x[p];
            this.x[2] ^= this.x[q];
            this.x[3] ^= this.x[r];
            this.x[4] ^= this.x[s];
            this.x[5] ^= this.x[t];
            this.x[6] ^= this.x[u];
            this.x[7] ^= this.x[v];
            this.x[i] = this.x[8] + this.x[i];
            this.x[8] = (this.x[8] << 11) | (this.x[8] >>> (32 - 11));
            this.x[j] = this.x[9] + this.x[j];
            this.x[9] = (this.x[9] << 11) | (this.x[9] >>> (32 - 11));
            this.x[g] = this.x[a] + this.x[g];
            this.x[a] = (this.x[a] << 11) | (this.x[a] >>> (32 - 11));
            this.x[h] = this.x[b] + this.x[h];
            this.x[b] = (this.x[b] << 11) | (this.x[b] >>> (32 - 11));
            this.x[m] = this.x[c] + this.x[m];
            this.x[c] = (this.x[c] << 11) | (this.x[c] >>> (32 - 11));
            this.x[n] = this.x[d] + this.x[n];
            this.x[d] = (this.x[d] << 11) | (this.x[d] >>> (32 - 11));
            this.x[k] = this.x[e] + this.x[k];
            this.x[e] = (this.x[e] << 11) | (this.x[e] >>> (32 - 11));
            this.x[l] = this.x[f] + this.x[l];
            this.x[f] = (this.x[f] << 11) | (this.x[f] >>> (32 - 11));
            this.x[q] = this.x[0] + this.x[q];
            this.x[0] = (this.x[0] << 11) | (this.x[0] >>> (32 - 11));
            this.x[r] = this.x[1] + this.x[r];
            this.x[1] = (this.x[1] << 11) | (this.x[1] >>> (32 - 11));
            this.x[o] = this.x[2] + this.x[o];
            this.x[2] = (this.x[2] << 11) | (this.x[2] >>> (32 - 11));
            this.x[p] = this.x[3] + this.x[p];
            this.x[3] = (this.x[3] << 11) | (this.x[3] >>> (32 - 11));
            this.x[u] = this.x[4] + this.x[u];
            this.x[4] = (this.x[4] << 11) | (this.x[4] >>> (32 - 11));
            this.x[v] = this.x[5] + this.x[v];
            this.x[5] = (this.x[5] << 11) | (this.x[5] >>> (32 - 11));
            this.x[s] = this.x[6] + this.x[s];
            this.x[6] = (this.x[6] << 11) | (this.x[6] >>> (32 - 11));
            this.x[t] = this.x[7] + this.x[t];
            this.x[7] = (this.x[7] << 11) | (this.x[7] >>> (32 - 11));
            this.x[c] ^= this.x[i];
            this.x[d] ^= this.x[j];
            this.x[e] ^= this.x[g];
            this.x[f] ^= this.x[h];
            this.x[8] ^= this.x[m];
            this.x[9] ^= this.x[n];
            this.x[a] ^= this.x[k];
            this.x[b] ^= this.x[l];
            this.x[4] ^= this.x[q];
            this.x[5] ^= this.x[r];
            this.x[6] ^= this.x[o];
            this.x[7] ^= this.x[p];
            this.x[0] ^= this.x[u];
            this.x[1] ^= this.x[v];
            this.x[2] ^= this.x[s];
            this.x[3] ^= this.x[t];

            this.x[j] = this.x[c] + this.x[j];
            this.x[c] = (this.x[c] << 7) | (this.x[c] >>> (32 - 7));
            this.x[i] = this.x[d] + this.x[i];
            this.x[d] = (this.x[d] << 7) | (this.x[d] >>> (32 - 7));
            this.x[h] = this.x[e] + this.x[h];
            this.x[e] = (this.x[e] << 7) | (this.x[e] >>> (32 - 7));
            this.x[g] = this.x[f] + this.x[g];
            this.x[f] = (this.x[f] << 7) | (this.x[f] >>> (32 - 7));
            this.x[n] = this.x[8] + this.x[n];
            this.x[8] = (this.x[8] << 7) | (this.x[8] >>> (32 - 7));
            this.x[m] = this.x[9] + this.x[m];
            this.x[9] = (this.x[9] << 7) | (this.x[9] >>> (32 - 7));
            this.x[l] = this.x[a] + this.x[l];
            this.x[a] = (this.x[a] << 7) | (this.x[a] >>> (32 - 7));
            this.x[k] = this.x[b] + this.x[k];
            this.x[b] = (this.x[b] << 7) | (this.x[b] >>> (32 - 7));
            this.x[r] = this.x[4] + this.x[r];
            this.x[4] = (this.x[4] << 7) | (this.x[4] >>> (32 - 7));
            this.x[q] = this.x[5] + this.x[q];
            this.x[5] = (this.x[5] << 7) | (this.x[5] >>> (32 - 7));
            this.x[p] = this.x[6] + this.x[p];
            this.x[6] = (this.x[6] << 7) | (this.x[6] >>> (32 - 7));
            this.x[o] = this.x[7] + this.x[o];
            this.x[7] = (this.x[7] << 7) | (this.x[7] >>> (32 - 7));
            this.x[v] = this.x[0] + this.x[v];
            this.x[0] = (this.x[0] << 7) | (this.x[0] >>> (32 - 7));
            this.x[u] = this.x[1] + this.x[u];
            this.x[1] = (this.x[1] << 7) | (this.x[1] >>> (32 - 7));
            this.x[t] = this.x[2] + this.x[t];
            this.x[2] = (this.x[2] << 7) | (this.x[2] >>> (32 - 7));
            this.x[s] = this.x[3] + this.x[s];
            this.x[3] = (this.x[3] << 7) | (this.x[3] >>> (32 - 7));
            this.x[4] ^= this.x[j];
            this.x[5] ^= this.x[i];
            this.x[6] ^= this.x[h];
            this.x[7] ^= this.x[g];
            this.x[0] ^= this.x[n];
            this.x[1] ^= this.x[m];
            this.x[2] ^= this.x[l];
            this.x[3] ^= this.x[k];
            this.x[c] ^= this.x[r];
            this.x[d] ^= this.x[q];
            this.x[e] ^= this.x[p];
            this.x[f] ^= this.x[o];
            this.x[8] ^= this.x[v];
            this.x[9] ^= this.x[u];
            this.x[a] ^= this.x[t];
            this.x[b] ^= this.x[s];
            this.x[h] = this.x[4] + this.x[h];
            this.x[4] = (this.x[4] << 11) | (this.x[4] >>> (32 - 11));
            this.x[g] = this.x[5] + this.x[g];
            this.x[5] = (this.x[5] << 11) | (this.x[5] >>> (32 - 11));
            this.x[j] = this.x[6] + this.x[j];
            this.x[6] = (this.x[6] << 11) | (this.x[6] >>> (32 - 11));
            this.x[i] = this.x[7] + this.x[i];
            this.x[7] = (this.x[7] << 11) | (this.x[7] >>> (32 - 11));
            this.x[l] = this.x[0] + this.x[l];
            this.x[0] = (this.x[0] << 11) | (this.x[0] >>> (32 - 11));
            this.x[k] = this.x[1] + this.x[k];
            this.x[1] = (this.x[1] << 11) | (this.x[1] >>> (32 - 11));
            this.x[n] = this.x[2] + this.x[n];
            this.x[2] = (this.x[2] << 11) | (this.x[2] >>> (32 - 11));
            this.x[m] = this.x[3] + this.x[m];
            this.x[3] = (this.x[3] << 11) | (this.x[3] >>> (32 - 11));
            this.x[p] = this.x[c] + this.x[p];
            this.x[c] = (this.x[c] << 11) | (this.x[c] >>> (32 - 11));
            this.x[o] = this.x[d] + this.x[o];
            this.x[d] = (this.x[d] << 11) | (this.x[d] >>> (32 - 11));
            this.x[r] = this.x[e] + this.x[r];
            this.x[e] = (this.x[e] << 11) | (this.x[e] >>> (32 - 11));
            this.x[q] = this.x[f] + this.x[q];
            this.x[f] = (this.x[f] << 11) | (this.x[f] >>> (32 - 11));
            this.x[t] = this.x[8] + this.x[t];
            this.x[8] = (this.x[8] << 11) | (this.x[8] >>> (32 - 11));
            this.x[s] = this.x[9] + this.x[s];
            this.x[9] = (this.x[9] << 11) | (this.x[9] >>> (32 - 11));
            this.x[v] = this.x[a] + this.x[v];
            this.x[a] = (this.x[a] << 11) | (this.x[a] >>> (32 - 11));
            this.x[u] = this.x[b] + this.x[u];
            this.x[b] = (this.x[b] << 11) | (this.x[b] >>> (32 - 11));
            this.x[0] ^= this.x[h];
            this.x[1] ^= this.x[g];
            this.x[2] ^= this.x[j];
            this.x[3] ^= this.x[i];
            this.x[4] ^= this.x[l];
            this.x[5] ^= this.x[k];
            this.x[6] ^= this.x[n];
            this.x[7] ^= this.x[m];
            this.x[8] ^= this.x[p];
            this.x[9] ^= this.x[o];
            this.x[a] ^= this.x[r];
            this.x[b] ^= this.x[q];
            this.x[c] ^= this.x[t];
            this.x[d] ^= this.x[s];
            this.x[e] ^= this.x[v];
            this.x[f] ^= this.x[u];
        }
    }

    private encodeLEInt(val: number, buf: Uint8Array, off: number): void {
        buf[off] = val & 0xFF;
        buf[off + 1] = (val >> 8) & 0xFF;
        buf[off + 2] = (val >> 16) & 0xFF;
        buf[off + 3] = (val >> 24) & 0xFF;
    }

    private decodeLEInt(buf: Uint8Array, off: number): number {
        const value = (buf[off] | (buf[off + 1] << 8) | (buf[off + 2] << 16) | (buf[off + 3] << 24)) >>> 0;
        return value;
    }

    protected engineReset(): void {
        this.doReset();
    }

    protected processBlock(data: Uint8Array): void {
        this.inputBlock(data);
        this.sixteenRounds();
    }

    protected doPadding(out: Uint8Array, off: number): void {
        var ptr = this.flush();
        const buf = this.getBlockBuffer();
        const a = 10; const b = 11; const c = 12;
        const d = 13; const e = 14; const f = 15;
        const g = 16; const h = 17; const i = 18;
        const j = 19; const k = 20; const l = 21;
        const m = 22; const n = 23; const o = 24;
        const p = 25; const q = 26; const r = 27;
        const s = 28; const t = 29; const u = 30;
        const v = 31;
        buf[ptr++] = 0x80;
        while(ptr < 32){
            buf[ptr ++] = 0x00;
        }
        this.inputBlock(buf);
        this.sixteenRounds();
        this.x[v] ^= 1;
        for (let i = 0; i < 10; i++) {
            this.sixteenRounds();
        }
        const dlen = this.getDigestLength();
        this.encodeLEInt(this.x[0], out, off + 0);
        this.encodeLEInt(this.x[1], out, off + 4);
        this.encodeLEInt(this.x[2], out, off + 8);
        this.encodeLEInt(this.x[3], out, off + 12);
        this.encodeLEInt(this.x[4], out, off + 16);
        this.encodeLEInt(this.x[5], out, off + 20);
        this.encodeLEInt(this.x[6], out, off + 24);
        if (dlen == 28) {
            return;
        }
        this.encodeLEInt(this.x[7], out, off + 28);
        if (dlen == 32) {
            return;
        }
        this.encodeLEInt(this.x[8], out, off + 32);
        this.encodeLEInt(this.x[9], out, off + 36);
        this.encodeLEInt(this.x[a], out, off + 40);
        this.encodeLEInt(this.x[b], out, off + 44);
        if (dlen == 48) {
            return;
        }
        this.encodeLEInt(this.x[c], out, off + 48);
        this.encodeLEInt(this.x[d], out, off + 52);
        this.encodeLEInt(this.x[e], out, off + 56);
        this.encodeLEInt(this.x[f], out, off + 60);
    }

    protected doInit() {
        this.doReset();
    }

    protected abstract getIV(): Uint32Array;

    getInternalBlockLength() {
        return 32;
    }

    getBlockLength(): number {
        return -32;
    }

    protected doReset() {
        this.x = this.getIV();
    }

    protected copyState<T>(dst: CubeHashCore): T {
        dst.x = this.x;
        return super.copyState(dst);
    }

    String() {
        return "CubeHash-" + (this.getDigestLength() << 3);
    }
    protected dup(): DigestEngine {
        const x = Object.create(Object.getPrototypeOf(this)) as CubeHashCore;
        x.x = this.x.slice();
        return x;
    }
}

/**
 * This class implements the CubeHash-224 digest algorithm under the
 * {@link Digest} API.
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
 * @version   $Revision: 183 $
 * @author    Thomas Pornin <thomas.pornin@cryptolog.com>
 */

export class CubeHash224 extends CubeHashCore {

    constructor() {
        super();
    }

    protected getIV() {
        return new Uint32Array([
            0xB0FC8217, 0x1BEE1A90, 0x829E1A22, 0x6362C342, 
            0x24D91C30, 0x03A7AA24, 0xA63721C8, 0x85B0E2EF,
            0xF35D13F3, 0x41DA807D, 0x21A70CA6, 0x1F4E9774,
            0xB3E1C932, 0xEB0A79A8, 0xCDDAAA66, 0xE2F6ECAA, 
            0x0A713362, 0xAA3080E0, 0xD8F23A32, 0xCEF15E28, 
            0xDB086314, 0x7F709DF7, 0xACD228A4, 0x704D6ECE,
            0xAA3EC95F, 0xE387C214, 0x3A6445FF, 0x9CAB81C3, 
            0xC73D4B98, 0xD277AEBE, 0xFD20151C, 0x00CB573E
        ]);
    }

    getDigestLength(): number {
        return 28;
    }

    protected dup(): CubeHash224 {
        return new CubeHash224();
    }
}

/**
 * This class implements the CubeHash-256 digest algorithm under the
 * {@link Digest} API.
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
 * @version   $Revision: 183 $
 * @author    Thomas Pornin <thomas.pornin@cryptolog.com>
 */

export class CubeHash256 extends CubeHashCore {

    constructor() {
        super();
    }

    protected getIV(): Uint32Array {
        return new Uint32Array([
            0xEA2BD4B4, 0xCCD6F29F, 0x63117E71, 0x35481EAE, 
            0x22512D5B, 0xE5D94E63, 0x7E624131, 0xF4CC12BE, 
            0xC2D0B696, 0x42AF2070, 0xD0720C35, 0x3361DA8C,
            0x28CCECA4, 0x8EF8AD83, 0x4680AC00, 0x40E5FBAB, 
            0xD89041C3, 0x6107FBD5, 0x6C859D41, 0xF0B26679, 
            0x09392549, 0x5FA25603, 0x65C892FD, 0x93CB6285, 
            0x2AF2B5AE, 0x9E4B4E60, 0x774ABFDD, 0x85254725, 
            0x15815AEB, 0x4AB6AAD6, 0x9CDAF8AF, 0xD6032C0A
        ]);
    }

    getDigestLength(): number {
        return 32;
    }

    protected dup(): CubeHash256 {
        return new CubeHash256();
    }
}

/**
 * This class implements the CubeHash-384 digest algorithm under the
 * {@link Digest} API.
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
 * @version   $Revision: 183 $
 * @author    Thomas Pornin <thomas.pornin@cryptolog.com>
 */

export class CubeHash384 extends CubeHashCore {

    constructor() {
        super();
    }

    protected getIV(): Uint32Array {
        return new Uint32Array([
            0xE623087E, 0x04C00C87, 0x5EF46453, 0x69524B13, 
            0x1A05C7A9, 0x3528DF88, 0x6BDD01B5, 0x5057B792, 
            0x6AA7A922, 0x649C7EEE, 0xF426309F, 0xCB629052,
            0xFC8E20ED, 0xB3482BAB, 0xF89E5E7E, 0xD83D4DE4, 
            0x44BFC10D, 0x5FC1E63D, 0x2104E6CB, 0x17958F7F, 
            0xDBEAEF70, 0xB4B97E1E, 0x32C195F6, 0x6184A8E4, 
            0x796C2543, 0x23DE176D, 0xD33BBAEC, 0x0C12E5D2, 
            0x4EB95A7B, 0x2D18BA01, 0x04EE475F, 0x1FC5F22E
        ]);
    }

    getDigestLength(): number {
        return 48;
    }

    protected dup(): CubeHash384 {
        return new CubeHash384();
    }
}

/**
 * This class implements the CubeHash-512 digest algorithm under the
 * {@link Digest} API.
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
 * @version   $Revision: 183 $
 * @author    Thomas Pornin <thomas.pornin@cryptolog.com>
 */

export class CubeHash512 extends CubeHashCore {

    constructor() {
        super();
    }

    protected getIV(): Uint32Array {
        return new Uint32Array([
            0x2AEA2A61, 0x50F494D4, 0x2D538B8B, 0x4167D83E, 
            0x3FEE2313, 0xC701CF8C, 0xCC39968E, 0x50AC5695, 
            0x4D42C787, 0xA647A8B3, 0x97CF0BEF, 0x825B4537, 
            0xEEF864D2, 0xF22090C4, 0xD0E5CD33, 0xA23911AE, 
            0xFCD398D9, 0x148FE485, 0x1B017BEF, 0xB6444532, 
            0x6A536159, 0x2FF5781C, 0x91FA7934, 0x0DBADEA9, 
            0xD65C8A2B, 0xA5A70E75, 0xB1C62456, 0xBC796576, 
            0x1921C8F7, 0xE7989AF1, 0x7795D246, 0xD43E3B44
        ]);
    }

    getDigestLength(): number {
        return 64;
    }

    protected dup(): CubeHash512 {
        return new CubeHash512();
    }
}

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
    private kipad!:Uint8Array
    private kopad!:Uint8Array;
    private outputLength!:number;
    private tmpOut!:Uint8Array;
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
    constructor(dig:Digest, key:Uint8Array, outputLength?:number)
    {
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
            if (len > B){
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
        if (outputLength && outputLength < dig.getDigestLength()){
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
    private _HMAC(dig:Digest, kipad:Uint8Array, kopad:Uint8Array, outputLength:number)
    {
        this.dig = dig;
        this.kipad = kipad;
        this.kopad = kopad;
        this.outputLength = outputLength;
        this.tmpOut = new Uint8Array(dig.getDigestLength());
        return this;
    }

    private processKey(keyB:Uint8Array)
    {
        var B = keyB.length;
        this.kipad = new Uint8Array(B);
        this.kopad = new Uint8Array(B);
        for (let i = 0; i < B; i ++) {
            var x = keyB[i];
            this.kipad[i] = (x ^ 0x36);
            this.kopad[i] = (x ^ 0x5C);
        }
    }

    /** @see Digest */
    public copy(): Digest
    {
        const h = this._HMAC(this.dig.copy(), this.kipad, this.kopad, this.outputLength);
        return this.copyState(h);
    }

    /** @see Digest */
    public getDigestLength(): number
    {
        /*
         * At construction time, outputLength is first set to 0,
         * which means that this method will return 0, which is
         * appropriate since at that time "dig" has not yet been
         * set.
         */
        return this.outputLength < 0 ? this.dig.getDigestLength() : this.outputLength;
    }

    /** @see Digest */
    public getBlockLength(): number
    {
        /*
         * Internal block length is not defined for HMAC, which
         * is not, stricto-sensu, an iterated hash function.
         * The value 64 should provide correct buffering. Do NOT
         * change this value without checking doPadding().
         */
        return 64;
    }

    /** @see DigestEngine */
    protected engineReset()
    {
        this.dig.reset();
        this.dig.update(this.kipad);
    }

    /** @see DigestEngine */
    protected processBlock(data:Uint8Array)
    {
        if (this.onlyThis > 0) {
            this.dig.update(data, 0, this.onlyThis);
            this.onlyThis = 0;
        } else {
            this.dig.update(data);
        }
    }

    /** @see DigestEngine */
    protected doPadding(output:Uint8Array, outputOffset:number)
    {
        /*
         * This is slightly ugly... we need to get the still
         * buffered data, but the only way to get it from
         * DigestEngine is to input some more bytes and wait
         * for the processBlock() call. We set a variable
         * with the count of actual data bytes, so that
         * processBlock() knows what to do.
         */
        this.onlyThis = this.flush();
        if (this.onlyThis > 0){
            this.update(HMAC.zeroPad, 0, 64 - this.onlyThis);
        }
        var olen = this.tmpOut.length;
        this.dig.digest(this.tmpOut, 0, olen);
        this.dig.update(this.kopad);
        this.dig.update(this.tmpOut);
        this.dig.digest(this.tmpOut, 0, olen);
        if (this.outputLength >= 0){
            olen = this.outputLength;
        }
        arraycopy(this.tmpOut, 0, output, outputOffset, olen);
    }

    /** @see DigestEngine */
    protected doInit()
    {
        /*
         * Empty: we do not want to do anything here because
         * it would prevent correct cloning. The initialization
         * job is done in the constructor.
         */
    }

    /** @see Digest */
    public toString(): string
    {
        return "HMAC/" + this.dig.toString();
    }
}

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

function formatMessage(message: InputData): Uint8Array {
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

function bytesToHex(bytes: Uint8Array | Buffer): string {
    for (var hex: string[] = [], i = 0; i < bytes.length; i++) {
        hex.push((bytes[i] >>> 4).toString(16));
        hex.push((bytes[i] & 0xF).toString(16));
    }
    return hex.join("");
}

function arrayType():OutputFormat{
	if (typeof window !== 'undefined') {
		return "array" as OutputFormat;
	} else {
    return "buffer" as OutputFormat;
	}
};

/**
 * Creates a vary length Cube Hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {number?} outBits - length of hash (default 512 bit or 64 bytes)
 * @returns `string|Uint8Array|Buffer`
 */
export function _CUBEHASH(message: InputData, format: OutputFormat = arrayType(), outBits: 224|256|384|512 = 512) {
    var hash;
    if(outBits == 224){
        hash = new CubeHash224();
    } else if(outBits == 256){
        hash = new CubeHash256();
    } else if(outBits == 384){
        hash = new CubeHash384();
    } else {
        hash = new CubeHash512();
    }
    hash.update(formatMessage(message));
    const digestbytes = hash.digest();
    if (format === "hex") {
        return bytesToHex(digestbytes);
    } else if (format === "buffer") {
        return Buffer.from(digestbytes);
    } else {
        return digestbytes;
    }
};

/**
 * Creates a vary length keyed Cube Hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @param {number?} outBits - length of hash (default 512 bit or 64 bytes)
 * @returns `string|Uint8Array|Buffer`
 */
export function CUBEHASH_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType(), outBits: 224|256|384|512 = 512) {
    var hash;
    if(outBits == 224){
        hash = new CubeHash224();
    } else if(outBits == 256){
        hash = new CubeHash256();
    } else if(outBits == 384){
        hash = new CubeHash384();
    } else {
        hash = new CubeHash512();
    }
    const mac = new HMAC(hash, formatMessage(key));
    mac.update(formatMessage(message));
    const digestbytes = mac.digest();
    if (format === "hex") {
        return bytesToHex(digestbytes);
    } else if (format === "buffer") {
        return Buffer.from(digestbytes);
    } else {
        return digestbytes;
    }
};

/**
 * Creates a 28 byte Cube Hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function CUBEHASH224(message: InputData, format: OutputFormat = arrayType()) {
    const hash = new CubeHash224();
    hash.update(formatMessage(message));
    const digestbytes = hash.digest();
    if (format === "hex") {
        return bytesToHex(digestbytes);
    } else if (format === "buffer") {
        return Buffer.from(digestbytes);
    } else {
        return digestbytes;
    }
}

/**
 * Creates a 28 byte keyed Cube Hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function CUBEHASH224_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType()) {
    const hash = new CubeHash224();
    const mac = new HMAC(hash, formatMessage(key));
    mac.update(formatMessage(message));
    const digestbytes = mac.digest();
    if (format === "hex") {
        return bytesToHex(digestbytes);
    } else if (format === "buffer") {
        return Buffer.from(digestbytes);
    } else {
        return digestbytes;
    }
};

/**
 * Creates a 32 byte Cube Hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function CUBEHASH256(message: InputData, format: OutputFormat = arrayType()) {
    const hash = new CubeHash256();
    hash.update(formatMessage(message));
    const digestbytes = hash.digest();
    if (format === "hex") {
        return bytesToHex(digestbytes);
    } else if (format === "buffer") {
        return Buffer.from(digestbytes);
    } else {
        return digestbytes;
    }
};

/**
 * Creates a 32 byte keyed Cube Hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function CUBEHASH256_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType()) {
    const hash = new CubeHash256();
    const mac = new HMAC(hash, formatMessage(key));
    mac.update(formatMessage(message));
    const digestbytes = mac.digest();
    if (format === "hex") {
        return bytesToHex(digestbytes);
    } else if (format === "buffer") {
        return Buffer.from(digestbytes);
    } else {
        return digestbytes;
    }
};

/**
 * Creates a 48 byte Cube Hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function CUBEHASH384(message: InputData, format: OutputFormat = arrayType()) {
    const hash = new CubeHash384();
    hash.update(formatMessage(message));
    const digestbytes = hash.digest();
    if (format === "hex") {
        return bytesToHex(digestbytes);
    } else if (format === "buffer") {
        return Buffer.from(digestbytes);
    } else {
        return digestbytes;
    }
};

/**
 * Creates a 48 byte keyed Cube Hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function CUBEHASH384_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType()) {
    const hash = new CubeHash384();
    const mac = new HMAC(hash, formatMessage(key));
    mac.update(formatMessage(message));
    const digestbytes = mac.digest();
    if (format === "hex") {
        return bytesToHex(digestbytes);
    } else if (format === "buffer") {
        return Buffer.from(digestbytes);
    } else {
        return digestbytes;
    }
};

/**
 * Creates a 64 byte Cube Hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function CUBEHASH512(message: InputData, format: OutputFormat = arrayType()) {
    const hash = new CubeHash512();
    hash.update(formatMessage(message));
    const digestbytes = hash.digest();
    if (format === "hex") {
        return bytesToHex(digestbytes);
    } else if (format === "buffer") {
        return Buffer.from(digestbytes);
    } else {
        return digestbytes;
    }
}

/**
 * Creates a 64 byte keyed Cube Hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function CUBEHASH512_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType()) {
    const hash = new CubeHash512();
    const mac = new HMAC(hash, formatMessage(key));
    mac.update(formatMessage(message));
    const digestbytes = mac.digest();
    if (format === "hex") {
        return bytesToHex(digestbytes);
    } else if (format === "buffer") {
        return Buffer.from(digestbytes);
    } else {
        return digestbytes;
    }
};

// Input types
type InputData = string | Uint8Array | Buffer;

// Output formats
type OutputFormat = 'hex' | 'array' | 'buffer';

/**
 * Static class of all Cube Hash functions
 */
export class CUBEHASH{
    static CUBEHASH = _CUBEHASH;
    static CUBEHASH_HMAC = CUBEHASH_HMAC;
    static CubeHash224 = CubeHash224;
    static CUBEHASH224 = CUBEHASH224;
    static CUBEHASH224_HMAC = CUBEHASH224_HMAC;
    static CubeHash256 = CubeHash256;
    static CUBEHASH256 = CUBEHASH256;
    static CUBEHASH256_HMAC = CUBEHASH256_HMAC;
    static CubeHash384 = CubeHash384;
    static CUBEHASH384 = CUBEHASH384;
    static CUBEHASH384_HMAC = CUBEHASH384_HMAC;
    static CubeHash512 = CubeHash512;
    static CUBEHASH512_HMAC = CUBEHASH512_HMAC;
    static CUBEHASH512 = CUBEHASH512;
    /**
     * List of all hashes in class
     */
    static get FUNCTION_LIST(){
        return [
            "CUBEHASH",
            "CUBEHASH_HMAC",
            "CUBEHASH224",
            "CUBEHASH224_HMAC",
            "CUBEHASH256",
            "CUBEHASH256_HMAC",
            "CUBEHASH384",
            "CUBEHASH384_HMAC",
            "CUBEHASH512",
            "CUBEHASH512_HMAC",
        ];
    }
}