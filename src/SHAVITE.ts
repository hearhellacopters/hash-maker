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
    src: Int32Array | Uint8Array | Uint16Array | Uint32Array | Float32Array | Uint8ClampedArray,
    srcPos: number = 0,
    dst: Int32Array | Uint8Array | Uint16Array | Uint32Array | Float32Array | Uint8ClampedArray,
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
 * This class implements SHAvite-224 and SHAvite-256.
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
 * @version   $Revision: 222 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

abstract class SHAviteSmallCore extends DigestEngine {

	private h!: Int32Array;
    private rk!: Int32Array;

	/**
	 * Create the object.
	 */
	constructor()
	{
		super();
	}

	private static AES0 = new Int32Array([
		0xA56363C6, 0x847C7CF8, 0x997777EE, 0x8D7B7BF6,
		0x0DF2F2FF, 0xBD6B6BD6, 0xB16F6FDE, 0x54C5C591,
		0x50303060, 0x03010102, 0xA96767CE, 0x7D2B2B56,
		0x19FEFEE7, 0x62D7D7B5, 0xE6ABAB4D, 0x9A7676EC,
		0x45CACA8F, 0x9D82821F, 0x40C9C989, 0x877D7DFA,
		0x15FAFAEF, 0xEB5959B2, 0xC947478E, 0x0BF0F0FB,
		0xECADAD41, 0x67D4D4B3, 0xFDA2A25F, 0xEAAFAF45,
		0xBF9C9C23, 0xF7A4A453, 0x967272E4, 0x5BC0C09B,
		0xC2B7B775, 0x1CFDFDE1, 0xAE93933D, 0x6A26264C,
		0x5A36366C, 0x413F3F7E, 0x02F7F7F5, 0x4FCCCC83,
		0x5C343468, 0xF4A5A551, 0x34E5E5D1, 0x08F1F1F9,
		0x937171E2, 0x73D8D8AB, 0x53313162, 0x3F15152A,
		0x0C040408, 0x52C7C795, 0x65232346, 0x5EC3C39D,
		0x28181830, 0xA1969637, 0x0F05050A, 0xB59A9A2F,
		0x0907070E, 0x36121224, 0x9B80801B, 0x3DE2E2DF,
		0x26EBEBCD, 0x6927274E, 0xCDB2B27F, 0x9F7575EA,
		0x1B090912, 0x9E83831D, 0x742C2C58, 0x2E1A1A34,
		0x2D1B1B36, 0xB26E6EDC, 0xEE5A5AB4, 0xFBA0A05B,
		0xF65252A4, 0x4D3B3B76, 0x61D6D6B7, 0xCEB3B37D,
		0x7B292952, 0x3EE3E3DD, 0x712F2F5E, 0x97848413,
		0xF55353A6, 0x68D1D1B9, 0x00000000, 0x2CEDEDC1,
		0x60202040, 0x1FFCFCE3, 0xC8B1B179, 0xED5B5BB6,
		0xBE6A6AD4, 0x46CBCB8D, 0xD9BEBE67, 0x4B393972,
		0xDE4A4A94, 0xD44C4C98, 0xE85858B0, 0x4ACFCF85,
		0x6BD0D0BB, 0x2AEFEFC5, 0xE5AAAA4F, 0x16FBFBED,
		0xC5434386, 0xD74D4D9A, 0x55333366, 0x94858511,
		0xCF45458A, 0x10F9F9E9, 0x06020204, 0x817F7FFE,
		0xF05050A0, 0x443C3C78, 0xBA9F9F25, 0xE3A8A84B,
		0xF35151A2, 0xFEA3A35D, 0xC0404080, 0x8A8F8F05,
		0xAD92923F, 0xBC9D9D21, 0x48383870, 0x04F5F5F1,
		0xDFBCBC63, 0xC1B6B677, 0x75DADAAF, 0x63212142,
		0x30101020, 0x1AFFFFE5, 0x0EF3F3FD, 0x6DD2D2BF,
		0x4CCDCD81, 0x140C0C18, 0x35131326, 0x2FECECC3,
		0xE15F5FBE, 0xA2979735, 0xCC444488, 0x3917172E,
		0x57C4C493, 0xF2A7A755, 0x827E7EFC, 0x473D3D7A,
		0xAC6464C8, 0xE75D5DBA, 0x2B191932, 0x957373E6,
		0xA06060C0, 0x98818119, 0xD14F4F9E, 0x7FDCDCA3,
		0x66222244, 0x7E2A2A54, 0xAB90903B, 0x8388880B,
		0xCA46468C, 0x29EEEEC7, 0xD3B8B86B, 0x3C141428,
		0x79DEDEA7, 0xE25E5EBC, 0x1D0B0B16, 0x76DBDBAD,
		0x3BE0E0DB, 0x56323264, 0x4E3A3A74, 0x1E0A0A14,
		0xDB494992, 0x0A06060C, 0x6C242448, 0xE45C5CB8,
		0x5DC2C29F, 0x6ED3D3BD, 0xEFACAC43, 0xA66262C4,
		0xA8919139, 0xA4959531, 0x37E4E4D3, 0x8B7979F2,
		0x32E7E7D5, 0x43C8C88B, 0x5937376E, 0xB76D6DDA,
		0x8C8D8D01, 0x64D5D5B1, 0xD24E4E9C, 0xE0A9A949,
		0xB46C6CD8, 0xFA5656AC, 0x07F4F4F3, 0x25EAEACF,
		0xAF6565CA, 0x8E7A7AF4, 0xE9AEAE47, 0x18080810,
		0xD5BABA6F, 0x887878F0, 0x6F25254A, 0x722E2E5C,
		0x241C1C38, 0xF1A6A657, 0xC7B4B473, 0x51C6C697,
		0x23E8E8CB, 0x7CDDDDA1, 0x9C7474E8, 0x211F1F3E,
		0xDD4B4B96, 0xDCBDBD61, 0x868B8B0D, 0x858A8A0F,
		0x907070E0, 0x423E3E7C, 0xC4B5B571, 0xAA6666CC,
		0xD8484890, 0x05030306, 0x01F6F6F7, 0x120E0E1C,
		0xA36161C2, 0x5F35356A, 0xF95757AE, 0xD0B9B969,
		0x91868617, 0x58C1C199, 0x271D1D3A, 0xB99E9E27,
		0x38E1E1D9, 0x13F8F8EB, 0xB398982B, 0x33111122,
		0xBB6969D2, 0x70D9D9A9, 0x898E8E07, 0xA7949433,
		0xB69B9B2D, 0x221E1E3C, 0x92878715, 0x20E9E9C9,
		0x49CECE87, 0xFF5555AA, 0x78282850, 0x7ADFDFA5,
		0x8F8C8C03, 0xF8A1A159, 0x80898909, 0x170D0D1A,
		0xDABFBF65, 0x31E6E6D7, 0xC6424284, 0xB86868D0,
		0xC3414182, 0xB0999929, 0x772D2D5A, 0x110F0F1E,
		0xCBB0B07B, 0xFC5454A8, 0xD6BBBB6D, 0x3A16162C
	]);

	private static AES1 = new Int32Array([
		0x6363C6A5, 0x7C7CF884, 0x7777EE99, 0x7B7BF68D,
		0xF2F2FF0D, 0x6B6BD6BD, 0x6F6FDEB1, 0xC5C59154,
		0x30306050, 0x01010203, 0x6767CEA9, 0x2B2B567D,
		0xFEFEE719, 0xD7D7B562, 0xABAB4DE6, 0x7676EC9A,
		0xCACA8F45, 0x82821F9D, 0xC9C98940, 0x7D7DFA87,
		0xFAFAEF15, 0x5959B2EB, 0x47478EC9, 0xF0F0FB0B,
		0xADAD41EC, 0xD4D4B367, 0xA2A25FFD, 0xAFAF45EA,
		0x9C9C23BF, 0xA4A453F7, 0x7272E496, 0xC0C09B5B,
		0xB7B775C2, 0xFDFDE11C, 0x93933DAE, 0x26264C6A,
		0x36366C5A, 0x3F3F7E41, 0xF7F7F502, 0xCCCC834F,
		0x3434685C, 0xA5A551F4, 0xE5E5D134, 0xF1F1F908,
		0x7171E293, 0xD8D8AB73, 0x31316253, 0x15152A3F,
		0x0404080C, 0xC7C79552, 0x23234665, 0xC3C39D5E,
		0x18183028, 0x969637A1, 0x05050A0F, 0x9A9A2FB5,
		0x07070E09, 0x12122436, 0x80801B9B, 0xE2E2DF3D,
		0xEBEBCD26, 0x27274E69, 0xB2B27FCD, 0x7575EA9F,
		0x0909121B, 0x83831D9E, 0x2C2C5874, 0x1A1A342E,
		0x1B1B362D, 0x6E6EDCB2, 0x5A5AB4EE, 0xA0A05BFB,
		0x5252A4F6, 0x3B3B764D, 0xD6D6B761, 0xB3B37DCE,
		0x2929527B, 0xE3E3DD3E, 0x2F2F5E71, 0x84841397,
		0x5353A6F5, 0xD1D1B968, 0x00000000, 0xEDEDC12C,
		0x20204060, 0xFCFCE31F, 0xB1B179C8, 0x5B5BB6ED,
		0x6A6AD4BE, 0xCBCB8D46, 0xBEBE67D9, 0x3939724B,
		0x4A4A94DE, 0x4C4C98D4, 0x5858B0E8, 0xCFCF854A,
		0xD0D0BB6B, 0xEFEFC52A, 0xAAAA4FE5, 0xFBFBED16,
		0x434386C5, 0x4D4D9AD7, 0x33336655, 0x85851194,
		0x45458ACF, 0xF9F9E910, 0x02020406, 0x7F7FFE81,
		0x5050A0F0, 0x3C3C7844, 0x9F9F25BA, 0xA8A84BE3,
		0x5151A2F3, 0xA3A35DFE, 0x404080C0, 0x8F8F058A,
		0x92923FAD, 0x9D9D21BC, 0x38387048, 0xF5F5F104,
		0xBCBC63DF, 0xB6B677C1, 0xDADAAF75, 0x21214263,
		0x10102030, 0xFFFFE51A, 0xF3F3FD0E, 0xD2D2BF6D,
		0xCDCD814C, 0x0C0C1814, 0x13132635, 0xECECC32F,
		0x5F5FBEE1, 0x979735A2, 0x444488CC, 0x17172E39,
		0xC4C49357, 0xA7A755F2, 0x7E7EFC82, 0x3D3D7A47,
		0x6464C8AC, 0x5D5DBAE7, 0x1919322B, 0x7373E695,
		0x6060C0A0, 0x81811998, 0x4F4F9ED1, 0xDCDCA37F,
		0x22224466, 0x2A2A547E, 0x90903BAB, 0x88880B83,
		0x46468CCA, 0xEEEEC729, 0xB8B86BD3, 0x1414283C,
		0xDEDEA779, 0x5E5EBCE2, 0x0B0B161D, 0xDBDBAD76,
		0xE0E0DB3B, 0x32326456, 0x3A3A744E, 0x0A0A141E,
		0x494992DB, 0x06060C0A, 0x2424486C, 0x5C5CB8E4,
		0xC2C29F5D, 0xD3D3BD6E, 0xACAC43EF, 0x6262C4A6,
		0x919139A8, 0x959531A4, 0xE4E4D337, 0x7979F28B,
		0xE7E7D532, 0xC8C88B43, 0x37376E59, 0x6D6DDAB7,
		0x8D8D018C, 0xD5D5B164, 0x4E4E9CD2, 0xA9A949E0,
		0x6C6CD8B4, 0x5656ACFA, 0xF4F4F307, 0xEAEACF25,
		0x6565CAAF, 0x7A7AF48E, 0xAEAE47E9, 0x08081018,
		0xBABA6FD5, 0x7878F088, 0x25254A6F, 0x2E2E5C72,
		0x1C1C3824, 0xA6A657F1, 0xB4B473C7, 0xC6C69751,
		0xE8E8CB23, 0xDDDDA17C, 0x7474E89C, 0x1F1F3E21,
		0x4B4B96DD, 0xBDBD61DC, 0x8B8B0D86, 0x8A8A0F85,
		0x7070E090, 0x3E3E7C42, 0xB5B571C4, 0x6666CCAA,
		0x484890D8, 0x03030605, 0xF6F6F701, 0x0E0E1C12,
		0x6161C2A3, 0x35356A5F, 0x5757AEF9, 0xB9B969D0,
		0x86861791, 0xC1C19958, 0x1D1D3A27, 0x9E9E27B9,
		0xE1E1D938, 0xF8F8EB13, 0x98982BB3, 0x11112233,
		0x6969D2BB, 0xD9D9A970, 0x8E8E0789, 0x949433A7,
		0x9B9B2DB6, 0x1E1E3C22, 0x87871592, 0xE9E9C920,
		0xCECE8749, 0x5555AAFF, 0x28285078, 0xDFDFA57A,
		0x8C8C038F, 0xA1A159F8, 0x89890980, 0x0D0D1A17,
		0xBFBF65DA, 0xE6E6D731, 0x424284C6, 0x6868D0B8,
		0x414182C3, 0x999929B0, 0x2D2D5A77, 0x0F0F1E11,
		0xB0B07BCB, 0x5454A8FC, 0xBBBB6DD6, 0x16162C3A
	]);

	private static AES2 = new Int32Array([
		0x63C6A563, 0x7CF8847C, 0x77EE9977, 0x7BF68D7B,
		0xF2FF0DF2, 0x6BD6BD6B, 0x6FDEB16F, 0xC59154C5,
		0x30605030, 0x01020301, 0x67CEA967, 0x2B567D2B,
		0xFEE719FE, 0xD7B562D7, 0xAB4DE6AB, 0x76EC9A76,
		0xCA8F45CA, 0x821F9D82, 0xC98940C9, 0x7DFA877D,
		0xFAEF15FA, 0x59B2EB59, 0x478EC947, 0xF0FB0BF0,
		0xAD41ECAD, 0xD4B367D4, 0xA25FFDA2, 0xAF45EAAF,
		0x9C23BF9C, 0xA453F7A4, 0x72E49672, 0xC09B5BC0,
		0xB775C2B7, 0xFDE11CFD, 0x933DAE93, 0x264C6A26,
		0x366C5A36, 0x3F7E413F, 0xF7F502F7, 0xCC834FCC,
		0x34685C34, 0xA551F4A5, 0xE5D134E5, 0xF1F908F1,
		0x71E29371, 0xD8AB73D8, 0x31625331, 0x152A3F15,
		0x04080C04, 0xC79552C7, 0x23466523, 0xC39D5EC3,
		0x18302818, 0x9637A196, 0x050A0F05, 0x9A2FB59A,
		0x070E0907, 0x12243612, 0x801B9B80, 0xE2DF3DE2,
		0xEBCD26EB, 0x274E6927, 0xB27FCDB2, 0x75EA9F75,
		0x09121B09, 0x831D9E83, 0x2C58742C, 0x1A342E1A,
		0x1B362D1B, 0x6EDCB26E, 0x5AB4EE5A, 0xA05BFBA0,
		0x52A4F652, 0x3B764D3B, 0xD6B761D6, 0xB37DCEB3,
		0x29527B29, 0xE3DD3EE3, 0x2F5E712F, 0x84139784,
		0x53A6F553, 0xD1B968D1, 0x00000000, 0xEDC12CED,
		0x20406020, 0xFCE31FFC, 0xB179C8B1, 0x5BB6ED5B,
		0x6AD4BE6A, 0xCB8D46CB, 0xBE67D9BE, 0x39724B39,
		0x4A94DE4A, 0x4C98D44C, 0x58B0E858, 0xCF854ACF,
		0xD0BB6BD0, 0xEFC52AEF, 0xAA4FE5AA, 0xFBED16FB,
		0x4386C543, 0x4D9AD74D, 0x33665533, 0x85119485,
		0x458ACF45, 0xF9E910F9, 0x02040602, 0x7FFE817F,
		0x50A0F050, 0x3C78443C, 0x9F25BA9F, 0xA84BE3A8,
		0x51A2F351, 0xA35DFEA3, 0x4080C040, 0x8F058A8F,
		0x923FAD92, 0x9D21BC9D, 0x38704838, 0xF5F104F5,
		0xBC63DFBC, 0xB677C1B6, 0xDAAF75DA, 0x21426321,
		0x10203010, 0xFFE51AFF, 0xF3FD0EF3, 0xD2BF6DD2,
		0xCD814CCD, 0x0C18140C, 0x13263513, 0xECC32FEC,
		0x5FBEE15F, 0x9735A297, 0x4488CC44, 0x172E3917,
		0xC49357C4, 0xA755F2A7, 0x7EFC827E, 0x3D7A473D,
		0x64C8AC64, 0x5DBAE75D, 0x19322B19, 0x73E69573,
		0x60C0A060, 0x81199881, 0x4F9ED14F, 0xDCA37FDC,
		0x22446622, 0x2A547E2A, 0x903BAB90, 0x880B8388,
		0x468CCA46, 0xEEC729EE, 0xB86BD3B8, 0x14283C14,
		0xDEA779DE, 0x5EBCE25E, 0x0B161D0B, 0xDBAD76DB,
		0xE0DB3BE0, 0x32645632, 0x3A744E3A, 0x0A141E0A,
		0x4992DB49, 0x060C0A06, 0x24486C24, 0x5CB8E45C,
		0xC29F5DC2, 0xD3BD6ED3, 0xAC43EFAC, 0x62C4A662,
		0x9139A891, 0x9531A495, 0xE4D337E4, 0x79F28B79,
		0xE7D532E7, 0xC88B43C8, 0x376E5937, 0x6DDAB76D,
		0x8D018C8D, 0xD5B164D5, 0x4E9CD24E, 0xA949E0A9,
		0x6CD8B46C, 0x56ACFA56, 0xF4F307F4, 0xEACF25EA,
		0x65CAAF65, 0x7AF48E7A, 0xAE47E9AE, 0x08101808,
		0xBA6FD5BA, 0x78F08878, 0x254A6F25, 0x2E5C722E,
		0x1C38241C, 0xA657F1A6, 0xB473C7B4, 0xC69751C6,
		0xE8CB23E8, 0xDDA17CDD, 0x74E89C74, 0x1F3E211F,
		0x4B96DD4B, 0xBD61DCBD, 0x8B0D868B, 0x8A0F858A,
		0x70E09070, 0x3E7C423E, 0xB571C4B5, 0x66CCAA66,
		0x4890D848, 0x03060503, 0xF6F701F6, 0x0E1C120E,
		0x61C2A361, 0x356A5F35, 0x57AEF957, 0xB969D0B9,
		0x86179186, 0xC19958C1, 0x1D3A271D, 0x9E27B99E,
		0xE1D938E1, 0xF8EB13F8, 0x982BB398, 0x11223311,
		0x69D2BB69, 0xD9A970D9, 0x8E07898E, 0x9433A794,
		0x9B2DB69B, 0x1E3C221E, 0x87159287, 0xE9C920E9,
		0xCE8749CE, 0x55AAFF55, 0x28507828, 0xDFA57ADF,
		0x8C038F8C, 0xA159F8A1, 0x89098089, 0x0D1A170D,
		0xBF65DABF, 0xE6D731E6, 0x4284C642, 0x68D0B868,
		0x4182C341, 0x9929B099, 0x2D5A772D, 0x0F1E110F,
		0xB07BCBB0, 0x54A8FC54, 0xBB6DD6BB, 0x162C3A16
	]);

	private static AES3 = new Int32Array([
		0xC6A56363, 0xF8847C7C, 0xEE997777, 0xF68D7B7B,
		0xFF0DF2F2, 0xD6BD6B6B, 0xDEB16F6F, 0x9154C5C5,
		0x60503030, 0x02030101, 0xCEA96767, 0x567D2B2B,
		0xE719FEFE, 0xB562D7D7, 0x4DE6ABAB, 0xEC9A7676,
		0x8F45CACA, 0x1F9D8282, 0x8940C9C9, 0xFA877D7D,
		0xEF15FAFA, 0xB2EB5959, 0x8EC94747, 0xFB0BF0F0,
		0x41ECADAD, 0xB367D4D4, 0x5FFDA2A2, 0x45EAAFAF,
		0x23BF9C9C, 0x53F7A4A4, 0xE4967272, 0x9B5BC0C0,
		0x75C2B7B7, 0xE11CFDFD, 0x3DAE9393, 0x4C6A2626,
		0x6C5A3636, 0x7E413F3F, 0xF502F7F7, 0x834FCCCC,
		0x685C3434, 0x51F4A5A5, 0xD134E5E5, 0xF908F1F1,
		0xE2937171, 0xAB73D8D8, 0x62533131, 0x2A3F1515,
		0x080C0404, 0x9552C7C7, 0x46652323, 0x9D5EC3C3,
		0x30281818, 0x37A19696, 0x0A0F0505, 0x2FB59A9A,
		0x0E090707, 0x24361212, 0x1B9B8080, 0xDF3DE2E2,
		0xCD26EBEB, 0x4E692727, 0x7FCDB2B2, 0xEA9F7575,
		0x121B0909, 0x1D9E8383, 0x58742C2C, 0x342E1A1A,
		0x362D1B1B, 0xDCB26E6E, 0xB4EE5A5A, 0x5BFBA0A0,
		0xA4F65252, 0x764D3B3B, 0xB761D6D6, 0x7DCEB3B3,
		0x527B2929, 0xDD3EE3E3, 0x5E712F2F, 0x13978484,
		0xA6F55353, 0xB968D1D1, 0x00000000, 0xC12CEDED,
		0x40602020, 0xE31FFCFC, 0x79C8B1B1, 0xB6ED5B5B,
		0xD4BE6A6A, 0x8D46CBCB, 0x67D9BEBE, 0x724B3939,
		0x94DE4A4A, 0x98D44C4C, 0xB0E85858, 0x854ACFCF,
		0xBB6BD0D0, 0xC52AEFEF, 0x4FE5AAAA, 0xED16FBFB,
		0x86C54343, 0x9AD74D4D, 0x66553333, 0x11948585,
		0x8ACF4545, 0xE910F9F9, 0x04060202, 0xFE817F7F,
		0xA0F05050, 0x78443C3C, 0x25BA9F9F, 0x4BE3A8A8,
		0xA2F35151, 0x5DFEA3A3, 0x80C04040, 0x058A8F8F,
		0x3FAD9292, 0x21BC9D9D, 0x70483838, 0xF104F5F5,
		0x63DFBCBC, 0x77C1B6B6, 0xAF75DADA, 0x42632121,
		0x20301010, 0xE51AFFFF, 0xFD0EF3F3, 0xBF6DD2D2,
		0x814CCDCD, 0x18140C0C, 0x26351313, 0xC32FECEC,
		0xBEE15F5F, 0x35A29797, 0x88CC4444, 0x2E391717,
		0x9357C4C4, 0x55F2A7A7, 0xFC827E7E, 0x7A473D3D,
		0xC8AC6464, 0xBAE75D5D, 0x322B1919, 0xE6957373,
		0xC0A06060, 0x19988181, 0x9ED14F4F, 0xA37FDCDC,
		0x44662222, 0x547E2A2A, 0x3BAB9090, 0x0B838888,
		0x8CCA4646, 0xC729EEEE, 0x6BD3B8B8, 0x283C1414,
		0xA779DEDE, 0xBCE25E5E, 0x161D0B0B, 0xAD76DBDB,
		0xDB3BE0E0, 0x64563232, 0x744E3A3A, 0x141E0A0A,
		0x92DB4949, 0x0C0A0606, 0x486C2424, 0xB8E45C5C,
		0x9F5DC2C2, 0xBD6ED3D3, 0x43EFACAC, 0xC4A66262,
		0x39A89191, 0x31A49595, 0xD337E4E4, 0xF28B7979,
		0xD532E7E7, 0x8B43C8C8, 0x6E593737, 0xDAB76D6D,
		0x018C8D8D, 0xB164D5D5, 0x9CD24E4E, 0x49E0A9A9,
		0xD8B46C6C, 0xACFA5656, 0xF307F4F4, 0xCF25EAEA,
		0xCAAF6565, 0xF48E7A7A, 0x47E9AEAE, 0x10180808,
		0x6FD5BABA, 0xF0887878, 0x4A6F2525, 0x5C722E2E,
		0x38241C1C, 0x57F1A6A6, 0x73C7B4B4, 0x9751C6C6,
		0xCB23E8E8, 0xA17CDDDD, 0xE89C7474, 0x3E211F1F,
		0x96DD4B4B, 0x61DCBDBD, 0x0D868B8B, 0x0F858A8A,
		0xE0907070, 0x7C423E3E, 0x71C4B5B5, 0xCCAA6666,
		0x90D84848, 0x06050303, 0xF701F6F6, 0x1C120E0E,
		0xC2A36161, 0x6A5F3535, 0xAEF95757, 0x69D0B9B9,
		0x17918686, 0x9958C1C1, 0x3A271D1D, 0x27B99E9E,
		0xD938E1E1, 0xEB13F8F8, 0x2BB39898, 0x22331111,
		0xD2BB6969, 0xA970D9D9, 0x07898E8E, 0x33A79494,
		0x2DB69B9B, 0x3C221E1E, 0x15928787, 0xC920E9E9,
		0x8749CECE, 0xAAFF5555, 0x50782828, 0xA57ADFDF,
		0x038F8C8C, 0x59F8A1A1, 0x09808989, 0x1A170D0D,
		0x65DABFBF, 0xD731E6E6, 0x84C64242, 0xD0B86868,
		0x82C34141, 0x29B09999, 0x5A772D2D, 0x1E110F0F,
		0x7BCBB0B0, 0xA8FC5454, 0x6DD6BBBB, 0x2C3A1616
	]);

	/** @see Digest */
	public getBlockLength()
	{
		return 64;
	}

	/** @see DigestEngine */
	protected copyState<T>(dst: SHAviteSmallCore): T
	{
		arraycopy(this.h, 0, dst.h, 0, this.h.length);
		return super.copyState(dst) as T;
	}

	/** @see DigestEngine */
	protected  engineReset()
	{
		arraycopy(this.getInitVal(), 0, this.h, 0, this.h.length);
	}

	/**
	 * Get the initial value for this algorithm.
	 *
	 * @return  the initial value
	 */
	abstract getInitVal(): Int32Array;

	/** @see DigestEngine */
	protected doPadding( output:Uint8Array, outputOffset:number)
	{
		var ptr = this.flush();
		var bc = this.getBlockCount();
		var bitLen = (bc << BigInt(9)) + BigInt(ptr << 3);
		var cnt0 = Number(bitLen);
		var cnt1 = Number(lshr(bitLen, 32));
		const buf = this.getBlockBuffer();
		if (ptr == 0) {
			buf[0] = 0x80;
			for (let i = 1; i < 54; i ++){
				buf[i] = 0;
			}
			cnt0 = cnt1 = 0;
		} else if (ptr < 54) {
			buf[ptr++] = 0x80;
			while (ptr < 54){
				buf[ptr++] = 0;
			}
		} else {
			buf[ptr++] = 0x80;
			while (ptr < 64){
				buf[ptr++] = 0;
			}
			this.process(buf, cnt0, cnt1);
			for (let i = 0; i < 54; i ++){
				buf[i] = 0;
			}
			cnt0 = cnt1 = 0;
		}
		this.encodeLEInt(Number(bitLen), buf, 54);
		this.encodeLEInt(Number(bitLen >> BigInt(32)), buf, 58);
		var dlen = this.getDigestLength();
		buf[62] = (dlen << 3);
		buf[63] = (dlen >>> 5);
		this.process(buf, cnt0, cnt1);
		for (let i = 0; i < dlen; i += 4){
			this.encodeLEInt(this.h[i >>> 2], output, outputOffset + i);
		}
	}

	/** @see DigestEngine */
	protected doInit()
	{
		this.h = new Int32Array(8);
		this.rk = new Int32Array(144);
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
	private encodeLEInt(val:number, buf:Uint8Array, off:number)
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
	private decodeLEInt(buf:Uint8Array, off:number)
	{
		return (buf[off] & 0xFF)
			| ((buf[off + 1] & 0xFF) << 8)
			| ((buf[off + 2] & 0xFF) << 16)
			| ((buf[off + 3] & 0xFF) << 24);
	}

	/** @see DigestEngine */
	protected processBlock(data:Uint8Array)
	{
		var bitLen = BigInt(this.getBlockCount() + BigInt(1)) << BigInt(9);
		this.process(data, Number(bitLen), Number(lshr(bitLen, 32)));
	}

	private process(data:Uint8Array, cnt0:number, cnt1:number)
	{
		const p = new Int32Array(8);
		const x = new Int32Array(4);
		const t = new Int32Array(4);
		var u;

		for (u = 0; u < 16; u += 4) {
			this.rk[u + 0] = this.decodeLEInt(data, (u << 2) +  0);
			this.rk[u + 1] = this.decodeLEInt(data, (u << 2) +  4);
			this.rk[u + 2] = this.decodeLEInt(data, (u << 2) +  8);
			this.rk[u + 3] = this.decodeLEInt(data, (u << 2) + 12);
		}
		for (let r = 0; r < 4; r ++) {
			for (let s = 0; s < 2; s ++) {
				x[0] = this.rk[u - 15];
				x[1] = this.rk[u - 14];
				x[2] = this.rk[u - 13];
				x[3] = this.rk[u - 16];
				t[0] =  SHAviteSmallCore.AES0[x[0] & 0xFF]
					^ SHAviteSmallCore.AES1[(x[1] >>> 8) & 0xFF]
					^ SHAviteSmallCore.AES2[(x[2] >>> 16) & 0xFF]
					^ SHAviteSmallCore.AES3[x[3] >>> 24];
				t[1] =  SHAviteSmallCore.AES0[x[1] & 0xFF]
					^ SHAviteSmallCore.AES1[(x[2] >>> 8) & 0xFF]
					^ SHAviteSmallCore.AES2[(x[3] >>> 16) & 0xFF]
					^ SHAviteSmallCore.AES3[x[0] >>> 24];
				t[2] =  SHAviteSmallCore.AES0[x[2] & 0xFF]
					^ SHAviteSmallCore.AES1[(x[3] >>> 8) & 0xFF]
					^ SHAviteSmallCore.AES2[(x[0] >>> 16) & 0xFF]
					^ SHAviteSmallCore.AES3[x[1] >>> 24];
				t[3] =  SHAviteSmallCore.AES0[x[3] & 0xFF]
					^ SHAviteSmallCore.AES1[(x[0] >>> 8) & 0xFF]
					^ SHAviteSmallCore.AES2[(x[1] >>> 16) & 0xFF]
					^ SHAviteSmallCore.AES3[x[2] >>> 24];
				this.rk[u + 0] = t[0] ^ this.rk[u - 4];
				this.rk[u + 1] = t[1] ^ this.rk[u - 3];
				this.rk[u + 2] = t[2] ^ this.rk[u - 2];
				this.rk[u + 3] = t[3] ^ this.rk[u - 1];
				if (u == 16) {
					this.rk[ 16] ^= cnt0;
					this.rk[ 17] ^= ~cnt1;
				} else if (u == 56) {
					this.rk[ 57] ^= cnt1;
					this.rk[ 58] ^= ~cnt0;
				}
				u += 4;

				x[0] = this.rk[u - 15];
				x[1] = this.rk[u - 14];
				x[2] = this.rk[u - 13];
				x[3] = this.rk[u - 16];
				t[0] = SHAviteSmallCore.AES0[x[0] & 0xFF]
					^  SHAviteSmallCore.AES1[(x[1] >>> 8) & 0xFF]
					^  SHAviteSmallCore.AES2[(x[2] >>> 16) & 0xFF]
					^  SHAviteSmallCore.AES3[x[3] >>> 24];
				t[1] =   SHAviteSmallCore.AES0[x[1] & 0xFF]
					^  SHAviteSmallCore.AES1[(x[2] >>> 8) & 0xFF]
					^  SHAviteSmallCore.AES2[(x[3] >>> 16) & 0xFF]
					^  SHAviteSmallCore.AES3[x[0] >>> 24];
				t[2] =   SHAviteSmallCore.AES0[x[2] & 0xFF]
					^  SHAviteSmallCore.AES1[(x[3] >>> 8) & 0xFF]
					^  SHAviteSmallCore.AES2[(x[0] >>> 16) & 0xFF]
					^  SHAviteSmallCore.AES3[x[1] >>> 24];
				t[3] =   SHAviteSmallCore.AES0[x[3] & 0xFF]
					^  SHAviteSmallCore.AES1[(x[0] >>> 8) & 0xFF]
					^  SHAviteSmallCore.AES2[(x[1] >>> 16) & 0xFF]
					^  SHAviteSmallCore.AES3[x[2] >>> 24];
				this.rk[u + 0] = t[0] ^ this.rk[u - 4];
				this.rk[u + 1] = t[1] ^ this.rk[u - 3];
				this.rk[u + 2] = t[2] ^ this.rk[u - 2];
				this.rk[u + 3] = t[3] ^ this.rk[u - 1];
				if (u == 84) {
					this.rk[ 86] ^= cnt1;
					this.rk[ 87] ^= ~cnt0;
				} else if (u == 124) {
					this.rk[124] ^= cnt0;
					this.rk[127] ^= ~cnt1;
				}
				u += 4;
			}
			for (let s = 0; s < 4; s ++) {
				this.rk[u + 0] = this.rk[u - 16] ^ this.rk[u - 3];
				this.rk[u + 1] = this.rk[u - 15] ^ this.rk[u - 2];
				this.rk[u + 2] = this.rk[u - 14] ^ this.rk[u - 1];
				this.rk[u + 3] = this.rk[u - 13] ^ this.rk[u - 0];
				u += 4;
			}
		}

		p[0] = this.h[0x0];
		p[1] = this.h[0x1];
		p[2] = this.h[0x2];
		p[3] = this.h[0x3];
		p[4] = this.h[0x4];
		p[5] = this.h[0x5];
		p[6] = this.h[0x6];
		p[7] = this.h[0x7];
		u = 0;
		for (let r = 0; r < 6; r ++) {
			x[0] = p[4] ^ this.rk[u ++];
			x[1] = p[5] ^ this.rk[u ++];
			x[2] = p[6] ^ this.rk[u ++];
			x[3] = p[7] ^ this.rk[u ++];
			t[0] = SHAviteSmallCore.AES0[x[0] & 0xFF]
				^ SHAviteSmallCore.AES1[(x[1] >>> 8) & 0xFF]
				^ SHAviteSmallCore.AES2[(x[2] >>> 16) & 0xFF]
				^ SHAviteSmallCore.AES3[x[3] >>> 24];
			t[1] =  SHAviteSmallCore.AES0[x[1] & 0xFF]
				^ SHAviteSmallCore.AES1[(x[2] >>> 8) & 0xFF]
				^ SHAviteSmallCore.AES2[(x[3] >>> 16) & 0xFF]
				^ SHAviteSmallCore.AES3[x[0] >>> 24];
			t[2] =  SHAviteSmallCore.AES0[x[2] & 0xFF]
				^ SHAviteSmallCore.AES1[(x[3] >>> 8) & 0xFF]
				^ SHAviteSmallCore.AES2[(x[0] >>> 16) & 0xFF]
				^ SHAviteSmallCore.AES3[x[1] >>> 24];
			t[3] =  SHAviteSmallCore.AES0[x[3] & 0xFF]
				^ SHAviteSmallCore.AES1[(x[0] >>> 8) & 0xFF]
				^ SHAviteSmallCore.AES2[(x[1] >>> 16) & 0xFF]
				^ SHAviteSmallCore.AES3[x[2] >>> 24];
			x[0] = t[0] ^ this.rk[u ++];
			x[1] = t[1] ^ this.rk[u ++];
			x[2] = t[2] ^ this.rk[u ++];
			x[3] = t[3] ^ this.rk[u ++];
			t[0] = SHAviteSmallCore.AES0[x[0] & 0xFF]
				^  SHAviteSmallCore.AES1[(x[1] >>> 8) & 0xFF]
				^  SHAviteSmallCore.AES2[(x[2] >>> 16) & 0xFF]
				^  SHAviteSmallCore.AES3[x[3] >>> 24];
			t[1] =   SHAviteSmallCore.AES0[x[1] & 0xFF]
				^  SHAviteSmallCore.AES1[(x[2] >>> 8) & 0xFF]
				^  SHAviteSmallCore.AES2[(x[3] >>> 16) & 0xFF]
				^  SHAviteSmallCore.AES3[x[0] >>> 24];
			t[2] =   SHAviteSmallCore.AES0[x[2] & 0xFF]
				^  SHAviteSmallCore.AES1[(x[3] >>> 8) & 0xFF]
				^  SHAviteSmallCore.AES2[(x[0] >>> 16) & 0xFF]
				^  SHAviteSmallCore.AES3[x[1] >>> 24];
			t[3] =   SHAviteSmallCore.AES0[x[3] & 0xFF]
				^  SHAviteSmallCore.AES1[(x[0] >>> 8) & 0xFF]
				^  SHAviteSmallCore.AES2[(x[1] >>> 16) & 0xFF]
				^  SHAviteSmallCore.AES3[x[2] >>> 24];
			x[0] = t[0] ^ this.rk[u ++];
			x[1] = t[1] ^ this.rk[u ++];
			x[2] = t[2] ^ this.rk[u ++];
			x[3] = t[3] ^ this.rk[u ++];
			t[0] = SHAviteSmallCore.AES0[x[0] & 0xFF]
				^  SHAviteSmallCore.AES1[(x[1] >>> 8) & 0xFF]
				^  SHAviteSmallCore.AES2[(x[2] >>> 16) & 0xFF]
				^  SHAviteSmallCore.AES3[x[3] >>> 24];
			t[1] =   SHAviteSmallCore.AES0[x[1] & 0xFF]
				^  SHAviteSmallCore.AES1[(x[2] >>> 8) & 0xFF]
				^  SHAviteSmallCore.AES2[(x[3] >>> 16) & 0xFF]
				^  SHAviteSmallCore.AES3[x[0] >>> 24];
			t[2] =   SHAviteSmallCore.AES0[x[2] & 0xFF]
				^  SHAviteSmallCore.AES1[(x[3] >>> 8) & 0xFF]
				^  SHAviteSmallCore.AES2[(x[0] >>> 16) & 0xFF]
				^  SHAviteSmallCore.AES3[x[1] >>> 24];
			t[3] =   SHAviteSmallCore.AES0[x[3] & 0xFF]
				^  SHAviteSmallCore.AES1[(x[0] >>> 8) & 0xFF]
				^  SHAviteSmallCore.AES2[(x[1] >>> 16) & 0xFF]
				^  SHAviteSmallCore.AES3[x[2] >>> 24];
			p[0] ^= t[0];
			p[1] ^= t[1];
			p[2] ^= t[2];
			p[3] ^= t[3];

			x[0] = p[0] ^ this.rk[u ++];
			x[1] = p[1] ^ this.rk[u ++];
			x[2] = p[2] ^ this.rk[u ++];
			x[3] = p[3] ^ this.rk[u ++];
			t[0] = SHAviteSmallCore.AES0[x[0] & 0xFF]
				^  SHAviteSmallCore.AES1[(x[1] >>> 8) & 0xFF]
				^  SHAviteSmallCore.AES2[(x[2] >>> 16) & 0xFF]
				^  SHAviteSmallCore.AES3[x[3] >>> 24];
			t[1] =   SHAviteSmallCore.AES0[x[1] & 0xFF]
				^  SHAviteSmallCore.AES1[(x[2] >>> 8) & 0xFF]
				^  SHAviteSmallCore.AES2[(x[3] >>> 16) & 0xFF]
				^  SHAviteSmallCore.AES3[x[0] >>> 24];
			t[2] =   SHAviteSmallCore.AES0[x[2] & 0xFF]
				^  SHAviteSmallCore.AES1[(x[3] >>> 8) & 0xFF]
				^  SHAviteSmallCore.AES2[(x[0] >>> 16) & 0xFF]
				^  SHAviteSmallCore.AES3[x[1] >>> 24];
			t[3] =   SHAviteSmallCore.AES0[x[3] & 0xFF]
				^  SHAviteSmallCore.AES1[(x[0] >>> 8) & 0xFF]
				^  SHAviteSmallCore.AES2[(x[1] >>> 16) & 0xFF]
				^  SHAviteSmallCore.AES3[x[2] >>> 24];
			x[0] = t[0] ^ this.rk[u ++];
			x[1] = t[1] ^ this.rk[u ++];
			x[2] = t[2] ^ this.rk[u ++];
			x[3] = t[3] ^ this.rk[u ++];
			t[0] =  SHAviteSmallCore.AES0[x[0] & 0xFF]
				^ SHAviteSmallCore.AES1[(x[1] >>> 8) & 0xFF]
				^ SHAviteSmallCore.AES2[(x[2] >>> 16) & 0xFF]
				^ SHAviteSmallCore.AES3[x[3] >>> 24];
			t[1] =  SHAviteSmallCore.AES0[x[1] & 0xFF]
				^ SHAviteSmallCore.AES1[(x[2] >>> 8) & 0xFF]
				^ SHAviteSmallCore.AES2[(x[3] >>> 16) & 0xFF]
				^ SHAviteSmallCore.AES3[x[0] >>> 24];
			t[2] =  SHAviteSmallCore.AES0[x[2] & 0xFF]
				^ SHAviteSmallCore.AES1[(x[3] >>> 8) & 0xFF]
				^ SHAviteSmallCore.AES2[(x[0] >>> 16) & 0xFF]
				^ SHAviteSmallCore.AES3[x[1] >>> 24];
			t[3] =  SHAviteSmallCore.AES0[x[3] & 0xFF]
				^ SHAviteSmallCore.AES1[(x[0] >>> 8) & 0xFF]
				^ SHAviteSmallCore.AES2[(x[1] >>> 16) & 0xFF]
				^ SHAviteSmallCore.AES3[x[2] >>> 24];
			x[0] = t[0] ^ this.rk[u ++];
			x[1] = t[1] ^ this.rk[u ++];
			x[2] = t[2] ^ this.rk[u ++];
			x[3] = t[3] ^ this.rk[u ++];
			t[0] =  SHAviteSmallCore.AES0[x[0] & 0xFF]
				^ SHAviteSmallCore.AES1[(x[1] >>> 8) & 0xFF]
				^ SHAviteSmallCore.AES2[(x[2] >>> 16) & 0xFF]
				^ SHAviteSmallCore.AES3[x[3] >>> 24];
			t[1] =  SHAviteSmallCore.AES0[x[1] & 0xFF]
				^ SHAviteSmallCore.AES1[(x[2] >>> 8) & 0xFF]
				^ SHAviteSmallCore.AES2[(x[3] >>> 16) & 0xFF]
				^ SHAviteSmallCore.AES3[x[0] >>> 24];
			t[2] =  SHAviteSmallCore.AES0[x[2] & 0xFF]
				^ SHAviteSmallCore.AES1[(x[3] >>> 8) & 0xFF]
				^ SHAviteSmallCore.AES2[(x[0] >>> 16) & 0xFF]
				^ SHAviteSmallCore.AES3[x[1] >>> 24];
			t[3] =  SHAviteSmallCore.AES0[x[3] & 0xFF]
				^ SHAviteSmallCore.AES1[(x[0] >>> 8) & 0xFF]
				^ SHAviteSmallCore.AES2[(x[1] >>> 16) & 0xFF]
				^ SHAviteSmallCore.AES3[x[2] >>> 24];
			p[4] ^= t[0];
			p[5] ^= t[1];
			p[6] ^= t[2];
			p[7] ^= t[3];
		}
		this.h[0x0] ^= p[0];
		this.h[0x1] ^= p[1];
		this.h[0x2] ^= p[2];
		this.h[0x3] ^= p[3];
		this.h[0x4] ^= p[4];
		this.h[0x5] ^= p[5];
		this.h[0x6] ^= p[6];
		this.h[0x7] ^= p[7];
	}

	/** @see Digest */
	public toString()
	{
		return "SHAvite-" + (this.getDigestLength() << 3);
	}
}

/**
 * This class implements SHAvite-384 and SHAvite-512.
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
 * @version   $Revision: 222 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

abstract class SHAviteBigCore extends DigestEngine {

	private h!: Int32Array;
    private rk!: Int32Array;

	/**
	 * Create the object.
	 */
	constructor()
	{
		super();
	}

	private static AES0 = new Int32Array([
		0xA56363C6, 0x847C7CF8, 0x997777EE, 0x8D7B7BF6,
		0x0DF2F2FF, 0xBD6B6BD6, 0xB16F6FDE, 0x54C5C591,
		0x50303060, 0x03010102, 0xA96767CE, 0x7D2B2B56,
		0x19FEFEE7, 0x62D7D7B5, 0xE6ABAB4D, 0x9A7676EC,
		0x45CACA8F, 0x9D82821F, 0x40C9C989, 0x877D7DFA,
		0x15FAFAEF, 0xEB5959B2, 0xC947478E, 0x0BF0F0FB,
		0xECADAD41, 0x67D4D4B3, 0xFDA2A25F, 0xEAAFAF45,
		0xBF9C9C23, 0xF7A4A453, 0x967272E4, 0x5BC0C09B,
		0xC2B7B775, 0x1CFDFDE1, 0xAE93933D, 0x6A26264C,
		0x5A36366C, 0x413F3F7E, 0x02F7F7F5, 0x4FCCCC83,
		0x5C343468, 0xF4A5A551, 0x34E5E5D1, 0x08F1F1F9,
		0x937171E2, 0x73D8D8AB, 0x53313162, 0x3F15152A,
		0x0C040408, 0x52C7C795, 0x65232346, 0x5EC3C39D,
		0x28181830, 0xA1969637, 0x0F05050A, 0xB59A9A2F,
		0x0907070E, 0x36121224, 0x9B80801B, 0x3DE2E2DF,
		0x26EBEBCD, 0x6927274E, 0xCDB2B27F, 0x9F7575EA,
		0x1B090912, 0x9E83831D, 0x742C2C58, 0x2E1A1A34,
		0x2D1B1B36, 0xB26E6EDC, 0xEE5A5AB4, 0xFBA0A05B,
		0xF65252A4, 0x4D3B3B76, 0x61D6D6B7, 0xCEB3B37D,
		0x7B292952, 0x3EE3E3DD, 0x712F2F5E, 0x97848413,
		0xF55353A6, 0x68D1D1B9, 0x00000000, 0x2CEDEDC1,
		0x60202040, 0x1FFCFCE3, 0xC8B1B179, 0xED5B5BB6,
		0xBE6A6AD4, 0x46CBCB8D, 0xD9BEBE67, 0x4B393972,
		0xDE4A4A94, 0xD44C4C98, 0xE85858B0, 0x4ACFCF85,
		0x6BD0D0BB, 0x2AEFEFC5, 0xE5AAAA4F, 0x16FBFBED,
		0xC5434386, 0xD74D4D9A, 0x55333366, 0x94858511,
		0xCF45458A, 0x10F9F9E9, 0x06020204, 0x817F7FFE,
		0xF05050A0, 0x443C3C78, 0xBA9F9F25, 0xE3A8A84B,
		0xF35151A2, 0xFEA3A35D, 0xC0404080, 0x8A8F8F05,
		0xAD92923F, 0xBC9D9D21, 0x48383870, 0x04F5F5F1,
		0xDFBCBC63, 0xC1B6B677, 0x75DADAAF, 0x63212142,
		0x30101020, 0x1AFFFFE5, 0x0EF3F3FD, 0x6DD2D2BF,
		0x4CCDCD81, 0x140C0C18, 0x35131326, 0x2FECECC3,
		0xE15F5FBE, 0xA2979735, 0xCC444488, 0x3917172E,
		0x57C4C493, 0xF2A7A755, 0x827E7EFC, 0x473D3D7A,
		0xAC6464C8, 0xE75D5DBA, 0x2B191932, 0x957373E6,
		0xA06060C0, 0x98818119, 0xD14F4F9E, 0x7FDCDCA3,
		0x66222244, 0x7E2A2A54, 0xAB90903B, 0x8388880B,
		0xCA46468C, 0x29EEEEC7, 0xD3B8B86B, 0x3C141428,
		0x79DEDEA7, 0xE25E5EBC, 0x1D0B0B16, 0x76DBDBAD,
		0x3BE0E0DB, 0x56323264, 0x4E3A3A74, 0x1E0A0A14,
		0xDB494992, 0x0A06060C, 0x6C242448, 0xE45C5CB8,
		0x5DC2C29F, 0x6ED3D3BD, 0xEFACAC43, 0xA66262C4,
		0xA8919139, 0xA4959531, 0x37E4E4D3, 0x8B7979F2,
		0x32E7E7D5, 0x43C8C88B, 0x5937376E, 0xB76D6DDA,
		0x8C8D8D01, 0x64D5D5B1, 0xD24E4E9C, 0xE0A9A949,
		0xB46C6CD8, 0xFA5656AC, 0x07F4F4F3, 0x25EAEACF,
		0xAF6565CA, 0x8E7A7AF4, 0xE9AEAE47, 0x18080810,
		0xD5BABA6F, 0x887878F0, 0x6F25254A, 0x722E2E5C,
		0x241C1C38, 0xF1A6A657, 0xC7B4B473, 0x51C6C697,
		0x23E8E8CB, 0x7CDDDDA1, 0x9C7474E8, 0x211F1F3E,
		0xDD4B4B96, 0xDCBDBD61, 0x868B8B0D, 0x858A8A0F,
		0x907070E0, 0x423E3E7C, 0xC4B5B571, 0xAA6666CC,
		0xD8484890, 0x05030306, 0x01F6F6F7, 0x120E0E1C,
		0xA36161C2, 0x5F35356A, 0xF95757AE, 0xD0B9B969,
		0x91868617, 0x58C1C199, 0x271D1D3A, 0xB99E9E27,
		0x38E1E1D9, 0x13F8F8EB, 0xB398982B, 0x33111122,
		0xBB6969D2, 0x70D9D9A9, 0x898E8E07, 0xA7949433,
		0xB69B9B2D, 0x221E1E3C, 0x92878715, 0x20E9E9C9,
		0x49CECE87, 0xFF5555AA, 0x78282850, 0x7ADFDFA5,
		0x8F8C8C03, 0xF8A1A159, 0x80898909, 0x170D0D1A,
		0xDABFBF65, 0x31E6E6D7, 0xC6424284, 0xB86868D0,
		0xC3414182, 0xB0999929, 0x772D2D5A, 0x110F0F1E,
		0xCBB0B07B, 0xFC5454A8, 0xD6BBBB6D, 0x3A16162C
	]);

	private static AES1 = new Int32Array([
		0x6363C6A5, 0x7C7CF884, 0x7777EE99, 0x7B7BF68D,
		0xF2F2FF0D, 0x6B6BD6BD, 0x6F6FDEB1, 0xC5C59154,
		0x30306050, 0x01010203, 0x6767CEA9, 0x2B2B567D,
		0xFEFEE719, 0xD7D7B562, 0xABAB4DE6, 0x7676EC9A,
		0xCACA8F45, 0x82821F9D, 0xC9C98940, 0x7D7DFA87,
		0xFAFAEF15, 0x5959B2EB, 0x47478EC9, 0xF0F0FB0B,
		0xADAD41EC, 0xD4D4B367, 0xA2A25FFD, 0xAFAF45EA,
		0x9C9C23BF, 0xA4A453F7, 0x7272E496, 0xC0C09B5B,
		0xB7B775C2, 0xFDFDE11C, 0x93933DAE, 0x26264C6A,
		0x36366C5A, 0x3F3F7E41, 0xF7F7F502, 0xCCCC834F,
		0x3434685C, 0xA5A551F4, 0xE5E5D134, 0xF1F1F908,
		0x7171E293, 0xD8D8AB73, 0x31316253, 0x15152A3F,
		0x0404080C, 0xC7C79552, 0x23234665, 0xC3C39D5E,
		0x18183028, 0x969637A1, 0x05050A0F, 0x9A9A2FB5,
		0x07070E09, 0x12122436, 0x80801B9B, 0xE2E2DF3D,
		0xEBEBCD26, 0x27274E69, 0xB2B27FCD, 0x7575EA9F,
		0x0909121B, 0x83831D9E, 0x2C2C5874, 0x1A1A342E,
		0x1B1B362D, 0x6E6EDCB2, 0x5A5AB4EE, 0xA0A05BFB,
		0x5252A4F6, 0x3B3B764D, 0xD6D6B761, 0xB3B37DCE,
		0x2929527B, 0xE3E3DD3E, 0x2F2F5E71, 0x84841397,
		0x5353A6F5, 0xD1D1B968, 0x00000000, 0xEDEDC12C,
		0x20204060, 0xFCFCE31F, 0xB1B179C8, 0x5B5BB6ED,
		0x6A6AD4BE, 0xCBCB8D46, 0xBEBE67D9, 0x3939724B,
		0x4A4A94DE, 0x4C4C98D4, 0x5858B0E8, 0xCFCF854A,
		0xD0D0BB6B, 0xEFEFC52A, 0xAAAA4FE5, 0xFBFBED16,
		0x434386C5, 0x4D4D9AD7, 0x33336655, 0x85851194,
		0x45458ACF, 0xF9F9E910, 0x02020406, 0x7F7FFE81,
		0x5050A0F0, 0x3C3C7844, 0x9F9F25BA, 0xA8A84BE3,
		0x5151A2F3, 0xA3A35DFE, 0x404080C0, 0x8F8F058A,
		0x92923FAD, 0x9D9D21BC, 0x38387048, 0xF5F5F104,
		0xBCBC63DF, 0xB6B677C1, 0xDADAAF75, 0x21214263,
		0x10102030, 0xFFFFE51A, 0xF3F3FD0E, 0xD2D2BF6D,
		0xCDCD814C, 0x0C0C1814, 0x13132635, 0xECECC32F,
		0x5F5FBEE1, 0x979735A2, 0x444488CC, 0x17172E39,
		0xC4C49357, 0xA7A755F2, 0x7E7EFC82, 0x3D3D7A47,
		0x6464C8AC, 0x5D5DBAE7, 0x1919322B, 0x7373E695,
		0x6060C0A0, 0x81811998, 0x4F4F9ED1, 0xDCDCA37F,
		0x22224466, 0x2A2A547E, 0x90903BAB, 0x88880B83,
		0x46468CCA, 0xEEEEC729, 0xB8B86BD3, 0x1414283C,
		0xDEDEA779, 0x5E5EBCE2, 0x0B0B161D, 0xDBDBAD76,
		0xE0E0DB3B, 0x32326456, 0x3A3A744E, 0x0A0A141E,
		0x494992DB, 0x06060C0A, 0x2424486C, 0x5C5CB8E4,
		0xC2C29F5D, 0xD3D3BD6E, 0xACAC43EF, 0x6262C4A6,
		0x919139A8, 0x959531A4, 0xE4E4D337, 0x7979F28B,
		0xE7E7D532, 0xC8C88B43, 0x37376E59, 0x6D6DDAB7,
		0x8D8D018C, 0xD5D5B164, 0x4E4E9CD2, 0xA9A949E0,
		0x6C6CD8B4, 0x5656ACFA, 0xF4F4F307, 0xEAEACF25,
		0x6565CAAF, 0x7A7AF48E, 0xAEAE47E9, 0x08081018,
		0xBABA6FD5, 0x7878F088, 0x25254A6F, 0x2E2E5C72,
		0x1C1C3824, 0xA6A657F1, 0xB4B473C7, 0xC6C69751,
		0xE8E8CB23, 0xDDDDA17C, 0x7474E89C, 0x1F1F3E21,
		0x4B4B96DD, 0xBDBD61DC, 0x8B8B0D86, 0x8A8A0F85,
		0x7070E090, 0x3E3E7C42, 0xB5B571C4, 0x6666CCAA,
		0x484890D8, 0x03030605, 0xF6F6F701, 0x0E0E1C12,
		0x6161C2A3, 0x35356A5F, 0x5757AEF9, 0xB9B969D0,
		0x86861791, 0xC1C19958, 0x1D1D3A27, 0x9E9E27B9,
		0xE1E1D938, 0xF8F8EB13, 0x98982BB3, 0x11112233,
		0x6969D2BB, 0xD9D9A970, 0x8E8E0789, 0x949433A7,
		0x9B9B2DB6, 0x1E1E3C22, 0x87871592, 0xE9E9C920,
		0xCECE8749, 0x5555AAFF, 0x28285078, 0xDFDFA57A,
		0x8C8C038F, 0xA1A159F8, 0x89890980, 0x0D0D1A17,
		0xBFBF65DA, 0xE6E6D731, 0x424284C6, 0x6868D0B8,
		0x414182C3, 0x999929B0, 0x2D2D5A77, 0x0F0F1E11,
		0xB0B07BCB, 0x5454A8FC, 0xBBBB6DD6, 0x16162C3A
	]);

	private static AES2 = new Int32Array([
		0x63C6A563, 0x7CF8847C, 0x77EE9977, 0x7BF68D7B,
		0xF2FF0DF2, 0x6BD6BD6B, 0x6FDEB16F, 0xC59154C5,
		0x30605030, 0x01020301, 0x67CEA967, 0x2B567D2B,
		0xFEE719FE, 0xD7B562D7, 0xAB4DE6AB, 0x76EC9A76,
		0xCA8F45CA, 0x821F9D82, 0xC98940C9, 0x7DFA877D,
		0xFAEF15FA, 0x59B2EB59, 0x478EC947, 0xF0FB0BF0,
		0xAD41ECAD, 0xD4B367D4, 0xA25FFDA2, 0xAF45EAAF,
		0x9C23BF9C, 0xA453F7A4, 0x72E49672, 0xC09B5BC0,
		0xB775C2B7, 0xFDE11CFD, 0x933DAE93, 0x264C6A26,
		0x366C5A36, 0x3F7E413F, 0xF7F502F7, 0xCC834FCC,
		0x34685C34, 0xA551F4A5, 0xE5D134E5, 0xF1F908F1,
		0x71E29371, 0xD8AB73D8, 0x31625331, 0x152A3F15,
		0x04080C04, 0xC79552C7, 0x23466523, 0xC39D5EC3,
		0x18302818, 0x9637A196, 0x050A0F05, 0x9A2FB59A,
		0x070E0907, 0x12243612, 0x801B9B80, 0xE2DF3DE2,
		0xEBCD26EB, 0x274E6927, 0xB27FCDB2, 0x75EA9F75,
		0x09121B09, 0x831D9E83, 0x2C58742C, 0x1A342E1A,
		0x1B362D1B, 0x6EDCB26E, 0x5AB4EE5A, 0xA05BFBA0,
		0x52A4F652, 0x3B764D3B, 0xD6B761D6, 0xB37DCEB3,
		0x29527B29, 0xE3DD3EE3, 0x2F5E712F, 0x84139784,
		0x53A6F553, 0xD1B968D1, 0x00000000, 0xEDC12CED,
		0x20406020, 0xFCE31FFC, 0xB179C8B1, 0x5BB6ED5B,
		0x6AD4BE6A, 0xCB8D46CB, 0xBE67D9BE, 0x39724B39,
		0x4A94DE4A, 0x4C98D44C, 0x58B0E858, 0xCF854ACF,
		0xD0BB6BD0, 0xEFC52AEF, 0xAA4FE5AA, 0xFBED16FB,
		0x4386C543, 0x4D9AD74D, 0x33665533, 0x85119485,
		0x458ACF45, 0xF9E910F9, 0x02040602, 0x7FFE817F,
		0x50A0F050, 0x3C78443C, 0x9F25BA9F, 0xA84BE3A8,
		0x51A2F351, 0xA35DFEA3, 0x4080C040, 0x8F058A8F,
		0x923FAD92, 0x9D21BC9D, 0x38704838, 0xF5F104F5,
		0xBC63DFBC, 0xB677C1B6, 0xDAAF75DA, 0x21426321,
		0x10203010, 0xFFE51AFF, 0xF3FD0EF3, 0xD2BF6DD2,
		0xCD814CCD, 0x0C18140C, 0x13263513, 0xECC32FEC,
		0x5FBEE15F, 0x9735A297, 0x4488CC44, 0x172E3917,
		0xC49357C4, 0xA755F2A7, 0x7EFC827E, 0x3D7A473D,
		0x64C8AC64, 0x5DBAE75D, 0x19322B19, 0x73E69573,
		0x60C0A060, 0x81199881, 0x4F9ED14F, 0xDCA37FDC,
		0x22446622, 0x2A547E2A, 0x903BAB90, 0x880B8388,
		0x468CCA46, 0xEEC729EE, 0xB86BD3B8, 0x14283C14,
		0xDEA779DE, 0x5EBCE25E, 0x0B161D0B, 0xDBAD76DB,
		0xE0DB3BE0, 0x32645632, 0x3A744E3A, 0x0A141E0A,
		0x4992DB49, 0x060C0A06, 0x24486C24, 0x5CB8E45C,
		0xC29F5DC2, 0xD3BD6ED3, 0xAC43EFAC, 0x62C4A662,
		0x9139A891, 0x9531A495, 0xE4D337E4, 0x79F28B79,
		0xE7D532E7, 0xC88B43C8, 0x376E5937, 0x6DDAB76D,
		0x8D018C8D, 0xD5B164D5, 0x4E9CD24E, 0xA949E0A9,
		0x6CD8B46C, 0x56ACFA56, 0xF4F307F4, 0xEACF25EA,
		0x65CAAF65, 0x7AF48E7A, 0xAE47E9AE, 0x08101808,
		0xBA6FD5BA, 0x78F08878, 0x254A6F25, 0x2E5C722E,
		0x1C38241C, 0xA657F1A6, 0xB473C7B4, 0xC69751C6,
		0xE8CB23E8, 0xDDA17CDD, 0x74E89C74, 0x1F3E211F,
		0x4B96DD4B, 0xBD61DCBD, 0x8B0D868B, 0x8A0F858A,
		0x70E09070, 0x3E7C423E, 0xB571C4B5, 0x66CCAA66,
		0x4890D848, 0x03060503, 0xF6F701F6, 0x0E1C120E,
		0x61C2A361, 0x356A5F35, 0x57AEF957, 0xB969D0B9,
		0x86179186, 0xC19958C1, 0x1D3A271D, 0x9E27B99E,
		0xE1D938E1, 0xF8EB13F8, 0x982BB398, 0x11223311,
		0x69D2BB69, 0xD9A970D9, 0x8E07898E, 0x9433A794,
		0x9B2DB69B, 0x1E3C221E, 0x87159287, 0xE9C920E9,
		0xCE8749CE, 0x55AAFF55, 0x28507828, 0xDFA57ADF,
		0x8C038F8C, 0xA159F8A1, 0x89098089, 0x0D1A170D,
		0xBF65DABF, 0xE6D731E6, 0x4284C642, 0x68D0B868,
		0x4182C341, 0x9929B099, 0x2D5A772D, 0x0F1E110F,
		0xB07BCBB0, 0x54A8FC54, 0xBB6DD6BB, 0x162C3A16
	]);

	private static AES3 = new Int32Array([
		0xC6A56363, 0xF8847C7C, 0xEE997777, 0xF68D7B7B,
		0xFF0DF2F2, 0xD6BD6B6B, 0xDEB16F6F, 0x9154C5C5,
		0x60503030, 0x02030101, 0xCEA96767, 0x567D2B2B,
		0xE719FEFE, 0xB562D7D7, 0x4DE6ABAB, 0xEC9A7676,
		0x8F45CACA, 0x1F9D8282, 0x8940C9C9, 0xFA877D7D,
		0xEF15FAFA, 0xB2EB5959, 0x8EC94747, 0xFB0BF0F0,
		0x41ECADAD, 0xB367D4D4, 0x5FFDA2A2, 0x45EAAFAF,
		0x23BF9C9C, 0x53F7A4A4, 0xE4967272, 0x9B5BC0C0,
		0x75C2B7B7, 0xE11CFDFD, 0x3DAE9393, 0x4C6A2626,
		0x6C5A3636, 0x7E413F3F, 0xF502F7F7, 0x834FCCCC,
		0x685C3434, 0x51F4A5A5, 0xD134E5E5, 0xF908F1F1,
		0xE2937171, 0xAB73D8D8, 0x62533131, 0x2A3F1515,
		0x080C0404, 0x9552C7C7, 0x46652323, 0x9D5EC3C3,
		0x30281818, 0x37A19696, 0x0A0F0505, 0x2FB59A9A,
		0x0E090707, 0x24361212, 0x1B9B8080, 0xDF3DE2E2,
		0xCD26EBEB, 0x4E692727, 0x7FCDB2B2, 0xEA9F7575,
		0x121B0909, 0x1D9E8383, 0x58742C2C, 0x342E1A1A,
		0x362D1B1B, 0xDCB26E6E, 0xB4EE5A5A, 0x5BFBA0A0,
		0xA4F65252, 0x764D3B3B, 0xB761D6D6, 0x7DCEB3B3,
		0x527B2929, 0xDD3EE3E3, 0x5E712F2F, 0x13978484,
		0xA6F55353, 0xB968D1D1, 0x00000000, 0xC12CEDED,
		0x40602020, 0xE31FFCFC, 0x79C8B1B1, 0xB6ED5B5B,
		0xD4BE6A6A, 0x8D46CBCB, 0x67D9BEBE, 0x724B3939,
		0x94DE4A4A, 0x98D44C4C, 0xB0E85858, 0x854ACFCF,
		0xBB6BD0D0, 0xC52AEFEF, 0x4FE5AAAA, 0xED16FBFB,
		0x86C54343, 0x9AD74D4D, 0x66553333, 0x11948585,
		0x8ACF4545, 0xE910F9F9, 0x04060202, 0xFE817F7F,
		0xA0F05050, 0x78443C3C, 0x25BA9F9F, 0x4BE3A8A8,
		0xA2F35151, 0x5DFEA3A3, 0x80C04040, 0x058A8F8F,
		0x3FAD9292, 0x21BC9D9D, 0x70483838, 0xF104F5F5,
		0x63DFBCBC, 0x77C1B6B6, 0xAF75DADA, 0x42632121,
		0x20301010, 0xE51AFFFF, 0xFD0EF3F3, 0xBF6DD2D2,
		0x814CCDCD, 0x18140C0C, 0x26351313, 0xC32FECEC,
		0xBEE15F5F, 0x35A29797, 0x88CC4444, 0x2E391717,
		0x9357C4C4, 0x55F2A7A7, 0xFC827E7E, 0x7A473D3D,
		0xC8AC6464, 0xBAE75D5D, 0x322B1919, 0xE6957373,
		0xC0A06060, 0x19988181, 0x9ED14F4F, 0xA37FDCDC,
		0x44662222, 0x547E2A2A, 0x3BAB9090, 0x0B838888,
		0x8CCA4646, 0xC729EEEE, 0x6BD3B8B8, 0x283C1414,
		0xA779DEDE, 0xBCE25E5E, 0x161D0B0B, 0xAD76DBDB,
		0xDB3BE0E0, 0x64563232, 0x744E3A3A, 0x141E0A0A,
		0x92DB4949, 0x0C0A0606, 0x486C2424, 0xB8E45C5C,
		0x9F5DC2C2, 0xBD6ED3D3, 0x43EFACAC, 0xC4A66262,
		0x39A89191, 0x31A49595, 0xD337E4E4, 0xF28B7979,
		0xD532E7E7, 0x8B43C8C8, 0x6E593737, 0xDAB76D6D,
		0x018C8D8D, 0xB164D5D5, 0x9CD24E4E, 0x49E0A9A9,
		0xD8B46C6C, 0xACFA5656, 0xF307F4F4, 0xCF25EAEA,
		0xCAAF6565, 0xF48E7A7A, 0x47E9AEAE, 0x10180808,
		0x6FD5BABA, 0xF0887878, 0x4A6F2525, 0x5C722E2E,
		0x38241C1C, 0x57F1A6A6, 0x73C7B4B4, 0x9751C6C6,
		0xCB23E8E8, 0xA17CDDDD, 0xE89C7474, 0x3E211F1F,
		0x96DD4B4B, 0x61DCBDBD, 0x0D868B8B, 0x0F858A8A,
		0xE0907070, 0x7C423E3E, 0x71C4B5B5, 0xCCAA6666,
		0x90D84848, 0x06050303, 0xF701F6F6, 0x1C120E0E,
		0xC2A36161, 0x6A5F3535, 0xAEF95757, 0x69D0B9B9,
		0x17918686, 0x9958C1C1, 0x3A271D1D, 0x27B99E9E,
		0xD938E1E1, 0xEB13F8F8, 0x2BB39898, 0x22331111,
		0xD2BB6969, 0xA970D9D9, 0x07898E8E, 0x33A79494,
		0x2DB69B9B, 0x3C221E1E, 0x15928787, 0xC920E9E9,
		0x8749CECE, 0xAAFF5555, 0x50782828, 0xA57ADFDF,
		0x038F8C8C, 0x59F8A1A1, 0x09808989, 0x1A170D0D,
		0x65DABFBF, 0xD731E6E6, 0x84C64242, 0xD0B86868,
		0x82C34141, 0x29B09999, 0x5A772D2D, 0x1E110F0F,
		0x7BCBB0B0, 0xA8FC5454, 0x6DD6BBBB, 0x2C3A1616
	]);

	/** @see Digest */
	public getBlockLength()
	{
		return 128;
	}

	/** @see DigestEngine */
	protected copyState<T>(dst: SHAviteBigCore): T
	{
		arraycopy(this.h, 0, dst.h, 0, this.h.length);
		return super.copyState(dst) as T;
	}

	/** @see DigestEngine */
	protected  engineReset()
	{
		arraycopy(this.getInitVal(), 0, this.h, 0, this.h.length);
	}

	/**
	 * Get the initial value for this algorithm.
	 *
	 * @return  the initial value
	 */
	abstract getInitVal(): Int32Array;

	/** @see DigestEngine */
	protected doPadding( output:Uint8Array, outputOffset:number)
	{
		var ptr = this.flush();
		var bc = this.getBlockCount();
		var bitLen = BigInt(bc << BigInt(10)) + BigInt(ptr << 3);
		var cnt0 = Number(bitLen);
		var cnt1 = Number(lshr(bitLen, 32));
		var cnt2 = Number(lshr(bc, 54));
		const buf = this.getBlockBuffer();
		if (ptr == 0) {
			buf[0] = 0x80;
			for (let i = 1; i < 110; i ++){
				buf[i] = 0;
			}
			cnt0 = cnt1 = cnt2 = 0;
		} else if (ptr < 110) {
			buf[ptr++] = 0x80;
			while (ptr < 110){
				buf[ptr++] = 0;
			}
		} else {
			buf[ptr++] = 0x80;
			while (ptr < 128){
				buf[ptr++] = 0;
			}
			this.process(buf, cnt0, cnt1, cnt2);
			for (let i = 0; i < 110; i ++){
				buf[i] = 0;
			}
			cnt0 = cnt1 = cnt2 = 0;
		}
		this.encodeLEInt(Number(bitLen), buf, 110);
		this.encodeLEInt(Number(lshr(bitLen, 32)), buf, 114);
		this.encodeLEInt(Number(lshr(bc, 54)), buf, 118);
		buf[122] = buf[123] = buf[124] = buf[125] = 0;
		var dlen = this.getDigestLength();
		buf[126] = (dlen << 3);
		buf[127] = (dlen >>> 5);
		this.process(buf, cnt0, cnt1, cnt2);
		for (let i = 0; i < dlen; i += 4){
			this.encodeLEInt(this.h[i >>> 2], output, outputOffset + i);
		}
	}

	/** @see DigestEngine */
	protected doInit()
	{
		this.h = new Int32Array(16);
		this.rk = new Int32Array(448);
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
	private encodeLEInt(val:number, buf:Uint8Array, off:number)
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
	private decodeLEInt(buf:Uint8Array, off:number)
	{
		return (buf[off] & 0xFF)
			| ((buf[off + 1] & 0xFF) << 8)
			| ((buf[off + 2] & 0xFF) << 16)
			| ((buf[off + 3] & 0xFF) << 24);
	}

	/** @see DigestEngine */
	protected processBlock(data:Uint8Array)
	{
		var bc = this.getBlockCount() + BigInt(1);
		var bitLen = bc << BigInt(10); 
		this.process(data, Number(bitLen), Number(lshr(bitLen, 32)), Number(lshr(bc, 54)));
	}

	/**
	 * Process one block. This implementation supports up to about
	 * 2^64 input blocks, i.e. 2^74 bits. Thus, the counter highest
	 * word (cnt3) is always zero.
	 *
	 * @param data   the data block (128 bytes)
	 * @param cnt0   the first (least significant) bit counter word
	 * @param cnt1   the second bit count word
	 * @param cnt2   the third bit count word
	 */
	private process(data:Uint8Array, cnt0:number, cnt1:number, cnt2:number)
	{
		const p = new Int32Array(16);
		const A = 10;
		const B = 11;
		const C = 12;
		const D = 13;
		const E = 14;
		const F = 15;
		const x = new Int32Array(4);
		const t = new Int32Array(4);
		var u;

		for (u = 0; u < 32; u += 4) {
			this.rk[u + 0] = this.decodeLEInt(data, (u << 2) +  0);
			this.rk[u + 1] = this.decodeLEInt(data, (u << 2) +  4);
			this.rk[u + 2] = this.decodeLEInt(data, (u << 2) +  8);
			this.rk[u + 3] = this.decodeLEInt(data, (u << 2) + 12);
		}
		for (;;) {
			for (let s = 0; s < 4; s ++) {
				x[0] = this.rk[u - 31];
				x[1] = this.rk[u - 30];
				x[2] = this.rk[u - 29];
				x[3] = this.rk[u - 32];
				t[0] =  SHAviteBigCore.AES0[ x[0] & 0xFF]
					^ SHAviteBigCore.AES1[(x[1] >>> 8) & 0xFF]
					^ SHAviteBigCore.AES2[(x[2] >>> 16) & 0xFF]
					^ SHAviteBigCore.AES3[ x[3] >>> 24];
				t[1] =  SHAviteBigCore.AES0[ x[1] & 0xFF]
					^ SHAviteBigCore.AES1[(x[2] >>> 8) & 0xFF]
					^ SHAviteBigCore.AES2[(x[3] >>> 16) & 0xFF]
					^ SHAviteBigCore.AES3[ x[0] >>> 24];
				t[2] =  SHAviteBigCore.AES0[ x[2] & 0xFF]
					^ SHAviteBigCore.AES1[(x[3] >>> 8) & 0xFF]
					^ SHAviteBigCore.AES2[(x[0] >>> 16) & 0xFF]
					^ SHAviteBigCore.AES3[ x[1] >>> 24];
				t[3] =  SHAviteBigCore.AES0[ x[3] & 0xFF]
					^ SHAviteBigCore.AES1[(x[0] >>> 8) & 0xFF]
					^ SHAviteBigCore.AES2[(x[1] >>> 16) & 0xFF]
					^ SHAviteBigCore.AES3[ x[2] >>> 24];
				this.rk[u + 0] = t[0] ^ this.rk[u - 4];
				this.rk[u + 1] = t[1] ^ this.rk[u - 3];
				this.rk[u + 2] = t[2] ^ this.rk[u - 2];
				this.rk[u + 3] = t[3] ^ this.rk[u - 1];
				if (u == 32) {
					this.rk[ 32] ^= cnt0;
					this.rk[ 33] ^= cnt1;
					this.rk[ 34] ^= cnt2;
					this.rk[ 35] ^= ~0;
				} else if (u == 440) {
					this.rk[440] ^= cnt1;
					this.rk[441] ^= cnt0;
					// this.rk[442] ^= 0;
					this.rk[443] ^= ~cnt2;
				}
				u += 4;

				x[0] = this.rk[u - 31];
				x[1] = this.rk[u - 30];
				x[2] = this.rk[u - 29];
				x[3] = this.rk[u - 32];
				t[0] =  SHAviteBigCore.AES0[ x[0] & 0xFF]
					^ SHAviteBigCore.AES1[(x[1] >>> 8) & 0xFF]
					^ SHAviteBigCore.AES2[(x[2] >>> 16) & 0xFF]
					^ SHAviteBigCore.AES3[ x[3] >>> 24];
				t[1] =  SHAviteBigCore.AES0[ x[1] & 0xFF]
					^ SHAviteBigCore.AES1[(x[2] >>> 8) & 0xFF]
					^ SHAviteBigCore.AES2[(x[3] >>> 16) & 0xFF]
					^ SHAviteBigCore.AES3[ x[0] >>> 24];
				t[2] =  SHAviteBigCore.AES0[ x[2] & 0xFF]
					^ SHAviteBigCore.AES1[(x[3] >>> 8) & 0xFF]
					^ SHAviteBigCore.AES2[(x[0] >>> 16) & 0xFF]
					^ SHAviteBigCore.AES3[ x[1] >>> 24];
				t[3] =  SHAviteBigCore.AES0[ x[3] & 0xFF]
					^ SHAviteBigCore.AES1[(x[0] >>> 8) & 0xFF]
					^ SHAviteBigCore.AES2[(x[1] >>> 16) & 0xFF]
					^ SHAviteBigCore.AES3[ x[2] >>> 24];
				this.rk[u + 0] = t[0] ^ this.rk[u - 4];
				this.rk[u + 1] = t[1] ^ this.rk[u - 3];
				this.rk[u + 2] = t[2] ^ this.rk[u - 2];
				this.rk[u + 3] = t[3] ^ this.rk[u - 1];
				if (u == 164) {
					// this.rk[164] ^= 0;
					this.rk[165] ^= cnt2;
					this.rk[166] ^= cnt1;
					this.rk[167] ^= ~cnt0;
				} else if (u == 316) {
					this.rk[316] ^= cnt2;
					//this.rk[317] ^= 0;
					this.rk[318] ^= cnt0;
					this.rk[319] ^= ~cnt1;
				}
				u += 4;
			}
			if (u == 448)
				break;
			for (let s = 0; s < 8; s ++) {
				this.rk[u + 0] = this.rk[u - 32] ^ this.rk[u - 7];
				this.rk[u + 1] = this.rk[u - 31] ^ this.rk[u - 6];
				this.rk[u + 2] = this.rk[u - 30] ^ this.rk[u - 5];
				this.rk[u + 3] = this.rk[u - 29] ^ this.rk[u - 4];
				u += 4;
			}
		}

		p[0] = this.h[0x0];
		p[1] = this.h[0x1];
		p[2] = this.h[0x2];
		p[3] = this.h[0x3];
		p[4] = this.h[0x4];
		p[5] = this.h[0x5];
		p[6] = this.h[0x6];
		p[7] = this.h[0x7];
		p[8] = this.h[0x8];
		p[9] = this.h[0x9];
		p[A] = this.h[0xA];
		p[B] = this.h[0xB];
		p[C] = this.h[0xC];
		p[D] = this.h[0xD];
		p[E] = this.h[0xE];
		p[F] = this.h[0xF];
		u = 0;
		for (let r = 0; r < 14; r ++) {
			x[0] = p[4] ^ this.rk[u ++];
			x[1] = p[5] ^ this.rk[u ++];
			x[2] = p[6] ^ this.rk[u ++];
			x[3] = p[7] ^ this.rk[u ++];
			t[0] =  SHAviteBigCore.AES0[ x[0] & 0xFF]
				^ SHAviteBigCore.AES1[(x[1] >>> 8) & 0xFF]
				^ SHAviteBigCore.AES2[(x[2] >>> 16) & 0xFF]
				^ SHAviteBigCore.AES3[ x[3] >>> 24];
			t[1] =  SHAviteBigCore.AES0[ x[1] & 0xFF]
				^ SHAviteBigCore.AES1[(x[2] >>> 8) & 0xFF]
				^ SHAviteBigCore.AES2[(x[3] >>> 16) & 0xFF]
				^ SHAviteBigCore.AES3[ x[0] >>> 24];
			t[2] =  SHAviteBigCore.AES0[ x[2] & 0xFF]
				^ SHAviteBigCore.AES1[(x[3] >>> 8) & 0xFF]
				^ SHAviteBigCore.AES2[(x[0] >>> 16) & 0xFF]
				^ SHAviteBigCore.AES3[ x[1] >>> 24];
			t[3] =  SHAviteBigCore.AES0[ x[3] & 0xFF]
				^ SHAviteBigCore.AES1[(x[0] >>> 8) & 0xFF]
				^ SHAviteBigCore.AES2[(x[1] >>> 16) & 0xFF]
				^ SHAviteBigCore.AES3[ x[2] >>> 24];
			x[0] = t[0] ^ this.rk[u ++];
			x[1] = t[1] ^ this.rk[u ++];
			x[2] = t[2] ^ this.rk[u ++];
			x[3] = t[3] ^ this.rk[u ++];
			t[0] =SHAviteBigCore.AES0[ x[0] & 0xFF]
				^ SHAviteBigCore.AES1[(x[1] >>> 8) & 0xFF]
				^ SHAviteBigCore.AES2[(x[2] >>> 16) & 0xFF]
				^ SHAviteBigCore.AES3[ x[3] >>> 24];
			t[1] =  SHAviteBigCore.AES0[ x[1] & 0xFF]
				^ SHAviteBigCore.AES1[(x[2] >>> 8) & 0xFF]
				^ SHAviteBigCore.AES2[(x[3] >>> 16) & 0xFF]
				^ SHAviteBigCore.AES3[ x[0] >>> 24];
			t[2] =  SHAviteBigCore.AES0[ x[2] & 0xFF]
				^ SHAviteBigCore.AES1[(x[3] >>> 8) & 0xFF]
				^ SHAviteBigCore.AES2[(x[0] >>> 16) & 0xFF]
				^ SHAviteBigCore.AES3[ x[1] >>> 24];
			t[3] =  SHAviteBigCore.AES0[ x[3] & 0xFF]
				^ SHAviteBigCore.AES1[(x[0] >>> 8) & 0xFF]
				^ SHAviteBigCore.AES2[(x[1] >>> 16) & 0xFF]
				^ SHAviteBigCore.AES3[ x[2] >>> 24];
			x[0] = t[0] ^ this.rk[u ++];
			x[1] = t[1] ^ this.rk[u ++];
			x[2] = t[2] ^ this.rk[u ++];
			x[3] = t[3] ^ this.rk[u ++];
			t[0] =SHAviteBigCore.AES0[ x[0] & 0xFF]
				^ SHAviteBigCore.AES1[(x[1] >>> 8) & 0xFF]
				^ SHAviteBigCore.AES2[(x[2] >>> 16) & 0xFF]
				^ SHAviteBigCore.AES3[ x[3] >>> 24];
			t[1] =  SHAviteBigCore.AES0[ x[1] & 0xFF]
				^ SHAviteBigCore.AES1[(x[2] >>> 8) & 0xFF]
				^ SHAviteBigCore.AES2[(x[3] >>> 16) & 0xFF]
				^ SHAviteBigCore.AES3[ x[0] >>> 24];
			t[2] =  SHAviteBigCore.AES0[ x[2] & 0xFF]
				^ SHAviteBigCore.AES1[(x[3] >>> 8) & 0xFF]
				^ SHAviteBigCore.AES2[(x[0] >>> 16) & 0xFF]
				^ SHAviteBigCore.AES3[ x[1] >>> 24];
			t[3] =  SHAviteBigCore.AES0[ x[3] & 0xFF]
				^ SHAviteBigCore.AES1[(x[0] >>> 8) & 0xFF]
				^ SHAviteBigCore.AES2[(x[1] >>> 16) & 0xFF]
				^ SHAviteBigCore.AES3[ x[2] >>> 24];
			x[0] = t[0] ^ this.rk[u ++];
			x[1] = t[1] ^ this.rk[u ++];
			x[2] = t[2] ^ this.rk[u ++];
			x[3] = t[3] ^ this.rk[u ++];
			t[0] =SHAviteBigCore.AES0[ x[0] & 0xFF]
				^ SHAviteBigCore.AES1[(x[1] >>> 8) & 0xFF]
				^ SHAviteBigCore.AES2[(x[2] >>> 16) & 0xFF]
				^ SHAviteBigCore.AES3[ x[3] >>> 24];
			t[1] =  SHAviteBigCore.AES0[ x[1] & 0xFF]
				^ SHAviteBigCore.AES1[(x[2] >>> 8) & 0xFF]
				^ SHAviteBigCore.AES2[(x[3] >>> 16) & 0xFF]
				^ SHAviteBigCore.AES3[ x[0] >>> 24];
			t[2] =  SHAviteBigCore.AES0[ x[2] & 0xFF]
				^ SHAviteBigCore.AES1[(x[3] >>> 8) & 0xFF]
				^ SHAviteBigCore.AES2[(x[0] >>> 16) & 0xFF]
				^ SHAviteBigCore.AES3[ x[1] >>> 24];
			t[3] =  SHAviteBigCore.AES0[ x[3] & 0xFF]
				^ SHAviteBigCore.AES1[(x[0] >>> 8) & 0xFF]
				^ SHAviteBigCore.AES2[(x[1] >>> 16) & 0xFF]
				^ SHAviteBigCore.AES3[ x[2] >>> 24];
			p[0] ^= t[0];
			p[1] ^= t[1];
			p[2] ^= t[2];
			p[3] ^= t[3];

			x[0] = p[C] ^ this.rk[u ++];
			x[1] = p[D] ^ this.rk[u ++];
			x[2] = p[E] ^ this.rk[u ++];
			x[3] = p[F] ^ this.rk[u ++];
			t[0] =SHAviteBigCore.AES0[ x[0] & 0xFF]
				^ SHAviteBigCore.AES1[(x[1] >>> 8) & 0xFF]
				^ SHAviteBigCore.AES2[(x[2] >>> 16) & 0xFF]
				^ SHAviteBigCore.AES3[ x[3] >>> 24];
			t[1] =  SHAviteBigCore.AES0[ x[1] & 0xFF]
				^ SHAviteBigCore.AES1[(x[2] >>> 8) & 0xFF]
				^ SHAviteBigCore.AES2[(x[3] >>> 16) & 0xFF]
				^ SHAviteBigCore.AES3[ x[0] >>> 24];
			t[2] =  SHAviteBigCore.AES0[ x[2] & 0xFF]
				^ SHAviteBigCore.AES1[(x[3] >>> 8) & 0xFF]
				^ SHAviteBigCore.AES2[(x[0] >>> 16) & 0xFF]
				^ SHAviteBigCore.AES3[ x[1] >>> 24];
			t[3] =  SHAviteBigCore.AES0[ x[3] & 0xFF]
				^ SHAviteBigCore.AES1[(x[0] >>> 8) & 0xFF]
				^ SHAviteBigCore.AES2[(x[1] >>> 16) & 0xFF]
				^ SHAviteBigCore.AES3[ x[2] >>> 24];
			x[0] = t[0] ^ this.rk[u ++];
			x[1] = t[1] ^ this.rk[u ++];
			x[2] = t[2] ^ this.rk[u ++];
			x[3] = t[3] ^ this.rk[u ++];
			t[0] =SHAviteBigCore.AES0[ x[0] & 0xFF]
				^ SHAviteBigCore.AES1[(x[1] >>> 8) & 0xFF]
				^ SHAviteBigCore.AES2[(x[2] >>> 16) & 0xFF]
				^ SHAviteBigCore.AES3[ x[3] >>> 24];
			t[1] =SHAviteBigCore.AES0[ x[1] & 0xFF]
				^ SHAviteBigCore.AES1[(x[2] >>> 8) & 0xFF]
				^ SHAviteBigCore.AES2[(x[3] >>> 16) & 0xFF]
				^ SHAviteBigCore.AES3[ x[0] >>> 24];
			t[2] =SHAviteBigCore.AES0[ x[2] & 0xFF]
				^ SHAviteBigCore.AES1[(x[3] >>> 8) & 0xFF]
				^ SHAviteBigCore.AES2[(x[0] >>> 16) & 0xFF]
				^ SHAviteBigCore.AES3[ x[1] >>> 24];
			t[3] =SHAviteBigCore.AES0[ x[3] & 0xFF]
				^ SHAviteBigCore.AES1[(x[0] >>> 8) & 0xFF]
				^ SHAviteBigCore.AES2[(x[1] >>> 16) & 0xFF]
				^ SHAviteBigCore.AES3[ x[2] >>> 24];
			x[0] = t[0] ^ this.rk[u ++];
			x[1] = t[1] ^ this.rk[u ++];
			x[2] = t[2] ^ this.rk[u ++];
			x[3] = t[3] ^ this.rk[u ++];
			t[0] =SHAviteBigCore.AES0[ x[0] & 0xFF]
				^ SHAviteBigCore.AES1[(x[1] >>> 8) & 0xFF]
				^ SHAviteBigCore.AES2[(x[2] >>> 16) & 0xFF]
				^ SHAviteBigCore.AES3[ x[3] >>> 24];
			t[1] =  SHAviteBigCore.AES0[ x[1] & 0xFF]
				^ SHAviteBigCore.AES1[(x[2] >>> 8) & 0xFF]
				^ SHAviteBigCore.AES2[(x[3] >>> 16) & 0xFF]
				^ SHAviteBigCore.AES3[ x[0] >>> 24];
			t[2] =  SHAviteBigCore.AES0[ x[2] & 0xFF]
				^ SHAviteBigCore.AES1[(x[3] >>> 8) & 0xFF]
				^ SHAviteBigCore.AES2[(x[0] >>> 16) & 0xFF]
				^ SHAviteBigCore.AES3[ x[1] >>> 24];
			t[3] =  SHAviteBigCore.AES0[ x[3] & 0xFF]
				^ SHAviteBigCore.AES1[(x[0] >>> 8) & 0xFF]
				^ SHAviteBigCore.AES2[(x[1] >>> 16) & 0xFF]
				^ SHAviteBigCore.AES3[ x[2] >>> 24];
			x[0] = t[0] ^ this.rk[u ++];
			x[1] = t[1] ^ this.rk[u ++];
			x[2] = t[2] ^ this.rk[u ++];
			x[3] = t[3] ^ this.rk[u ++];
			t[0] =SHAviteBigCore.AES0[ x[0] & 0xFF]
				^ SHAviteBigCore.AES1[(x[1] >>> 8) & 0xFF]
				^ SHAviteBigCore.AES2[(x[2] >>> 16) & 0xFF]
				^ SHAviteBigCore.AES3[ x[3] >>> 24];
			t[1] =SHAviteBigCore.AES0[ x[1] & 0xFF]
				^ SHAviteBigCore.AES1[(x[2] >>> 8) & 0xFF]
				^ SHAviteBigCore.AES2[(x[3] >>> 16) & 0xFF]
				^ SHAviteBigCore.AES3[ x[0] >>> 24];
			t[2] =SHAviteBigCore.AES0[ x[2] & 0xFF]
				^ SHAviteBigCore.AES1[(x[3] >>> 8) & 0xFF]
				^ SHAviteBigCore.AES2[(x[0] >>> 16) & 0xFF]
				^ SHAviteBigCore.AES3[ x[1] >>> 24];
			t[3] =SHAviteBigCore.AES0[ x[3] & 0xFF]
				^ SHAviteBigCore.AES1[(x[0] >>> 8) & 0xFF]
				^ SHAviteBigCore.AES2[(x[1] >>> 16) & 0xFF]
				^ SHAviteBigCore.AES3[ x[2] >>> 24];
			p[8] ^= t[0];
			p[9] ^= t[1];
			p[A] ^= t[2];
			p[B] ^= t[3];

			var tmp = p[C];
			p[C] = p[8];
			p[8] = p[4];
			p[4] = p[0];
			p[0] = tmp;
			tmp = p[D];
			p[D] = p[9];
			p[9] = p[5];
			p[5] = p[1];
			p[1] = tmp;
			tmp = p[E];
			p[E] = p[A];
			p[A] = p[6];
			p[6] = p[2];
			p[2] = tmp;
			tmp = p[F];
			p[F] = p[B];
			p[B] = p[7];
			p[7] = p[3];
			p[3] = tmp;
		}
		this.h[0x0] ^= p[0];
		this.h[0x1] ^= p[1];
		this.h[0x2] ^= p[2];
		this.h[0x3] ^= p[3];
		this.h[0x4] ^= p[4];
		this.h[0x5] ^= p[5];
		this.h[0x6] ^= p[6];
		this.h[0x7] ^= p[7];
		this.h[0x8] ^= p[8];
		this.h[0x9] ^= p[9];
		this.h[0xA] ^= p[A];
		this.h[0xB] ^= p[B];
		this.h[0xC] ^= p[C];
		this.h[0xD] ^= p[D];
		this.h[0xE] ^= p[E];
		this.h[0xF] ^= p[F];
	}

	/** @see Digest */
	public toString()
	{
		return "SHAvite-" + (this.getDigestLength() << 3);
	}
}

/**
 * <p>This class implements the SHAvite-224 digest algorithm under the
 * {@link Digest} API (in the SHAvite-3 specification, this function
 * is known as "SHAvite-3 with a 224-bit output").</p>
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
 * @version   $Revision: 222 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

export class SHAvite224 extends SHAviteSmallCore {

	/**
	 * Create the engine.
	 */
	constructor()
	{
		super();
	}

	/** The initial value for SHAvite-224. */
	private static initVal = new Int32Array([
		0x6774F31C, 0x990AE210, 0xC87D4274, 0xC9546371,
		0x62B2AEA8, 0x4B5801D8, 0x1B702860, 0x842F3017
	]);

	/** @see SHAviteSmallCore */
	getInitVal()
	{
		return SHAvite224.initVal;
	}

	/** @see Digest */
	public getDigestLength()
	{
		return 28;
	}

	/** @see Digest */
	public  copy(): Digest
	{
		return this.copyState(new SHAvite224());
	}
}

/**
 * <p>This class implements the SHAvite-256 digest algorithm under the
 * {@link Digest} API (in the SHAvite-3 specification, this function
 * is known as "SHAvite-3 with a 256-bit output").</p>
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
 * @version   $Revision: 222 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

export class SHAvite256 extends SHAviteSmallCore {

	/**
	 * Create the engine.
	 */
	constructor()
	{
		super();
	}

	/** The initial value for SHAvite-256. */
	private static initVal = new Int32Array([
		0x49BB3E47, 0x2674860D, 0xA8B392AC, 0x021AC4E6,
		0x409283CF, 0x620E5D86, 0x6D929DCB, 0x96CC2A8B
	]);

	/** @see SHAviteSmallCore */
	getInitVal()
	{
		return SHAvite256.initVal;
	}

	/** @see Digest */
	public getDigestLength()
	{
		return 32;
	}

	/** @see Digest */
	public  copy(): Digest
	{
		return this.copyState(new SHAvite256());
	}
}

/**
 * <p>This class implements the SHAvite-384 digest algorithm under the
 * {@link Digest} API (in the SHAvite-3 specification, this function
 * is known as "SHAvite-3 with a 384-bit output").</p>
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
 * @version   $Revision: 222 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

export class SHAvite384 extends SHAviteBigCore {

	/**
	 * Create the engine.
	 */
	constructor()
	{
		super();
	}

	/** The initial value for SHAvite-384. */
	private static initVal = new Int32Array([
		0x83DF1545, 0xF9AAEC13, 0xF4803CB0, 0x11FE1F47,
		0xDA6CD269, 0x4F53FCD7, 0x950529A2, 0x97908147,
		0xB0A4D7AF, 0x2B9132BF, 0x226E607D, 0x3C0F8D7C,
		0x487B3F0F, 0x04363E22, 0x0155C99C, 0xEC2E20D3
	]);

	/** @see SHAviteBigCore */
	getInitVal()
	{
		return SHAvite384.initVal;
	}

	/** @see Digest */
	public getDigestLength()
	{
		return 48;
	}

	/** @see Digest */
	public  copy(): Digest
	{
		return this.copyState(new SHAvite384());
	}
}

/**
 * <p>This class implements the SHAvite-512 digest algorithm under the
 * {@link Digest} API (in the SHAvite-3 specification, this function
 * is known as "SHAvite-3 with a 512-bit output").</p>
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
 * @version   $Revision: 222 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

export class SHAvite512 extends SHAviteBigCore {

	/**
	 * Create the engine.
	 */
	constructor()
	{
		super();
	}

	/** The initial value for SHAvite-512. */
	private static initVal = new Int32Array([
		0x72FCCDD8, 0x79CA4727, 0x128A077B, 0x40D55AEC,
		0xD1901A06, 0x430AE307, 0xB29F5CD1, 0xDF07FBFC,
		0x8E45D73D, 0x681AB538, 0xBDE86578, 0xDD577E47,
		0xE275EADE, 0x502D9FCD, 0xB9357178, 0x022A4B9A
	]);

	/** @see SHAviteBigCore */
	getInitVal()
	{
		return SHAvite512.initVal;
	}

	/** @see Digest */
	public getDigestLength()
	{
		return 64;
	}

	/** @see Digest */
	public  copy(): Digest
	{
		return this.copyState(new SHAvite512());
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
 * Creates a vary byte length SHAvite hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {224 | 256 | 384 | 512} bitLen - length of hash (default 512 bits AKA 64 bytes)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function _SHAVITE(message: InputData, bitLen: 224|256|384|512 = 256, format: OutputFormat = arrayType()){
    var hash;
    switch (bitLen) {
        case 224:
            hash = new SHAvite224();
            break;
        case 256:
            hash = new SHAvite256();
            break;
        case 384:
            hash = new SHAvite384();
            break;
        case 512:
            hash = new SHAvite512();
            break;
        default:
            hash = new SHAvite512();
            break;
    }
    hash.update(formatMessage(message));
    const digestbytes = hash.digest() as Uint8Array;
    if(format == "buffer"){
        return Buffer.from(digestbytes);
    } else if(format == "hex"){
        return toHex(digestbytes);
    }
    return digestbytes;
};

/**
 * Creates a vary byte length keyed SHAvite hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {224 | 256 | 384 | 512} bitLen - length of hash (default 512 bits AKA 64 bytes)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function SHAVITE_HMAC(message: InputData, key: InputData, bitLen: 224|256|384|512 = 256, format: OutputFormat = arrayType()){
    var hash;
    switch (bitLen) {
        case 224:
            hash = new SHAvite224();
            break;
        case 256:
            hash = new SHAvite256();
            break;
        case 384:
            hash = new SHAvite384();
            break;
        case 512:
            hash = new SHAvite512();
            break;
        default:
            hash = new SHAvite512();
            break;
    }
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
 * Creates a 28 byte SHAvite hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function SHAVITE224(message: InputData, format: OutputFormat = arrayType()){
    const hash = new SHAvite224();
    hash.update(formatMessage(message));
    const digestbytes = hash.digest() as Uint8Array;
    if(format == "buffer"){
        return Buffer.from(digestbytes);
    } else if(format == "hex"){
        return toHex(digestbytes);
    }
    return digestbytes;
};

/**
 * Creates a 28 byte keyed SHAvite hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function SHAVITE224_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType()){
    const hash = new SHAvite224();
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
 * Creates a 32 byte SHAvite hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function SHAVITE256(message: InputData, format: OutputFormat = arrayType()){
    const hash = new SHAvite256();
    hash.update(formatMessage(message));
    const digestbytes = hash.digest() as Uint8Array;
    if(format == "buffer"){
        return Buffer.from(digestbytes);
    } else if(format == "hex"){
        return toHex(digestbytes);
    }
    return digestbytes;
};

/**
 * Creates a 32 byte keyed SHAvite hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function SHAVITE256_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType()){
    const hash = new SHAvite256();
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
 * Creates a 48 byte SHAvite hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function SHAVITE384(message: InputData, format: OutputFormat = arrayType()){
    const hash = new SHAvite384();
    hash.update(formatMessage(message));
    const digestbytes = hash.digest() as Uint8Array;
    if(format == "buffer"){
        return Buffer.from(digestbytes);
    } else if(format == "hex"){
        return toHex(digestbytes);
    }
    return digestbytes;
};

/**
 * Creates a 48 byte keyed SHAvite hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function SHAVITE384_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType()){
    const hash = new SHAvite384();
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
 * Creates a 64 byte SHAvite hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function SHAVITE512(message: InputData, format: OutputFormat = arrayType()){
    const hash = new SHAvite512();
    hash.update(formatMessage(message));
    const digestbytes = hash.digest() as Uint8Array;
    if(format == "buffer"){
        return Buffer.from(digestbytes);
    } else if(format == "hex"){
        return toHex(digestbytes);
    }
    return digestbytes;
};

/**
 * Creates a 64 byte keyed SHAvite hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function SHAVITE512_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType()){
    const hash = new SHAvite512();
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
 * Static class of all SHAvite functions and classes
 */
export class SHAVITE{
    static SHAVITE = _SHAVITE;
    static SHAvite224 = SHAvite224;
    static SHAVITE224 = SHAVITE224;
    static SHAVITE224_HMAC = SHAVITE224_HMAC;
    static SHAvite256 = SHAvite256;
    static SHAVITE256 =      SHAVITE256;
    static SHAVITE256_HMAC = SHAVITE256_HMAC;
    static SHAvite384 = SHAvite384;
    static SHAVITE384 =      SHAVITE384;
    static SHAVITE384_HMAC = SHAVITE384_HMAC;
    static SHAvite512 = SHAvite512;
    static SHAVITE512 =      SHAVITE512;
    static SHAVITE512_HMAC = SHAVITE512_HMAC;

    static SHAVITE_HMAC = SHAVITE_HMAC;
    /**
     * List of all hashes in class
     */
    static get FUNCTION_LIST() {
        return [
            "SHAVITE",
            "SHAVITE224",
            "SHAVITE224_HMAC",

            "SHAVITE256",
            "SHAVITE256_HMAC",

            "SHAVITE384",
            "SHAVITE384_HMAC",

            "SHAVITE512",
            "SHAVITE512_HMAC",

            "SHAVITE_HMAC",
        ]
    }
}