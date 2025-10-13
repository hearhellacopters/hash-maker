type LSHAlgorithm = "LSH256_224" | "LSH256_256" | "LSH512_224" | "LSH512_256" | "LSH512_384" | "LSH512_512";

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

function toU32(inner: Uint8Array, inOff: number, out: Int32Array, outOff: number, length: number) {
	for (let idx = outOff; idx < outOff + length; ++idx, ++inOff) {
		out[idx] = inner[inOff] & 0xff;
		out[idx] |= (inner[++inOff] & 0xff) << 8;
		out[idx] |= (inner[++inOff] & 0xff) << 16;
		out[idx] |= (inner[++inOff] & 0xff) << 24;
	}
}


function toU64(inner: Uint8Array, inOff: number, out: BigInt64Array, outOff: number, length: number) {
	for (let idx = outOff; idx < outOff + length; ++idx, ++inOff) {
		out[idx] = BigInt(inner[inOff] & 0xff);
		out[idx] |= BigInt((inner[++inOff] & 0xff)) << BigInt(8);
		out[idx] |= BigInt((inner[++inOff] & 0xff)) << BigInt(16);
		out[idx] |= BigInt((inner[++inOff] & 0xff)) << BigInt(24);
		out[idx] |= BigInt((inner[++inOff] & 0xff)) << BigInt(32);
		out[idx] |= BigInt((inner[++inOff] & 0xff)) << BigInt(40);
		out[idx] |= BigInt((inner[++inOff] & 0xff)) << BigInt(48);
		out[idx] |= BigInt((inner[++inOff] & 0xff)) << BigInt(56);
	}
}

function toHex(bytes: Uint8Array): string {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
};

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

abstract class Hash {

	/**
	 * Creates and returns an object with the same output length.
	 * 
	 * @return LSHDigest object
	 */
	public abstract newInstance(): Hash;

	/**
	 * Returns the message block bit length used for internal calculations.
	 * 
	 * @return Message block bit length
	 */
	public abstract getBlockSize(): number;

	/**
	 * Returns the length of the hash output.
	 * 
	 * @return Hash output length (in bits)
	 */
	public abstract getOutlenbits(): number;

	/**
	 * Initializes internal state to prepare for computing a new message digest.
	 */
	public abstract reset(): void;

	/**
	 * mProcesses data to compute message digest.
	 * 
	 * @param data
	 *            Data to calculate message digest
	 */
	public update(data?: Uint8Array, offset?: number, lenbits?: number) {
		if (data != undefined && offset == undefined && lenbits == undefined) {
			this.update(data, 0, data.length * 8);
		}
	}

	/**
	 * Add data to calculate the final message digest.
	 * 
	 * @param data
	 *            Data to calculate message digest
	 * @param offset
	 *            Start offset of data array
	 * @param lenbits
	 *            Length of data (in bits)
	 */
	public doFinal(data?: Uint8Array, offset?: number, lenbits?: number): Uint8Array {
		if (data != undefined && lenbits != undefined && lenbits > 0) {
			this.update(data, offset, lenbits);
		}

		if (data != undefined) {
			this.update(data);
		}

		return this.doFinal();
	}

	/**
	 * Returns a hash function object corresponding to the algorithm
	 * 
	 * @param algorithm
	 *            Algorithm
	 * @return Hash function object
	 */
	public static getInstance(algorithm: LSHAlgorithm): Hash {

		var lsh

		switch (algorithm) {

			case "LSH256_224":
				lsh = new Lsh256(224);
				break;

			case "LSH256_256":
				lsh = new Lsh256(256);
				break;

			case "LSH512_224":
				lsh = new Lsh512(224);
				break;

			case "LSH512_256":
				lsh = new Lsh512(256);
				break;

			case "LSH512_384":
				lsh = new Lsh512(384);
				break;

			case 'LSH512_512':
				lsh = new Lsh512(512);
				break;
			default:
				throw new Error("Unsupported algorithm");
		}

		return lsh;
	}

	/**
	 * Calculate hash using algorithm
	 */
	public static digest(arg1: LSHAlgorithm | number, arg2?: Uint8Array | number, arg3?: Uint8Array | number, arg4?: number, arg5?: number): any {
		if (typeof arg1 == "string" && typeof arg2 != "number" && (arg3 == undefined || arg4 == undefined)) {
			// Algorithm algorithm, byte[] data
			return this.digest(arg1, arg2, 0, arg2 == undefined ? 0 : arg2.length << 3);
		} else if (typeof arg1 == "string" && typeof arg2 != "number" && typeof arg3 == "number") {
			// Algorithm algorithm, byte[] data, int offset, int lenbits
			const lsh = Hash.getInstance(arg1);
			lsh.update(arg2, arg3, arg4);
			return lsh.doFinal();
		} else if (typeof arg1 == "number" && typeof arg2 == "number" && typeof arg3 != "number") {
			// int wordlenbits, int hashlenbits, byte[] data
			return this.digest(arg1, arg2, arg2, 0, arg3 == undefined ? 0 : arg3.length * 8);
		} else {
			// int wordlenbits, int hashlenbits, byte[] data, int offset, int lenbits
			var lsh;
			if (arg1 == 256) {
				lsh = new Lsh256(arg2 as number);
			} else if (arg1 == 512) {
				lsh = new Lsh512(arg2 as number);
			} else {
				throw new Error("Unsupported wordlenbits");
			}

			lsh.update(arg3 as Uint8Array, arg4 as number, arg5 as number);
			return lsh.doFinal();
		}
	}
}

/**
 * LSH256 algorithm implementation
 * 
 * Word length: 32-bit (4-byte) Chain variable length: 512-bit (64-byte) Message block length: 1024-bit
 * (128-byte)
 */
export class Lsh256 extends Hash {

	private BLOCKSIZE = 128;

	private NUMSTEP = 26;

	/// IV for precomputed 224-bit output
	private static IV224 = new Int32Array([
		0x068608D3, 0x62D8F7A7, 0xD76652AB, 0x4C600A43, 0xBDC40AA8, 0x1ECA0B68, 0xDA1A89BE, 0x3147D354,
		0x707EB4F9, 0xF65B3862, 0x6B0B2ABE, 0x56B8EC0A, 0xCF237286, 0xEE0D1727, 0x33636595, 0x8BB8D05F,
	]);

	/// IV for precomputed 256-bit output
	private static IV256 = new Int32Array([
		0x46a10f1f, 0xfddce486, 0xb41443a8, 0x198e6b9d, 0x3304388d, 0xb0f5a3c7, 0xb36061c4, 0x7adbd553,
		0x105d5378, 0x2f74de54, 0x5c2f2d95, 0xf2553fbe, 0x8051357a, 0x138668c8, 0x47aa4484, 0xe01afb41
	]);

	/// STEP constant
	private static STEP = new Int32Array([
		0x917caf90, 0x6c1b10a2, 0x6f352943, 0xcf778243, 0x2ceb7472, 0x29e96ff2, 0x8a9ba428, 0x2eeb2642,
		0x0e2c4021, 0x872bb30e, 0xa45e6cb2, 0x46f9c612, 0x185fe69e, 0x1359621b, 0x263fccb2, 0x1a116870,
		0x3a6c612f, 0xb2dec195, 0x02cb1f56, 0x40bfd858, 0x784684b6, 0x6cbb7d2e, 0x660c7ed8, 0x2b79d88a,
		0xa6cd9069, 0x91a05747, 0xcdea7558, 0x00983098, 0xbecb3b2e, 0x2838ab9a, 0x728b573e, 0xa55262b5,
		0x745dfa0f, 0x31f79ed8, 0xb85fce25, 0x98c8c898, 0x8a0669ec, 0x60e445c2, 0xfde295b0, 0xf7b5185a,
		0xd2580983, 0x29967709, 0x182df3dd, 0x61916130, 0x90705676, 0x452a0822, 0xe07846ad, 0xaccd7351,
		0x2a618d55, 0xc00d8032, 0x4621d0f5, 0xf2f29191, 0x00c6cd06, 0x6f322a67, 0x58bef48d, 0x7a40c4fd,
		0x8beee27f, 0xcd8db2f2, 0x67f2c63b, 0xe5842383, 0xc793d306, 0xa15c91d6, 0x17b381e5, 0xbb05c277,
		0x7ad1620a, 0x5b40a5bf, 0x5ab901a2, 0x69a7a768, 0x5b66d9cd, 0xfdee6877, 0xcb3566fc, 0xc0c83a32,
		0x4c336c84, 0x9be6651a, 0x13baa3fc, 0x114f0fd1, 0xc240a728, 0xec56e074, 0x009c63c7, 0x89026cf2,
		0x7f9ff0d0, 0x824b7fb5, 0xce5ea00f, 0x605ee0e2, 0x02e7cfea, 0x43375560, 0x9d002ac7, 0x8b6f5f7b,
		0x1f90c14f, 0xcdcb3537, 0x2cfeafdd, 0xbf3fc342, 0xeab7b9ec, 0x7a8cb5a3, 0x9d2af264, 0xfacedb06,
		0xb052106e, 0x99006d04, 0x2bae8d09, 0xff030601, 0xa271a6d6, 0x0742591d, 0xc81d5701, 0xc9a9e200,
		0x02627f1e, 0x996d719d, 0xda3b9634, 0x02090800, 0x14187d78, 0x499b7624, 0xe57458c9, 0x738be2c9,
		0x64e19d20, 0x06df0f36, 0x15d1cb0e, 0x0b110802, 0x2c95f58c, 0xe5119a6d, 0x59cd22ae, 0xff6eac3c,
		0x467ebd84, 0xe5ee453c, 0xe79cd923, 0x1c190a0d, 0xc28b81b8, 0xf6ac0852, 0x26efd107, 0x6e1ae93b,
		0xc53c41ca, 0xd4338221, 0x8475fd0a, 0x35231729, 0x4e0d3a7a, 0xa2b45b48, 0x16c0d82d, 0x890424a9,
		0x017e0c8f, 0x07b5a3f5, 0xfa73078e, 0x583a405e, 0x5b47b4c8, 0x570fa3ea, 0xd7990543, 0x8d28ce32,
		0x7f8a9b90, 0xbd5998fc, 0x6d7a9688, 0x927a9eb6, 0xa2fc7d23, 0x66b38e41, 0x709e491a, 0xb5f700bf,
		0x0a262c0f, 0x16f295b9, 0xe8111ef5, 0x0d195548, 0x9f79a0c5, 0x1a41cfa7, 0x0ee7638a, 0xacf7c074,
		0x30523b19, 0x09884ecf, 0xf93014dd, 0x266e9d55, 0x191a6664, 0x5c1176c1, 0xf64aed98, 0xa4b83520,
		0x828d5449, 0x91d71dd8, 0x2944f2d6, 0x950bf27b, 0x3380ca7d, 0x6d88381d, 0x4138868e, 0x5ced55c4,
		0x0fe19dcb, 0x68f4f669, 0x6e37c8ff, 0xa0fe6e10, 0xb44b47b0, 0xf5c0558a, 0x79bf14cf, 0x4a431a20,
		0xf17f68da, 0x5deb5fd1, 0xa600c86d, 0x9f6c7eb0, 0xff92f864, 0xb615e07f, 0x38d3e448, 0x8d5d3a6a,
		0x70e843cb, 0x494b312e, 0xa6c93613, 0x0beb2f4f, 0x928b5d63, 0xcbf66035, 0x0cb82c80, 0xea97a4f7,
		0x592c0f3b, 0x947c5f77, 0x6fff49b9, 0xf71a7e5a, 0x1de8c0f5, 0xc2569600, 0xc4e4ac8c, 0x823c9ce1
	]);

	private ALPHA_EVEN = 29;
	private ALPHA_ODD = 5;

	private BETA_EVEN = 1;
	private BETA_ODD = 17;

	private static GAMMA = new Int32Array([0, 8, 16, 24, 24, 16, 8, 0]);

	private cv!: Int32Array;
	private tcv!: Int32Array;
	private msg!: Int32Array;
	private block!: Uint8Array;

	private boff!: number;
	private outlenbits!: number;

	/**
	 * LSH256 constructor
	 * 
	 * Default constructor, 256-bit output setting
	 * 
	 * @param outlenbits
	 *            Output length, in bits
	 */
	constructor(outlenbits?: number) {
		super();
		if (outlenbits == undefined) {
			outlenbits = 256;
		}
		if (outlenbits < 0 || outlenbits > 256) {
			throw new Error("invalid hash length");
		}

		this.cv = new Int32Array(16);
		this.tcv = new Int32Array(16);
		this.msg = new Int32Array(16 * (this.NUMSTEP + 1));
		this.block = new Uint8Array(this.BLOCKSIZE);
		this.outlenbits = outlenbits;

		this.init();
	}

	/**
	 * Creates and returns an object with the same output length.
	 * 
	 * @return LSH256 object
	 */
	public newInstance(): Hash {
		return new Lsh256(this.outlenbits) as Hash;
	}

	private init() {
		this.boff = 0;

		switch (this.outlenbits) {
			case 224:
				arraycopy(Lsh256.IV224, 0, this.cv, 0, this.cv.length);
				break;

			case 256:
				arraycopy(Lsh256.IV256, 0, this.cv, 0, this.cv.length);
				break;

			default:
				this.generateIV();
				break;
		}
	}

	/**
	 * Returns the internal block size.
	 * 
	 * @return Internal block size
	 */
	public getBlockSize() {
		return this.BLOCKSIZE;
	}

	/**
	 * Returns the output length.
	 * 
	 * @return Output length, in bits
	 */
	public getOutlenbits() {
		return this.outlenbits;
	}

	/**
	 * Initialize state variables
	 */
	public reset() {
		for (let i = 0; i < this.tcv.length; i++) {
			this.tcv[i] = 0;
		}
		for (let i = 0; i < this.msg.length; i++) {
			this.msg[i] = 0;
		}
		for (let i = 0; i < this.block.length; i++) {
			this.block[i] = 0;
		}

		this.init();
	}

	/**
	 * Message handling functions for online operations
	 * 
	 * @param data
	 *            data
	 * @param offset
	 *            Data start offset
	 * @param lenbits
	 *            Data length (bits)
	 */
	public update(data: Uint8Array, offset?: number, lenbits?: number) {
		if (data != undefined && offset == undefined && lenbits == undefined) {
			this.update(data, 0, data.length * 8);
		} else {
			if (data == undefined || data.length == 0) {
				return;
			}
			lenbits = lenbits as number;
			offset = offset as number;

			var rbytes = lenbits >> 3;
			var rbits = lenbits & 0x7;
			var blkidx = this.boff >> 3;

			if ((this.boff & 0x7) > 0) {
				throw new Error("bit level update is not allowed");
			}

			var gap = this.BLOCKSIZE - blkidx;
			if (blkidx > 0 && rbytes >= gap) {
				arraycopy(data, offset, this.block, blkidx, gap);
				this.compress(this.block, 0);
				this.boff = 0;
				rbytes -= gap;
				offset += gap;
			}

			while (rbytes >= this.block.length) {
				this.compress(data, offset);
				this.boff = 0;
				offset += this.BLOCKSIZE;
				rbytes -= this.BLOCKSIZE;
			}

			if (rbytes > 0) {
				blkidx = this.boff >> 3;
				arraycopy(data, offset, this.block, blkidx, rbytes);
				this.boff += rbytes << 3;
				offset += rbytes;
			}

			if (rbits > 0) {
				blkidx = this.boff >> 3;
				this.block[blkidx] = (data[offset] & ((0xff >> rbits) ^ 0xff));
				this.boff += rbits;
			}
		}
	}

	/**
	 * Update the final internal state and return the hash value.
	 * 
	 * @return Hash value
	 */
	public doFinal(data?: Uint8Array, offset?: number, lenbits?: number): Uint8Array {
		if (data != undefined && lenbits != undefined && lenbits > 0) {
			this.update(data, offset, lenbits);
		} else if (data != undefined) {
			this.update(data);
		}

		var rbytes = this.boff >> 3;
		var rbits = this.boff & 0x7;

		if (rbits > 0) {
			this.block[rbytes] |= (0x1 << (7 - rbits));
		} else {
			this.block[rbytes] = 0x80;
		}

		//Arrays.fill(block, rbytes + 1, block.length, (byte) 0);
		for (let i = (rbytes + 1); i < this.block.length; i++) {
			this.block[i] = 0;
		}

		this.compress(this.block, 0);

		const temp = new Int32Array(8);
		for (let i = 0; i < temp.length; ++i) {
			temp[i] = this.cv[i] ^ this.cv[i + 8];
		}

		this.reset();

		rbytes = this.outlenbits >> 3;
		rbits = this.outlenbits & 0x7;
		const result = new Uint8Array(rbits > 0 ? rbytes + 1 : rbytes);
		for (let i = 0; i < result.length; ++i) {
			result[i] = (temp[i >> 2] >> ((i << 3) & 0x1f));
		}

		if (rbits > 0) {
			result[rbytes] &= 0xff << (8 - rbits);
		}

		return result;
	}

	/**
	 * IV generation
	 */
	private generateIV() {
		for (let i = 0; i < this.cv.length; i++) {
			this.cv[i] = 0;
		}
		for (let i = 0; i < this.block.length; i++) {
			this.block[i] = 0;
		}

		this.cv[0] = 32;
		this.cv[1] = this.outlenbits;

		this.compress(this.block, 0);
	}

	/**
	 * Compression operation of the LSH algorithm
	 * 
	 * @param data
	 *            data
	 * @param offset
	 *            Data start offset
	 */
	private compress(data: Uint8Array, offset: number) {
		this.msgExpansion(data, offset);

		for (let i = 0; i < this.NUMSTEP / 2; ++i) {
			this.step(2 * i, this.ALPHA_EVEN, this.BETA_EVEN);
			this.step(2 * i + 1, this.ALPHA_ODD, this.BETA_ODD);
		}

		// msg add
		for (let i = 0; i < 16; ++i) {
			this.cv[i] ^= this.msg[16 * this.NUMSTEP + i];
		}
	}

	/**
	 * Message expansion operation used in the Compress function, processing BLOCKSIZE units at a time
	 * 
	 * @param in
	 *            data
	 * @param offset
	 *            Data start offset (bytes)
	 */
	private msgExpansion(inner: Uint8Array, offset: number) {
		toU32(inner, offset, this.msg, 0, 32);

		for (let i = 2; i <= this.NUMSTEP; ++i) {
			var idx = 16 * i;
			this.msg[idx] = this.msg[idx - 16] + this.msg[idx - 29];
			this.msg[idx + 1] = this.msg[idx - 15] + this.msg[idx - 30];
			this.msg[idx + 2] = this.msg[idx - 14] + this.msg[idx - 32];
			this.msg[idx + 3] = this.msg[idx - 13] + this.msg[idx - 31];
			this.msg[idx + 4] = this.msg[idx - 12] + this.msg[idx - 25];
			this.msg[idx + 5] = this.msg[idx - 11] + this.msg[idx - 28];
			this.msg[idx + 6] = this.msg[idx - 10] + this.msg[idx - 27];
			this.msg[idx + 7] = this.msg[idx - 9] + this.msg[idx - 26];
			this.msg[idx + 8] = this.msg[idx - 8] + this.msg[idx - 21];
			this.msg[idx + 9] = this.msg[idx - 7] + this.msg[idx - 22];
			this.msg[idx + 10] = this.msg[idx - 6] + this.msg[idx - 24];
			this.msg[idx + 11] = this.msg[idx - 5] + this.msg[idx - 23];
			this.msg[idx + 12] = this.msg[idx - 4] + this.msg[idx - 17];
			this.msg[idx + 13] = this.msg[idx - 3] + this.msg[idx - 20];
			this.msg[idx + 14] = this.msg[idx - 2] + this.msg[idx - 19];
			this.msg[idx + 15] = this.msg[idx - 1] + this.msg[idx - 18];
		}
	}

	/**
	 * Message add & mix operations used in the Compress function
	 * 
	 * @param stepidx
	 *            Step Index
	 * @param alpha
	 *            Left rotation value to apply to the upper 8 words
	 * @param beta
	 *            Left rotation value to apply to the lower 8 words
	 */
	private step(stepidx: number, alpha: number, beta: number) {
		var vl, vr;
		for (let colidx = 0; colidx < 8; ++colidx) {
			vl = this.cv[colidx] ^ this.msg[16 * stepidx + colidx];
			vr = this.cv[colidx + 8] ^ this.msg[16 * stepidx + colidx + 8];
			vl = this.rol32(vl + vr, alpha) ^ Lsh256.STEP[8 * stepidx + colidx];
			vr = this.rol32(vl + vr, beta);
			this.tcv[colidx] = vr + vl;
			this.tcv[colidx + 8] = this.rol32(vr, Lsh256.GAMMA[colidx]);
		}

		this.wordPermutation();
	}

	/**
	 * LSH's word permutation operation
	 */
	private wordPermutation() {
		this.cv[0] = this.tcv[6];
		this.cv[1] = this.tcv[4];
		this.cv[2] = this.tcv[5];
		this.cv[3] = this.tcv[7];
		this.cv[4] = this.tcv[12];
		this.cv[5] = this.tcv[15];
		this.cv[6] = this.tcv[14];
		this.cv[7] = this.tcv[13];
		this.cv[8] = this.tcv[2];
		this.cv[9] = this.tcv[0];
		this.cv[10] = this.tcv[1];
		this.cv[11] = this.tcv[3];
		this.cv[12] = this.tcv[8];
		this.cv[13] = this.tcv[11];
		this.cv[14] = this.tcv[10];
		this.cv[15] = this.tcv[9];
	}

	/**
	 * 332-bit left rotation operation
	 * 
	 * @param value
	 *            operand
	 * @param rot
	 *            Rotation value
	 * @return The value rotated left by rot
	 */
	private rol32(value: number, rot: number) {
		return (value << rot) | (value >>> (32 - rot));
	}
}

/**
 * LSH512 algorithm implementation
 * 
 * Word length: 64-bit (8-byte) Chain variable length: 1024-bit (128-byte) Message block length: 2048-bit
 * (256-byte)
 */
export class Lsh512 extends Hash {

	private BLOCKSIZE = 256;

	private NUMSTEP = 28;

	/// IV for precomputed 224-bit output
	private static IV224 = new BigInt64Array([
		BigInt("0x0c401e9fe8813a55"), BigInt("0x4a5f446268fd3d35"), BigInt("0xff13e452334f612a"), BigInt("0xf8227661037e354a"),
		BigInt("0xa5f223723c9ca29d"), BigInt("0x95d965a11aed3979"), BigInt("0x01e23835b9ab02cc"), BigInt("0x52d49cbad5b30616"),
		BigInt("0x9e5c2027773f4ed3"), BigInt("0x66a5c8801925b701"), BigInt("0x22bbc85b4c6779d9"), BigInt("0xc13171a42c559c23"),
		BigInt("0x31e2b67d25be3813"), BigInt("0xd522c4deed8e4d83"), BigInt("0xa79f5509b43fbafe"), BigInt("0xe00d2cd88b4b6c6a"),
	]);

	/// IV for precomputed 256-bit output
	private static IV256 = new BigInt64Array([
		BigInt("0x6dc57c33df989423"), BigInt("0xd8ea7f6e8342c199"), BigInt("0x76df8356f8603ac4"), BigInt("0x40f1b44de838223a"),
		BigInt("0x39ffe7cfc31484cd"), BigInt("0x39c4326cc5281548"), BigInt("0x8a2ff85a346045d8"), BigInt("0xff202aa46dbdd61e"),
		BigInt("0xcf785b3cd5fcdb8b"), BigInt("0x1f0323b64a8150bf"), BigInt("0xff75d972f29ea355"), BigInt("0x2e567f30bf1ca9e1"),
		BigInt("0xb596875bf8ff6dba"), BigInt("0xfcca39b089ef4615"), BigInt("0xecff4017d020b4b6"), BigInt("0x7e77384c772ed802"),
	]);

	/// IV for precomputed 384-bit output
	private static IV384 = new BigInt64Array([
		BigInt("0x53156a66292808f6"), BigInt("0xb2c4f362b204c2bc"), BigInt("0xb84b7213bfa05c4e"), BigInt("0x976ceb7c1b299f73"),
		BigInt("0xdf0cc63c0570ae97"), BigInt("0xda4441baa486ce3f"), BigInt("0x6559f5d9b5f2acc2"), BigInt("0x22dacf19b4b52a16"),
		BigInt("0xbbcdacefde80953a"), BigInt("0xc9891a2879725b3e"), BigInt("0x7c9fe6330237e440"), BigInt("0xa30ba550553f7431"),
		BigInt("0xbb08043fb34e3e30"), BigInt("0xa0dec48d54618ead"), BigInt("0x150317267464bc57"), BigInt("0x32d1501fde63dc93"),
	]);

	/// IV for precomputed 512-bit output
	private static IV512 = new BigInt64Array([
		BigInt("0xadd50f3c7f07094e"), BigInt("0xe3f3cee8f9418a4f"), BigInt("0xb527ecde5b3d0ae9"), BigInt("0x2ef6dec68076f501"),
		BigInt("0x8cb994cae5aca216"), BigInt("0xfbb9eae4bba48cc7"), BigInt("0x650a526174725fea"), BigInt("0x1f9a61a73f8d8085"),
		BigInt("0xb6607378173b539b"), BigInt("0x1bc99853b0c0b9ed"), BigInt("0xdf727fc19b182d47"), BigInt("0xdbef360cf893a457"),
		BigInt("0x4981f5e570147e80"), BigInt("0xd00c4490ca7d3e30"), BigInt("0x5d73940c0e4ae1ec"), BigInt("0x894085e2edb2d819"),
	]);

	/// STEP constant
	private static STEP = new BigInt64Array([
		BigInt("0x97884283c938982a"), BigInt("0xba1fca93533e2355"), BigInt("0xc519a2e87aeb1c03"), BigInt("0x9a0fc95462af17b1"),
		BigInt("0xfc3dda8ab019a82b"), BigInt("0x02825d079a895407"), BigInt("0x79f2d0a7ee06a6f7"), BigInt("0xd76d15eed9fdf5fe"),
		BigInt("0x1fcac64d01d0c2c1"), BigInt("0xd9ea5de69161790f"), BigInt("0xdebc8b6366071fc8"), BigInt("0xa9d91db711c6c94b"),
		BigInt("0x3a18653ac9c1d427"), BigInt("0x84df64a223dd5b09"), BigInt("0x6cc37895f4ad9e70"), BigInt("0x448304c8d7f3f4d5"),
		BigInt("0xea91134ed29383e0"), BigInt("0xc4484477f2da88e8"), BigInt("0x9b47eec96d26e8a6"), BigInt("0x82f6d4c8d89014f4"),
		BigInt("0x527da0048b95fb61"), BigInt("0x644406c60138648d"), BigInt("0x303c0e8aa24c0edc"), BigInt("0xc787cda0cbe8ca19"),
		BigInt("0x7ba46221661764ca"), BigInt("0x0c8cbc6acd6371ac"), BigInt("0xe336b836940f8f41"), BigInt("0x79cb9da168a50976"),
		BigInt("0xd01da49021915cb3"), BigInt("0xa84accc7399cf1f1"), BigInt("0x6c4a992cee5aeb0c"), BigInt("0x4f556e6cb4b2e3e0"),
		BigInt("0x200683877d7c2f45"), BigInt("0x9949273830d51db8"), BigInt("0x19eeeecaa39ed124"), BigInt("0x45693f0a0dae7fef"),
		BigInt("0xedc234b1b2ee1083"), BigInt("0xf3179400d68ee399"), BigInt("0xb6e3c61b4945f778"), BigInt("0xa4c3db216796c42f"),
		BigInt("0x268a0b04f9ab7465"), BigInt("0xe2705f6905f2d651"), BigInt("0x08ddb96e426ff53d"), BigInt("0xaea84917bc2e6f34"),
		BigInt("0xaff6e664a0fe9470"), BigInt("0x0aab94d765727d8c"), BigInt("0x9aa9e1648f3d702e"), BigInt("0x689efc88fe5af3d3"),
		BigInt("0xb0950ffea51fd98b"), BigInt("0x52cfc86ef8c92833"), BigInt("0xe69727b0b2653245"), BigInt("0x56f160d3ea9da3e2"),
		BigInt("0xa6dd4b059f93051f"), BigInt("0xb6406c3cd7f00996"), BigInt("0x448b45f3ccad9ec8"), BigInt("0x079b8587594ec73b"),
		BigInt("0x45a50ea3c4f9653b"), BigInt("0x22983767c1f15b85"), BigInt("0x7dbed8631797782b"), BigInt("0x485234be88418638"),
		BigInt("0x842850a5329824c5"), BigInt("0xf6aca914c7f9a04c"), BigInt("0xcfd139c07a4c670c"), BigInt("0xa3210ce0a8160242"),
		BigInt("0xeab3b268be5ea080"), BigInt("0xbacf9f29b34ce0a7"), BigInt("0x3c973b7aaf0fa3a8"), BigInt("0x9a86f346c9c7be80"),
		BigInt("0xac78f5d7cabcea49"), BigInt("0xa355bddcc199ed42"), BigInt("0xa10afa3ac6b373db"), BigInt("0xc42ded88be1844e5"),
		BigInt("0x9e661b271cff216a"), BigInt("0x8a6ec8dd002d8861"), BigInt("0xd3d2b629beb34be4"), BigInt("0x217a3a1091863f1a"),
		BigInt("0x256ecda287a733f5"), BigInt("0xf9139a9e5b872fe5"), BigInt("0xac0535017a274f7c"), BigInt("0xf21b7646d65d2aa9"),
		BigInt("0x048142441c208c08"), BigInt("0xf937a5dd2db5e9eb"), BigInt("0xa688dfe871ff30b7"), BigInt("0x9bb44aa217c5593b"),
		BigInt("0x943c702a2edb291a"), BigInt("0x0cae38f9e2b715de"), BigInt("0xb13a367ba176cc28"), BigInt("0x0d91bd1d3387d49b"),
		BigInt("0x85c386603cac940c"), BigInt("0x30dd830ae39fd5e4"), BigInt("0x2f68c85a712fe85d"), BigInt("0x4ffeecb9dd1e94d6"),
		BigInt("0xd0ac9a590a0443ae"), BigInt("0xbae732dc99ccf3ea"), BigInt("0xeb70b21d1842f4d9"), BigInt("0x9f4eda50bb5c6fa8"),
		BigInt("0x4949e69ce940a091"), BigInt("0x0e608dee8375ba14"), BigInt("0x983122cba118458c"), BigInt("0x4eeba696fbb36b25"),
		BigInt("0x7d46f3630e47f27e"), BigInt("0xa21a0f7666c0dea4"), BigInt("0x5c22cf355b37cec4"), BigInt("0xee292b0c17cc1847"),
		BigInt("0x9330838629e131da"), BigInt("0x6eee7c71f92fce22"), BigInt("0xc953ee6cb95dd224"), BigInt("0x3a923d92af1e9073"),
		BigInt("0xc43a5671563a70fb"), BigInt("0xbc2985dd279f8346"), BigInt("0x7ef2049093069320"), BigInt("0x17543723e3e46035"),
		BigInt("0xc3b409b00b130c6d"), BigInt("0x5d6aee6b28fdf090"), BigInt("0x1d425b26172ff6ed"), BigInt("0xcccfd041cdaf03ad"),
		BigInt("0xfe90c7c790ab6cbf"), BigInt("0xe5af6304c722ca02"), BigInt("0x70f695239999b39e"), BigInt("0x6b8b5b07c844954c"),
		BigInt("0x77bdb9bb1e1f7a30"), BigInt("0xc859599426ee80ed"), BigInt("0x5f9d813d4726e40a"), BigInt("0x9ca0120f7cb2b179"),
		BigInt("0x8f588f583c182cbd"), BigInt("0x951267cbe9eccce7"), BigInt("0x678bb8bd334d520e"), BigInt("0xf6e662d00cd9e1b7"),
		BigInt("0x357774d93d99aaa7"), BigInt("0x21b2edbb156f6eb5"), BigInt("0xfd1ebe846e0aee69"), BigInt("0x3cb2218c2f642b15"),
		BigInt("0xe7e7e7945444ea4c"), BigInt("0xa77a33b5d6b9b47c"), BigInt("0xf34475f0809f6075"), BigInt("0xdd4932dce6bb99ad"),
		BigInt("0xacec4e16d74451dc"), BigInt("0xd4a0a8d084de23d6"), BigInt("0x1bdd42f278f95866"), BigInt("0xeed3adbb938f4051"),
		BigInt("0xcfcf7be8992f3733"), BigInt("0x21ade98c906e3123"), BigInt("0x37ba66711fffd668"), BigInt("0x267c0fc3a255478a"),
		BigInt("0x993a64ee1b962e88"), BigInt("0x754979556301faaa"), BigInt("0xf920356b7251be81"), BigInt("0xc281694f22cf923f"),
		BigInt("0x9f4b6481c8666b02"), BigInt("0xcf97761cfe9f5444"), BigInt("0xf220d7911fd63e9f"), BigInt("0xa28bd365f79cd1b0"),
		BigInt("0xd39f5309b1c4b721"), BigInt("0xbec2ceb864fca51f"), BigInt("0x1955a0ddc410407a"), BigInt("0x43eab871f261d201"),
		BigInt("0xeaafe64a2ed16da1"), BigInt("0x670d931b9df39913"), BigInt("0x12f868b0f614de91"), BigInt("0x2e5f395d946e8252"),
		BigInt("0x72f25cbb767bd8f4"), BigInt("0x8191871d61a1c4dd"), BigInt("0x6ef67ea1d450ba93"), BigInt("0x2ea32a645433d344"),
		BigInt("0x9a963079003f0f8b"), BigInt("0x74a0aeb9918cac7a"), BigInt("0x0b6119a70af36fa3"), BigInt("0x8d9896f202f0d480"),
		BigInt("0x654f1831f254cd66"), BigInt("0x1318a47f0366a25e"), BigInt("0x65752076250b4e01"), BigInt("0xd1cd8eb888071772"),
		BigInt("0x30c6a9793f4e9b25"), BigInt("0x154f684b1e3926ee"), BigInt("0x6c7ac0b1fe6312ae"), BigInt("0x262f88f4f3c5550d"),
		BigInt("0xb4674a24472233cb"), BigInt("0x2bbd23826a090071"), BigInt("0xda95969b30594f66"), BigInt("0x9f5c47408f1e8a43"),
		BigInt("0xf77022b88de9c055"), BigInt("0x64b7b36957601503"), BigInt("0xe73b72b06175c11a"), BigInt("0x55b87de8b91a6233"),
		BigInt("0x1bb16e6b6955ff7f"), BigInt("0xe8e0a5ec7309719c"), BigInt("0x702c31cb89a8b640"), BigInt("0xfba387cfada8cde2"),
		BigInt("0x6792db4677aa164c"), BigInt("0x1c6b1cc0b7751867"), BigInt("0x22ae2311d736dc01"), BigInt("0x0e3666a1d37c9588"),
		BigInt("0xcd1fd9d4bf557e9a"), BigInt("0xc986925f7c7b0e84"), BigInt("0x9c5dfd55325ef6b0"), BigInt("0x9f2b577d5676b0dd"),
		BigInt("0xfa6e21be21c062b3"), BigInt("0x8787dd782c8d7f83"), BigInt("0xd0d134e90e12dd23"), BigInt("0x449d087550121d96"),
		BigInt("0xecf9ae9414d41967"), BigInt("0x5018f1dbf789934d"), BigInt("0xfa5b52879155a74c"), BigInt("0xca82d4d3cd278e7c"),
		BigInt("0x688fdfdfe22316ad"), BigInt("0x0f6555a4ba0d030a"), BigInt("0xa2061df720f000f3"), BigInt("0xe1a57dc5622fb3da"),
		BigInt("0xe6a842a8e8ed8153"), BigInt("0x690acdd3811ce09d"), BigInt("0x55adda18e6fcf446"), BigInt("0x4d57a8a0f4b60b46"),
		BigInt("0xf86fbfc20539c415"), BigInt("0x74bafa5ec7100d19"), BigInt("0xa824151810f0f495"), BigInt("0x8723432791e38ebb"),
		BigInt("0x8eeaeb91d66ed539"), BigInt("0x73d8a1549dfd7e06"), BigInt("0x0387f2ffe3f13a9b"), BigInt("0xa5004995aac15193"),
		BigInt("0x682f81c73efdda0d"), BigInt("0x2fb55925d71d268d"), BigInt("0xcc392d2901e58a3d"), BigInt("0xaa666ab975724a42")
	]);

	private ALPHA_EVEN = 23;
	private ALPHA_ODD = 7;

	private BETA_EVEN = 59;
	private BETA_ODD = 3;

	private static GAMMA = new Int32Array([0, 16, 32, 48, 8, 24, 40, 56]);

	private cv!: BigInt64Array;
	private tcv!: BigInt64Array;
	private msg!: BigInt64Array;
	private block!: Uint8Array;

	private boff!: number;
	private outlenbits!: number;

	/**
	 * LSH512 constructor
	 * 
	 * @param outlenbits
	 *            Output length, in bits
	 */
	constructor(outlenbits?: number) {
		super();
		if (outlenbits == undefined) {
			outlenbits = 512;
		}
		if (outlenbits < 0 || outlenbits > 512) {
			throw new Error("invalid hash length");
		}

		this.cv = new BigInt64Array(16);
		this.tcv = new BigInt64Array(16);
		this.msg = new BigInt64Array(16 * (this.NUMSTEP + 1));
		this.block = new Uint8Array(this.BLOCKSIZE);
		this.outlenbits = outlenbits;

		this.init();
	}

	/**
	 * Creates and returns an object with the same output length.
	 * 
	 * @return LSH512 object
	 */
	public newInstance(): Hash {
		return new Lsh512(this.outlenbits) as Hash;
	}

	private init() {
		this.boff = 0;

		switch (this.outlenbits) {
			case 224:
				arraycopy(Lsh512.IV224, 0, this.cv, 0, this.cv.length);
				break;

			case 256:
				arraycopy(Lsh512.IV256, 0, this.cv, 0, this.cv.length);
				break;

			case 384:
				arraycopy(Lsh512.IV384, 0, this.cv, 0, this.cv.length);
				break;

			case 512:
				arraycopy(Lsh512.IV512, 0, this.cv, 0, this.cv.length);
				break;

			default:
				this.generateIV();
				break;
		}
	}

	/**
	 * Return internal block size
	 * 
	 * @return Internal block size
	 */
	public getBlockSize() {
		return this.BLOCKSIZE;
	}

	/**
	 * Returns the output length.
	 * 
	 * @return Output length, in bits
	 */
	public getOutlenbits() {
		return this.outlenbits;
	}

	/**
	 * Initialize state variables
	 */
	public reset() {
		for (let i = 0; i < this.tcv.length; i++) {
			this.tcv[i] = BigInt(0);
		}
		for (let i = 0; i < this.msg.length; i++) {
			this.msg[i] = BigInt(0);
		}
		for (let i = 0; i < this.block.length; i++) {
			this.block[i] = 0;
		}
		this.init();
	}

	/**
	 * Message handling functions for online operations
	 * 
	 * @param data
	 *            data
	 * @param offset
	 *            Data start offset
	 * @param lenbits
	 *            Data length (bits)
	 */
	public update(data?: Uint8Array, offset?: number, lenbits?: number) {

		if (data != undefined && offset == undefined && lenbits == undefined) {
			this.update(data, 0, data.length * 8);

		}
		if (data == undefined || data.length == 0) {
			return;
		}

		lenbits = lenbits as number;
		offset = offset as number;

		var rbytes = lenbits >> 3;
		var rbits = lenbits & 0x7;
		var blkidx = this.boff >> 3;

		if ((this.boff & 0x7) > 0) {
			throw new Error("bit level update is not allowed");
		}

		var gap = this.BLOCKSIZE - blkidx;
		if (blkidx > 0 && rbytes >= gap) {
			arraycopy(data, offset, this.block, blkidx, gap);
			this.compress(this.block, 0);
			this.boff = 0;
			rbytes -= gap;
			offset += gap;
		}
		
		while (rbytes >= this.block.length) {
			this.compress(data, offset);
			this.boff = 0;
			offset += this.BLOCKSIZE;
			rbytes -= this.BLOCKSIZE;
		}
		
		if (rbytes > 0) {
			blkidx = this.boff >> 3;
			arraycopy(data, offset, this.block, blkidx, rbytes);
			this.boff += rbytes << 3;
			offset += rbytes;
		}

		if (rbits > 0) {
			blkidx = this.boff >> 3;
			this.block[blkidx] = (data[offset] & ((0xff >> rbits) ^ 0xff));
			this.boff += rbits;
		}
	}

	/**
	 * Update the final internal state and return the hash value.
	 * 
	 * @return Hash value
	 */
	public doFinal(data?: Uint8Array, offset?: number, lenbits?: number): Uint8Array {
		if (data != undefined && lenbits != undefined && lenbits > 0) {
			this.update(data, offset, lenbits);
		} else if (data != undefined) {
			this.update(data);
		}

		var rbytes = this.boff >> 3;
		var rbits = this.boff & 0x7;

		if (rbits > 0) {
			this.block[rbytes] |= (0x1 << (7 - rbits));
		} else {
			this.block[rbytes] = 0x80;
		}

		//Arrays.fill(block, rbytes + 1, block.length, (byte) 0);
		for (let i = (rbytes + 1); i < this.block.length; i++) {
			this.block[i] = 0;
		}
		this.compress(this.block, 0);

		const temp = new BigInt64Array(8);
		for (let i = 0; i < temp.length; ++i) {
			temp[i] = this.cv[i] ^ this.cv[i + 8];
		}

		this.reset();

		rbytes = this.outlenbits >> 3;
		rbits = this.outlenbits & 0x7;
		var result = new Uint8Array(temp.buffer);
		if(rbits > 0){
			result = result.subarray(0, rbytes + 1);
		} else {
			result = result.subarray(0, rbytes);
		}
		//for (let i = 0; i < result.length; ++i) {
		//	var value = Number(temp[i >> 3] >> BigInt((i << 3) & 0x3f)) & 0xFF;
		//	result[i] = value;
		//}

		if (rbits > 0) {
			result[rbytes] = (result[rbytes] & (0xff << (8 - rbits)));
		}

		return result;
	}

	/**
	 * IV generation
	 */
	private generateIV() {
		for (let i = 0; i < this.cv.length; i++) {
			this.cv[i] = BigInt(0);
		}
		for (let i = 0; i < this.block.length; i++) {
			this.block[i] = 0;
		}

		this.cv[0] = BigInt(64);
		this.cv[1] = BigInt(this.outlenbits);

		this.compress(this.block, 0);
	}

	/**
	 * Compression operation of the LSH algorithm
	 * 
	 * @param data
	 *            data
	 * @param offset
	 *            Data start offset
	 */
	private compress(data: Uint8Array, offset: number) {
		this.msgExpansion(data, offset);

		for (let i = 0; i < this.NUMSTEP / 2; ++i) {
			this.step(2 * i, this.ALPHA_EVEN, this.BETA_EVEN);
			this.step(2 * i + 1, this.ALPHA_ODD, this.BETA_ODD);
		}

		// msg add
		for (let i = 0; i < 16; ++i) {
			this.cv[i] ^= this.msg[16 * this.NUMSTEP + i];
		}
	}

	/**
	 * Message expansion operation used in the Compress function, processing BLOCKSIZE units at a time
	 * 
	 * @param in
	 *            data
	 * @param offset
	 *            Data start offset (bytes)
	 */
	private msgExpansion(inner: Uint8Array, offset: number) {
		toU64(inner, offset, this.msg, 0, 32);
		
		for (let i = 2; i <= this.NUMSTEP; ++i) {
			var idx = 16 * i;
			this.msg[idx] =      this.msg[idx - 16] + this.msg[idx - 29];
			this.msg[idx + 1] =  this.msg[idx - 15] + this.msg[idx - 30];
			this.msg[idx + 2] =  this.msg[idx - 14] + this.msg[idx - 32];
			this.msg[idx + 3] =  this.msg[idx - 13] + this.msg[idx - 31];
			this.msg[idx + 4] =  this.msg[idx - 12] + this.msg[idx - 25];
			this.msg[idx + 5] =  this.msg[idx - 11] + this.msg[idx - 28];
			this.msg[idx + 6] =  this.msg[idx - 10] + this.msg[idx - 27];
			this.msg[idx + 7] =  this.msg[idx - 9] +  this.msg[idx - 26];
			this.msg[idx + 8] =  this.msg[idx - 8] +  this.msg[idx - 21];
			this.msg[idx + 9] =  this.msg[idx - 7] +  this.msg[idx - 22];
			this.msg[idx + 10] = this.msg[idx - 6] +  this.msg[idx - 24];
			this.msg[idx + 11] = this.msg[idx - 5] +  this.msg[idx - 23];
			this.msg[idx + 12] = this.msg[idx - 4] +  this.msg[idx - 17];
			this.msg[idx + 13] = this.msg[idx - 3] +  this.msg[idx - 20];
			this.msg[idx + 14] = this.msg[idx - 2] +  this.msg[idx - 19];
			this.msg[idx + 15] = this.msg[idx - 1] +  this.msg[idx - 18];
		}
		
	}

	/**
	 * Message add & mix operations used in the Compress function
	 * 
	 * @param stepidx
	 *            Step Index
	 * @param alpha
	 *            Left rotation value to apply to the upper 8 words
	 * @param beta
	 *            Left rotation value to apply to the lower 8 words
	 */
	private step(stepidx: number, alpha: number, beta: number) {
		const v = new BigInt64Array(2);
		var l = 0;
		var r = 1;
		for (let colidx = 0; colidx < 8; ++colidx) {
			v[l] = this.cv[colidx] ^ this.msg[16 * stepidx + colidx];
			v[r] = this.cv[colidx + 8] ^ this.msg[16 * stepidx + colidx + 8];
			v[l] = this.rol64(v[l] + v[r], alpha) ^ Lsh512.STEP[8 * stepidx + colidx];
			v[r] = this.rol64(v[l] + v[r], beta);
			this.tcv[colidx] = v[r] + v[l];
			this.tcv[colidx + 8] = this.rol64(v[r], Lsh512.GAMMA[colidx]);
		}
		this.wordPermutation();
	}

	/**
	 * LSH's word permutation operation
	 */
	private wordPermutation() {
		this.cv[0] = this.tcv[6];
		this.cv[1] = this.tcv[4];
		this.cv[2] = this.tcv[5];
		this.cv[3] = this.tcv[7];
		this.cv[4] = this.tcv[12];
		this.cv[5] = this.tcv[15];
		this.cv[6] = this.tcv[14];
		this.cv[7] = this.tcv[13];
		this.cv[8] = this.tcv[2];
		this.cv[9] = this.tcv[0];
		this.cv[10] = this.tcv[1];
		this.cv[11] = this.tcv[3];
		this.cv[12] = this.tcv[8];
		this.cv[13] = this.tcv[11];
		this.cv[14] = this.tcv[10];
		this.cv[15] = this.tcv[9];
	}

	/**
	 * 64-bit unit left rotation operation
	 * 
	 * @param value
	 *            operand
	 * @param shift
	 *            Rotation value
	 * @return The value rotated left by rot
	 */
	private rol64(x: bigint, n: number) {
		const mask = (BigInt(1) << BigInt(64)) - BigInt(1);
        const s = BigInt(n & 63);
        const ux = x & mask; // unsigned 64-bit
        const rotated = ((ux << s) | (ux >> (BigInt(64) - s))) & mask;
        const value = rotated >= (BigInt(1) << BigInt(63)) ? rotated - (BigInt(1) << BigInt(64)) : rotated;
        return value;
	}
}

/**
 * Interface for MAC implementation
 */
abstract class Mac {

	/**
	 * Initialization function
	 * 
	 * @param key
	 *            secret key
	 */
	public abstract init(key:Uint8Array): void;

	/**
	 * Initialize an object for MAC calculation for new messages.
	 */
	public abstract reset(): void;

	/**
	 * Add message
	 * 
	 * @param msg
	 *            Message to add
	 */
	public abstract update(msg?: Uint8Array): void;

	/**
	 * MAC calculation including the last message
	 * 
	 * @param msg
	 *            Last message
	 * @return MAC value
	 */
	public doFinal(msg?:Uint8Array): Uint8Array {
		this.update(msg);
		return this.doFinal();
	}

	/**
	 * Creating an object for MAC calculation
	 * 
	 * @param algorithm
	 *            MessageDigest algorithm
	 * @return Mac object
	 */
	public static getInstance(algorithm: LSHAlgorithm): Mac {
		const md = Hash.getInstance(algorithm);
		return new HMac(md);
	}
}

/**
 * HMAC implementation
 */
export class HMac extends Mac {

	private IPAD = 0x36;
	private OPAD = 0x5c;

	private blocksize!: number;
	private _digest!: Hash;

	private i_key_pad!: Uint8Array;
	private o_key_pad!: Uint8Array;

	/**
	 * Constructor
	 * 
	 * @param md
	 *            MessageDigest object
	 */
	constructor(md: Hash) {
		super();
		if (md == undefined) {
			throw new Error("md should not be null");
		}

		this._digest = md.newInstance();
		this.blocksize = this._digest.getBlockSize();

		this.i_key_pad = new Uint8Array(this.blocksize);
		this.o_key_pad = new Uint8Array(this.blocksize);
	}

	/**
	 * Initialize internal state
	 * 
	 * @param key
	 *            secret key
	 */
	public init(key:Uint8Array) {

		if (key == undefined) {
			throw new Error("key should not be null");
		}

		if (key.length > this.blocksize) {
			this._digest.reset();
			key = this._digest.doFinal(key);
		}

		//Arrays.fill(i_key_pad, IPAD);
		for (let i = 0; i < this.i_key_pad.length; i++) {
			this.i_key_pad[i] = this.IPAD;
		}

		//Arrays.fill(o_key_pad, OPAD);
		for (let i = 0; i < this.o_key_pad.length; i++) {
			this.o_key_pad[i] = this.OPAD;
		}
		
		for (let i = 0; i < key.length; ++i) {
			this.i_key_pad[i] ^= (key[i]);
			this.o_key_pad[i] ^= (key[i]);
		}

		this.reset();
	}

	/**
	 * Initialize the hash function and put i_key_pad into the hash function.
	 */
	public reset() {
		this._digest.reset();
		this._digest.update(this.i_key_pad);
	}

	/**
	 * Put the message for which you want to calculate the MAC into a hash function
	 */
	public update( msg:Uint8Array) {
		if (msg == undefined) {
			return;
		}

		this._digest.update(msg);
	}

	/**
	 * Compute H(i_key_pad || msg) and compute H(o_key_pad || H(i_key_pad || msg)).
	 */
	public doFinal(msg?:Uint8Array): Uint8Array {
		if(msg != undefined){
			this.update(msg);
			return this.doFinal();
		} else {
			var result = this._digest.doFinal();
			this._digest.reset();
			this._digest.update(this.o_key_pad);
			result = this._digest.doFinal(result);

			this.reset();
			return result;	
		}
	}

	public static digest(algorithm: LSHAlgorithm, key:Uint8Array, msg:Uint8Array) {
		const hash = Hash.getInstance(algorithm);
		const hmac = new HMac(hash);
		hmac.init(key);
		return hmac.doFinal(msg);
	}
}

/**
 * Creates a vary byte length LSH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {256 | 512} bitLen - hash function to use
 * @param {224 | 256 | 384 | 512} hashLen - return hash length in bits (default 256, can't be greater than bitLen)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function _LSH(message: InputData, bitLen: 256 | 512 = 256, hashLen: 224 | 256 | 384 | 512 = 256, format: OutputFormat = arrayType()){
	if(hashLen > bitLen){
		hashLen = bitLen;
	}
	//@ts-ignore
	const digestbytes = Hash.digest(`LSH${bitLen}_${hashLen}`, formatMessage(message));
	if (format == "buffer") {
		return Buffer.from(digestbytes);
	} else if (format == "hex") {
		return toHex(digestbytes);
	}
	return digestbytes;
}

/**
 * Creates a vary byte length keyed LSH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {256 | 512} bitLen - hash function to use
 * @param {224 | 256 | 384 | 512} hashLen - return hash length in bits (default 256, can't be greater than bitLen)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function LSH_HMAC(message: InputData, key: InputData, bitLen: 256 | 512 = 256, hashLen: 224 | 256 | 384 | 512 = 256, format: OutputFormat = arrayType()){
	if(hashLen > bitLen){
		hashLen = bitLen;
	}
	//@ts-ignore
	const digestbytes = HMac.digest(`LSH${bitLen}_${hashLen}`, formatMessage(key), formatMessage(message));
	if (format == "buffer") {
		return Buffer.from(digestbytes);
	} else if (format == "hex") {
		return toHex(digestbytes);
	}
	return digestbytes;
}

/**
 * Creates up to 32 bytes LSH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {224 | 256} hashLen - return hash length in bits (default 256, can't be greater than bitLen)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function LSH256(message: InputData, hashLen: 224 | 256 = 256, format: OutputFormat = arrayType()){
	if(hashLen > 256){
		hashLen = 256;
	}
	const digestbytes = Hash.digest(`LSH256_${hashLen}`, formatMessage(message));
	if (format == "buffer") {
		return Buffer.from(digestbytes);
	} else if (format == "hex") {
		return toHex(digestbytes);
	}
	return digestbytes;
}

/**
 * Creates up to 32 bytes keyed LSH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {224 | 256} hashLen - return hash length in bits (default 256, can't be greater than bitLen)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function LSH256_HMAC(message: InputData, key: InputData, hashLen: 224 | 256 = 256, format: OutputFormat = arrayType()){
	if(hashLen > 256){
		hashLen = 256;
	}
	const digestbytes = HMac.digest(`LSH256_${hashLen}`, formatMessage(key), formatMessage(message));
	if (format == "buffer") {
		return Buffer.from(digestbytes);
	} else if (format == "hex") {
		return toHex(digestbytes);
	}
	return digestbytes;
}

/**
 * Creates a 28 byte LSH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function LSH256_224(message: InputData, format: OutputFormat = arrayType()){
	const digestbytes = Hash.digest(`LSH256_224`, formatMessage(message));
	if (format == "buffer") {
		return Buffer.from(digestbytes);
	} else if (format == "hex") {
		return toHex(digestbytes);
	}
	return digestbytes;
}

/**
 * Creates a 28 byte keyed LSH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function LSH256_224_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType()){
	const digestbytes = HMac.digest(`LSH256_224`, formatMessage(key), formatMessage(message));
	if (format == "buffer") {
		return Buffer.from(digestbytes);
	} else if (format == "hex") {
		return toHex(digestbytes);
	}
	return digestbytes;
}

/**
 * Creates a 32 byte LSH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function LSH256_256(message: InputData, format: OutputFormat = arrayType()){
	const digestbytes = Hash.digest(`LSH256_256`, formatMessage(message));
	if (format == "buffer") {
		return Buffer.from(digestbytes);
	} else if (format == "hex") {
		return toHex(digestbytes);
	}
	return digestbytes;
}

/**
 * Creates a 32 byte keyed LSH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function LSH256_256_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType()){
	const digestbytes = HMac.digest(`LSH256_256`, formatMessage(key), formatMessage(message));
	if (format == "buffer") {
		return Buffer.from(digestbytes);
	} else if (format == "hex") {
		return toHex(digestbytes);
	}
	return digestbytes;
}

/**
 * Creates up to 64 bytes LSH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {224 | 256 | 384 | 512} hashLen - return hash length in bits (default 256, can't be greater than 512)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function LSH512(message: InputData, hashLen: 224 | 256 | 384 | 512 = 256, format: OutputFormat = arrayType()){
	if(hashLen > 512){
		hashLen = 512;
	}
	const digestbytes = Hash.digest(`LSH512_${hashLen}`, formatMessage(message));
	if (format == "buffer") {
		return Buffer.from(digestbytes);
	} else if (format == "hex") {
		return toHex(digestbytes);
	}
	return digestbytes;
}

/**
 * Creates up to 64 bytes keyed LSH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {224 | 256 | 384 | 512} hashLen - return hash length in bits (default 256, can't be greater than 512)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function LSH512_HMAC(message: InputData, key: InputData, hashLen: 224 | 256 | 384 | 512 = 256, format: OutputFormat = arrayType()){
	if(hashLen > 512){
		hashLen = 512;
	}
	const digestbytes = HMac.digest(`LSH512_${hashLen}`, formatMessage(key), formatMessage(message));
	if (format == "buffer") {
		return Buffer.from(digestbytes);
	} else if (format == "hex") {
		return toHex(digestbytes);
	}
	return digestbytes;
}

/**
 * Creates a 28 byte LSH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function LSH512_224(message: InputData, format: OutputFormat = arrayType()){
	const digestbytes = Hash.digest(`LSH512_224`, formatMessage(message));
	if (format == "buffer") {
		return Buffer.from(digestbytes);
	} else if (format == "hex") {
		return toHex(digestbytes);
	}
	return digestbytes;
}

/**
 * Creates a 28 byte keyed LSH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function LSH512_224_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType()){
	const digestbytes = HMac.digest(`LSH512_224`, formatMessage(key), formatMessage(message));
	if (format == "buffer") {
		return Buffer.from(digestbytes);
	} else if (format == "hex") {
		return toHex(digestbytes);
	}
	return digestbytes;
}

/**
 * Creates a 32 byte LSH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function LSH512_256(message: InputData, format: OutputFormat = arrayType()){
	const digestbytes = Hash.digest(`LSH512_256`, formatMessage(message));
	if (format == "buffer") {
		return Buffer.from(digestbytes);
	} else if (format == "hex") {
		return toHex(digestbytes);
	}
	return digestbytes;
}

/**
 * Creates a 32 byte keyed LSH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function LSH512_256_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType()){
	const digestbytes = HMac.digest(`LSH512_256`, formatMessage(key), formatMessage(message));
	if (format == "buffer") {
		return Buffer.from(digestbytes);
	} else if (format == "hex") {
		return toHex(digestbytes);
	}
	return digestbytes;
}

/**
 * Creates a 48 byte LSH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function LSH512_384(message: InputData, format: OutputFormat = arrayType()){
	const digestbytes = Hash.digest(`LSH512_384`, formatMessage(message));
	if (format == "buffer") {
		return Buffer.from(digestbytes);
	} else if (format == "hex") {
		return toHex(digestbytes);
	}
	return digestbytes;
}

/**
 * Creates a 48 byte keyed LSH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function LSH512_384_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType()){
	const digestbytes = HMac.digest(`LSH512_384`, formatMessage(key), formatMessage(message));
	if (format == "buffer") {
		return Buffer.from(digestbytes);
	} else if (format == "hex") {
		return toHex(digestbytes);
	}
	return digestbytes;
}

/**
 * Creates a 64 byte LSH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function LSH512_512(message: InputData, format: OutputFormat = arrayType()){
	const digestbytes = Hash.digest(`LSH512_512`, formatMessage(message));
	if (format == "buffer") {
		return Buffer.from(digestbytes);
	} else if (format == "hex") {
		return toHex(digestbytes);
	}
	return digestbytes;
}

/**
 * Creates a 64 byte keyed LSH of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function LSH512_512_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType()){
	const digestbytes = HMac.digest(`LSH512_512`, formatMessage(key), formatMessage(message));
	if (format == "buffer") {
		return Buffer.from(digestbytes);
	} else if (format == "hex") {
		return toHex(digestbytes);
	}
	return digestbytes;
}

/**
 * Static class of all Locality-Sensitive Hashing (LSH) functions and classes
 */
export class LSH{
	static Lsh256          = Lsh256;
	static LSH             = _LSH;
	static LSH256          = LSH256;
	static LSH256_HMAC     = LSH256_HMAC;
	static LSH256_224      = LSH256_224;
	static LSH256_224_HMAC = LSH256_224_HMAC;
	static LSH256_256      = LSH256_256;
	static LSH256_256_HMAC = LSH256_256_HMAC;
	static Lsh512          = Lsh512;
	static LSH512          = LSH512;
	static LSH512_HMAC     = LSH512_HMAC;
	static LSH512_224      = LSH512_224;
	static LSH512_224_HMAC = LSH512_224_HMAC;
	static LSH512_256      = LSH512_256;
	static LSH512_256_HMAC = LSH512_256_HMAC;
	static LSH512_384      = LSH512_384;
	static LSH512_384_HMAC = LSH512_384_HMAC;
	static LSH512_512      = LSH512_512;
	static LSH512_512_HMAC = LSH512_512_HMAC;
	static LSH_HMAC        = LSH_HMAC;
	/**
     * List of all hashes in class
     */
  	static get FUNCTION_LIST() {
    	return [
			"LSH",
      		"LSH256",
			"LSH256_HMAC",
			"LSH256_224",
			"LSH256_224_HMAC",
			"LSH256_256",
			"LSH256_256_HMAC",

			"LSH512",
			"LSH512_HMAC",
			"LSH512_224",
			"LSH512_224_HMAC",
			"LSH512_256",
			"LSH512_256_HMAC",
			"LSH512_384",
			"LSH512_384_HMAC",
			"LSH512_512",
			"LSH512_512_HMAC",
			"LSH_HMAC"
    	]
  	}
}