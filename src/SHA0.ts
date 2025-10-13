function arrayType():OutputFormat{
	if (typeof window !== 'undefined') {
		return "array" as OutputFormat;
	} else {
    return "buffer" as OutputFormat;
	}
};

/*
 * A JavaScript implementation of the Secure Hash Algorithm, SHA-0, as defined
 * in FIPS PUB 180-1
 * This source code is derived from sha1.js of the same repository.
 * The difference between SHA-0 and SHA-1 is just a bitwise rotate left
 * operation was added.
 */

// prototype class for hash functions
class Hash {
	_block;
	_finalSize;
	_blockSize;
	_len;
	constructor(blockSize: number, finalSize: number) {
		this._block = new Uint8Array(blockSize);
		this._finalSize = finalSize;
		this._blockSize = blockSize;
		this._len = 0;
	}

	update(data: string | Uint8Array | Buffer) {

		data = formatMessage(data);

		var block = this._block;
		var blockSize = this._blockSize;
		var length = data.length;
		var accum = this._len;

		for (var offset = 0; offset < length;) {
			var assigned = accum % blockSize;
			var remainder = Math.min(length - offset, blockSize - assigned);

			for (var i = 0; i < remainder; i++) {
				block[assigned + i] = data[offset + i];
			}

			accum += remainder;
			offset += remainder;

			if ((accum % blockSize) === 0) {
				this._update(block);
			}
		}

		this._len += length;
		return this;
	};

	_update(block: Uint8Array) {
		throw new Error('_update must be implemented by subclass');
	}

	_hash(): Uint8Array {
		throw new Error('_hash must be implemented by subclass');
	}

	digest() {
		var rem = this._len % this._blockSize;

		this._block[rem] = 0x80;

		/*
		* zero (rem + 1) trailing bits, where (rem + 1) is the smallest
		* non-negative solution to the equation (length + 1 + (rem + 1)) === finalSize mod blockSize
		*/
		this._block.fill(0, rem + 1);

		if (rem >= this._finalSize) {
			this._update(this._block);
			this._block.fill(0);
		}

		var bits = this._len * 8;

		// uint32
		if (bits <= 0xffffffff) {
			writeInt32BE(this._block, bits, this._blockSize - 4);

			// uint64
		} else {
			var lowBits = (bits & 0xffffffff) >>> 0;
			var highBits = (bits - lowBits) / 0x100000000;

			writeInt32BE(this._block, highBits, this._blockSize - 8);
			writeInt32BE(this._block, lowBits, this._blockSize - 4);
		}

		this._update(this._block);
		var hash = this._hash();

		return hash;
	};
}

function writeInt32BE(array: Uint8Array | Buffer, value: number, index: number): void {
	array[index] = (value >> 24) & 0xFF;
	array[index + 1] = (value >> 16) & 0xFF;
	array[index + 2] = (value >> 8) & 0xFF;
	array[index + 3] = value & 0xFF;
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

function formatMessage(message: string | Uint8Array | Buffer): Uint8Array | Buffer {
	if (message === undefined) {
		throw new Error('input is invalid type');
	}

	if (typeof message === 'string') {
		return strToUint8Array(message);
	}

	if (message instanceof Uint8Array || Buffer.isBuffer(message)) {
		return message;
	}

	throw new Error('input is invalid type');
}

var K = [
	0x5a827999, 0x6ed9eba1, 0x8f1bbcdc | 0, 0xca62c1d6 | 0
];

var W = new Array(80);

class Sha extends Hash {
	_a = 0x67452301;
	_b = 0xefcdab89;
	_c = 0x98badcfe;
	_d = 0x10325476;
	_e = 0xc3d2e1f0;
	_w: any[];
	constructor(blockSize: number = 64, finalSize: number = 56) {
		super(blockSize, finalSize);
		this.init();
		this._w = W;
	}

	init() {
		this._a = 0x67452301;
		this._b = 0xefcdab89;
		this._c = 0x98badcfe;
		this._d = 0x10325476;
		this._e = 0xc3d2e1f0;

		return this;
	};

	_update(M: Buffer | Uint8Array) {
		var w = this._w;

		var a = this._a | 0;
		var b = this._b | 0;
		var c = this._c | 0;
		var d = this._d | 0;
		var e = this._e | 0;

		for (var i = 0; i < 16; ++i) {
			w[i] = readInt32BE(M, i * 4);
		}
		for (; i < 80; ++i) {
			w[i] = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
		}

		for (var j = 0; j < 80; ++j) {
			var s = ~~(j / 20);
			var t = (rotl5(a) + ft(s, b, c, d) + e + w[j] + K[s]) | 0;

			e = d;
			d = c;
			c = rotl30(b);
			b = a;
			a = t;
		}

		this._a = (a + this._a) | 0;
		this._b = (b + this._b) | 0;
		this._c = (c + this._c) | 0;
		this._d = (d + this._d) | 0;
		this._e = (e + this._e) | 0;
	}

	_hash(): Uint8Array {
		var H = new Uint8Array(20);

		writeInt32BE(H, this._a | 0, 0);
		writeInt32BE(H, this._b | 0, 4);
		writeInt32BE(H, this._c | 0, 8);
		writeInt32BE(H, this._d | 0, 12);
		writeInt32BE(H, this._e | 0, 16);

		return H;
	};
}

function rotl5(num: number) {
	return (num << 5) | (num >>> 27);
}

function rotl30(num: number) {
	return (num << 30) | (num >>> 2);
}

function ft(s: number, b: number, c: number, d: number) {
	if (s === 0) {
		return (b & c) | (~b & d);
	}
	if (s === 2) {
		return (b & c) | (b & d) | (c & d);
	}
	return b ^ c ^ d;
}

function readInt32BE(array: Uint8Array | Buffer, index: number): number {
	return (((array[index] & 0xFF) << 24) |
		((array[index + 1] & 0xFF) << 16) |
		((array[index + 2] & 0xFF) << 8) |
		(array[index + 3] & 0xFF)
	);
}

function bytesToHex(bytes: Uint8Array): string {
	for (var hex: string[] = [], i = 0; i < bytes.length; i++) {
		hex.push((bytes[i] >>> 4).toString(16));
		hex.push((bytes[i] & 0xF).toString(16));
	}
	return hex.join("");
}

// Input types
type InputData = string | Uint8Array | Buffer;

// Output formats
type OutputFormat = 'hex' | 'array' | 'buffer';

/**
 * Creates a 20 byte SHA0 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function SHA0(message: InputData, format: OutputFormat = arrayType()) {
	const hash = new Sha();
	hash.update(message);
	const digestbytes = hash.digest();
	if (format == "hex") {
		return bytesToHex(digestbytes)
	} else if (format == "buffer") {
		return Buffer.from(digestbytes);
	}
	return digestbytes;
}

/**
 * Creates a 20 byte keyed SHA0 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function SHA0_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType()) {
	const key_length = 64;
	const hash_len = 20;
	key = formatMessage(key);
	message = formatMessage(message);
	if (key.length > key_length) {
		key = SHA0(key, "array") as Uint8Array;
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
	result.set(SHA0(msg, "array") as Uint8Array, key_length);

	var digestbytes = SHA0(result, "array") as Uint8Array;
	if (format == "hex") {
		return bytesToHex(digestbytes)
	} else if (format == "buffer") {
		return Buffer.from(digestbytes);
	}
	return digestbytes;
}