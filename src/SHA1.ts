function arrayType():OutputFormat{
	if (typeof window !== 'undefined') {
		return "array" as OutputFormat;
	} else {
    return "buffer" as OutputFormat;
	}
};

function bytesToWords(bytes: Uint8Array | Buffer): number[] {
  for (var words: number[] = [], i = 0, b = 0; i < bytes.length; i++, b += 8) {
    words[b >>> 5] |= (bytes[i] & 0xFF) << (24 - b % 32);
  }
  return words;
}

function bytesToHex(bytes: number[]): string {
  for (var hex: string[] = [], i = 0; i < bytes.length; i++) {
    hex.push((bytes[i] >>> 4).toString(16));
    hex.push((bytes[i] & 0xF).toString(16));
  }
  return hex.join("");
}

function wordsToBytes(words: number[]): number[] {
  for (var bytes: number[] = [], b = 0; b < words.length * 32; b += 8) {
    bytes.push((words[b >>> 5] >>> (24 - b % 32)) & 0xFF);
  }
  return bytes;
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
    return new Uint8Array(0);
  }

  if (typeof message === 'string') {
    return strToUint8Array(message);
  }

  if (message instanceof Uint8Array || Buffer.isBuffer(message)) {
    return message;
  }

  throw new Error('input is invalid type');
}

function sha1(message: string | Uint8Array | Buffer) {
  // Convert to byte array
  var message2 = formatMessage(message);

  // otherwise assume byte array

  var m = bytesToWords(message2),
    l = message.length * 8,
    w: number[] = [],
    H0 = 0x67452301,
    H1 = 0xefcdab89,
    H2 = 0x98badcfe,
    H3 = 0x10325476,
    H4 = 0xc3d2e1f0;

  // Padding
  m[l >> 5] |= 0x80 << (24 - l % 32);
  m[((l + 64 >>> 9) << 4) + 15] = l;

  for (var i = 0; i < m.length; i += 16) {
    var a = H0,
      b = H1,
      c = H2,
      d = H3,
      e = H4;

    for (var j = 0; j < 80; j++) {

      if (j < 16)
        w[j] = m[i + j];
      else {
        var n = w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16];
        w[j] = (n << 1) | (n >>> 31);
      }

      var t = ((H0 << 5) | (H0 >>> 27)) + H4 + (w[j] >>> 0) + (
        j < 20 ? (H1 & H2 | ~H1 & H3) + 1518500249 :
          j < 40 ? (H1 ^ H2 ^ H3) + 1859775393 :
            j < 60 ? (H1 & H2 | H1 & H3 | H2 & H3) - 1894007588 :
              (H1 ^ H2 ^ H3) - 899497514);

      H4 = H3;
      H3 = H2;
      H2 = (H1 << 30) | (H1 >>> 2);
      H1 = H0;
      H0 = t;
    }

    H0 += a;
    H1 += b;
    H2 += c;
    H3 += d;
    H4 += e;
  }

  return [H0, H1, H2, H3, H4];
}

// Input types
type InputData = string | Uint8Array | Buffer;

// Output formats
type OutputFormat = 'hex' | 'array' | 'buffer';

/**
 * Creates a 20 byte SHA1 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function SHA1(message: InputData, format: OutputFormat = arrayType()): string | Uint8Array | Buffer {
  var digestbytes = wordsToBytes(sha1(message));
  if (format == "hex") {
    return bytesToHex(digestbytes);
  } else if (format == "buffer") {
    return Buffer.from(digestbytes);
  }
  return new Uint8Array(digestbytes);
};

/**
 * Creates a 20 byte keyed SHA1 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
export function SHA1_HMAC(message: InputData, key: InputData, format: OutputFormat = arrayType()): string | Uint8Array | Buffer {
  const key_length = 64;
  const hash_len = 20;
  key = formatMessage(key);
  message = formatMessage(message);
  if (key.length > key_length) {
    key = new Uint8Array(wordsToBytes(sha1(key)));
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
  result.set(new Uint8Array(wordsToBytes(sha1(msg))), key_length);

  var digestbytes = wordsToBytes(sha1(result));
  if (format == "hex") {
    return bytesToHex(digestbytes);
  } else if (format == "buffer") {
    return Buffer.from(digestbytes);
  }
  return new Uint8Array(digestbytes);
};
