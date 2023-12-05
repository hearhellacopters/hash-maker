function isBuffer(obj: Buffer|Uint8Array): boolean {
  return (typeof Buffer !== 'undefined' && obj instanceof Buffer);
}

function arraybuffcheck(obj:  Buffer|Uint8Array): boolean {
  return obj instanceof Uint8Array || isBuffer(obj);
}

function bytesToWords(bytes:number[]):number[] {
    for (var words:number[] = [], i = 0, b = 0; i < bytes.length; i++, b += 8){
        words[b >>> 5] |= (bytes[i] & 0xFF)<< (24 - b % 32);
    }
    return words;
}

function bytesToHex(bytes:number[]):string {
  for (var hex:string[] = [], i = 0; i < bytes.length; i++) {
      hex.push((bytes[i] >>> 4).toString(16));
      hex.push((bytes[i] & 0xF).toString(16));
  }
  return hex.join("");
}

function wordsToBytes(words:number[]):number[] {
  for (var bytes:number[] = [], b = 0; b < words.length * 32; b += 8){
      bytes.push((words[b >>> 5] >>> (24 - b % 32)) & 0xFF);
  }
  return bytes;
}

function stringToBytes(str:string):number[] {
  for (var bytes:number[] = [], i = 0; i < str.length; i++){
      bytes.push(str.charCodeAt(i) & 0xFF);
  }
  return bytes;
}

function bytesToString(bytes:number[]):string {
  for (var str:string[] = [], i = 0; i < bytes.length; i++){
      str.push(String.fromCharCode(bytes[i]));
  }
  return str.join('');
}

function sha1(message:string|Uint8Array|Buffer) {
  // Convert to byte array
  var message2:number[] = [];
  if (message.constructor == String) {
    message2 = stringToBytes(message);
  } else if (arraybuffcheck(message as Uint8Array|Buffer)) {
    message2 = Array.prototype.slice.call(message, 0);
  } else {
    throw new Error("Message must be either String, Buffer or Uint8Array")
  }

    // otherwise assume byte array

    var m  = bytesToWords(message2),
        l  = message.length * 8,
        w:number[]  = [],
        H0 =  1732584193,
        H1 = -271733879,
        H2 = -1732584194,
        H3 =  271733878,
        H4 = -1009589776;

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

interface Options {
  asString?:boolean,
  asBuffer?:boolean,
  asArray?:boolean,
  asHex?:boolean
}

/**
 * Creates a 20 byte SHA1 hash of the message as either a string, hex, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 * 
 * @param {string|Uint8Array|Buffer} message - Message to hash
 * @param {Options} options - Object with asString, asBuffer, asArray or asHex as true (default as hex string)
 * @returns ```string|Uint8Array|Buffer```
 */
export function SHA1(message:string|Uint8Array|Buffer, options?:Options) {
    var digestbytes = wordsToBytes(sha1(message));
    return options && options.asArray ? new Uint8Array(digestbytes) :
        options && options.asString ? bytesToString(digestbytes) :
        options && options.asBuffer ? Buffer.from(digestbytes) :
        bytesToHex(digestbytes);
};
