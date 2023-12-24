var K = [];
function isPrime(n) {
    var sqrtN = Math.sqrt(n);
    for (var factor = 2; factor <= sqrtN; factor++) {
        if (!(n % factor))
            return false;
    }
    return true;
}
function getFractionalBits(n) {
    return ((n - (n | 0)) * 0x100000000) | 0;
}
function bytesToWords(bytes) {
    for (var words = [], i = 0, b = 0; i < bytes.length; i++, b += 8) {
        words[b >>> 5] |= (bytes[i] & 0xFF) << (24 - b % 32);
    }
    return words;
}
function wordsToBytes(words) {
    for (var bytes = [], b = 0; b < words.length * 32; b += 8) {
        bytes.push((words[b >>> 5] >>> (24 - b % 32)) & 0xFF);
    }
    return bytes;
}
function bytesToHex(bytes) {
    for (var hex = [], i = 0; i < bytes.length; i++) {
        hex.push((bytes[i] >>> 4).toString(16));
        hex.push((bytes[i] & 0xF).toString(16));
    }
    return hex.join("");
}
function bytesToString(bytes) {
    for (var str = [], i = 0; i < bytes.length; i++) {
        str.push(String.fromCharCode(bytes[i]));
    }
    return str.join('');
}
function stringToBytes(str) {
    for (var bytes = [], i = 0; i < str.length; i++) {
        bytes.push(str.charCodeAt(i) & 0xFF);
    }
    return bytes;
}
// Reusable object
var W = [];
var processBlock = function (H, M, offset) {
    // Working variables
    var a = H[0], b = H[1], c = H[2], d = H[3];
    var e = H[4], f = H[5], g = H[6], h = H[7];
    // Computation
    for (var i = 0; i < 64; i++) {
        if (i < 16) {
            W[i] = M[offset + i] | 0;
        }
        else {
            var gamma0x = W[i - 15];
            var gamma0 = ((gamma0x << 25) | (gamma0x >>> 7)) ^
                ((gamma0x << 14) | (gamma0x >>> 18)) ^
                (gamma0x >>> 3);
            var gamma1x = W[i - 2];
            var gamma1 = ((gamma1x << 15) | (gamma1x >>> 17)) ^
                ((gamma1x << 13) | (gamma1x >>> 19)) ^
                (gamma1x >>> 10);
            W[i] = gamma0 + W[i - 7] + gamma1 + W[i - 16];
        }
        var ch = (e & f) ^ (~e & g);
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var sigma0 = ((a << 30) | (a >>> 2)) ^ ((a << 19) | (a >>> 13)) ^ ((a << 10) | (a >>> 22));
        var sigma1 = ((e << 26) | (e >>> 6)) ^ ((e << 21) | (e >>> 11)) ^ ((e << 7) | (e >>> 25));
        var t1 = h + sigma1 + ch + K[i] + W[i];
        var t2 = sigma0 + maj;
        h = g;
        g = f;
        f = e;
        e = (d + t1) | 0;
        d = c;
        c = b;
        b = a;
        a = (t1 + t2) | 0;
    }
    // Intermediate hash value
    H[0] = (H[0] + a) | 0;
    H[1] = (H[1] + b) | 0;
    H[2] = (H[2] + c) | 0;
    H[3] = (H[3] + d) | 0;
    H[4] = (H[4] + e) | 0;
    H[5] = (H[5] + f) | 0;
    H[6] = (H[6] + g) | 0;
    H[7] = (H[7] + h) | 0;
};
/**
 * Creates a 32 byte SHA256 hash of the message as either a string, hex, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {string|Uint8Array|Buffer} message - Message to hash
 * @param {Options} options - Object with asString, asBuffer, asArray or asHex as true (default as hex string)
 * @returns ```string|Uint8Array|Buffer```
 */
export function SHA256(message, options) {
    ;
    var message2 = [];
    if (message.constructor === String) {
        message2 = stringToBytes(message);
    }
    else {
        message2 = message;
    }
    var n = 2;
    var nPrime = 0;
    while (nPrime < 64) {
        if (isPrime(n)) {
            K[nPrime] = getFractionalBits(Math.pow(n, 1 / 3));
            nPrime++;
        }
        n++;
    }
    var H = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19];
    var m = bytesToWords(message2);
    var l = message2.length * 8;
    m[l >> 5] |= 0x80 << (24 - l % 32);
    m[((l + 64 >> 9) << 4) + 15] = l;
    for (var i = 0; i < m.length; i += 16) {
        processBlock(H, m, i);
    }
    var digestbytes = wordsToBytes(H);
    return options && options.asArray ? new Uint8Array(digestbytes) :
        options && options.asString ? bytesToString(digestbytes) :
            options && options.asBuffer ? Buffer.from(digestbytes) :
                bytesToHex(digestbytes);
}
/**
 * Creates a 28 byte SHA224 hash of the message as either a string, hex, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {string|Uint8Array|Buffer} message - Message to hash
 * @param {Options} options - Object with asString, asBuffer, asArray or asHex as true (default as hex string)
 * @returns ```string|Uint8Array|Buffer```
 */
export function SHA224(message, options) {
    ;
    var message2 = [];
    if (message.constructor === String) {
        message2 = stringToBytes(message);
    }
    else {
        message2 = message;
    }
    var n = 2;
    var nPrime = 0;
    while (nPrime < 64) {
        if (isPrime(n)) {
            K[nPrime] = getFractionalBits(Math.pow(n, 1 / 3));
            nPrime++;
        }
        n++;
    }
    var H = [
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
        0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
    ];
    var m = bytesToWords(message2);
    var l = message2.length * 8;
    m[l >> 5] |= 0x80 << (24 - l % 32);
    m[((l + 64 >> 9) << 4) + 15] = l;
    for (var i = 0; i < m.length; i += 16) {
        processBlock(H, m, i);
    }
    var digestbytes = wordsToBytes(H).slice(0, 28);
    return options && options.asArray ? new Uint8Array(digestbytes) :
        options && options.asString ? bytesToString(digestbytes) :
            options && options.asBuffer ? Buffer.from(digestbytes) :
                bytesToHex(digestbytes);
}
//# sourceMappingURL=SHA256.js.map