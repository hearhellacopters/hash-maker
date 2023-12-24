class Int64 {
    constructor(h, l) {
        this.h = h;
        this.l = l;
    }
    static copy(dst, src) {
        dst.h = src.h;
        dst.l = src.l;
    }
    static shr(dst, x, shift) {
        dst.l = x.l >>> shift | x.h << 32 - shift;
        dst.h = x.h >>> shift;
    }
    static rotr(dst, x, shift) {
        dst.l = x.l >>> shift | x.h << 32 - shift;
        dst.h = x.h >>> shift | x.l << 32 - shift;
    }
    static rotl(dst, x, shift) {
        dst.l = x.h >>> shift | x.l << 32 - shift;
        dst.h = x.l >>> shift | x.h << 32 - shift;
    }
    static add(dst, x, y) {
        const w0 = (x.l & 0xffff) + (y.l & 0xffff), w1 = (x.l >>> 16) + (y.l >>> 16) + (w0 >>> 16), w2 = (x.h & 0xffff) + (y.h & 0xffff) + (w1 >>> 16), w3 = (x.h >>> 16) + (y.h >>> 16) + (w2 >>> 16);
        dst.l = w0 & 0xffff | w1 << 16;
        dst.h = w2 & 0xffff | w3 << 16;
    }
    static add4(dst, a, b, c, d) {
        const w0 = (a.l & 0xffff) + (b.l & 0xffff) + (c.l & 0xffff) + (d.l & 0xffff), w1 = (a.l >>> 16) + (b.l >>> 16) + (c.l >>> 16) + (d.l >>> 16) + (w0 >>> 16), w2 = (a.h & 0xffff) + (b.h & 0xffff) + (c.h & 0xffff) + (d.h & 0xffff) + (w1 >>> 16), w3 = (a.h >>> 16) + (b.h >>> 16) + (c.h >>> 16) + (d.h >>> 16) + (w2 >>> 16);
        dst.l = w0 & 0xffff | w1 << 16;
        dst.h = w2 & 0xffff | w3 << 16;
    }
    static add5(dst, a, b, c, d, e) {
        const w0 = (a.l & 0xffff) + (b.l & 0xffff) + (c.l & 0xffff) + (d.l & 0xffff) + (e.l & 0xffff), w1 = (a.l >>> 16) + (b.l >>> 16) + (c.l >>> 16) + (d.l >>> 16) + (e.l >>> 16) + (w0 >>> 16), w2 = (a.h & 0xffff) + (b.h & 0xffff) + (c.h & 0xffff) + (d.h & 0xffff) + (e.h & 0xffff) + (w1 >>> 16), w3 = (a.h >>> 16) + (b.h >>> 16) + (c.h >>> 16) + (d.h >>> 16) + (e.h >>> 16) + (w2 >>> 16);
        dst.l = w0 & 0xffff | w1 << 16;
        dst.h = w2 & 0xffff | w3 << 16;
    }
}
function isBuffer(obj) {
    return (typeof Buffer !== 'undefined' && obj instanceof Buffer);
}
function arraybuffcheck(obj) {
    return obj instanceof Uint8Array || isBuffer(obj);
}
class Sha512 {
    constructor(h) {
        this.H0 = new Int64(h[0], h[1]);
        this.H1 = new Int64(h[2], h[3]);
        this.H2 = new Int64(h[4], h[5]);
        this.H3 = new Int64(h[6], h[7]);
        this.H4 = new Int64(h[8], h[9]);
        this.H5 = new Int64(h[10], h[11]);
        this.H6 = new Int64(h[12], h[13]);
        this.H7 = new Int64(h[14], h[15]);
    }
    hash(msg, is384, options) {
        var digestbytes;
        if (typeof msg == 'string') {
            digestbytes = this.wordsToBytes(this.run(this.stringToArray(msg), msg.length * 8));
        }
        else if (arraybuffcheck(msg)) {
            digestbytes = this.wordsToBytes(this.run(msg, msg.length * 8));
        }
        else {
            throw new Error("Message must be either String, Buffer or Uint8Array");
        }
        if (is384) {
            digestbytes = digestbytes.slice(0, 48);
        }
        return options && options.asArray ? new Uint8Array(digestbytes) :
            options && options.asString ? this.bytesToString(digestbytes) :
                options && options.asBuffer ? Buffer.from(digestbytes) :
                    this.bytesToHex(digestbytes);
    }
    run(input, len) {
        const K = [
            new Int64(0x428a2f98, -685199838), new Int64(0x71374491, 0x23ef65cd),
            new Int64(-1245643825, -330482897), new Int64(-373957723, -2121671748),
            new Int64(0x3956c25b, -213338824), new Int64(0x59f111f1, -1241133031),
            new Int64(-1841331548, -1357295717), new Int64(-1424204075, -630357736),
            new Int64(-670586216, -1560083902), new Int64(0x12835b01, 0x45706fbe),
            new Int64(0x243185be, 0x4ee4b28c), new Int64(0x550c7dc3, -704662302),
            new Int64(0x72be5d74, -226784913), new Int64(-2132889090, 0x3b1696b1),
            new Int64(-1680079193, 0x25c71235), new Int64(-1046744716, -815192428),
            new Int64(-459576895, -1628353838), new Int64(-272742522, 0x384f25e3),
            new Int64(0xfc19dc6, -1953704523), new Int64(0x240ca1cc, 0x77ac9c65),
            new Int64(0x2de92c6f, 0x592b0275), new Int64(0x4a7484aa, 0x6ea6e483),
            new Int64(0x5cb0a9dc, -1119749164), new Int64(0x76f988da, -2096016459),
            new Int64(-1740746414, -295247957), new Int64(-1473132947, 0x2db43210),
            new Int64(-1341970488, -1728372417), new Int64(-1084653625, -1091629340),
            new Int64(-958395405, 0x3da88fc2), new Int64(-710438585, -1828018395),
            new Int64(0x6ca6351, -536640913), new Int64(0x14292967, 0xa0e6e70),
            new Int64(0x27b70a85, 0x46d22ffc), new Int64(0x2e1b2138, 0x5c26c926),
            new Int64(0x4d2c6dfc, 0x5ac42aed), new Int64(0x53380d13, -1651133473),
            new Int64(0x650a7354, -1951439906), new Int64(0x766a0abb, 0x3c77b2a8),
            new Int64(-2117940946, 0x47edaee6), new Int64(-1838011259, 0x1482353b),
            new Int64(-1564481375, 0x4cf10364), new Int64(-1474664885, -1136513023),
            new Int64(-1035236496, -789014639), new Int64(-949202525, 0x654be30),
            new Int64(-778901479, -688958952), new Int64(-694614492, 0x5565a910),
            new Int64(-200395387, 0x5771202a), new Int64(0x106aa070, 0x32bbd1b8),
            new Int64(0x19a4c116, -1194143544), new Int64(0x1e376c08, 0x5141ab53),
            new Int64(0x2748774c, -544281703), new Int64(0x34b0bcb5, -509917016),
            new Int64(0x391c0cb3, -976659869), new Int64(0x4ed8aa4a, -482243893),
            new Int64(0x5b9cca4f, 0x7763e373), new Int64(0x682e6ff3, -692930397),
            new Int64(0x748f82ee, 0x5defb2fc), new Int64(0x78a5636f, 0x43172f60),
            new Int64(-2067236844, -1578062990), new Int64(-1933114872, 0x1a6439ec),
            new Int64(-1866530822, 0x23631e28), new Int64(-1538233109, -561857047),
            new Int64(-1090935817, -1295615723), new Int64(-965641998, -479046869),
            new Int64(-903397682, -366583396), new Int64(-779700025, 0x21c0c207),
            new Int64(-354779690, -840897762), new Int64(-176337025, -294727304),
            new Int64(0x6f067aa, 0x72176fba), new Int64(0xa637dc5, -1563912026),
            new Int64(0x113f9804, -1090974290), new Int64(0x1b710b35, 0x131c471b),
            new Int64(0x28db77f5, 0x23047d84), new Int64(0x32caab7b, 0x40c72493),
            new Int64(0x3c9ebe0a, 0x15c9bebc), new Int64(0x431d67c4, -1676669620),
            new Int64(0x4cc5d4be, -885112138), new Int64(0x597f299c, -60457430),
            new Int64(0x5fcb6fab, 0x3ad6faec), new Int64(0x6c44198c, 0x4a475817)
        ];
        const T1 = new Int64(0, 0), T2 = new Int64(0, 0), W = new Array(80), a = new Int64(0, 0), b = new Int64(0, 0), c = new Int64(0, 0), d = new Int64(0, 0), e = new Int64(0, 0), f = new Int64(0, 0), g = new Int64(0, 0), h = new Int64(0, 0), s0 = new Int64(0, 0), s1 = new Int64(0, 0), Ch = new Int64(0, 0), Maj = new Int64(0, 0), r1 = new Int64(0, 0), r2 = new Int64(0, 0), r3 = new Int64(0, 0);
        let j = 0, i = 0, l = 0;
        for (i = 0; i < 80; i += 1) {
            W[i] = new Int64(0, 0);
        }
        input[len >> 5] |= 0x80 << 24 - (len & 0x1f);
        input[(len + 128 >> 10 << 5) + 31] = len;
        l = input.length;
        for (i = 0; i < l; i += 32) {
            Int64.copy(a, this.H0);
            Int64.copy(b, this.H1);
            Int64.copy(c, this.H2);
            Int64.copy(d, this.H3);
            Int64.copy(e, this.H4);
            Int64.copy(f, this.H5);
            Int64.copy(g, this.H6);
            Int64.copy(h, this.H7);
            for (j = 0; j < 16; j += 1) {
                W[j].h = input[i + 2 * j];
                W[j].l = input[i + 2 * j + 1];
            }
            for (j = 16; j < 80; j += 1) {
                Int64.rotr(r1, W[j - 2], 19);
                Int64.rotl(r2, W[j - 2], 29);
                Int64.shr(r3, W[j - 2], 6);
                s1.l = r1.l ^ r2.l ^ r3.l;
                s1.h = r1.h ^ r2.h ^ r3.h;
                Int64.rotr(r1, W[j - 15], 1);
                Int64.rotr(r2, W[j - 15], 8);
                Int64.shr(r3, W[j - 15], 7);
                s0.l = r1.l ^ r2.l ^ r3.l;
                s0.h = r1.h ^ r2.h ^ r3.h;
                Int64.add4(W[j], s1, W[j - 7], s0, W[j - 16]);
            }
            for (j = 0; j < 80; j += 1) {
                Ch.l = e.l & f.l ^ ~e.l & g.l;
                Ch.h = e.h & f.h ^ ~e.h & g.h;
                Int64.rotr(r1, e, 14);
                Int64.rotr(r2, e, 18);
                Int64.rotl(r3, e, 9);
                s1.l = r1.l ^ r2.l ^ r3.l;
                s1.h = r1.h ^ r2.h ^ r3.h;
                Int64.rotr(r1, a, 28);
                Int64.rotl(r2, a, 2);
                Int64.rotl(r3, a, 7);
                s0.l = r1.l ^ r2.l ^ r3.l;
                s0.h = r1.h ^ r2.h ^ r3.h;
                Maj.l = a.l & b.l ^ a.l & c.l ^ b.l & c.l;
                Maj.h = a.h & b.h ^ a.h & c.h ^ b.h & c.h;
                Int64.add5(T1, h, s1, Ch, K[j], W[j]);
                Int64.add(T2, s0, Maj);
                Int64.copy(h, g);
                Int64.copy(g, f);
                Int64.copy(f, e);
                Int64.add(e, d, T1);
                Int64.copy(d, c);
                Int64.copy(c, b);
                Int64.copy(b, a);
                Int64.add(a, T1, T2);
            }
            Int64.add(this.H0, this.H0, a);
            Int64.add(this.H1, this.H1, b);
            Int64.add(this.H2, this.H2, c);
            Int64.add(this.H3, this.H3, d);
            Int64.add(this.H4, this.H4, e);
            Int64.add(this.H5, this.H5, f);
            Int64.add(this.H6, this.H6, g);
            Int64.add(this.H7, this.H7, h);
        }
        return [this.H0.h, this.H0.l, this.H1.h, this.H1.l, this.H2.h, this.H2.l, this.H3.h, this.H3.l, this.H4.h, this.H4.l, this.H5.h, this.H5.l, this.H6.h, this.H6.l, this.H7.h, this.H7.l];
    }
    arrayToString(input) {
        const l = input.length * 32;
        let i = 0, output = '';
        for (i = 0; i < l; i += 8) {
            output += String.fromCharCode(input[i >> 5] >>> 24 - i % 32 & 0xFF);
        }
        return output;
    }
    stringToArray(input) {
        const l = input.length * 8;
        const output = Array(input.length >> 2);
        const lo = output.length;
        let i = 0;
        for (i = 0; i < lo; i += 1) {
            output[i] = 0;
        }
        for (i = 0; i < l; i += 8) {
            output[i >> 5] |= (input.charCodeAt(i / 8) & 0xFF) << 24 - i % 32;
        }
        return output;
    }
    stringToHex(input) {
        const hex = '0123456789abcdef';
        const l = input.length;
        let output = '', x = null, i = 0;
        for (; i < l; i += 1) {
            x = input.charCodeAt(i);
            output += hex.charAt(x >>> 4 & 0x0F) + hex.charAt(x & 0x0F);
        }
        return output;
    }
    wordsToBytes(words) {
        for (var bytes = [], b = 0; b < words.length * 32; b += 8) {
            bytes.push((words[b >>> 5] >>> (24 - b % 32)) & 0xFF);
        }
        return bytes;
    }
    bytesToHex(bytes) {
        for (var hex = [], i = 0; i < bytes.length; i++) {
            hex.push((bytes[i] >>> 4).toString(16));
            hex.push((bytes[i] & 0xF).toString(16));
        }
        return hex.join("");
    }
    bytesToString(bytes) {
        for (var str = [], i = 0; i < bytes.length; i++) {
            str.push(String.fromCharCode(bytes[i]));
        }
        return str.join('');
    }
}
/**
 * Creates a 64 byte SHA512 hash of the message as either a string, hex, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {string|Uint8Array|Buffer} message - Message to hash
 * @param {Options} options - Object with asString, asBuffer, asArray or asHex as true (default as hex string)
 * @returns ```string|Uint8Array|Buffer```
 */
export function SHA512(message, options) {
    var h = [0x6a09e667, -205731576,
        -1150833019, -2067093701,
        0x3c6ef372, -23791573,
        -1521486534, 0x5f1d36f1,
        0x510e527f, -1377402159,
        -1694144372, 0x2b3e6c1f,
        0x1f83d9ab, -79577749,
        0x5be0cd19, 0x137e2179];
    return new Sha512(h).hash(message, false, options);
}
/**
 * Creates a 48 byte SHA384 hash of the message as either a string, hex, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {string|Uint8Array|Buffer} message - Message to hash
 * @param {Options} options - Object with asString, asBuffer, asArray or asHex as true (default as hex string)
 * @returns ```string|Uint8Array|Buffer```
 */
export function SHA384(message, options) {
    var h = [-876896931, -1056596264,
        1654270250, 914150663,
        -1856437926, 812702999,
        355462360, -150054599,
        1731405415, -4191439,
        -1900787065, 1750603025,
        -619958771, 1694076839,
        1203062813, -1090891868];
    return new Sha512(h).hash(message, true, options);
}
//# sourceMappingURL=SHA512.js.map