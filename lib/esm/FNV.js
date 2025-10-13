"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.FNV1A_32_HMAC = exports.FNV1A_32 = exports.FNV1A_HMAC = exports.FNV1A = exports.FNV1_1024_HMAC = exports.FNV1_1024 = exports.FNV1_512_HMAC = exports.FNV1_512 = exports.FNV1_256_HMAC = exports.FNV1_256 = exports.FNV1_128_HMAC = exports.FNV1_128 = exports.FNV1_64_HMAC = exports.FNV1_64 = exports.FNV1_32_HMAC = exports.FNV1_32 = exports.FNV1_HMAC = exports.FNV1 = exports.FNV0_1024_HMAC = exports.FNV0_1024 = exports.FNV0_512_HMAC = exports.FNV0_512 = exports.FNV0_256_HMAC = exports.FNV0_256 = exports.FNV0_128_HMAC = exports.FNV0_128 = exports.FNV0_64_HMAC = exports.FNV0_64 = exports.FNV0_32_HMAC = exports.FNV0_32 = exports.FNV0_HMAC = exports.FNV0 = exports.Fnv1a_1024 = exports.Fnv1a_512 = exports.Fnv1a_256 = exports.Fnv1a_128 = exports.Fnv1a_64 = exports.Fnv1a_32 = exports.Fnv1_1024 = exports.Fnv1_512 = exports.Fnv1_256 = exports.Fnv1_128 = exports.Fnv1_64 = exports.Fnv1_32 = exports.Fnv0_1024 = exports.Fnv0_512 = exports.Fnv0_256 = exports.Fnv0_128 = exports.Fnv0_64 = exports.Fnv0_32 = void 0;
exports.FNV = exports.FNV_HMAC = exports._FNV = exports.FNV1A_1024_HMAC = exports.FNV1A_1024 = exports.FNV1A_512_HMAC = exports.FNV1A_512 = exports.FNV1A_256_HMAC = exports.FNV1A_256 = exports.FNV1A_128_HMAC = exports.FNV1A_128 = exports.FNV1A_64_HMAC = exports.FNV1A_64 = void 0;
function arrayType() {
    if (typeof window !== 'undefined') {
        return "array";
    }
    else {
        return "buffer";
    }
}
;
;
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
class DigestEngine {
    constructor() {
        this.doInit();
        this.digestLen = this.getDigestLength();
        this.blockLen = this.getInternalBlockLength();
        this.inputBuf = new Uint8Array(this.blockLen);
        this.outputBuf = new Uint8Array(this.digestLen);
        this.inputLen = 0;
        this.blockCount = BigInt(0);
    }
    adjustDigestLen() {
        if (this.digestLen == undefined || this.digestLen === 0) {
            this.digestLen = this.getDigestLength();
            this.outputBuf = new Uint8Array(this.digestLen);
        }
    }
    digest(input, offset, len) {
        if (input === undefined) {
            this.adjustDigestLen();
            const result = new Uint8Array(this.digestLen);
            this.digest(result, 0, this.digestLen);
            return result;
        }
        else if (offset === undefined || len === undefined) {
            this.update(input, 0, input.length);
            return this.digest();
        }
        else {
            this.adjustDigestLen();
            if (len >= this.digestLen) {
                this.doPadding(input, offset);
                this.reset();
                return this.digestLen;
            }
            else {
                this.doPadding(this.outputBuf, 0);
                arraycopy(this.outputBuf, 0, input, offset, len);
                this.reset();
                return len;
            }
        }
    }
    reset() {
        this.engineReset();
        this.inputLen = 0;
        this.blockCount = BigInt(0);
    }
    update(input, offset, len) {
        if (typeof input === 'number') {
            this.inputBuf[this.inputLen++] = input;
            if (this.inputLen === this.blockLen) {
                this.processBlock(this.inputBuf);
                this.blockCount++;
                this.inputLen = 0;
            }
        }
        else if (offset === undefined || len === undefined) {
            this.update(input, 0, input.length);
        }
        else {
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
    getInternalBlockLength() {
        return this.getBlockLength();
    }
    flush() {
        return this.inputLen;
    }
    getBlockBuffer() {
        return this.inputBuf;
    }
    getBlockCount() {
        return this.blockCount;
    }
    copyState(dest) {
        dest.inputLen = this.inputLen;
        dest.blockCount = this.blockCount;
        arraycopy(this.inputBuf, 0, dest.inputBuf, 0, this.inputBuf.length);
        this.adjustDigestLen();
        dest.adjustDigestLen();
        arraycopy(this.outputBuf, 0, dest.outputBuf, 0, this.outputBuf.length);
        return dest;
    }
    getDigestLength() {
        throw new Error('Method not implemented.');
    }
    copy() {
        throw new Error('Method not implemented.');
    }
    getBlockLength() {
        throw new Error('Method not implemented.');
    }
    toString() {
        throw new Error('Method not implemented.');
    }
}
;
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
    constructor(dig, key, outputLength) {
        super();
        this.onlyThis = 0;
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
    _HMAC(dig, kipad, kopad, outputLength) {
        this.dig = dig;
        this.kipad = kipad;
        this.kopad = kopad;
        this.outputLength = outputLength;
        this.tmpOut = new Uint8Array(dig.getDigestLength());
        return this;
    }
    processKey(keyB) {
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
    copy() {
        const h = this._HMAC(this.dig.copy(), this.kipad, this.kopad, this.outputLength);
        return this.copyState(h);
    }
    /** @see Digest */
    getDigestLength() {
        /*
         * At construction time, outputLength is first set to 0,
         * which means that this method will return 0, which is
         * appropriate since at that time "dig" has not yet been
         * set.
         */
        return this.outputLength < 0 ? this.dig.getDigestLength() : this.outputLength;
    }
    /** @see Digest */
    getBlockLength() {
        /*
         * Internal block length is not defined for HMAC, which
         * is not, stricto-sensu, an iterated hash function.
         * The value 64 should provide correct buffering. Do NOT
         * change this value without checking doPadding().
         */
        return 64;
    }
    /** @see DigestEngine */
    engineReset() {
        this.dig.reset();
        this.dig.update(this.kipad);
    }
    /** @see DigestEngine */
    processBlock(data) {
        if (this.onlyThis > 0) {
            this.dig.update(data, 0, this.onlyThis);
            this.onlyThis = 0;
        }
        else {
            this.dig.update(data);
        }
    }
    /** @see DigestEngine */
    doPadding(output, outputOffset) {
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
    doInit() {
        /*
         * Empty: we do not want to do anything here because
         * it would prevent correct cloning. The initialization
         * job is done in the constructor.
         */
    }
    /** @see Digest */
    toString() {
        return "HMAC/" + this.dig.toString();
    }
}
HMAC.zeroPad = new Uint8Array(64);
;
function arraycopy(src, srcPos = 0, dst, destPos = 0, length) {
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
}
;
function strToUint8Array(str) {
    // Check if the browser supports TextDecoder API
    try {
        const encoder = new TextEncoder();
        // Encode the string and return as a Uint8Array
        return encoder.encode(str);
    }
    catch (e) { }
    // Fallback for older systems without TextDecoder support
    let result = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
        const codePoint = str.charCodeAt(i);
        if (codePoint <= 255) {
            result[i] = codePoint;
        }
        else {
            result.set([codePoint >> 8, codePoint & 0xFF], i * 2);
        }
    }
    return result;
}
;
function formatMessage(message) {
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
}
;
function toHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
;
/**
 * Implementation of the 32-bit FNV-0 hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 * FNV-0 is historic and deprecated, equivalent to FNV-1 with initial hash = 0.
 *
 * The repository provides utilities and library for FNV hashes, but the core algorithm is standard and implemented here faithfully.
 *
 * For HMAC compatibility, block length is set to 64 bytes (as per FNV standard recommendation).
 */
class Fnv0_32 extends DigestEngine {
    doInit() {
        this.engineReset();
    }
    engineReset() {
        this.hash = Fnv0_32.INIT;
    }
    processBlock(data) {
        for (let i = 0; i < data.length; i++) {
            this.hash = (this.hash * Fnv0_32.PRIME) & Fnv0_32.MASK;
            this.hash = (this.hash ^ BigInt(data[i])) & Fnv0_32.MASK;
        }
    }
    doPadding(buf, off) {
        let h = this.hash;
        buf[off] = Number((h >> BigInt(24)) & BigInt(0xFF));
        buf[off + 1] = Number((h >> BigInt(16)) & BigInt(0xFF));
        buf[off + 2] = Number((h >> BigInt(8)) & BigInt(0xFF));
        buf[off + 3] = Number(h & BigInt(0xFF));
    }
    getDigestLength() {
        return 4;
    }
    getBlockLength() {
        return 64;
    }
    getInternalBlockLength() {
        return 1; //this.getBlockLength();
    }
    dup() {
        const x = new Fnv0_32();
        x.hash = this.hash;
        return x;
    }
    getAlgorithmName() {
        return "FNV0-32";
    }
}
exports.Fnv0_32 = Fnv0_32;
Fnv0_32.PRIME = BigInt(0x01000193);
Fnv0_32.INIT = BigInt(0);
Fnv0_32.MASK = BigInt(0xFFFFFFFF);
/**
 * Implementation of the 64-bit FNV-0 hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 * FNV-0 is historic and deprecated, equivalent to FNV-1 with initial hash = 0.
 *
 * The repository provides utilities and library for FNV hashes, but the core algorithm is standard and implemented here faithfully.
 * For HMAC compatibility, block length is set to 128 bytes (as per FNV standard recommendation).
 */
class Fnv0_64 extends DigestEngine {
    doInit() {
        this.engineReset();
    }
    engineReset() {
        this.hash = Fnv0_64.INIT;
    }
    processBlock(data) {
        for (let i = 0; i < data.length; i++) {
            this.hash = (this.hash * Fnv0_64.PRIME) & Fnv0_64.MASK;
            this.hash = (this.hash ^ BigInt(data[i])) & Fnv0_64.MASK;
        }
    }
    doPadding(buf, off) {
        let h = this.hash;
        for (let i = 7; i >= 0; i--) {
            buf[off + i] = Number((h >> BigInt(i * 8)) & BigInt(0xFF));
        }
    }
    getDigestLength() {
        return 8;
    }
    getBlockLength() {
        return 128;
    }
    getInternalBlockLength() {
        return 1; //this.getBlockLength();
    }
    dup() {
        const x = new Fnv0_64();
        x.hash = this.hash;
        return x;
    }
    getAlgorithmName() {
        return "FNV0-64";
    }
}
exports.Fnv0_64 = Fnv0_64;
Fnv0_64.PRIME = BigInt("0x100000001b3");
Fnv0_64.INIT = BigInt(0);
Fnv0_64.MASK = BigInt("0xFFFFFFFFFFFFFFFF");
;
/**
 * Implementation of the 128-bit FNV-0 hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 * FNV-0 is historic and deprecated, equivalent to FNV-1 with initial hash = 0.
 *
 * Parameters from http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
 *
 * For HMAC compatibility, block length is set to 256 bytes (scaled from smaller variants).
 */
class Fnv0_128 extends DigestEngine {
    doInit() {
        this.engineReset();
    }
    engineReset() {
        this.hash = Fnv0_128.INIT;
    }
    processBlock(data) {
        for (let i = 0; i < data.length; i++) {
            this.hash = ((this.hash * Fnv0_128.PRIME) ^ BigInt(data[i])) & Fnv0_128.MASK;
        }
    }
    doPadding(buf, off) {
        let h = this.hash;
        for (let i = 15; i >= 0; i--) {
            buf[off + (15 - i)] = Number((h >> BigInt(i * 8)) & BigInt(0xFF));
        }
    }
    getDigestLength() {
        return 16;
    }
    getBlockLength() {
        return 256;
    }
    getInternalBlockLength() {
        return 1; //this.getBlockLength();
    }
    dup() {
        const x = new Fnv0_128();
        x.hash = this.hash;
        return x;
    }
    getAlgorithmName() {
        return "FNV0-128";
    }
}
exports.Fnv0_128 = Fnv0_128;
Fnv0_128.PRIME = BigInt("0x1000000000000000000013B");
Fnv0_128.INIT = BigInt(0);
Fnv0_128.MASK = (BigInt(1) << BigInt(128)) - BigInt(1);
;
/**
 * Implementation of the 256-bit FNV-0 hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 * FNV-0 is historic and deprecated, equivalent to FNV-1 with initial hash = 0.
 *
 * Parameters from http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
 *
 * For HMAC compatibility, block length is set to 512 bytes (scaled from smaller variants).
 */
class Fnv0_256 extends DigestEngine {
    doInit() {
        this.engineReset();
    }
    engineReset() {
        this.hash = Fnv0_256.INIT;
    }
    processBlock(data) {
        for (let i = 0; i < data.length; i++) {
            this.hash = ((this.hash * Fnv0_256.PRIME) ^ BigInt(data[i])) & Fnv0_256.MASK;
        }
    }
    doPadding(buf, off) {
        let h = this.hash;
        for (let i = 31; i >= 0; i--) {
            buf[off + (31 - i)] = Number((h >> BigInt(i * 8)) & BigInt(0xFF));
        }
    }
    getDigestLength() {
        return 32;
    }
    getBlockLength() {
        return 512;
    }
    getInternalBlockLength() {
        return 1; //this.getBlockLength();
    }
    dup() {
        const x = new Fnv0_256();
        x.hash = this.hash;
        return x;
    }
    getAlgorithmName() {
        return "FNV0-256";
    }
}
exports.Fnv0_256 = Fnv0_256;
Fnv0_256.PRIME = BigInt("0x1000000000000000000000B3");
Fnv0_256.INIT = BigInt(0);
Fnv0_256.MASK = (BigInt(1) << BigInt(256)) - BigInt(1);
;
/**
 * Implementation of the 512-bit FNV-0 hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 * FNV-0 is historic and deprecated, equivalent to FNV-1 with initial hash = 0.
 *
 * Parameters from http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
 *
 * For HMAC compatibility, block length is set to 1024 bytes (scaled from smaller variants).
 */
class Fnv0_512 extends DigestEngine {
    doInit() {
        this.engineReset();
    }
    engineReset() {
        this.hash = Fnv0_512.INIT;
    }
    processBlock(data) {
        for (let i = 0; i < data.length; i++) {
            this.hash = ((this.hash * Fnv0_512.PRIME) ^ BigInt(data[i])) & Fnv0_512.MASK;
        }
    }
    doPadding(buf, off) {
        let h = this.hash;
        for (let i = 63; i >= 0; i--) {
            buf[off + (63 - i)] = Number((h >> BigInt(i * 8)) & BigInt(0xFF));
        }
    }
    getDigestLength() {
        return 64;
    }
    getBlockLength() {
        return 1024;
    }
    getInternalBlockLength() {
        return 1; // this.getBlockLength();
    }
    dup() {
        const x = new Fnv0_512();
        x.hash = this.hash;
        return x;
    }
    getAlgorithmName() {
        return "FNV0-512";
    }
}
exports.Fnv0_512 = Fnv0_512;
Fnv0_512.PRIME = BigInt("0x1000000000000000000000000000000B5");
Fnv0_512.INIT = BigInt(0);
Fnv0_512.MASK = (BigInt(1) << BigInt(512)) - BigInt(1);
;
/**
 * Implementation of the 1024-bit FNV-0 hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 * FNV-0 is historic and deprecated, equivalent to FNV-1 with initial hash = 0.
 *
 * Parameters from http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
 *
 * For HMAC compatibility, block length is set to 2048 bytes (scaled from smaller variants).
 */
class Fnv0_1024 extends DigestEngine {
    doInit() {
        this.engineReset();
    }
    engineReset() {
        this.hash = Fnv0_1024.INIT;
    }
    processBlock(data) {
        for (let i = 0; i < data.length; i++) {
            this.hash = ((this.hash * Fnv0_1024.PRIME) ^ BigInt(data[i])) & Fnv0_1024.MASK;
        }
    }
    doPadding(buf, off) {
        let h = this.hash;
        for (let i = 127; i >= 0; i--) {
            buf[off + (127 - i)] = Number((h >> BigInt(i * 8)) & BigInt(0xFF));
        }
    }
    getDigestLength() {
        return 128;
    }
    getBlockLength() {
        return 2048;
    }
    getInternalBlockLength() {
        return 1; // this.getBlockLength();
    }
    dup() {
        const x = new Fnv0_1024();
        x.hash = this.hash;
        return x;
    }
    getAlgorithmName() {
        return "FNV0-1024";
    }
}
exports.Fnv0_1024 = Fnv0_1024;
Fnv0_1024.PRIME = BigInt("0x1000000000000000000000000000000000000000000000000B7");
Fnv0_1024.INIT = BigInt(0);
Fnv0_1024.MASK = (BigInt(1) << BigInt(1024)) - BigInt(1);
;
/**
 * Implementation of the 32-bit FNV-1 hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 *
 * The repository provides utilities and library for FNV hashes, but the core algorithm is standard and implemented here faithfully.
 * For HMAC compatibility, block length is set to 64 bytes.
 */
class Fnv1_32 extends DigestEngine {
    doInit() {
        this.engineReset();
    }
    engineReset() {
        this.hash = Fnv1_32.INIT;
    }
    processBlock(data) {
        for (let i = 0; i < data.length; i++) {
            this.hash = (this.hash * Fnv1_32.PRIME) & Fnv1_32.MASK;
            this.hash = (this.hash ^ BigInt(data[i])) & Fnv1_32.MASK;
        }
    }
    doPadding(buf, off) {
        let h = this.hash;
        buf[off] = Number((h >> BigInt(24)) & BigInt(0xFF));
        buf[off + 1] = Number((h >> BigInt(16)) & BigInt(0xFF));
        buf[off + 2] = Number((h >> BigInt(8)) & BigInt(0xFF));
        buf[off + 3] = Number(h & BigInt(0xFF));
    }
    getDigestLength() {
        return 4;
    }
    getBlockLength() {
        return 64;
    }
    getInternalBlockLength() {
        return 1; //this.getBlockLength();
    }
    dup() {
        const x = new Fnv1_32();
        x.hash = this.hash;
        return x;
    }
    getAlgorithmName() {
        return "FNV1-32";
    }
}
exports.Fnv1_32 = Fnv1_32;
Fnv1_32.PRIME = BigInt(0x01000193);
Fnv1_32.INIT = BigInt(0x811c9dc5);
Fnv1_32.MASK = BigInt(0xFFFFFFFF);
/**
 * Implementation of the 64-bit FNV-1 hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 *
 * The repository provides utilities and library for FNV hashes, but the core algorithm is standard and implemented here faithfully.
 * For HMAC compatibility, block length is set to 128 bytes.
 */
class Fnv1_64 extends DigestEngine {
    doInit() {
        this.engineReset();
    }
    engineReset() {
        this.hash = Fnv1_64.INIT;
    }
    processBlock(data) {
        for (let i = 0; i < data.length; i++) {
            this.hash = (this.hash * Fnv1_64.PRIME) & Fnv1_64.MASK;
            this.hash = (this.hash ^ BigInt(data[i])) & Fnv1_64.MASK;
        }
    }
    doPadding(buf, off) {
        let h = this.hash;
        for (let i = 7; i >= 0; i--) {
            buf[off + i] = Number((h >> BigInt(i * 8)) & BigInt(0xFF));
        }
    }
    getDigestLength() {
        return 8;
    }
    getBlockLength() {
        return 128;
    }
    getInternalBlockLength() {
        return 1; //this.getBlockLength();
    }
    dup() {
        const x = new Fnv1_64();
        x.hash = this.hash;
        return x;
    }
    getAlgorithmName() {
        return "FNV1-64";
    }
}
exports.Fnv1_64 = Fnv1_64;
Fnv1_64.PRIME = BigInt("0x100000001b3");
Fnv1_64.INIT = BigInt("0xcbf29ce484222325");
Fnv1_64.MASK = BigInt("0xFFFFFFFFFFFFFFFF");
;
/**
 * Implementation of the 128-bit FNV-1 hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 *
 * Parameters from http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
 *
 * For HMAC compatibility, block length is set to 256 bytes (scaled from smaller variants).
 */
class Fnv1_128 extends DigestEngine {
    doInit() {
        this.engineReset();
    }
    engineReset() {
        this.hash = Fnv1_128.INIT;
    }
    processBlock(data) {
        for (let i = 0; i < data.length; i++) {
            this.hash = ((this.hash * Fnv1_128.PRIME) ^ BigInt(data[i])) & Fnv1_128.MASK;
        }
    }
    doPadding(buf, off) {
        let h = this.hash;
        for (let i = 15; i >= 0; i--) {
            buf[off + (15 - i)] = Number((h >> BigInt(i * 8)) & BigInt(0xFF));
        }
    }
    getDigestLength() {
        return 16;
    }
    getBlockLength() {
        return 256;
    }
    getInternalBlockLength() {
        return 1; //this.getBlockLength();
    }
    dup() {
        const x = new Fnv1_128();
        x.hash = this.hash;
        return x;
    }
    getAlgorithmName() {
        return "FNV1-128";
    }
}
exports.Fnv1_128 = Fnv1_128;
Fnv1_128.PRIME = BigInt("0x1000000000000000000013B");
Fnv1_128.INIT = BigInt("0x6c62272e07bb014262b821756295c58d");
Fnv1_128.MASK = (BigInt(1) << BigInt(128)) - BigInt(1);
;
/**
 * Implementation of the 256-bit FNV-1 hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 *
 * Parameters from http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
 *
 * For HMAC compatibility, block length is set to 512 bytes (scaled from smaller variants).
 */
class Fnv1_256 extends DigestEngine {
    doInit() {
        this.engineReset();
    }
    engineReset() {
        this.hash = Fnv1_256.INIT;
    }
    processBlock(data) {
        for (let i = 0; i < data.length; i++) {
            this.hash = ((this.hash * Fnv1_256.PRIME) ^ BigInt(data[i])) & Fnv1_256.MASK;
        }
    }
    doPadding(buf, off) {
        let h = this.hash;
        for (let i = 31; i >= 0; i--) {
            buf[off + (31 - i)] = Number((h >> BigInt(i * 8)) & BigInt(0xFF));
        }
    }
    getDigestLength() {
        return 32;
    }
    getBlockLength() {
        return 512;
    }
    getInternalBlockLength() {
        return 1; //this.getBlockLength();
    }
    dup() {
        const x = new Fnv1_256();
        x.hash = this.hash;
        return x;
    }
    getAlgorithmName() {
        return "FNV1-256";
    }
}
exports.Fnv1_256 = Fnv1_256;
Fnv1_256.PRIME = BigInt("0x1000000000000000000000B3");
Fnv1_256.INIT = BigInt("0xdd268dbcaac550362d98c384c4e576cc");
Fnv1_256.MASK = (BigInt(1) << BigInt(256)) - BigInt(1);
;
/**
 * Implementation of the 512-bit FNV-1 hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 *
 * Parameters from http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
 *
 * For HMAC compatibility, block length is set to 1024 bytes (scaled from smaller variants).
 */
class Fnv1_512 extends DigestEngine {
    doInit() {
        this.engineReset();
    }
    engineReset() {
        this.hash = Fnv1_512.INIT;
    }
    processBlock(data) {
        for (let i = 0; i < data.length; i++) {
            this.hash = ((this.hash * Fnv1_512.PRIME) ^ BigInt(data[i])) & Fnv1_512.MASK;
        }
    }
    doPadding(buf, off) {
        let h = this.hash;
        for (let i = 63; i >= 0; i--) {
            buf[off + (63 - i)] = Number((h >> BigInt(i * 8)) & BigInt(0xFF));
        }
    }
    getDigestLength() {
        return 64;
    }
    getBlockLength() {
        return 1024;
    }
    getInternalBlockLength() {
        return 1; //this.getBlockLength();
    }
    dup() {
        const x = new Fnv1_512();
        x.hash = this.hash;
        return x;
    }
    getAlgorithmName() {
        return "FNV1-512";
    }
}
exports.Fnv1_512 = Fnv1_512;
Fnv1_512.PRIME = BigInt("0x1000000000000000000000000000000B5");
Fnv1_512.INIT = BigInt("0xb86db0b1171f4416dca1e50f309990ac");
Fnv1_512.MASK = (BigInt(1) << BigInt(512)) - BigInt(1);
;
/**
 * Implementation of the 1024-bit FNV-1 hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 *
 * Parameters from http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
 *
 * For HMAC compatibility, block length is set to 2048 bytes (scaled from smaller variants).
 */
class Fnv1_1024 extends DigestEngine {
    doInit() {
        this.engineReset();
    }
    engineReset() {
        this.hash = Fnv1_1024.INIT;
    }
    processBlock(data) {
        for (let i = 0; i < data.length; i++) {
            this.hash = ((this.hash * Fnv1_1024.PRIME) ^ BigInt(data[i])) & Fnv1_1024.MASK;
        }
    }
    doPadding(buf, off) {
        let h = this.hash;
        for (let i = 127; i >= 0; i--) {
            buf[off + (127 - i)] = Number((h >> BigInt(i * 8)) & BigInt(0xFF));
        }
    }
    getDigestLength() {
        return 128;
    }
    getBlockLength() {
        return 2048;
    }
    getInternalBlockLength() {
        return 1; //this.getBlockLength();
    }
    dup() {
        const x = new Fnv1_1024();
        x.hash = this.hash;
        return x;
    }
    getAlgorithmName() {
        return "FNV1-1024";
    }
}
exports.Fnv1_1024 = Fnv1_1024;
Fnv1_1024.PRIME = BigInt("0x1000000000000000000000000000000000000000000000000B7");
Fnv1_1024.INIT = BigInt("0x0707d8d4a74da77c3b54d6f3c21b9a6f");
Fnv1_1024.MASK = (BigInt(1) << BigInt(1024)) - BigInt(1);
;
/**
 * Implementation of the 32-bit FNV-1a hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 * FNV-1a is the recommended variant for better hash distribution.
 *
 * The repository provides utilities and library for FNV hashes, but the core algorithm is standard and implemented here faithfully.
 * For HMAC compatibility, block length is set to 64 bytes.
 */
class Fnv1a_32 extends DigestEngine {
    doInit() {
        this.engineReset();
    }
    engineReset() {
        this.hash = Fnv1a_32.INIT;
    }
    processBlock(data) {
        for (let i = 0; i < data.length; i++) {
            this.hash = (this.hash ^ BigInt(data[i])) & Fnv1a_32.MASK;
            this.hash = (this.hash * Fnv1a_32.PRIME) & Fnv1a_32.MASK;
        }
    }
    doPadding(buf, off) {
        let h = this.hash;
        buf[off] = Number(h & BigInt(0xFF));
        buf[off + 1] = Number((h >> BigInt(8)) & BigInt(0xFF));
        buf[off + 2] = Number((h >> BigInt(16)) & BigInt(0xFF));
        buf[off + 3] = Number((h >> BigInt(24)) & BigInt(0xFF));
    }
    getDigestLength() {
        return 4;
    }
    getBlockLength() {
        return 64;
    }
    getInternalBlockLength() {
        return 1; //this.getBlockLength();
    }
    dup() {
        const x = new Fnv1a_32();
        x.hash = this.hash;
        return x;
    }
    getAlgorithmName() {
        return "FNV1a-32";
    }
}
exports.Fnv1a_32 = Fnv1a_32;
Fnv1a_32.PRIME = BigInt(0x01000193);
Fnv1a_32.INIT = BigInt(0x811c9dc5);
Fnv1a_32.MASK = BigInt(0xFFFFFFFF);
;
/**
 * Implementation of the 64-bit FNV-1a hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 * FNV-1a is the recommended variant for better hash distribution.
 *
 * The repository provides utilities and library for FNV hashes, but the core algorithm is standard and implemented here faithfully.
 * For HMAC compatibility, block length is set to 128 bytes.
 */
class Fnv1a_64 extends DigestEngine {
    doInit() {
        this.engineReset();
    }
    engineReset() {
        this.hash = Fnv1a_64.INIT;
    }
    processBlock(data) {
        for (let i = 0; i < data.length; i++) {
            this.hash = (this.hash ^ BigInt(data[i])) & Fnv1a_64.MASK;
            this.hash = (this.hash * Fnv1a_64.PRIME) & Fnv1a_64.MASK;
        }
    }
    doPadding(buf, off) {
        let h = this.hash;
        for (let i = 7; i >= 0; i--) {
            buf[off + i] = Number((h >> BigInt(i * 8)) & BigInt(0xFF));
        }
    }
    getDigestLength() {
        return 8;
    }
    getBlockLength() {
        return 128;
    }
    getInternalBlockLength() {
        return 1; //this.getBlockLength();
    }
    dup() {
        const x = new Fnv1a_64();
        x.hash = this.hash;
        return x;
    }
    getAlgorithmName() {
        return "FNV1a-64";
    }
}
exports.Fnv1a_64 = Fnv1a_64;
Fnv1a_64.PRIME = BigInt("0x100000001b3");
Fnv1a_64.INIT = BigInt("0xcbf29ce484222325");
Fnv1a_64.MASK = BigInt("0xFFFFFFFFFFFFFFFF");
;
/**
 * Implementation of the 128-bit FNV-1a hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 * FNV-1a is the recommended variant for better hash distribution.
 *
 * Parameters from http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
 *
 * For HMAC compatibility, block length is set to 256 bytes (scaled from smaller variants).
 */
class Fnv1a_128 extends DigestEngine {
    doInit() {
        this.engineReset();
    }
    engineReset() {
        this.hash = Fnv1a_128.INIT;
    }
    processBlock(data) {
        for (let i = 0; i < data.length; i++) {
            this.hash = ((this.hash ^ BigInt(data[i])) * Fnv1a_128.PRIME) & Fnv1a_128.MASK;
        }
    }
    doPadding(buf, off) {
        let h = this.hash;
        for (let i = 15; i >= 0; i--) {
            buf[off + (15 - i)] = Number((h >> BigInt(i * 8)) & BigInt(0xFF));
        }
    }
    getDigestLength() {
        return 16;
    }
    getBlockLength() {
        return 256;
    }
    getInternalBlockLength() {
        return 1; //this.getBlockLength();
    }
    dup() {
        const x = new Fnv1a_128();
        x.hash = this.hash;
        return x;
    }
    getAlgorithmName() {
        return "FNV1a-128";
    }
}
exports.Fnv1a_128 = Fnv1a_128;
Fnv1a_128.PRIME = BigInt("0x1000000000000000000013B");
Fnv1a_128.INIT = BigInt("0x6c62272e07bb014262b821756295c58d");
Fnv1a_128.MASK = (BigInt(1) << BigInt(128)) - BigInt(1);
;
/**
 * Implementation of the 256-bit FNV-1a hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 * FNV-1a is the recommended variant for better hash distribution.
 *
 * Parameters from http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
 *
 * For HMAC compatibility, block length is set to 512 bytes (scaled from smaller variants).
 */
class Fnv1a_256 extends DigestEngine {
    doInit() {
        this.engineReset();
    }
    engineReset() {
        this.hash = Fnv1a_256.INIT;
    }
    processBlock(data) {
        for (let i = 0; i < data.length; i++) {
            this.hash = ((this.hash ^ BigInt(data[i])) * Fnv1a_256.PRIME) & Fnv1a_256.MASK;
        }
    }
    doPadding(buf, off) {
        let h = this.hash;
        for (let i = 31; i >= 0; i--) {
            buf[off + (31 - i)] = Number((h >> BigInt(i * 8)) & BigInt(0xFF));
        }
    }
    getDigestLength() {
        return 32;
    }
    getBlockLength() {
        return 512;
    }
    getInternalBlockLength() {
        return 1; //this.getBlockLength();
    }
    dup() {
        const x = new Fnv1a_256();
        x.hash = this.hash;
        return x;
    }
    getAlgorithmName() {
        return "FNV1a-256";
    }
}
exports.Fnv1a_256 = Fnv1a_256;
Fnv1a_256.PRIME = BigInt("0x1000000000000000000000B3");
Fnv1a_256.INIT = BigInt("0xdd268dbcaac550362d98c384c4e576cc");
Fnv1a_256.MASK = (BigInt(1) << BigInt(256)) - BigInt(1);
;
/**
 * Implementation of the 512-bit FNV-1a hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 * FNV-1a is the recommended variant for better hash distribution.
 *
 * Parameters from http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
 *
 * For HMAC compatibility, block length is set to 1024 bytes (scaled from smaller variants).
 */
class Fnv1a_512 extends DigestEngine {
    doInit() {
        this.engineReset();
    }
    engineReset() {
        this.hash = Fnv1a_512.INIT;
    }
    processBlock(data) {
        for (let i = 0; i < data.length; i++) {
            this.hash = ((this.hash ^ BigInt(data[i])) * Fnv1a_512.PRIME) & Fnv1a_512.MASK;
        }
    }
    doPadding(buf, off) {
        let h = this.hash;
        for (let i = 63; i >= 0; i--) {
            buf[off + (63 - i)] = Number((h >> BigInt(i * 8)) & BigInt(0xFF));
        }
    }
    getDigestLength() {
        return 64;
    }
    getBlockLength() {
        return 1024;
    }
    getInternalBlockLength() {
        return 1; //this.getBlockLength();
    }
    dup() {
        const x = new Fnv1a_512();
        x.hash = this.hash;
        return x;
    }
    getAlgorithmName() {
        return "FNV1a-512";
    }
}
exports.Fnv1a_512 = Fnv1a_512;
Fnv1a_512.PRIME = BigInt("0x1000000000000000000000000000000B5");
Fnv1a_512.INIT = BigInt("0xb86db0b1171f4416dca1e50f309990ac");
Fnv1a_512.MASK = (BigInt(1) << BigInt(512)) - BigInt(1);
;
/**
 * Implementation of the 1024-bit FNV-1a hash function, based on the Fowler/Noll/Vo algorithm from the lcn2/fnv repository.
 * FNV-1a is the recommended variant for better hash distribution.
 *
 * Parameters from http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
 *
 * For HMAC compatibility, block length is set to 2048 bytes (scaled from smaller variants).
 */
class Fnv1a_1024 extends DigestEngine {
    doInit() {
        this.engineReset();
    }
    engineReset() {
        this.hash = Fnv1a_1024.INIT;
    }
    processBlock(data) {
        for (let i = 0; i < data.length; i++) {
            this.hash = ((this.hash ^ BigInt(data[i])) * Fnv1a_1024.PRIME) & Fnv1a_1024.MASK;
        }
    }
    doPadding(buf, off) {
        let h = this.hash;
        for (let i = 127; i >= 0; i--) {
            buf[off + (127 - i)] = Number((h >> BigInt(i * 8)) & BigInt(0xFF));
        }
    }
    getDigestLength() {
        return 128;
    }
    getBlockLength() {
        return 2048;
    }
    getInternalBlockLength() {
        return 1; //this.getBlockLength();
    }
    dup() {
        const x = new Fnv1a_1024();
        x.hash = this.hash;
        return x;
    }
    getAlgorithmName() {
        return "FNV1a-1024";
    }
}
exports.Fnv1a_1024 = Fnv1a_1024;
Fnv1a_1024.PRIME = BigInt("0x1000000000000000000000000000000000000000000000000B7");
Fnv1a_1024.INIT = BigInt("0x0707d8d4a74da77c3b54d6f3c21b9a6f");
Fnv1a_1024.MASK = (BigInt(1) << BigInt(1024)) - BigInt(1);
class Fnv {
    constructor(type = "FNV1A_64") {
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
    update(message) {
        message = formatMessage(message);
        this.class.update(message);
    }
    digest(format) {
        if (format == "hex") {
            return toHex(this.class.digest());
        }
        else if (format == "buffer") {
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
function FNV0(message, bitLen = 64, format = arrayType()) {
    const hash = new Fnv(`FNV0_${bitLen}`);
    hash.update(message);
    return hash.digest(format);
}
exports.FNV0 = FNV0;
;
/**
 * Creates a keyed FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {32|64|128|256|512|1024} bitLen - Hash length (default 64 or 8 bytes)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function FNV0_HMAC(message, key, bitLen = 64, format = arrayType()) {
    const hash = new Fnv(`FNV0_${bitLen}`);
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    }
    else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
}
exports.FNV0_HMAC = FNV0_HMAC;
;
/**
 * Creates a 4 byte FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function FNV0_32(message, format = arrayType()) {
    const hash = new Fnv("FNV0_32");
    hash.update(message);
    return hash.digest(format);
}
exports.FNV0_32 = FNV0_32;
;
/**
 * Creates a 4 byte keyed FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function FNV0_32_HMAC(message, key, format = arrayType()) {
    const hash = new Fnv("FNV0_32");
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    }
    else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
}
exports.FNV0_32_HMAC = FNV0_32_HMAC;
;
/**
 * Creates a 8 byte FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function FNV0_64(message, format = arrayType()) {
    const hash = new Fnv("FNV0_64");
    hash.update(message);
    return hash.digest(format);
}
exports.FNV0_64 = FNV0_64;
;
/**
 * Creates a 8 byte keyed FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function FNV0_64_HMAC(message, key, format = arrayType()) {
    const hash = new Fnv("FNV0_64");
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    }
    else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
}
exports.FNV0_64_HMAC = FNV0_64_HMAC;
;
/**
 * Creates a 16 byte FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function FNV0_128(message, format = arrayType()) {
    const hash = new Fnv("FNV0_128");
    hash.update(message);
    return hash.digest(format);
}
exports.FNV0_128 = FNV0_128;
;
/**
 * Creates a 16 byte keyed FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function FNV0_128_HMAC(message, key, format = arrayType()) {
    const hash = new Fnv("FNV0_128");
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    }
    else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
}
exports.FNV0_128_HMAC = FNV0_128_HMAC;
;
/**
 * Creates a 32 byte FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function FNV0_256(message, format = arrayType()) {
    const hash = new Fnv("FNV0_256");
    hash.update(message);
    return hash.digest(format);
}
exports.FNV0_256 = FNV0_256;
;
/**
 * Creates a 32 byte keyed FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function FNV0_256_HMAC(message, key, format = arrayType()) {
    const hash = new Fnv("FNV0_256");
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    }
    else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
}
exports.FNV0_256_HMAC = FNV0_256_HMAC;
;
/**
 * Creates a 64 byte FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function FNV0_512(message, format = arrayType()) {
    const hash = new Fnv("FNV0_512");
    hash.update(message);
    return hash.digest(format);
}
exports.FNV0_512 = FNV0_512;
;
/**
 * Creates a 64 byte keyed FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function FNV0_512_HMAC(message, key, format = arrayType()) {
    const hash = new Fnv("FNV0_512");
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    }
    else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
}
exports.FNV0_512_HMAC = FNV0_512_HMAC;
;
/**
 * Creates a 128 byte FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function FNV0_1024(message, format = arrayType()) {
    const hash = new Fnv("FNV0_512");
    hash.update(message);
    return hash.digest(format);
}
exports.FNV0_1024 = FNV0_1024;
;
/**
 * Creates a 128 byte keyed FNV0 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function FNV0_1024_HMAC(message, key, format = arrayType()) {
    const hash = new Fnv("FNV0_512");
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    }
    else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
}
exports.FNV0_1024_HMAC = FNV0_1024_HMAC;
;
/**
 * Creates a FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param message - Message to hash
 * @param {32|64|128|256|512|1024} bitLen - Hash length (default 64 or 8 bytes)
 * @returns `string|Uint8Array|Buffer`
 */
function FNV1(message, bitLen = 64, format = arrayType()) {
    const hash = new Fnv(`FNV1_${bitLen}`);
    hash.update(message);
    return hash.digest(format);
}
exports.FNV1 = FNV1;
;
/**
 * Creates a keyed FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {32|64|128|256|512|1024} bitLen - Hash length (default 64 or 8 bytes)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function FNV1_HMAC(message, key, bitLen = 64, format = arrayType()) {
    const hash = new Fnv(`FNV1_${bitLen}`);
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    }
    else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
}
exports.FNV1_HMAC = FNV1_HMAC;
;
/**
 * Creates a 4 byte FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function FNV1_32(message, format = arrayType()) {
    const hash = new Fnv("FNV1_32");
    hash.update(message);
    return hash.digest(format);
}
exports.FNV1_32 = FNV1_32;
;
/**
 * Creates a 4 byte keyed FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function FNV1_32_HMAC(message, key, format = arrayType()) {
    const hash = new Fnv("FNV1_32");
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    }
    else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
}
exports.FNV1_32_HMAC = FNV1_32_HMAC;
;
/**
 * Creates a 8 byte FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function FNV1_64(message, format = arrayType()) {
    const hash = new Fnv("FNV1_64");
    hash.update(message);
    return hash.digest(format);
}
exports.FNV1_64 = FNV1_64;
;
/**
 * Creates a 8 byte keyed FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function FNV1_64_HMAC(message, key, format = arrayType()) {
    const hash = new Fnv("FNV1_64");
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    }
    else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
}
exports.FNV1_64_HMAC = FNV1_64_HMAC;
;
/**
 * Creates a 16 byte FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function FNV1_128(message, format = arrayType()) {
    const hash = new Fnv("FNV1_128");
    hash.update(message);
    return hash.digest(format);
}
exports.FNV1_128 = FNV1_128;
;
/**
 * Creates a 16 byte keyed FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function FNV1_128_HMAC(message, key, format = arrayType()) {
    const hash = new Fnv("FNV1_128");
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    }
    else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
}
exports.FNV1_128_HMAC = FNV1_128_HMAC;
;
/**
 * Creates a 32 byte FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function FNV1_256(message, format = arrayType()) {
    const hash = new Fnv("FNV1_256");
    hash.update(message);
    return hash.digest(format);
}
exports.FNV1_256 = FNV1_256;
;
/**
 * Creates a 32 byte keyed FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function FNV1_256_HMAC(message, key, format = arrayType()) {
    const hash = new Fnv("FNV1_256");
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    }
    else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
}
exports.FNV1_256_HMAC = FNV1_256_HMAC;
;
/**
 * Creates a 64 byte FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function FNV1_512(message, format = arrayType()) {
    const hash = new Fnv("FNV1_512");
    hash.update(message);
    return hash.digest(format);
}
exports.FNV1_512 = FNV1_512;
;
/**
 * Creates a 64 byte keyed FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function FNV1_512_HMAC(message, key, format = arrayType()) {
    const hash = new Fnv("FNV1_512");
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    }
    else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
}
exports.FNV1_512_HMAC = FNV1_512_HMAC;
;
/**
 * Creates a 128 byte FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function FNV1_1024(message, format = arrayType()) {
    const hash = new Fnv("FNV1_1024");
    hash.update(message);
    return hash.digest(format);
}
exports.FNV1_1024 = FNV1_1024;
;
/**
 * Creates a 128 byte keyed FNV1 of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function FNV1_1024_HMAC(message, key, format = arrayType()) {
    const hash = new Fnv("FNV1_1024");
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    }
    else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
}
exports.FNV1_1024_HMAC = FNV1_1024_HMAC;
;
/**
 * Creates a FNV1A of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param message - Message to hash
 * @param {32|64|128|256|512|1024} bitLen - Hash length (default 64 or 8 bytes)
 * @returns `string|Uint8Array|Buffer`
 */
function FNV1A(message, bitLen = 64, format = arrayType()) {
    const hash = new Fnv(`FNV1A_${bitLen}`);
    hash.update(message);
    return hash.digest(format);
}
exports.FNV1A = FNV1A;
;
/**
 * Creates a keyed FNV1A of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {32|64|128|256|512|1024} bitLen - Hash length (default 64 or 8 bytes)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function FNV1A_HMAC(message, key, bitLen = 64, format = arrayType()) {
    const hash = new Fnv(`FNV1A_${bitLen}`);
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    }
    else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
}
exports.FNV1A_HMAC = FNV1A_HMAC;
;
/**
 * Creates a 4 byte FNV1a of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function FNV1A_32(message, format = arrayType()) {
    const hash = new Fnv("FNV1A_32");
    hash.update(message);
    return hash.digest(format);
}
exports.FNV1A_32 = FNV1A_32;
;
/**
 * Creates a 4 byte keyed FNV1a of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function FNV1A_32_HMAC(message, key, format = arrayType()) {
    const hash = new Fnv("FNV1A_32");
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    }
    else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
}
exports.FNV1A_32_HMAC = FNV1A_32_HMAC;
;
/**
 * Creates a 8 byte FNV1a of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function FNV1A_64(message, format = arrayType()) {
    const hash = new Fnv("FNV1A_64");
    hash.update(message);
    return hash.digest(format);
}
exports.FNV1A_64 = FNV1A_64;
;
/**
 * Creates a 8 byte keyed FNV1a of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function FNV1A_64_HMAC(message, key, format = arrayType()) {
    const hash = new Fnv("FNV1A_64");
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    }
    else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
}
exports.FNV1A_64_HMAC = FNV1A_64_HMAC;
;
/**
 * Creates a 16 byte FNV1a of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function FNV1A_128(message, format = arrayType()) {
    const hash = new Fnv("FNV1A_128");
    hash.update(message);
    return hash.digest(format);
}
exports.FNV1A_128 = FNV1A_128;
;
/**
 * Creates a 16 byte keyed FNV1a of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function FNV1A_128_HMAC(message, key, format = arrayType()) {
    const hash = new Fnv("FNV1A_128");
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    }
    else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
}
exports.FNV1A_128_HMAC = FNV1A_128_HMAC;
;
/**
 * Creates a 32 byte FNV1a of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function FNV1A_256(message, format = arrayType()) {
    const hash = new Fnv("FNV1A_256");
    hash.update(message);
    return hash.digest(format);
}
exports.FNV1A_256 = FNV1A_256;
;
/**
 * Creates a 32 byte keyed FNV1a of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function FNV1A_256_HMAC(message, key, format = arrayType()) {
    const hash = new Fnv("FNV1A_256");
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    }
    else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
}
exports.FNV1A_256_HMAC = FNV1A_256_HMAC;
;
/**
 * Creates a 64 byte FNV1a of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function FNV1A_512(message, format = arrayType()) {
    const hash = new Fnv("FNV1A_512");
    hash.update(message);
    return hash.digest(format);
}
exports.FNV1A_512 = FNV1A_512;
;
/**
 * Creates a 64 byte keyed FNV1a of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function FNV1A_512_HMAC(message, key, format = arrayType()) {
    const hash = new Fnv("FNV1A_512");
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    }
    else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
}
exports.FNV1A_512_HMAC = FNV1A_512_HMAC;
;
/**
 * Creates a 128 byte FNV1a of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function FNV1A_1024(message, format = arrayType()) {
    const hash = new Fnv("FNV1A_1024");
    hash.update(message);
    return hash.digest(format);
}
exports.FNV1A_1024 = FNV1A_1024;
;
/**
 * Creates a 128 byte keyed FNV1a of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function FNV1A_1024_HMAC(message, key, format = arrayType()) {
    const hash = new Fnv("FNV1A_1024");
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    }
    else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
}
exports.FNV1A_1024_HMAC = FNV1A_1024_HMAC;
;
/**
 * Creates a FNV hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {0 | "0" | 1 | "1" | "1A"} type - FNV type (default 1A)
 * @param {32|64|128|256|512|1024} bitLen - Hash length (default 64 or 8 bytes)
 * @param {OutputFormat?} format - as a hex string, Uint8Array, Buffer
 * @returns `string|Uint8Array|Buffer`
 */
function _FNV(message, type = "1A", bitLen = 64, format = arrayType()) {
    const hash = new Fnv(`FNV${type}_${bitLen}`);
    hash.update(message);
    return hash.digest(format);
}
exports._FNV = _FNV;
;
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
function FNV_HMAC(message, key, type = "1A", bitLen = 64, format = arrayType()) {
    const hash = new Fnv(`FNV${type}_${bitLen}`);
    const mac = new HMAC(hash.class, formatMessage(key));
    mac.update(formatMessage(message));
    if (format == "buffer") {
        return Buffer.from(mac.digest());
    }
    else if (format == 'hex') {
        return toHex(mac.digest());
    }
    return mac.digest();
}
exports.FNV_HMAC = FNV_HMAC;
/**
 * Static class of all Fowler/Noll/Vo FNV functions and classes
 */
class FNV {
    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST() {
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
        ];
    }
}
exports.FNV = FNV;
FNV.Fnv = Fnv;
FNV.FNV = _FNV;
FNV.FNV0 = FNV0;
FNV.FNV0_HMAC = FNV0_HMAC;
FNV.FNV0_32_HMAC = FNV0_32_HMAC;
FNV.FNV0_32 = FNV0_32;
FNV.FNV0_64_HMAC = FNV0_64_HMAC;
FNV.FNV0_64 = FNV0_64;
FNV.FNV0_128_HMAC = FNV0_128_HMAC;
FNV.FNV0_128 = FNV0_128;
FNV.FNV0_256_HMAC = FNV0_256_HMAC;
FNV.FNV0_256 = FNV0_256;
FNV.FNV0_512_HMAC = FNV0_512_HMAC;
FNV.FNV0_512 = FNV0_512;
FNV.FNV0_1024_HMAC = FNV0_1024_HMAC;
FNV.FNV0_1024 = FNV0_1024;
FNV.FNV1 = FNV1;
FNV.FNV1_HMAC = FNV1_HMAC;
FNV.FNV1_32_HMAC = FNV1_32_HMAC;
FNV.FNV1_32 = FNV1_32;
FNV.FNV1_64_HMAC = FNV1_64_HMAC;
FNV.FNV1_64 = FNV1_64;
FNV.FNV1_128_HMAC = FNV1_128_HMAC;
FNV.FNV1_128 = FNV1_128;
FNV.FNV1_256_HMAC = FNV1_256_HMAC;
FNV.FNV1_256 = FNV1_256;
FNV.FNV1_512_HMAC = FNV1_512_HMAC;
FNV.FNV1_512 = FNV1_512;
FNV.FNV1_1024_HMAC = FNV1_1024_HMAC;
FNV.FNV1_1024 = FNV1_1024;
FNV.FNV1A = FNV1A;
FNV.FNV1A_HMAC = FNV1A_HMAC;
FNV.FNV1A_32_HMAC = FNV1A_32_HMAC;
FNV.FNV1A_32 = FNV1A_32;
FNV.FNV1A_64_HMAC = FNV1A_64_HMAC;
FNV.FNV1A_64 = FNV1A_64;
FNV.FNV1A_128_HMAC = FNV1A_128_HMAC;
FNV.FNV1A_128 = FNV1A_128;
FNV.FNV1A_256_HMAC = FNV1A_256_HMAC;
FNV.FNV1A_256 = FNV1A_256;
FNV.FNV1A_512_HMAC = FNV1A_512_HMAC;
FNV.FNV1A_512 = FNV1A_512;
FNV.FNV1A_1024_HMAC = FNV1A_1024_HMAC;
FNV.FNV1A_1024 = FNV1A_1024;
FNV.FNV_HMAC = FNV_HMAC;
;
//# sourceMappingURL=FNV.js.map