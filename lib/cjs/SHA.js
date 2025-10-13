"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.cSHAKE = exports.SHAKE = exports.KMAC = exports.KECCAK = exports.SHA = void 0;
const SHA0_1 = require("./SHA0");
const SHA1_1 = require("./SHA1");
const SHA256_1 = require("./SHA256");
const SHA512_1 = require("./SHA512");
const SHA3_1 = require("./SHA3");
/**
 * Static class of all SHA functions
 */
class SHA {
    /**
     * List of all functions in class
     */
    static get FUNCTION_LISTLISTLIST() {
        return [
            "SHA0",
            "SHA0_HMAC",
            "SHA1",
            "SHA1_HMAC",
            "SHA224",
            "SHA224_HMAC",
            "SHA256",
            "SHA256_HMAC",
            "SHA256_DOUBLE",
            "SHA512",
            "SHA512_HMAC",
            "SHA384",
            "SHA384_HMAC",
            "SHA512_256",
            "SHA512_256_HMAC",
            "SHA512_224",
            "SHA512_224_HMAC",
            "SHA3",
            "SHA3_224",
            "SHA3_224_HMAC",
            "SHA3_256",
            "SHA3_256_HMAC",
            "SHA3_384",
            "SHA3_384_HMAC",
            "SHA3_512",
            "SHA3_512_HMAC",
            "SHA3_HMAC"
        ];
    }
}
exports.SHA = SHA;
SHA.SHA0 = SHA0_1.SHA0;
SHA.SHA0_HMAC = SHA0_1.SHA0_HMAC;
SHA.SHA1 = SHA1_1.SHA1;
SHA.SHA1_HMAC = SHA1_1.SHA1_HMAC;
SHA.SHA224 = SHA256_1.SHA224;
SHA.SHA224_HMAC = SHA256_1.SHA224_HMAC;
SHA.SHA256 = SHA256_1.SHA256;
SHA.SHA256_HMAC = SHA256_1.SHA256_HMAC;
SHA.SHA256_DOUBLE = SHA256_1.SHA256_DOUBLE;
SHA.SHA512 = SHA512_1.SHA512;
SHA.SHA512_HMAC = SHA512_1.SHA512_HMAC;
SHA.SHA384 = SHA512_1.SHA384;
SHA.SHA384_HMAC = SHA512_1.SHA384_HMAC;
SHA.SHA512_256 = SHA512_1.SHA512_256;
SHA.SHA512_256_HMAC = SHA512_1.SHA512_256_HMAC;
SHA.SHA512_224 = SHA512_1.SHA512_224;
SHA.SHA512_224_HMAC = SHA512_1.SHA512_224_HMAC;
SHA.SHA3 = SHA3_1.SHA3;
SHA.SHA3_224 = SHA3_1.SHA3_224;
SHA.SHA3_224_HMAC = SHA3_1.SHA3_224_HMAC;
SHA.SHA3_256 = SHA3_1.SHA3_256;
SHA.SHA3_256_HMAC = SHA3_1.SHA3_256_HMAC;
SHA.SHA3_384 = SHA3_1.SHA3_384;
SHA.SHA3_384_HMAC = SHA3_1.SHA3_384_HMAC;
SHA.SHA3_512 = SHA3_1.SHA3_512;
SHA.SHA3_512_HMAC = SHA3_1.SHA3_512_HMAC;
SHA.SHA3_HMAC = SHA3_1.SHA3_HMAC;
;
/**
 * Static class of all Keccak functions
 */
class KECCAK {
    /**
     * Static class of all Keccak function
     */
    static get FUNCTION_LIST() {
        return [
            "KECCAK",
            "KECCAK224",
            "KECCAK224_HMAC",
            "KECCAK256",
            "KECCAK256_HMAC",
            "KECCAK384",
            "KECCAK384_HMAC",
            "KECCAK512",
            "KECCAK512_HMAC",
            "KECCAK_HMAC"
        ];
    }
}
exports.KECCAK = KECCAK;
KECCAK.KECCAK = SHA3_1._KECCAK;
KECCAK.KECCAK224 = SHA3_1.KECCAK224;
KECCAK.KECCAK224_HMAC = SHA3_1.KECCAK224_HMAC;
KECCAK.KECCAK256 = SHA3_1.KECCAK256;
KECCAK.KECCAK256_HMAC = SHA3_1.KECCAK256_HMAC;
KECCAK.KECCAK384 = SHA3_1.KECCAK384;
KECCAK.KECCAK384_HMAC = SHA3_1.KECCAK384_HMAC;
KECCAK.KECCAK512 = SHA3_1.KECCAK512;
KECCAK.KECCAK512_HMAC = SHA3_1.KECCAK512_HMAC;
KECCAK.KECCAK_HMAC = SHA3_1.KECCAK_HMAC;
;
/**
 * Static class of all KMAC functions
 */
class KMAC {
    /**
     * Static class of all KMAC function
     */
    static get FUNCTION_LIST() {
        return [
            "KMAC",
            "KMAC128",
            "KMAC256",
        ];
    }
}
exports.KMAC = KMAC;
KMAC.KMAC = SHA3_1._KMAC;
KMAC.KMAC128 = SHA3_1.KMAC128;
KMAC.KMAC256 = SHA3_1.KMAC256;
;
class SHAKE {
    /**
     * Static class of all SHAKE function
     */
    static get FUNCTION_LIST() {
        return [
            "SHAKE",
            "SHAKE128",
            "SHAKE256",
        ];
    }
}
exports.SHAKE = SHAKE;
SHAKE.SHAKE = SHA3_1._SHAKE;
SHAKE.SHAKE128 = SHA3_1.SHAKE128;
SHAKE.SHAKE256 = SHA3_1.SHAKE256;
;
/**
 * Static class of all cSHAKE functions
 */
class cSHAKE {
    /**
     * Static class of all cSHAKE function
     */
    static get FUNCTION_LIST() {
        return [
            "cSHAKE",
            "cSHAKE128",
            "cSHAKE256",
        ];
    }
}
exports.cSHAKE = cSHAKE;
cSHAKE.cSHAKE = SHA3_1._cSHAKE;
cSHAKE.cSHAKE128 = SHA3_1.cSHAKE128;
cSHAKE.cSHAKE256 = SHA3_1.cSHAKE256;
//# sourceMappingURL=SHA.js.map