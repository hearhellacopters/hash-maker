import { 
    SHA0,
    SHA0_HMAC
} from './SHA0';

import {
    SHA1,
    SHA1_HMAC
} from './SHA1';

import {
    SHA224,
    SHA224_HMAC,
    SHA256,
    SHA256_HMAC,
    SHA256_DOUBLE
} from './SHA256';

import {
    SHA512,
    SHA512_HMAC,

    SHA384,
    SHA384_HMAC,

    SHA512_256,
    SHA512_256_HMAC,

    SHA512_224,
    SHA512_224_HMAC,
} from './SHA512';

import {
    SHA3,
    SHA3_224,
    SHA3_224_HMAC,
    SHA3_256,
    SHA3_256_HMAC,
    SHA3_384,
    SHA3_384_HMAC,
    SHA3_512,
    SHA3_512_HMAC,
    SHA3_HMAC,

    _KECCAK,
    KECCAK224,
    KECCAK224_HMAC,
    KECCAK256,
    KECCAK256_HMAC,
    KECCAK384,
    KECCAK384_HMAC,
    KECCAK512,
    KECCAK512_HMAC,
    KECCAK_HMAC,

    _SHAKE,
    SHAKE128,
    SHAKE256,

    _KMAC,
    KMAC128,
    KMAC256,

    _cSHAKE,
    cSHAKE128,
    cSHAKE256,
} from './SHA3';

/**
 * Static class of all SHA functions
 */
export class SHA {
    static SHA0 = SHA0;
    static SHA0_HMAC = SHA0_HMAC;

    static SHA1 = SHA1;
    static SHA1_HMAC = SHA1_HMAC;

    static SHA224 = SHA224;
    static SHA224_HMAC = SHA224_HMAC;
    static SHA256 = SHA256;
    static SHA256_HMAC = SHA256_HMAC;
    static SHA256_DOUBLE = SHA256_DOUBLE;

    static SHA512 = SHA512;
    static SHA512_HMAC = SHA512_HMAC;
    static SHA384 = SHA384;
    static SHA384_HMAC = SHA384_HMAC;
    static SHA512_256 = SHA512_256;
    static SHA512_256_HMAC = SHA512_256_HMAC;
    static SHA512_224 = SHA512_224;
    static SHA512_224_HMAC = SHA512_224_HMAC;

    static SHA3 = SHA3;
    static SHA3_224 = SHA3_224;
    static SHA3_224_HMAC = SHA3_224_HMAC;
    static SHA3_256 = SHA3_256;
    static SHA3_256_HMAC = SHA3_256_HMAC;
    static SHA3_384 = SHA3_384;
    static SHA3_384_HMAC = SHA3_384_HMAC;
    static SHA3_512 = SHA3_512;
    static SHA3_512_HMAC = SHA3_512_HMAC;
    static SHA3_HMAC = SHA3_HMAC;

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
};

/**
 * Static class of all Keccak functions
 */
export class KECCAK {
    static KECCAK = _KECCAK;
    static KECCAK224 = KECCAK224;
    static KECCAK224_HMAC = KECCAK224_HMAC;
    static KECCAK256 = KECCAK256;
    static KECCAK256_HMAC = KECCAK256_HMAC;
    static KECCAK384 = KECCAK384;
    static KECCAK384_HMAC = KECCAK384_HMAC;
    static KECCAK512 = KECCAK512;
    static KECCAK512_HMAC = KECCAK512_HMAC;
    static KECCAK_HMAC = KECCAK_HMAC;

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
};

/**
 * Static class of all KMAC functions
 */
export class KMAC {
    static KMAC = _KMAC;
    static KMAC128 = KMAC128;
    static KMAC256 = KMAC256;

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
};

export class SHAKE {
    static SHAKE = _SHAKE;
    static SHAKE128 = SHAKE128;
    static SHAKE256 = SHAKE256;
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
};

/**
 * Static class of all cSHAKE functions
 */
export class cSHAKE {
    static cSHAKE = _cSHAKE;
    static cSHAKE128 = cSHAKE128;
    static cSHAKE256 = cSHAKE256;

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