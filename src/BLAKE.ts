import {
    Blake,
    BLAKE as _BLAKE,
    BLAKE224,
    BLAKE224_HMAC,
    BLAKE256,
    BLAKE256_HMAC,
    BLAKE384,
    BLAKE384_HMAC,
    BLAKE512,
    BLAKE512_HMAC,
    BLAKE_HMAC
} from './BLAKE1';

import {
    Blake2b,
    BLAKE2b,
    BLAKE2b224,
    BLAKE2b224_HMAC,
    BLAKE2b256,
    BLAKE2b256_HMAC,
    BLAKE2b384,
    BLAKE2b384_HMAC,
    BLAKE2b512,
    BLAKE2b512_HMAC,
    BLAKE2b_HMAC
} from './BLAKE2b';

import {
    Blake2s,
    BLAKE2s,
    BLAKE2s224,
    BLAKE2s224_HMAC,
    BLAKE2s256,
    BLAKE2s256_HMAC,
    BLAKE2s_HMAC
} from './BLAKE2s';

import {
    BLAKE3,
    BLAKE3_HMAC,
    BLAKE3_DeriveKey,
    Blake3
} from './BLAKE3';

/**
 * Static class of all BLAKE functions
 */
export class BLAKE {
    static Blake = Blake;
    static BLAKE = _BLAKE;
    static BLAKE224 = BLAKE224;
    static BLAKE224_HMAC = BLAKE224_HMAC;
    static BLAKE256 = BLAKE256;
    static BLAKE256_HMAC = BLAKE256_HMAC;
    static BLAKE384 = BLAKE384;
    static BLAKE384_HMAC = BLAKE384_HMAC;
    static BLAKE512 = BLAKE512;
    static BLAKE512_HMAC = BLAKE512_HMAC;
    static BLAKE_HMAC = BLAKE_HMAC;

    static Blake2b = Blake2b;
    static BLAKE2b = BLAKE2b;
    static BLAKE2b224 = BLAKE2b224;
    static BLAKE2b224_HMAC = BLAKE2b224_HMAC;
    static BLAKE2b256 = BLAKE2b256;
    static BLAKE2b256_HMAC = BLAKE2b256_HMAC;
    static BLAKE2b384 = BLAKE2b384;
    static BLAKE2b384_HMAC = BLAKE2b384_HMAC;
    static BLAKE2b512 = BLAKE2b512;
    static BLAKE2b512_HMAC = BLAKE2b512_HMAC;
    static BLAKE2b_HMAC = BLAKE2b_HMAC;

    static Blake2s = Blake2s;
    static BLAKE2s = BLAKE2s;
    static BLAKE2s224 = BLAKE2s224;
    static BLAKE2s224_HMAC = BLAKE2s224_HMAC;
    static BLAKE2s256 = BLAKE2s256;
    static BLAKE2s256_HMAC = BLAKE2s256_HMAC;
    static BLAKE2s_HMAC = BLAKE2s_HMAC;

    static Blake3 = Blake3;
    static BLAKE3 = BLAKE3;
    static BLAKE3_HMAC = BLAKE3_HMAC;
    static BLAKE3_DeriveKey = BLAKE3_DeriveKey;
    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST() {
        return [
            "BLAKE",
            "BLAKE224",
            "BLAKE224_HMAC",
            "BLAKE256",
            "BLAKE256_HMAC",
            "BLAKE384",
            "BLAKE384_HMAC",
            "BLAKE512",
            "BLAKE512_HMAC",
            "BLAKE_HMAC",

            "BLAKE2b",
            "BLAKE2b224",
            "BLAKE2b224_HMAC",
            "BLAKE2b256",
            "BLAKE2b256_HMAC",
            "BLAKE2b384",
            "BLAKE2b384_HMAC",
            "BLAKE2b512",
            "BLAKE2b512_HMAC",
            "BLAKE2b_HMAC",

            "BLAKE2s",
            "BLAKE2s224",
            "BLAKE2s224_HMAC",
            "BLAKE2s256",
            "BLAKE2s256_HMAC",
            "BLAKE2s_HMAC",

            "BLAKE3",
            "BLAKE3_HMAC",
            "BLAKE3_DeriveKey",
        ]
    };
};