import { SHA0, SHA0_HMAC } from './SHA0';
import { SHA1, SHA1_HMAC } from './SHA1';
import { SHA224, SHA224_HMAC, SHA256, SHA256_HMAC, SHA256_DOUBLE } from './SHA256';
import { SHA512, SHA512_HMAC, SHA384, SHA384_HMAC, SHA512_256, SHA512_256_HMAC, SHA512_224, SHA512_224_HMAC } from './SHA512';
import { SHA3, SHA3_224, SHA3_224_HMAC, SHA3_256, SHA3_256_HMAC, SHA3_384, SHA3_384_HMAC, SHA3_512, SHA3_512_HMAC, SHA3_HMAC, _KECCAK, KECCAK224, KECCAK224_HMAC, KECCAK256, KECCAK256_HMAC, KECCAK384, KECCAK384_HMAC, KECCAK512, KECCAK512_HMAC, KECCAK_HMAC, _SHAKE, SHAKE128, SHAKE256, _KMAC, KMAC128, KMAC256, _cSHAKE, cSHAKE128, cSHAKE256 } from './SHA3';
/**
 * Static class of all SHA functions
 */
export declare class SHA {
    static SHA0: typeof SHA0;
    static SHA0_HMAC: typeof SHA0_HMAC;
    static SHA1: typeof SHA1;
    static SHA1_HMAC: typeof SHA1_HMAC;
    static SHA224: typeof SHA224;
    static SHA224_HMAC: typeof SHA224_HMAC;
    static SHA256: typeof SHA256;
    static SHA256_HMAC: typeof SHA256_HMAC;
    static SHA256_DOUBLE: typeof SHA256_DOUBLE;
    static SHA512: typeof SHA512;
    static SHA512_HMAC: typeof SHA512_HMAC;
    static SHA384: typeof SHA384;
    static SHA384_HMAC: typeof SHA384_HMAC;
    static SHA512_256: typeof SHA512_256;
    static SHA512_256_HMAC: typeof SHA512_256_HMAC;
    static SHA512_224: typeof SHA512_224;
    static SHA512_224_HMAC: typeof SHA512_224_HMAC;
    static SHA3: typeof SHA3;
    static SHA3_224: typeof SHA3_224;
    static SHA3_224_HMAC: typeof SHA3_224_HMAC;
    static SHA3_256: typeof SHA3_256;
    static SHA3_256_HMAC: typeof SHA3_256_HMAC;
    static SHA3_384: typeof SHA3_384;
    static SHA3_384_HMAC: typeof SHA3_384_HMAC;
    static SHA3_512: typeof SHA3_512;
    static SHA3_512_HMAC: typeof SHA3_512_HMAC;
    static SHA3_HMAC: typeof SHA3_HMAC;
    /**
     * List of all functions in class
     */
    static get FUNCTION_LISTLISTLIST(): string[];
}
/**
 * Static class of all Keccak functions
 */
export declare class KECCAK {
    static KECCAK: typeof _KECCAK;
    static KECCAK224: typeof KECCAK224;
    static KECCAK224_HMAC: typeof KECCAK224_HMAC;
    static KECCAK256: typeof KECCAK256;
    static KECCAK256_HMAC: typeof KECCAK256_HMAC;
    static KECCAK384: typeof KECCAK384;
    static KECCAK384_HMAC: typeof KECCAK384_HMAC;
    static KECCAK512: typeof KECCAK512;
    static KECCAK512_HMAC: typeof KECCAK512_HMAC;
    static KECCAK_HMAC: typeof KECCAK_HMAC;
    /**
     * Static class of all Keccak function
     */
    static get FUNCTION_LIST(): string[];
}
/**
 * Static class of all KMAC functions
 */
export declare class KMAC {
    static KMAC: typeof _KMAC;
    static KMAC128: typeof KMAC128;
    static KMAC256: typeof KMAC256;
    /**
     * Static class of all KMAC function
     */
    static get FUNCTION_LIST(): string[];
}
export declare class SHAKE {
    static SHAKE: typeof _SHAKE;
    static SHAKE128: typeof SHAKE128;
    static SHAKE256: typeof SHAKE256;
    /**
     * Static class of all SHAKE function
     */
    static get FUNCTION_LIST(): string[];
}
/**
 * Static class of all cSHAKE functions
 */
export declare class cSHAKE {
    static cSHAKE: typeof _cSHAKE;
    static cSHAKE128: typeof cSHAKE128;
    static cSHAKE256: typeof cSHAKE256;
    /**
     * Static class of all cSHAKE function
     */
    static get FUNCTION_LIST(): string[];
}
//# sourceMappingURL=SHA.d.ts.map