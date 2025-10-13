import { MD2, MD2_HMAC } from "./MD2";
import { MD4, MD4_HMAC } from "./MD4";
import { MD5, MD5_HMAC } from "./MD5";
import { MD6, MD6_128, MD6_128_HMAC, MD6_224, MD6_224_HMAC, MD6_256, MD6_256_HMAC, MD6_384, MD6_384_HMAC, MD6_512, MD6_512_HMAC, MD6_HMAC } from "./MD6";
/**
 * Static class of all MD functions
 */
export declare class MD {
    static MD2: typeof MD2;
    static MD2_HMAC: typeof MD2_HMAC;
    static MD4: typeof MD4;
    static MD4_HMAC: typeof MD4_HMAC;
    static MD5: typeof MD5;
    static MD5_HMAC: typeof MD5_HMAC;
    static MD6: typeof MD6;
    static MD6_128: typeof MD6_128;
    static MD6_128_HMAC: typeof MD6_128_HMAC;
    static MD6_224: typeof MD6_224;
    static MD6_224_HMAC: typeof MD6_224_HMAC;
    static MD6_256: typeof MD6_256;
    static MD6_256_HMAC: typeof MD6_256_HMAC;
    static MD6_384: typeof MD6_384;
    static MD6_384_HMAC: typeof MD6_384_HMAC;
    static MD6_512: typeof MD6_512;
    static MD6_512_HMAC: typeof MD6_512_HMAC;
    static MD6_HMAC: typeof MD6_HMAC;
    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST(): string[];
}
//# sourceMappingURL=MD.d.ts.map