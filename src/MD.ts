import { 
    MD2, 
    MD2_HMAC 
} from "./MD2";
import { 
    MD4,
    MD4_HMAC
} from "./MD4";
import { 
    MD5, 
    MD5_HMAC
} from "./MD5";
import { 
    MD6,
    MD6_128,
    MD6_128_HMAC,
    MD6_224,
    MD6_224_HMAC,
    MD6_256,
    MD6_256_HMAC,
    MD6_384,
    MD6_384_HMAC,
    MD6_512,
    MD6_512_HMAC,
    MD6_HMAC,
} from "./MD6";

/**
 * Static class of all MD functions
 */
export class MD {
    static MD2 = MD2;
    static MD2_HMAC = MD2_HMAC;
    static MD4 = MD4;
    static MD4_HMAC = MD4_HMAC;
    static MD5 = MD5;
    static MD5_HMAC = MD5_HMAC;
    static MD6 = MD6;
    static MD6_128 = MD6_128;
    static MD6_128_HMAC = MD6_128_HMAC;
    static MD6_224 = MD6_224;
    static MD6_224_HMAC = MD6_224_HMAC;
    static MD6_256 = MD6_256;
    static MD6_256_HMAC = MD6_256_HMAC;
    static MD6_384 = MD6_384;
    static MD6_384_HMAC = MD6_384_HMAC;
    static MD6_512 = MD6_512;
    static MD6_512_HMAC = MD6_512_HMAC;
    static MD6_HMAC = MD6_HMAC;
    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST(){
        return[
            "MD2",
            "MD2_HMAC",
            "MD4",
            "MD4_HMAC",
            "MD5",
            "MD5_HMAC",

            "MD6",
            "MD6_128",
            "MD6_128_HMAC",
            "MD6_256",
            "MD6_256_HMAC",
            "MD6_384",
            "MD6_384_HMAC",
            "MD6_512",
            "MD6_512_HMAC",
            "MD6_HMAC",
        ]
    };
}