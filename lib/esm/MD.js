"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MD = void 0;
const MD2_1 = require("./MD2");
const MD4_1 = require("./MD4");
const MD5_1 = require("./MD5");
const MD6_1 = require("./MD6");
/**
 * Static class of all MD functions
 */
class MD {
    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST() {
        return [
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
        ];
    }
    ;
}
exports.MD = MD;
MD.MD2 = MD2_1.MD2;
MD.MD2_HMAC = MD2_1.MD2_HMAC;
MD.MD4 = MD4_1.MD4;
MD.MD4_HMAC = MD4_1.MD4_HMAC;
MD.MD5 = MD5_1.MD5;
MD.MD5_HMAC = MD5_1.MD5_HMAC;
MD.MD6 = MD6_1.MD6;
MD.MD6_128 = MD6_1.MD6_128;
MD.MD6_128_HMAC = MD6_1.MD6_128_HMAC;
MD.MD6_224 = MD6_1.MD6_224;
MD.MD6_224_HMAC = MD6_1.MD6_224_HMAC;
MD.MD6_256 = MD6_1.MD6_256;
MD.MD6_256_HMAC = MD6_1.MD6_256_HMAC;
MD.MD6_384 = MD6_1.MD6_384;
MD.MD6_384_HMAC = MD6_1.MD6_384_HMAC;
MD.MD6_512 = MD6_1.MD6_512;
MD.MD6_512_HMAC = MD6_1.MD6_512_HMAC;
MD.MD6_HMAC = MD6_1.MD6_HMAC;
//# sourceMappingURL=MD.js.map