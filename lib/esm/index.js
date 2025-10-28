"use strict";
// #region CheckSum
Object.defineProperty(exports, "__esModule", { value: true });
exports.UUID = exports.RandomBytes = exports.RANDOMXORSHIFT = exports.MERSENNETWISTER = exports.RNG = exports.LSH = exports.HIGHWAY = exports.SIMD = exports.SKEIN = exports.SHABAL = exports.LUFFA = exports.RADIOGATUN = exports.JH = exports.HAVAL = exports.HAMSI = exports.GROESTL = exports.FUGUE = exports.ECHO = exports.CUBEHASH = exports.JENKINS = exports.PEARSON = exports.HAS160 = exports.FNV = exports.BMW = exports.TIGER = exports.SNEFRU = exports.WHIRLPOOL = exports.SM3 = exports.RIPEMD = exports.BLAKE = exports.MD = exports.cSHAKE = exports.SHAKE = exports.KMAC = exports.KECCAK = exports.SHA = exports.HASH = exports.BUZHASH = exports.SFH = exports.SYSV = exports.BCC = exports.LCR = exports.FLETCHER = exports.ADLER = exports.BSD = exports.CRC = exports.MATH = exports.GPH = exports.CHECKSUM = void 0;
const GPH_1 = require("./GPH");
Object.defineProperty(exports, "GPH", { enumerable: true, get: function () { return GPH_1.GPH; } });
const MATH_1 = require("./MATH");
Object.defineProperty(exports, "MATH", { enumerable: true, get: function () { return MATH_1.MATH; } });
const CRC_1 = require("./CRC");
Object.defineProperty(exports, "CRC", { enumerable: true, get: function () { return CRC_1.CRC; } });
const ADLER_1 = require("./ADLER");
Object.defineProperty(exports, "ADLER", { enumerable: true, get: function () { return ADLER_1.ADLER; } });
const BSD_1 = require("./BSD");
Object.defineProperty(exports, "BSD", { enumerable: true, get: function () { return BSD_1.BSD; } });
const FLETCHER_1 = require("./FLETCHER");
Object.defineProperty(exports, "FLETCHER", { enumerable: true, get: function () { return FLETCHER_1.FLETCHER; } });
const LCR_1 = require("./LCR");
Object.defineProperty(exports, "LCR", { enumerable: true, get: function () { return LCR_1.LCR; } });
const BCC_1 = require("./BCC");
Object.defineProperty(exports, "BCC", { enumerable: true, get: function () { return BCC_1.BCC; } });
const SYSV_1 = require("./SYSV");
Object.defineProperty(exports, "SYSV", { enumerable: true, get: function () { return SYSV_1.SYSV; } });
const SFH_1 = require("./SFH");
Object.defineProperty(exports, "SFH", { enumerable: true, get: function () { return SFH_1.SFH; } });
const BUZHASH_1 = require("./BUZHASH");
Object.defineProperty(exports, "BUZHASH", { enumerable: true, get: function () { return BUZHASH_1.BUZHASH; } });
/**
 * Static class of all CheckSum classes
 */
class CHECKSUM {
    /**
     * List of all checksums in class
     */
    static get FUNCTION_LIST() {
        return [
            "GPH",
            "MATH",
            "CRC",
            "BSD",
            "ADLER",
            "FLETCHER",
            "LCR",
            "BCC",
            "SYSV",
            "SFH",
            "BUZHASH"
        ];
    }
    ;
}
exports.CHECKSUM = CHECKSUM;
CHECKSUM.GPH = GPH_1.GPH;
CHECKSUM.MATH = MATH_1.MATH;
CHECKSUM.CRC = CRC_1.CRC;
CHECKSUM.BSD = BSD_1.BSD;
CHECKSUM.ADLER = ADLER_1.ADLER;
CHECKSUM.FLETCHER = FLETCHER_1.FLETCHER;
CHECKSUM.LCR = LCR_1.LCR;
CHECKSUM.BCC = BCC_1.BCC;
CHECKSUM.SYSV = SYSV_1.SYSV;
CHECKSUM.SFH = SFH_1.SFH;
CHECKSUM.BUZHASH = BUZHASH_1.BUZHASH;
;
// #region Hash
const SHA_1 = require("./SHA");
Object.defineProperty(exports, "SHA", { enumerable: true, get: function () { return SHA_1.SHA; } });
Object.defineProperty(exports, "KECCAK", { enumerable: true, get: function () { return SHA_1.KECCAK; } });
Object.defineProperty(exports, "KMAC", { enumerable: true, get: function () { return SHA_1.KMAC; } });
Object.defineProperty(exports, "SHAKE", { enumerable: true, get: function () { return SHA_1.SHAKE; } });
Object.defineProperty(exports, "cSHAKE", { enumerable: true, get: function () { return SHA_1.cSHAKE; } });
const MD_1 = require("./MD");
Object.defineProperty(exports, "MD", { enumerable: true, get: function () { return MD_1.MD; } });
const BLAKE_1 = require("./BLAKE");
Object.defineProperty(exports, "BLAKE", { enumerable: true, get: function () { return BLAKE_1.BLAKE; } });
const RIPEMD_1 = require("./RIPEMD");
Object.defineProperty(exports, "RIPEMD", { enumerable: true, get: function () { return RIPEMD_1.RIPEMD; } });
const SM3_1 = require("./SM3");
Object.defineProperty(exports, "SM3", { enumerable: true, get: function () { return SM3_1.SM3; } });
const WHIRLPOOL_1 = require("./WHIRLPOOL");
Object.defineProperty(exports, "WHIRLPOOL", { enumerable: true, get: function () { return WHIRLPOOL_1.WHIRLPOOL; } });
const SNEFRU_1 = require("./SNEFRU");
Object.defineProperty(exports, "SNEFRU", { enumerable: true, get: function () { return SNEFRU_1.SNEFRU; } });
const TIGER_1 = require("./TIGER");
Object.defineProperty(exports, "TIGER", { enumerable: true, get: function () { return TIGER_1.TIGER; } });
const BMW_1 = require("./BMW");
Object.defineProperty(exports, "BMW", { enumerable: true, get: function () { return BMW_1.BMW; } });
const FNV_1 = require("./FNV");
Object.defineProperty(exports, "FNV", { enumerable: true, get: function () { return FNV_1.FNV; } });
const HAS_160_1 = require("./HAS-160");
Object.defineProperty(exports, "HAS160", { enumerable: true, get: function () { return HAS_160_1.HAS160; } });
const PEARSON_1 = require("./PEARSON");
Object.defineProperty(exports, "PEARSON", { enumerable: true, get: function () { return PEARSON_1.PEARSON; } });
const JENKINS_1 = require("./JENKINS");
Object.defineProperty(exports, "JENKINS", { enumerable: true, get: function () { return JENKINS_1.JENKINS; } });
const CUBEHASH_1 = require("./CUBEHASH");
Object.defineProperty(exports, "CUBEHASH", { enumerable: true, get: function () { return CUBEHASH_1.CUBEHASH; } });
const PANAMA_1 = require("./PANAMA");
const ECHO_1 = require("./ECHO");
Object.defineProperty(exports, "ECHO", { enumerable: true, get: function () { return ECHO_1.ECHO; } });
const FUGUE_1 = require("./FUGUE");
Object.defineProperty(exports, "FUGUE", { enumerable: true, get: function () { return FUGUE_1.FUGUE; } });
const GROESTL_1 = require("./GROESTL");
Object.defineProperty(exports, "GROESTL", { enumerable: true, get: function () { return GROESTL_1.GROESTL; } });
const HAMSI_1 = require("./HAMSI");
Object.defineProperty(exports, "HAMSI", { enumerable: true, get: function () { return HAMSI_1.HAMSI; } });
const HAVAL_1 = require("./HAVAL");
Object.defineProperty(exports, "HAVAL", { enumerable: true, get: function () { return HAVAL_1.HAVAL; } });
const JH_1 = require("./JH");
Object.defineProperty(exports, "JH", { enumerable: true, get: function () { return JH_1.JH; } });
const RADIOGATUN_1 = require("./RADIOGATUN");
Object.defineProperty(exports, "RADIOGATUN", { enumerable: true, get: function () { return RADIOGATUN_1.RADIOGATUN; } });
const LUFFA_1 = require("./LUFFA");
Object.defineProperty(exports, "LUFFA", { enumerable: true, get: function () { return LUFFA_1.LUFFA; } });
const SHABAL_1 = require("./SHABAL");
Object.defineProperty(exports, "SHABAL", { enumerable: true, get: function () { return SHABAL_1.SHABAL; } });
const SHAVITE_1 = require("./SHAVITE");
const SKEIN_1 = require("./SKEIN");
Object.defineProperty(exports, "SKEIN", { enumerable: true, get: function () { return SKEIN_1.SKEIN; } });
const SIMD_1 = require("./SIMD");
Object.defineProperty(exports, "SIMD", { enumerable: true, get: function () { return SIMD_1.SIMD; } });
const SIP_1 = require("./SIP");
const HIGHWAY_1 = require("./HIGHWAY");
Object.defineProperty(exports, "HIGHWAY", { enumerable: true, get: function () { return HIGHWAY_1.HIGHWAY; } });
const LSH_1 = require("./LSH");
Object.defineProperty(exports, "LSH", { enumerable: true, get: function () { return LSH_1.LSH; } });
const MURMUR_1 = require("./MURMUR");
const ARGON2_1 = require("./ARGON2");
/**
 * Static class of all Hash classes
 */
class HASH {
    /**
     * List of all hashes in class
     */
    static get FUNCTION_LIST() {
        return [
            "SHA",
            "KECCAK",
            "KMAC",
            "SHAKE",
            "cSHAKE",
            "MD",
            "BLAKE",
            "RIPEMD",
            "SM3",
            "WHIRLPOOL",
            "SNEFRU",
            "TIGER",
            "BMW",
            "FNV",
            "HAS160",
            "PEARSON",
            "JENKINS",
            "CUBEHASH",
            "PANAMA",
            "ECHO",
            "FUGUE",
            "GROESTL",
            "HAMSI",
            "HAVAL",
            "JH",
            "RADIOGATUN",
            "LUFFA",
            "SHABAL",
            "SHAVITE",
            "SKEIN",
            "SIMD",
            "SIP",
            "HIGHWAY",
            "LSH",
            "MURMUR",
            "ARGON2"
        ];
    }
    ;
}
exports.HASH = HASH;
HASH.SHA = SHA_1.SHA;
HASH.KECCAK = SHA_1.KECCAK;
HASH.KMAC = SHA_1.KMAC;
HASH.SHAKE = SHA_1.SHAKE;
HASH.cSHAKE = SHA_1.cSHAKE;
HASH.MD = MD_1.MD;
HASH.BLAKE = BLAKE_1.BLAKE;
HASH.RIPEMD = RIPEMD_1.RIPEMD;
HASH.SM3 = SM3_1.SM3;
HASH.WHIRLPOOL = WHIRLPOOL_1.WHIRLPOOL;
HASH.SNEFRU = SNEFRU_1.SNEFRU;
HASH.TIGER = TIGER_1.TIGER;
HASH.BMW = BMW_1.BMW;
HASH.FNV = FNV_1.FNV;
HASH.HAS160 = HAS_160_1.HAS160;
HASH.PEARSON = PEARSON_1.PEARSON;
HASH.JENKINS = JENKINS_1.JENKINS;
HASH.CUBEHASH = CUBEHASH_1.CUBEHASH;
HASH.PANAMA = PANAMA_1.PANAMA;
HASH.ECHO = ECHO_1.ECHO;
HASH.FUGUE = FUGUE_1.FUGUE;
HASH.GROESTL = GROESTL_1.GROESTL;
HASH.HAMSI = HAMSI_1.HAMSI;
HASH.HAVAL = HAVAL_1.HAVAL;
HASH.JH = JH_1.JH;
HASH.RADIOGATUN = RADIOGATUN_1.RADIOGATUN;
HASH.LUFFA = LUFFA_1.LUFFA;
HASH.SHABAL = SHABAL_1.SHABAL;
HASH.SHAVITE = SHAVITE_1.SHAVITE;
HASH.SKEIN = SKEIN_1.SKEIN;
HASH.SIMD = SIMD_1.SIMD;
HASH.SIP = SIP_1.SIP;
HASH.HIGHWAY = HIGHWAY_1.HIGHWAY;
HASH.LSH = LSH_1.LSH;
HASH.MURMUR = MURMUR_1.MURMUR;
HASH.ARGON2 = ARGON2_1.ARGON2;
// #region RNG
const MERSENNETWISTER_1 = require("./MERSENNETWISTER");
Object.defineProperty(exports, "MERSENNETWISTER", { enumerable: true, get: function () { return MERSENNETWISTER_1.MERSENNETWISTER; } });
const RANDOMXORSHIFT_1 = require("./RANDOMXORSHIFT");
Object.defineProperty(exports, "RANDOMXORSHIFT", { enumerable: true, get: function () { return RANDOMXORSHIFT_1.RANDOMXORSHIFT; } });
const RANDOM_1 = require("./RANDOM");
Object.defineProperty(exports, "RandomBytes", { enumerable: true, get: function () { return RANDOM_1.RandomBytes; } });
const UUID_1 = require("./UUID");
Object.defineProperty(exports, "UUID", { enumerable: true, get: function () { return UUID_1.UUID; } });
/**
 * Static class of all RNG functions and classes
 */
class RNG {
    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST() {
        return [
            "MersenneTwister",
            "RandomXORShift",
            "RandomBytes",
            "UUID"
        ];
    }
    ;
}
exports.RNG = RNG;
RNG.MersenneTwister = MERSENNETWISTER_1.MERSENNETWISTER;
RNG.RandomXORShift = RANDOMXORSHIFT_1.RANDOMXORSHIFT;
RNG.RandomBytes = RANDOM_1.RandomBytes;
RNG.UUID = UUID_1.UUID;
;
//# sourceMappingURL=index.js.map