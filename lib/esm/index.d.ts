import { GPH } from './GPH';
import { MATH } from './MATH';
import { CRC } from './CRC';
import { ADLER } from './ADLER';
import { BSD } from './BSD';
import { FLETCHER } from './FLETCHER';
import { LCR } from './LCR';
import { BCC } from './BCC';
import { SYSV } from './SYSV';
import { SFH } from './SFH';
import { BUZHASH } from './BUZHASH';
/**
 * Static class of all CheckSum classes
 */
declare class CHECKSUM {
    static GPH: typeof GPH;
    static MATH: typeof MATH;
    static CRC: typeof CRC;
    static BSD: typeof BSD;
    static ADLER: typeof ADLER;
    static FLETCHER: typeof FLETCHER;
    static LCR: typeof LCR;
    static BCC: typeof BCC;
    static SYSV: typeof SYSV;
    static SFH: typeof SFH;
    static BUZHASH: typeof BUZHASH;
    /**
     * List of all checksums in class
     */
    static get FUNCTION_LIST(): string[];
}
import { SHA, KECCAK, KMAC, SHAKE, cSHAKE } from './SHA';
import { MD } from './MD';
import { BLAKE } from './BLAKE';
import { RIPEMD } from './RIPEMD';
import { SM3 } from "./SM3";
import { WHIRLPOOL } from './WHIRLPOOL';
import { SNEFRU } from './SNEFRU';
import { TIGER } from './TIGER';
import { BMW } from './BMW';
import { FNV } from './FNV';
import { HAS160 } from './HAS-160';
import { PEARSON } from './PEARSON';
import { JENKINS } from './JENKINS';
import { CUBEHASH } from './CUBEHASH';
import { PANAMA } from './PANAMA';
import { ECHO } from './ECHO';
import { FUGUE } from './FUGUE';
import { GROESTL } from './GROESTL';
import { HAMSI } from './HAMSI';
import { HAVAL } from './HAVAL';
import { JH } from './JH';
import { RADIOGATUN } from './RADIOGATUN';
import { LUFFA } from './LUFFA';
import { SHABAL } from './SHABAL';
import { SHAVITE } from './SHAVITE';
import { SKEIN } from './SKEIN';
import { SIMD } from './SIMD';
import { SIP } from './SIP';
import { HIGHWAY } from './HIGHWAY';
import { LSH } from './LSH';
import { MURMUR } from './MURMUR';
/**
 * Static class of all Hash classes
 */
declare class HASH {
    static SHA: typeof SHA;
    static KECCAK: typeof KECCAK;
    static KMAC: typeof KMAC;
    static SHAKE: typeof SHAKE;
    static cSHAKE: typeof cSHAKE;
    static MD: typeof MD;
    static BLAKE: typeof BLAKE;
    static RIPEMD: typeof RIPEMD;
    static SM3: typeof SM3;
    static WHIRLPOOL: typeof WHIRLPOOL;
    static SNEFRU: typeof SNEFRU;
    static TIGER: typeof TIGER;
    static BMW: typeof BMW;
    static FNV: typeof FNV;
    static HAS160: typeof HAS160;
    static PEARSON: typeof PEARSON;
    static JENKINS: typeof JENKINS;
    static CUBEHASH: typeof CUBEHASH;
    static PANAMA: typeof PANAMA;
    static ECHO: typeof ECHO;
    static FUGUE: typeof FUGUE;
    static GROESTL: typeof GROESTL;
    static HAMSI: typeof HAMSI;
    static HAVAL: typeof HAVAL;
    static JH: typeof JH;
    static RADIOGATUN: typeof RADIOGATUN;
    static LUFFA: typeof LUFFA;
    static SHABAL: typeof SHABAL;
    static SHAVITE: typeof SHAVITE;
    static SKEIN: typeof SKEIN;
    static SIMD: typeof SIMD;
    static SIP: typeof SIP;
    static HIGHWAY: typeof HIGHWAY;
    static LSH: typeof LSH;
    static MURMUR: typeof MURMUR;
    /**
     * List of all hashes in class
     */
    static get FUNCTION_LIST(): string[];
}
import { MERSENNETWISTER } from './MERSENNETWISTER';
import { RANDOMXORSHIFT } from './RANDOMXORSHIFT';
import { RandomBytes } from './RANDOM';
import { UUID } from './UUID';
/**
 * Static class of all RNG functions and classes
 */
declare class RNG {
    static MersenneTwister: typeof MERSENNETWISTER;
    static RandomXORShift: typeof RANDOMXORSHIFT;
    static RandomBytes: typeof RandomBytes;
    static UUID: typeof UUID;
    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST(): string[];
}
export { CHECKSUM, GPH, MATH, CRC, BSD, ADLER, FLETCHER, LCR, BCC, SYSV, SFH, BUZHASH, HASH, SHA, KECCAK, KMAC, SHAKE, cSHAKE, MD, BLAKE, RIPEMD, SM3, WHIRLPOOL, SNEFRU, TIGER, BMW, FNV, HAS160, PEARSON, JENKINS, CUBEHASH, ECHO, FUGUE, GROESTL, HAMSI, HAVAL, JH, RADIOGATUN, LUFFA, SHABAL, SKEIN, SIMD, HIGHWAY, LSH, RNG, MERSENNETWISTER, RANDOMXORSHIFT, RandomBytes, UUID };
//# sourceMappingURL=index.d.ts.map