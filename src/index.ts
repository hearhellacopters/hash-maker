// #region CheckSum

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
class CHECKSUM {
    static GPH = GPH;
    static MATH = MATH;
    static CRC = CRC;
    static BSD = BSD;
    static ADLER = ADLER;
    static FLETCHER = FLETCHER;
    static LCR = LCR;
    static BCC = BCC;
    static SYSV = SYSV;
    static SFH = SFH;
    static BUZHASH = BUZHASH;
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
        ]
    };
};

// #region Hash

import {
    SHA,
    KECCAK,
    KMAC,
    SHAKE,
    cSHAKE,
} from './SHA';
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
import { SIP } from './SIP'
import { HIGHWAY } from './HIGHWAY';
import { LSH } from './LSH';
import { MURMUR } from './MURMUR'

/**
 * Static class of all Hash classes
 */
class HASH {
    static SHA = SHA;
    static KECCAK = KECCAK;
    static KMAC = KMAC;
    static SHAKE = SHAKE;
    static cSHAKE = cSHAKE;
    static MD = MD;
    static BLAKE = BLAKE;
    static RIPEMD = RIPEMD;
    static SM3 = SM3;
    static WHIRLPOOL = WHIRLPOOL;
    static SNEFRU = SNEFRU;
    static TIGER = TIGER;
    static BMW = BMW;
    static FNV = FNV;
    static HAS160 = HAS160;
    static PEARSON = PEARSON;
    static JENKINS = JENKINS;
    static CUBEHASH = CUBEHASH;
    static PANAMA = PANAMA;
    static ECHO = ECHO;
    static FUGUE = FUGUE;
    static GROESTL = GROESTL;
    static HAMSI = HAMSI;
    static HAVAL = HAVAL;
    static JH = JH;
    static RADIOGATUN = RADIOGATUN;
    static LUFFA = LUFFA;
    static SHABAL = SHABAL;
    static SHAVITE = SHAVITE;
    static SKEIN = SKEIN;
    static SIMD = SIMD;
    static SIP = SIP;
    static HIGHWAY = HIGHWAY;
    static LSH = LSH;
    static MURMUR = MURMUR;

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
            "MURMUR"
        ];
    };
}

// #region RNG

import { MERSENNETWISTER } from './MERSENNETWISTER';
import { RANDOMXORSHIFT } from './RANDOMXORSHIFT';
import { RandomBytes } from './RANDOM';
import { UUID } from './UUID';

/**
 * Static class of all RNG functions and classes
 */
class RNG {
    static MersenneTwister = MERSENNETWISTER;
    static RandomXORShift = RANDOMXORSHIFT;
    static RandomBytes = RandomBytes;
    static UUID = UUID;
    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST() {
        return [
            "MersenneTwister",
            "RandomXORShift",
            "RandomBytes",
            "UUID"
        ]
    };
};

export {
    // Checksums
    CHECKSUM,

    GPH,
    MATH,
    CRC,
    BSD,
    ADLER,
    FLETCHER,
    LCR,
    BCC,
    SYSV,
    SFH,
    BUZHASH,

    // Hashes
    HASH,

    SHA,
    KECCAK,
    KMAC,
    SHAKE,
    cSHAKE,
    MD,
    BLAKE,
    RIPEMD,
    SM3,
    WHIRLPOOL,
    SNEFRU,
    TIGER,

    BMW,

    FNV,

    HAS160,

    PEARSON,

    JENKINS,

    CUBEHASH,

    ECHO,

    FUGUE,

    GROESTL,

    HAMSI,

    HAVAL,

    JH,

    RADIOGATUN,

    LUFFA,

    SHABAL,

    SKEIN,

    SIMD,

    HIGHWAY,

    LSH,

    //RNG
    RNG,

    MERSENNETWISTER,

    RANDOMXORSHIFT,

    RandomBytes,

    UUID
};