/// <reference types="node" />
interface CRCOptions {
    name?: string;
    width: number;
    poly: number | number[];
    init: number | number[];
    refin: boolean;
    refout: boolean;
    xorout: number | number[];
    check?: number | number[];
    returnAs?: "hex" | "number" | 'array' | 'bigint';
}
/**
 * Raw crc class for creating your own CRC
 */
export declare class CrcCalculator {
    options: CRCOptions;
    name: CRCOptions["name"];
    width: CRCOptions["width"];
    poly: CRCOptions["poly"];
    init: CRCOptions["init"];
    refin: CRCOptions["refin"];
    refout: CRCOptions["refout"];
    xorout: CRCOptions["xorout"];
    check: CRCOptions["check"];
    returnAs: CRCOptions["returnAs"];
    multiWords: boolean;
    bitOffset: number;
    msbOffset: number;
    maskBits: number;
    msb: number;
    mask: number;
    tableId: string;
    table: number[] | number[][];
    crc: number | number[];
    finalized: boolean;
    test: Uint8Array;
    constructor(options: CRCOptions);
    /**
     *
     * @param {Uint8Array|Buffer|string} message - Data to hash
     * @returns {this}
     */
    update(message: Uint8Array | Buffer | string): this;
    private updateByte;
    finalize(): void;
    /**
     * Return hash as hex string
     *
     * @returns {string} - hex string of hash
     */
    hex(): string;
    /**
     * Return hash as hex string
     *
     * @returns {string} - hex string of hash
     */
    toString(): string;
    /**
     * Return hash as ubyte number array
     *
     * @returns {number[]} - ubyte number array of hash
     */
    array(): number[];
    /**
     * Return hash as number for hashes of 32 bit or less
     *
     * @returns `number` - hash as number
     */
    number(): number;
    /**
     * Return hash as bigit for hashes over 64 bit
     *
     * @returns {bigint} - hash as bigint
     */
    bigint(): bigint;
}
/**
 * Static class of CRC functions
 */
export declare class CRC {
    private static Compute;
    private static ensureLength;
    static CrcCalculator: typeof CrcCalculator;
    /**
     * Create your own CRC.
     *
     * Make sure the `option` object `returnAs` matched the hash bit size. `number` for under 32, `bigint` up to 64, `array` for anything over. Can also use `hex` string for all.
     *
     * @param {CRCOptions} options - options to create the CRC
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns
     */
    static CRC(options: CRCOptions, data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-3
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC3(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-3/GSM
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC3GSM(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-3/ROHC
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC3ROHC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-4/G-704
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC4G704(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-4/ITU
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC4ITU(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-5/EPC-C1G2
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC5EPCC1G2(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-5/EPC
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC5EPC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-5/G-704
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC5G704(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-5/ITU
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC5ITU(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-5/USB
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC5USB(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-6/CDMA2000-A
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC6CDMA2000A(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-6/CDMA2000-B
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC6CDMA2000B(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-6/DARC
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC6DARC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-6/G-704
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC6G704(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-6/ITU
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC6ITU(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-6/GSM
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC6GSM(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-7
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC7(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-7/MMC
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC7MMC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-7/ROHC
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC7ROHC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-7/UMTS
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC7UMTS(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-8/AUTOSAR
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8AUTOSAR(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-8/BLUETOOTH
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8BLUETOOTH(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-8/CDMA2000
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8CDMA2000(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-8/DARC
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8DARC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-8/DVB-S2
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8DVBS2(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-8/GSM-A
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8GSMA(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-8/GSM-B
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8GSMB(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-8/HITAG
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8HITAG(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-8/I-432-1
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8I4321(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-8/ITU
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8ITU(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-8/I-CODE
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8ICODE(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-8/LTE
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8LTE(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-8/MAXIM-DOW
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8MAXIMDOW(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-8/MAXIM
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8MAXIM(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * DOW-CRC
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static DOWCRC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-8/MIFARE-MAD
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8MIFAREMAD(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-8/NRSC-5
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8NRSC5(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-8/OPENSAFETY
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8OPENSAFETY(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-8/ROHC
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8ROHC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-8/SAE-J1850
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8SAEJ1850(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-8
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-8/SMBUS
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8SMBUS(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-8/TECH-3250
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8TECH3250(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-8/AES
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8AES(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-8/EBU
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8EBU(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-8/WCDMA
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8WCDMA(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-10/ATM
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC10ATM(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-10
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC10(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-10/I-610
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC10I610(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-10/CDMA2000
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC10CDMA2000(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-10/GSM
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC10GSM(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-11/FLEXRAY
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC11FLEXRAY(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-11
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC11(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-11/UMTS
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC11UMTS(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-12/CDMA2000
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC12CDMA2000(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-12/DECT
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC12DECT(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * X-CRC-12
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static XCRC12(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-12/GSM
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC12GSM(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-12/UMTS
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC12UMTS(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-12/3GPP
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC123GPP(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-13/BBC
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC13BBC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-14/DARC
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC14DARC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-14/GSM
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC14GSM(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-15/CAN
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC15CAN(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-15
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC15(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-15/MPT1327
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC15MPT1327(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/ARC
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16ARC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * ARC
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static ARC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/LHA
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16LHA(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-IBM
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRCIBM(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/CDMA2000
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16CDMA2000(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/CMS
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16CMS(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/DDS-110
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16DDS110(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/DECT-R
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16DECTR(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * R-CRC-16
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static RCRC16(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/DECT-X
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16DECTX(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * X-CRC-16
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static XCRC16(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/DNP
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16DNP(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/EN-13757
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16EN13757(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/GENIBUS
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16GENIBUS(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/DARC
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16DARC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/EPC
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16EPC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/EPC-C1G2
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16EPCC1G2(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/I-CODE
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16ICODE(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/GSM
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16GSM(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/IBM-3740
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16IBM3740(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/AUTOSAR
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16AUTOSAR(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/CCITT-FALSE
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16CCITTFALSE(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/IBM-SDLC
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16IBMSDLC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/ISO-HDLC
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16ISOHDLC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/ISO-IEC-14443-3-B
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16ISOIEC144433B(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/X-25
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16X25(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/B
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRCB(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * X-25
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static X25(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/ISO-IEC-14443-3-A
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16ISOIEC144433A(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-A
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRCA(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/KERMIT
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16KERMIT(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/BLUETOOTH
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16BLUETOOTH(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/CCITT
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16CCITT(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/CCITT-TRUE
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16CCITTTRUE(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/V-41-LSB
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16V41LSB(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-CCITT
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRCCCITT(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * KERMIT
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static KERMIT(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/LJ1200
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16LJ1200(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/M17
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16M17(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/MAXIM-DOW
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16MAXIMDOW(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/MAXIM
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16MAXIM(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/MCRF4XX
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16MCRF4XX(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/MODBUS
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16MODBUS(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * MODBUS
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static MODBUS(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/NRSC-5
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16NRSC5(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/OPENSAFETY-A
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16OPENSAFETYA(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/OPENSAFETY-B
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16OPENSAFETYB(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/PROFIBUS
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16PROFIBUS(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/IEC-61158-2
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16IEC611582(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/RIELLO
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16RIELLO(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/SPI-FUJITSU
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16SPIFUJITSU(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/AUG-CCITT
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16AUGCCITT(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/T10-DIF
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16T10DIF(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/TELEDISK
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16TELEDISK(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/TMS37157
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16TMS37157(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/UMTS
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16UMTS(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/BUYPASS
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16BUYPASS(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/VERIFONE
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16VERIFONE(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/USB
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16USB(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/XMODEM
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16XMODEM(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/ACORN
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16ACORN(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/LTE
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16LTE(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-16/V-41-MSB
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16V41MSB(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * XMODEM
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static XMODEM(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * ZMODEM
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static ZMODEM(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-17/CAN-FD
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC17CANFD(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-21/CAN-FD
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC21CANFD(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-24/BLE
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC24BLE(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-24/FLEXRAY-A
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC24FLEXRAYA(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-24/FLEXRAY-B
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC24FLEXRAyb(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-24/INTERLAKEN
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC24INTERLAKEN(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-24/LTE-A
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC24LTEA(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-24/LTE-B
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC24LTEB(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-24/OPENPGP
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC24OPENPGP(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-24
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC24(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-24/OS-9
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC24OS9(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-30/CDMA
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC30CDMA(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-31/PHILIPS
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC31PHILIPS(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-32/AIXM
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32AIXM(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-32Q
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32Q(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-32/AUTOSAR
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32AUTOSAR(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-32/BASE91-D
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32BASE91D(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-32D
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32D(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-32/BZIP2
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32BZIP2(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-32/AAL5
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32AAL5(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-32/DECT-B
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32DECTB(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * B-CRC-32
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static BCRC32(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-32/SqEnx
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32SQENX(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-32/CD-ROM-EDC
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32CDROMEDC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-32/CKSUM
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32CKSUM(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CKSUM
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CKSUM(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-32/POSIX
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32POSIX(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-32/ISCSI
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32ISCSI(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-32/BASE91-C
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32BASE91C(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-32/CASTAGNOLI
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32CASTAGNOLI(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-32/INTERLAKEN
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32INTERLAKEN(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-32C
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32C(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-32/NVME
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32NVME(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-32/ISO-HDLC
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32ISOHDLC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-32
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-32/ADCCP
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32ADCCP(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-32/V-42
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32V42(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-32/XZ
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32XZ(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * PKZIP
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static PKZIP(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-32/JAMCRC
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32JAMCRC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * JAMCRC
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static JAMCRC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-32/MEF
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32MEF(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-32/MPEG-2
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32MPEG2(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-32/XFER
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32XFER(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * XFER
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static XFER(data: Buffer | Uint8Array | string, offset?: number, length?: number): number;
    /**
     * CRC-40/GSM
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `bigint`
     */
    static CRC40GSM(data: Buffer | Uint8Array | string, offset?: number, length?: number): bigint;
    /**
     * CRC-64
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `bigint`
     */
    static CRC64(data: Buffer | Uint8Array | string, offset?: number, length?: number): bigint;
    /**
     * CRC-64/ECMA-182
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `bigint`
     */
    static CRC64ECMA182(data: Buffer | Uint8Array | string, offset?: number, length?: number): bigint;
    /**
     * CRC-64/GO-ISO
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `bigint`
     */
    static CRC64GOISO(data: Buffer | Uint8Array | string, offset?: number, length?: number): bigint;
    /**
     * CRC-64/MS
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `bigint`
     */
    static CRC64MS(data: Buffer | Uint8Array | string, offset?: number, length?: number): bigint;
    /**
     * CRC-64/NVME
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `bigint`
     */
    static CRC64NVMEN(data: Buffer | Uint8Array | string, offset?: number, length?: number): bigint;
    /**
     * CRC-64/REDIS
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `bigint`
     */
    static CRC64REDIS(data: Buffer | Uint8Array | string, offset?: number, length?: number): bigint;
    /**
     * CRC-64/WE
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `bigint`
     */
    static CRC64WE(data: Buffer | Uint8Array | string, offset?: number, length?: number): bigint;
    /**
     * CRC-64/XZ
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `bigint`
     */
    static CRC64XZ(data: Buffer | Uint8Array | string, offset?: number, length?: number): bigint;
    /**
     * CRC-64/GO-ECMA
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `bigint`
     */
    static CRC64GOECMA(data: Buffer | Uint8Array | string, offset?: number, length?: number): bigint;
    /**
     * CRC-82/DARC
     *
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number[]`
     */
    static CRC82DARC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number[];
    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST(): string[];
}
export {};
//# sourceMappingURL=CRC.d.ts.map