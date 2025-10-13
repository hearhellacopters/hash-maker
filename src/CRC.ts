var HEX_CHARS = '0123456789abcdef'.split('');

var isArray = Array.isArray;

function strToUint8Array(str: string): Uint8Array {
    // Check if the browser supports TextDecoder API
    try {
        const encoder = new TextEncoder();

        // Encode the string and return as a Uint8Array
        return encoder.encode(str);
    } catch (e) { }

    // Fallback for older systems without TextDecoder support
    let result = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
        const codePoint = str.charCodeAt(i);
        if (codePoint <= 255) {
            result[i] = codePoint;
        } else {
            result.set([codePoint >> 8, codePoint & 0xFF], i * 2);
        }
    }
    return result;
}

function formatMessage(message: string | Uint8Array | Buffer): Uint8Array | Buffer {
    if (message === undefined) {
        throw new Error('input is invalid type');
    }

    if (typeof message === 'string') {
        return strToUint8Array(message);
    }

    if (message instanceof Uint8Array || Buffer.isBuffer(message)) {
        return message;
    }

    throw new Error('input is invalid type');
}

function arrayToBigInt(numbers: number[], bitsPerNumber = 32) {
    let result = BigInt(0);
    const shiftAmount = BigInt(bitsPerNumber);
    const mask = (BigInt(1) << shiftAmount) - BigInt(1);

    for (const num of numbers) {
        const maskedNum = BigInt(num & Number(mask));
        result = (result << shiftAmount) | maskedNum;
    }

    if (result >= BigInt(0)) {
        return result;
    }

    // For negative values, convert to unsigned
    return result & mask;
}

function leftShift(words: number[], bits: number) {
    if (!bits) {
        return;
    }
    var i = 0;
    for (; i < words.length - 1; ++i) {
        words[i] = (words[i] << bits) | (words[i + 1] >>> (32 - bits));
    }
    words[i] = (words[i] << bits);
}

function rightShift(words: number[], bits: number) {
    if (!bits) {
        return;
    }
    var i = words.length - 1;
    for (; i > 0; --i) {
        words[i] = (words[i - 1] << (32 - bits)) | (words[i] >>> bits);
    }
    words[i] = words[i] >>> bits;
}

function xor(a: number[], b: number[]) {
    for (var i = 0; i < a.length; ++i) {
        a[i] ^= b[i];
    }
}

var TABLES: { [key: string]: number[] | number[][] } = {};

function getTable(tableId: string, poly: number | number[], msbOffset: number, msb: number) {
    if (!TABLES[tableId]) {
        TABLES[tableId] = createTable(poly, msbOffset, msb);
    }
    return TABLES[tableId];
}

function createTable(poly: number | number[], msbOffset: number, msb: number) {
    var table: number[] | number[][] = [];
    var multiWords = isArray(poly);
    if (!multiWords) {
        poly = [poly as number]
    }
    for (i = 0; i < 256; ++i) {
        var byte = [i << msbOffset];
        for (var j = 1; j < (poly as number[]).length; ++j) {
            byte[j] = 0;
        }
        for (var j = 0; j < 8; ++j) {
            if (byte[0] & msb) {
                leftShift(byte, 1);
                for (var k = 0; k < (poly as number[]).length; ++k) {
                    byte[k] = byte[k] ^ (poly as number[])[k];
                }
            } else {
                leftShift(byte, 1);
            }
        }
        table[i] = multiWords ? byte : byte[0];
    }
    return table;
}

function reverse(val: number, width: number) {
    var result = 0;
    for (var i = 0; val; ++i) {
        if (val & 1) {
            result |= (1 << ((width - 1) - i));
        }
        val = val >>> 1;
    }
    return result;
}

var REVERSE_BYTE: number[] = [];

for (var i = 0; i < 256; ++i) {
    REVERSE_BYTE[i] = reverse(i, 8);
}

interface CRCOptions {
    name?: string;
    width: number,
    poly: number | number[],
    init: number | number[],
    refin: boolean,
    refout: boolean,
    xorout: number | number[],
    check?: number | number[],
    returnAs?: "hex" | "number" | 'array' | 'bigint'
};

/**
 * Raw crc class for creating your own CRC
 */
export class CrcCalculator {
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

    finalized = false;

    test = new Uint8Array([49, 50, 51, 52, 53, 54, 55, 56, 57]);

    constructor(options: CRCOptions) {
        var bitOffset = 8 - (options.width % 8 || 8);
        var firstBlockBytes = Math.ceil(options.width / 8) % 4 || 4;
        var firstBlockBits = firstBlockBytes << 3;
        var msb = (1 << (firstBlockBits - 1)) >>> 0;
        var msbOffset = firstBlockBits - 8;
        var maskBits = options.width % 32 || 32;
        var crc, poly, tableId;
        var multiWords = options.width > 32;
        if (multiWords) {
            crc = (options.init as number[]).slice();
            poly = (options.poly as number[]).slice();
            leftShift(crc, bitOffset);
            leftShift(poly, bitOffset);
            tableId = [poly.join('-'), msbOffset, msb].join('_');
        } else {
            crc = (options.init as number) << bitOffset;
            poly = (options.poly as number) << bitOffset;
            tableId = [poly, msbOffset, msb].join('_');
        }

        this.options = options;
        this.name = options.name;
        this.width = options.width;
        this.poly = poly;
        this.init = options.init;
        this.refin = options.refin;
        this.refout = options.refout;
        this.xorout = options.xorout;
        this.check = options.check;
        this.returnAs = options.returnAs;

        this.multiWords = multiWords;
        this.bitOffset = bitOffset;
        this.msbOffset = msbOffset;
        this.maskBits = maskBits;
        this.msb = msb;
        this.mask = 2 ** maskBits - 1;

        this.tableId = tableId;

        this.table = getTable(tableId, poly, msbOffset, msb);
        if (this.multiWords) {
            this.crc = (crc as number[]).slice();
        } else {
            this.crc = crc;
        }
    }

    /**
     * 
     * @param {Uint8Array|Buffer|string} message - Data to hash
     * @returns {this}
     */
    update(message: Uint8Array | Buffer | string): this {
        if (this.finalized) {
            throw new Error('finalize already called');
        }
        var result = formatMessage(message);
        var i, length = result.length;
        for (i = 0; i < length; ++i) {
            this.updateByte(result[i]);
        }
        return this;
    }

    private updateByte(byte: number) {
        var crc = this.crc;
        if (this.refin) {
            byte = REVERSE_BYTE[byte];
        }
        if (this.multiWords && typeof crc == "object") {
            crc[0] = crc[0] ^ (byte << this.msbOffset);
            var cache = this.table[(crc[0] >> this.msbOffset) & 0xFF];
            leftShift(crc, 8);
            xor(crc, (cache as number[]));
        } else {
            crc = ((crc as number) ^ (byte << this.msbOffset));
            crc = (crc << 8) ^ (this.table[(crc >> this.msbOffset) & 0xFF] as number);
        }
        this.crc = crc;
    }

    finalize() {
        if (this.finalized) {
            return;
        }
        this.finalized = true;
        if (this.multiWords) {
            rightShift((this.crc as number[]), this.bitOffset);
            (this.crc as number[])[0] = (this.crc as number[])[0] & this.mask;
            if (this.refout) {
                leftShift((this.crc as number[]), 32 - this.maskBits);
                var crc = [];
                for (var i = 0; i < (this.crc as number[]).length; ++i) {
                    crc[(this.crc as number[]).length - i - 1] = reverse((this.crc as number[])[i], 32)
                }
                this.crc = crc;
            }
            xor(this.crc as number[], this.xorout as number[]);
        } else {
            this.crc = ((this.crc as number) >>> this.bitOffset) & this.mask;
            if (this.refout) {
                this.crc = reverse(this.crc, this.width);
            }
            this.crc ^= (this.xorout as number);
        }
    }

    /**
     * Return hash as hex string
     * 
     * @returns {string} - hex string of hash
     */
    hex(): string {
        this.finalize();
        var hex = '';
        var crc = this.crc;
        var length = this.options.width;
        if (this.multiWords) {
            crc = (crc as number[])[0];
            length = length % 32 || 32;
        }
        for (var i = (Math.ceil(length / 4) << 2) - 4; i >= 0; i -= 4) {
            hex += HEX_CHARS[((crc as number) >> i) & 0x0F];
        }
        if (this.multiWords) {
            for (var j = 1; j < (this.crc as number[]).length; ++j) {
                crc = (this.crc as number[])[j];
                for (i = 28; i >= 0; i -= 4) {
                    hex += HEX_CHARS[(crc >> i) & 0x0F];
                }
            }
        }
        return hex;
    }

    /**
     * Return hash as hex string
     * 
     * @returns {string} - hex string of hash
     */
    toString(): string {
        return this.hex();
    }

    /**
     * Return hash as ubyte number array
     * 
     * @returns {number[]} - ubyte number array of hash
     */
    array(): number[] {
        this.finalize();
        var arr = new Array(Math.ceil(this.options.width / 8));
        var crc = this.crc;
        var length = this.options.width;
        if (this.multiWords) {
            crc = (crc as number[])[0];
            length = length % 32 || 32;
        }
        var index = 0;
        for (var i = (Math.ceil(length / 8) << 3) - 8; i >= 0; i -= 8) {
            arr[index++] = ((crc as number) >> i) & 0xFF;
        }
        if (this.multiWords) {
            for (var j = 1; j < (this.crc as number[]).length; ++j) {
                crc = (this.crc as number[])[j];
                for (i = 24; i >= 0; i -= 8) {
                    arr[index++] = (crc >> i) & 0xFF;
                }
            }
        }
        return arr;
    }

    /**
     * Return hash as number for hashes of 32 bit or less
     * 
     * @returns `number` - hash as number
     */
    number(): number {
        this.finalize();
        if (this.multiWords) {
            // can't create number from array
            return 0;
        } else {
            return this.crc as number >>> 0;
        }
    }

    /**
     * Return hash as bigit for hashes over 64 bit
     * 
     * @returns {bigint} - hash as bigint
     */
    bigint(): bigint {
        this.finalize();
        if (!this.multiWords) {
            return BigInt(this.crc as number);
        } else if (this.options.width <= 64) {
            const array = this.array();
            return arrayToBigInt(array, this.width);
        } else {
            return BigInt(0);
        }
    }
};

const CrcTypes: { [key: string]: CRCOptions } = {
    'CRC3': {
        width: 3,
        poly: 0x3,
        init: 0x0,
        refin: false,
        refout: false,
        xorout: 0x7,
        name: 'CRC-3',
        returnAs: 'number'
    },
    'CRC3GSM': {
        width: 3,
        poly: 0x3,
        init: 0x0,
        refin: false,
        refout: false,
        xorout: 0x7,
        name: 'CRC-3/GSM',
        returnAs: 'number'
    },
    'CRC3ROHC': {
        width: 3,
        poly: 0x3,
        init: 0x7,
        refin: true,
        refout: true,
        xorout: 0x0,
        name: 'CRC-3/ROHC',
        returnAs: 'number'
    },
    'CRC4G704': {
        width: 4,
        poly: 0x3,
        init: 0x0,
        refin: true,
        refout: true,
        xorout: 0x0,
        name: 'CRC-4/G-704',
        returnAs: 'number'
    },
    'CRC4ITU': {
        width: 4,
        poly: 0x3,
        init: 0x0,
        refin: true,
        refout: true,
        xorout: 0x0,
        name: 'CRC-4/ITU',
        returnAs: 'number'
    },
    'CRC5EPCC1G2': {
        width: 5,
        poly: 0x09,
        init: 0x09,
        refin: false,
        refout: false,
        xorout: 0x00,
        name: 'CRC-5/EPC-C1G2',
        returnAs: 'number'
    },
    'CRC5EPC': {
        width: 5,
        poly: 0x09,
        init: 0x09,
        refin: false,
        refout: false,
        xorout: 0x00,
        name: 'CRC-5/EPC',
        returnAs: 'number'
    },
    "CRC5G704": {
        width: 5,
        poly: 0x15,
        init: 0x00,
        refin: true,
        refout: true,
        xorout: 0x00,
        name: 'CRC-5/G-704',
        returnAs: 'number'
    },
    "CRC5ITU": {
        width: 5,
        poly: 0x15,
        init: 0x00,
        refin: true,
        refout: true,
        xorout: 0x00,
        name: 'CRC-5/ITU',
        returnAs: 'number'
    },
    "CRC5USB": {
        width: 5,
        poly: 0x05,
        init: 0x1f,
        refin: true,
        refout: true,
        xorout: 0x1f,
        name: 'CRC-5/USB',
        returnAs: 'number'
    },
    "CRC6CDMA2000A": {
        width: 6,
        poly: 0x27,
        init: 0x3f,
        refin: false,
        refout: false,
        xorout: 0x00,
        name: 'CRC-6/CDMA2000-A',
        returnAs: 'number'
    },
    "CRC6CDMA2000B": {
        width: 6,
        poly: 0x07,
        init: 0x3f,
        refin: false,
        refout: false,
        xorout: 0x00,
        name: 'CRC-6/CDMA2000-B',
        returnAs: 'number'
    },
    "CRC6DARC": {
        width: 6,
        poly: 0x19,
        init: 0x00,
        refin: true,
        refout: true,
        xorout: 0x00,
        name: 'CRC-6/DARC',
        returnAs: 'number'
    },
    "CRC6G704": {
        width: 6,
        poly: 0x03,
        init: 0x00,
        refin: true,
        refout: true,
        xorout: 0x00,
        name: 'CRC-6/G-704',
        returnAs: 'number'
    },
    "CRC6ITU": {
        width: 6,
        poly: 0x03,
        init: 0x00,
        refin: true,
        refout: true,
        xorout: 0x00,
        name: 'CRC-6/ITU',
        returnAs: 'number'
    },
    "CRC6GSM": {
        width: 6,
        poly: 0x2f,
        init: 0x00,
        refin: false,
        refout: false,
        xorout: 0x3f,
        name: 'CRC-6/GSM',
        returnAs: 'number'
    },
    'CRC7': {
        width: 7,
        poly: 0x09,
        init: 0x00,
        refin: false,
        refout: false,
        xorout: 0x00,
        name: 'CRC-7',
        returnAs: 'number'
    },
    'CRC7MMC': {
        width: 7,
        poly: 0x09,
        init: 0x00,
        refin: false,
        refout: false,
        xorout: 0x00,
        name: 'CRC-7/MMC',
        returnAs: 'number'
    },
    "CRC7ROHC": {
        width: 7,
        poly: 0x4f,
        init: 0x7f,
        refin: true,
        refout: true,
        xorout: 0x00,
        name: 'CRC-7/ROHC',
        returnAs: 'number'
    },
    'CRC7UMTS': {
        width: 7,
        poly: 0x45,
        init: 0x00,
        refin: false,
        refout: false,
        xorout: 0x00,
        name: 'CRC-7/UMTS',
        returnAs: 'number'
    },
    'CRC8AUTOSAR': {
        width: 8,
        poly: 0x2f,
        init: 0xff,
        refin: false,
        refout: false,
        xorout: 0xff,
        name: 'CRC-8/AUTOSAR',
        returnAs: 'number'
    },
    'CRC8BLUETOOTH': {
        width: 8,
        poly: 0xa7,
        init: 0x00,
        refin: true,
        refout: true,
        xorout: 0x00,
        name: 'CRC-8/BLUETOOTH',
        returnAs: 'number'
    },
    "CRC8CDMA2000": {
        width: 8,
        poly: 0x9b,
        init: 0xff,
        refin: false,
        refout: false,
        xorout: 0x00,
        name: 'CRC-8/CDMA2000',
        returnAs: 'number'
    },
    'CRC8DARC': {
        width: 8,
        poly: 0x39,
        init: 0x00,
        refin: true,
        refout: true,
        xorout: 0x00,
        name: 'CRC-8/DARC',
        returnAs: 'number'
    },
    "CRC8DVBS2": {
        width: 8,
        poly: 0xd5,
        init: 0x00,
        refin: false,
        refout: false,
        xorout: 0x00,
        name: 'CRC-8/DVB-S2',
        returnAs: 'number'
    },
    'CRC8GSMA': {
        width: 8,
        poly: 0x1d,
        init: 0x00,
        refin: false,
        refout: false,
        xorout: 0x00,
        name: 'CRC-8/GSM-A',
        returnAs: 'number'
    },
    'CRC8GSMB': {
        width: 8,
        poly: 0x49,
        init: 0x00,
        refin: false,
        refout: false,
        xorout: 0xff,
        name: 'CRC-8/GSM-B',
        returnAs: 'number'
    },
    'CRC8HITAG': {
        width: 8,
        poly: 0x1d,
        init: 0xff,
        refin: false,
        refout: false,
        xorout: 0x00,
        name: 'CRC-8/HITAG',
        returnAs: 'number'
    },
    "CRC8I4321": {
        width: 8,
        poly: 0x07,
        init: 0x00,
        refin: false,
        refout: false,
        xorout: 0x55,
        name: 'CRC-8/I-432-1',
        returnAs: 'number'
    },
    "CRC8ITU": {
        width: 8,
        poly: 0x07,
        init: 0x00,
        refin: false,
        refout: false,
        xorout: 0x55,
        name: 'CRC-8/ITU',
        returnAs: 'number'
    },
    "CRC8ICODE": {
        width: 8,
        poly: 0x1d,
        init: 0xfd,
        refin: false,
        refout: false,
        xorout: 0x00,
        name: 'CRC-8/I-CODE',
        returnAs: 'number'
    },
    "CRC8LTE": {
        width: 8,
        poly: 0x9b,
        init: 0x00,
        refin: false,
        refout: false,
        xorout: 0x00,
        name: 'CRC-8/LTE',
        returnAs: 'number'
    },
    "CRC8MAXIMDOW": {
        width: 8,
        poly: 0x31,
        init: 0x00,
        refin: true,
        refout: true,
        xorout: 0x00,
        name: 'CRC-8/MAXIM-DOW',
        returnAs: 'number'
    },
    'CRC8MAXIM': {
        width: 8,
        poly: 0x31,
        init: 0x00,
        refin: true,
        refout: true,
        xorout: 0x00,
        name: 'CRC-8/MAXIM',
        returnAs: 'number'
    },
    'DOWCRC': {
        width: 8,
        poly: 0x31,
        init: 0x00,
        refin: true,
        refout: true,
        xorout: 0x00,
        name: 'DOW-CRC',
        returnAs: 'number'
    },
    'CRC8MIFAREMAD': {
        width: 8,
        poly: 0x1d,
        init: 0xc7,
        refin: false,
        refout: false,
        xorout: 0x00,
        name: 'CRC-8/MIFARE-MAD',
        returnAs: 'number'
    },
    'CRC8NRSC5': {
        width: 8,
        poly: 0x31,
        init: 0xff,
        refin: false,
        refout: false,
        xorout: 0x00,
        name: 'CRC-8/NRSC-5',
        returnAs: 'number'
    },
    'CRC8OPENSAFETY': {
        width: 8,
        poly: 0x2f,
        init: 0x00,
        refin: false,
        refout: false,
        xorout: 0x00,
        name: 'CRC-8/OPENSAFETY',
        returnAs: 'number'
    },
    'CRC8ROHC': {
        width: 8,
        poly: 0x07,
        init: 0xff,
        refin: true,
        refout: true,
        xorout: 0x00,
        name: 'CRC-8/ROHC',
        returnAs: 'number'
    },
    'CRC8SAEJ1850': {
        width: 8,
        poly: 0x1d,
        init: 0xff,
        refin: false,
        refout: false,
        xorout: 0xff,
        name: 'CRC-8/SAE-J1850',
        returnAs: 'number'
    },
    'CRC8': {
        width: 8,
        poly: 0x07,
        init: 0x00,
        refin: false,
        refout: false,
        xorout: 0x00,
        name: 'CRC-8',
        returnAs: 'number'
    },
    'CRC8SMBUS': {
        width: 8,
        poly: 0x07,
        init: 0x00,
        refin: false,
        refout: false,
        xorout: 0x00,
        name: 'CRC-8/SMBUS',
        returnAs: 'number'
    },
    'CRC8TECH3250': {
        width: 8,
        poly: 0x1d,
        init: 0xff,
        refin: true,
        refout: true,
        xorout: 0x00,
        name: 'CRC-8/TECH-3250',
        returnAs: 'number'
    },
    'CRC8AES': {
        width: 8,
        poly: 0x1d,
        init: 0xff,
        refin: true,
        refout: true,
        xorout: 0x00,
        name: 'CRC-8/AES',
        returnAs: 'number'
    },
    'CRC8EBU': {
        width: 8,
        poly: 0x1d,
        init: 0xff,
        refin: true,
        refout: true,
        xorout: 0x00,
        name: 'CRC-8/EBU',
        returnAs: 'number'
    },
    'CRC8WCDMA': {
        width: 8,
        poly: 0x9b,
        init: 0x00,
        refin: true,
        refout: true,
        xorout: 0x00,
        name: 'CRC-8/WCDMA',
        returnAs: 'number'
    },
    'CRC10ATM': {
        width: 10,
        poly: 0x233,
        init: 0x000,
        refin: false,
        refout: false,
        xorout: 0x000,
        name: 'CRC-10/ATM',
        returnAs: 'number'
    },
    "CRC10": {
        width: 10,
        poly: 0x233,
        init: 0x000,
        refin: false,
        refout: false,
        xorout: 0x000,
        name: 'CRC-10',
        returnAs: 'number'
    },
    "CRC10I610": {
        width: 10,
        poly: 0x233,
        init: 0x000,
        refin: false,
        refout: false,
        xorout: 0x000,
        name: 'CRC-10/I-610',
        returnAs: 'number'
    },
    "CRC10CDMA2000": {
        width: 10,
        poly: 0x3d9,
        init: 0x3ff,
        refin: false,
        refout: false,
        xorout: 0x000,
        name: 'CRC-10/CDMA2000',
        returnAs: 'number'
    },
    "CRC10GSM": {
        width: 10,
        poly: 0x175,
        init: 0x000,
        refin: false,
        refout: false,
        xorout: 0x3ff,
        name: 'CRC-10/GSM',
        returnAs: 'number'
    },
    "CRC11FLEXRAY": {
        width: 11,
        poly: 0x385,
        init: 0x01a,
        refin: false,
        refout: false,
        xorout: 0x000,
        name: 'CRC-11/FLEXRAY',
        returnAs: 'number'
    },
    'CRC11': {
        width: 11,
        poly: 0x385,
        init: 0x01a,
        refin: false,
        refout: false,
        xorout: 0x000,
        name: 'CRC-11',
        returnAs: 'number'
    },
    'CRC11UMTS': {
        width: 11,
        poly: 0x307,
        init: 0x000,
        refin: false,
        refout: false,
        xorout: 0x000,
        name: 'CRC-11/UMTS',
        returnAs: 'number'
    },
    'CRC12CDMA2000': {
        width: 12,
        poly: 0xf13,
        init: 0xfff,
        refin: false,
        refout: false,
        xorout: 0x000,
        name: 'CRC-12/CDMA2000',
        returnAs: 'number'
    },
    "CRC12DECT": {
        width: 12,
        poly: 0x80f,
        init: 0x000,
        refin: false,
        refout: false,
        xorout: 0x000,
        name: 'CRC-12/DECT',
        returnAs: 'number'
    },
    'XCRC12': {
        width: 12,
        poly: 0x80f,
        init: 0x000,
        refin: false,
        refout: false,
        xorout: 0x000,
        name: 'X-CRC-12',
        returnAs: 'number'
    },
    'CRC12GSM': {
        width: 12,
        poly: 0xd31,
        init: 0x000,
        refin: false,
        refout: false,
        xorout: 0xfff,
        name: 'CRC-12/GSM',
        returnAs: 'number'
    },
    "CRC12UMTS": {
        width: 12,
        poly: 0x80f,
        init: 0x000,
        refin: false,
        refout: true,
        xorout: 0x000,
        name: 'CRC-12/UMTS',
        returnAs: 'number'
    },
    'CRC123GPP': {
        width: 12,
        poly: 0x80f,
        init: 0x000,
        refin: false,
        refout: true,
        xorout: 0x000,
        name: 'CRC-12/3GPP',
        returnAs: 'number'
    },
    "CRC13BBC": {
        width: 13,
        poly: 0x1cf5,
        init: 0x0000,
        refin: false,
        refout: false,
        xorout: 0x0000,
        name: 'CRC-13/BBC',
        returnAs: 'number'
    },
    'CRC14DARC': {
        width: 14,
        poly: 0x0805,
        init: 0x0000,
        refin: true,
        refout: true,
        xorout: 0x0000,
        name: 'CRC-14/DARC',
        returnAs: 'number'
    },
    'CRC14GSM': {
        width: 14,
        poly: 0x202d,
        init: 0x0000,
        refin: false,
        refout: false,
        xorout: 0x3fff,
        name: 'CRC-14/GSM',
        returnAs: 'number'
    },
    "CRC15CAN": {
        width: 15,
        poly: 0x4599,
        init: 0x0000,
        refin: false,
        refout: false,
        xorout: 0x0000,
        name: 'CRC-15/CAN',
        returnAs: 'number'
    },
    'CRC15': {
        width: 15,
        poly: 0x4599,
        init: 0x0000,
        refin: false,
        refout: false,
        xorout: 0x0000,
        name: 'CRC-15',
        returnAs: 'number'
    },
    "CRC15MPT1327": {
        width: 15,
        poly: 0x6815,
        init: 0x0000,
        refin: false,
        refout: false,
        xorout: 0x0001,
        name: 'CRC-15/MPT1327',
        returnAs: 'number'
    },
    "CRC16ARC": {
        width: 16,
        poly: 0x8005,
        init: 0x0000,
        refin: true,
        refout: true,
        xorout: 0x0000,
        name: 'CRC-16/ARC',
        returnAs: 'number'
    },
    "ARC": {
        width: 16,
        poly: 0x8005,
        init: 0x0000,
        refin: true,
        refout: true,
        xorout: 0x0000,
        name: 'ARC',
        returnAs: 'number'
    },
    "CRC16": {
        width: 16,
        poly: 0x8005,
        init: 0x0000,
        refin: true,
        refout: true,
        xorout: 0x0000,
        name: 'CRC-16',
        returnAs: 'number'
    },
    "CRC16LHA": {
        width: 16,
        poly: 0x8005,
        init: 0x0000,
        refin: true,
        refout: true,
        xorout: 0x0000,
        name: 'CRC-16/LHA',
        returnAs: 'number'
    },
    "CRCIBM": {
        width: 16,
        poly: 0x8005,
        init: 0x0000,
        refin: true,
        refout: true,
        xorout: 0x0000,
        name: 'CRC-IBM',
        returnAs: 'number'
    },
    "CRC16CDMA2000": {
        width: 16,
        poly: 0xc867,
        init: 0xffff,
        refin: false,
        refout: false,
        xorout: 0x0000,
        name: 'CRC-16/CDMA2000',
        returnAs: 'number'
    },
    "CRC16CMS": {
        width: 16,
        poly: 0x8005,
        init: 0xffff,
        refin: false,
        refout: false,
        xorout: 0x0000,
        name: 'CRC-16/CMS',
        returnAs: 'number'
    },
    "CRC16DDS110": {
        width: 16,
        poly: 0x8005,
        init: 0x800d,
        refin: false,
        refout: false,
        xorout: 0x0000,
        name: 'CRC-16/DDS-110',
        returnAs: 'number'
    },
    "CRC16DECTR": {
        width: 16,
        poly: 0x0589,
        init: 0x0000,
        refin: false,
        refout: false,
        xorout: 0x0001,
        name: 'CRC-16/DECT-R',
        returnAs: 'number'
    },
    "RCRC16": {
        width: 16,
        poly: 0x0589,
        init: 0x0000,
        refin: false,
        refout: false,
        xorout: 0x0001,
        name: 'R-CRC-16',
        returnAs: 'number'
    },
    "CRC16DECTX": {
        width: 16,
        poly: 0x0589,
        init: 0x0000,
        refin: false,
        refout: false,
        xorout: 0x0000,
        name: 'CRC-16/DECT-X',
        returnAs: 'number'
    },
    "XCRC16": {
        width: 16,
        poly: 0x0589,
        init: 0x0000,
        refin: false,
        refout: false,
        xorout: 0x0000,
        name: 'X-CRC-16',
        returnAs: 'number'
    },
    "CRC16DNP": {
        width: 16,
        poly: 0x3d65,
        init: 0x0000,
        refin: true,
        refout: true,
        xorout: 0xffff,
        name: 'CRC-16/DNP',
        returnAs: 'number'
    },
    "CRC16EN13757": {
        width: 16,
        poly: 0x3d65,
        init: 0x0000,
        refin: false,
        refout: false,
        xorout: 0xffff,
        name: 'CRC-16/EN-13757',
        returnAs: 'number'
    },
    "CRC16GENIBUS": {
        width: 16,
        poly: 0x1021,
        init: 0xffff,
        refin: false,
        refout: false,
        xorout: 0xffff,
        name: 'CRC-16/GENIBUS',
        returnAs: 'number'
    },
    "CRC16DARC": {
        width: 16,
        poly: 0x1021,
        init: 0xffff,
        refin: false,
        refout: false,
        xorout: 0xffff,
        name: 'CRC-16/DARC',
        returnAs: 'number'
    },
    "CRC16EPC": {
        width: 16,
        poly: 0x1021,
        init: 0xffff,
        refin: false,
        refout: false,
        xorout: 0xffff,
        name: 'CRC-16/EPC',
        returnAs: 'number'
    },
    "CRC16EPCC1G2": {
        width: 16,
        poly: 0x1021,
        init: 0xffff,
        refin: false,
        refout: false,
        xorout: 0xffff,
        name: 'CRC-16/EPC-C1G2',
        returnAs: 'number'
    },
    "CRC16ICODE": {
        width: 16,
        poly: 0x1021,
        init: 0xffff,
        refin: false,
        refout: false,
        xorout: 0xffff,
        name: 'CRC-16/I-CODE',
        returnAs: 'number'
    },
    "CRC16GSM": {
        width: 16,
        poly: 0x1021,
        init: 0xffff,
        refin: false,
        refout: false,
        xorout: 0x0000,
        name: 'CRC-16/GSM',
        returnAs: 'number'
    },
    "CRC16IBM3740": {
        width: 16,
        poly: 0x1021,
        init: 0xffff,
        refin: false,
        refout: false,
        xorout: 0x0000,
        name: 'CRC-16/IBM-3740',
        returnAs: 'number'
    },
    "CRC16AUTOSAR": {
        width: 16,
        poly: 0x1021,
        init: 0xffff,
        refin: false,
        refout: false,
        xorout: 0x0000,
        name: 'CRC-16/AUTOSAR',
        returnAs: 'number'
    },
    "CRC16CCITTFALSE": {
        width: 16,
        poly: 0x1021,
        init: 0xffff,
        refin: true,
        refout: true,
        xorout: 0xffff,
        name: 'CRC-16/CCITT-FALSE',
        returnAs: 'number'
    },
    "CRC16IBMSDLC": {
        width: 16,
        poly: 0x1021,
        init: 0xffff,
        refin: true,
        refout: true,
        xorout: 0xffff,
        name: 'CRC-16/IBM-SDLC',
        returnAs: 'number'
    },
    "CRC16ISOHDLC": {
        width: 16,
        poly: 0x1021,
        init: 0xffff,
        refin: true,
        refout: true,
        xorout: 0xffff,
        name: 'CRC-16/ISO-HDLC',
        returnAs: 'number'
    },
    "CRC16ISOIEC144433B": {
        width: 16,
        poly: 0x1021,
        init: 0xffff,
        refin: true,
        refout: true,
        xorout: 0xffff,
        name: 'CRC-16/ISO-IEC-14443-3-B',
        returnAs: 'number'
    },
    "CRC16X25": {
        width: 16,
        poly: 0x1021,
        init: 0xffff,
        refin: true,
        refout: true,
        xorout: 0xffff,
        name: 'CRC-16/X-25',
        returnAs: 'number'
    },
    "CRCB": {
        width: 16,
        poly: 0x1021,
        init: 0xffff,
        refin: true,
        refout: true,
        xorout: 0xffff,
        name: 'CRC-16/B',
        returnAs: 'number'
    },
    "X25": {
        width: 16,
        poly: 0x1021,
        init: 0xffff,
        refin: true,
        refout: true,
        xorout: 0xffff,
        name: 'X-25',
        returnAs: 'number'
    },
    "CRC16ISOIEC144433A": {
        width: 16,
        poly: 0x1021,
        init: 0xc6c6,
        refin: true,
        refout: true,
        xorout: 0x0000,
        name: 'CRC-16/ISO-IEC-14443-3-A',
        returnAs: 'number'
    },
    "CRCA": {
        width: 16,
        poly: 0x1021,
        init: 0xc6c6,
        refin: true,
        refout: true,
        xorout: 0x0000,
        name: 'CRC-A',
        returnAs: 'number'
    },
    "CRC16KERMIT": {
        width: 16,
        poly: 0x1021,
        init: 0x0000,
        refin: true,
        refout: true,
        xorout: 0x0000,
        name: 'CRC-16/KERMIT',
        returnAs: 'number'
    },
    "CRC16BLUETOOTH": {
        width: 16,
        poly: 0x1021,
        init: 0x0000,
        refin: true,
        refout: true,
        xorout: 0x0000,
        name: 'CRC-16/BLUETOOTH',
        returnAs: 'number'
    },
    "CRC16CCITT": {
        width: 16,
        poly: 0x1021,
        init: 0x0000,
        refin: true,
        refout: true,
        xorout: 0x0000,
        name: 'CRC-16/CCITT',
        returnAs: 'number'
    },
    "CRC16CCITTTRUE": {
        width: 16,
        poly: 0x1021,
        init: 0x0000,
        refin: true,
        refout: true,
        xorout: 0x0000,
        name: 'CRC-16/CCITT-TRUE',
        returnAs: 'number'
    },
    "CRC16V41LSB": {
        width: 16,
        poly: 0x1021,
        init: 0x0000,
        refin: true,
        refout: true,
        xorout: 0x0000,
        name: 'CRC-16/V-41-LSB',
        returnAs: 'number'
    },
    "CRCCCITT": {
        width: 16,
        poly: 0x1021,
        init: 0x0000,
        refin: true,
        refout: true,
        xorout: 0x0000,
        name: 'CRC-CCITT',
        returnAs: 'number'
    },
    "KERMIT": {
        width: 16,
        poly: 0x1021,
        init: 0x0000,
        refin: true,
        refout: true,
        xorout: 0x0000,
        name: 'KERMIT',
        returnAs: 'number'
    },
    "CRC16LJ1200": {
        width: 16,
        poly: 0x6f63,
        init: 0xffff,
        refin: false,
        refout: false,
        xorout: 0x0000,
        name: 'CRC-16/LJ1200',
        returnAs: 'number'
    },
    "CRC16M17": {
        width: 16,
        poly: 0x5935,
        init: 0xffff,
        refin: false,
        refout: false,
        xorout: 0x0000,
        name: 'CRC-16/M17',
        returnAs: 'number'
    },
    "CRC16MAXIMDOW": {
        width: 16,
        poly: 0x8005,
        init: 0xffff,
        refin: true,
        refout: true,
        xorout: 0xffff,
        name: 'CRC-16/MAXIM-DOW',
        returnAs: 'number'
    },
    "CRC16MAXIM": {
        width: 16,
        poly: 0x8005,
        init: 0xffff,
        refin: true,
        refout: true,
        xorout: 0xffff,
        name: 'CRC-16/MAXIM',
        returnAs: 'number'
    },
    "CRC16MCRF4XX": {
        width: 16,
        poly: 0x1021,
        init: 0xffff,
        refin: true,
        refout: true,
        xorout: 0x0000,
        name: 'CRC-16/MCRF4XX',
        returnAs: 'number'
    },
    "CRC16MODBUS": {
        width: 16,
        poly: 0x8005,
        init: 0xffff,
        refin: true,
        refout: true,
        xorout: 0x0000,
        name: 'CRC-16/MODBUS',
        returnAs: 'number'
    },
    "MODBUS": {
        width: 16,
        poly: 0x8005,
        init: 0xffff,
        refin: true,
        refout: true,
        xorout: 0x0000,
        name: 'MODBUS',
        returnAs: 'number'
    },
    "CRC16NRSC5": {
        width: 16,
        poly: 0x080b,
        init: 0xffff,
        refin: true,
        refout: true,
        xorout: 0x0000,
        name: 'CRC-16/NRSC-5',
        returnAs: 'number'
    },
    "CRC16OPENSAFETYA": {
        width: 16,
        poly: 0x5935,
        init: 0x0000,
        refin: false,
        refout: false,
        xorout: 0x0000,
        name: 'CRC-16/OPENSAFETY-A',
        returnAs: 'number'
    },
    "CRC16OPENSAFETYB": {
        width: 16,
        poly: 0x755b,
        init: 0x0000,
        refin: false,
        refout: false,
        xorout: 0x0000,
        name: 'CRC-16/OPENSAFETY-B',
        returnAs: 'number'
    },
    "CRC16PROFIBUS": {
        width: 16,
        poly: 0x1dcf,
        init: 0xffff,
        refin: false,
        refout: false,
        xorout: 0xffff,
        name: 'CRC-16/PROFIBUS',
        returnAs: 'number'
    },
    "CRC16IEC611582": {
        width: 16,
        poly: 0x1dcf,
        init: 0xffff,
        refin: false,
        refout: false,
        xorout: 0xffff,
        name: 'CRC-16/IEC-61158-2',
        returnAs: 'number'
    },
    "CRC16RIELLO": {
        width: 16,
        poly: 0x1021,
        init: 0xb2aa,
        refin: true,
        refout: true,
        xorout: 0x0000,
        name: 'CRC-16/RIELLO',
        returnAs: 'number'
    },
    "CRC16SPIFUJITSU": {
        width: 16,
        poly: 0x1021,
        init: 0x1d0f,
        refin: false,
        refout: false,
        xorout: 0x0000,
        name: 'CRC-16/SPI-FUJITSU',
        returnAs: 'number'
    },
    "CRC16AUGCCITT": {
        width: 16,
        poly: 0x1021,
        init: 0x1d0f,
        refin: false,
        refout: false,
        xorout: 0x0000,
        name: 'CRC-16/AUG-CCITT',
        returnAs: 'number'
    },
    "CRC16T10DIF": {
        width: 16,
        poly: 0x8bb7,
        init: 0x0000,
        refin: false,
        refout: false,
        xorout: 0x0000,
        name: 'CRC-16/T10-DIF',
        returnAs: 'number'
    },
    "CRC16TELEDISK": {
        width: 16,
        poly: 0xa097,
        init: 0x0000,
        refin: false,
        refout: false,
        xorout: 0x0000,
        name: 'CRC-16/TELEDISK',
        returnAs: 'number'
    },
    "CRC16TMS37157": {
        width: 16,
        poly: 0x1021,
        init: 0x89ec,
        refin: true,
        refout: true,
        xorout: 0x0000,
        name: 'CRC-16/TMS37157',
        returnAs: 'number'
    },
    "CRC16UMTS": {
        width: 16,
        poly: 0x8005,
        init: 0x0000,
        refin: false,
        refout: false,
        xorout: 0x0000,
        name: 'CRC-16/UMTS',
        returnAs: 'number'
    },
    "CRC16BUYPASS": {
        width: 16,
        poly: 0x8005,
        init: 0x0000,
        refin: false,
        refout: false,
        xorout: 0x0000,
        name: 'CRC-16/BUYPASS',
        returnAs: 'number'
    },
    "CRC16VERIFONE": {
        width: 16,
        poly: 0x8005,
        init: 0x0000,
        refin: false,
        refout: false,
        xorout: 0x0000,
        name: 'CRC-16/VERIFONE',
        returnAs: 'number'
    },
    "CRC16USB": {
        width: 16,
        poly: 0x8005,
        init: 0xffff,
        refin: true,
        refout: true,
        xorout: 0xffff,
        name: 'CRC-16/USB',
        returnAs: 'number'
    },
    "CRC16XMODEM": {
        width: 16,
        poly: 0x1021,
        init: 0x0000,
        refin: false,
        refout: false,
        xorout: 0x0000,
        name: 'CRC-16/XMODEM',
        returnAs: 'number'
    },
    "CRC16ACORN": {
        width: 16,
        poly: 0x1021,
        init: 0x0000,
        refin: false,
        refout: false,
        xorout: 0x0000,
        name: 'CRC-16/ACORN',
        returnAs: 'number'
    },
    "CRC16LTE": {
        width: 16,
        poly: 0x1021,
        init: 0x0000,
        refin: false,
        refout: false,
        xorout: 0x0000,
        name: 'CRC-16/LTE',
        returnAs: 'number'
    },
    "CRC16V41MSB": {
        width: 16,
        poly: 0x1021,
        init: 0x0000,
        refin: false,
        refout: false,
        xorout: 0x0000,
        name: 'CRC-16/V-41-MSB',
        returnAs: 'number'
    },
    "XMODEM": {
        width: 16,
        poly: 0x1021,
        init: 0x0000,
        refin: false,
        refout: false,
        xorout: 0x0000,
        name: 'XMODEM',
        returnAs: 'number'
    },
    "ZMODEM": {
        width: 16,
        poly: 0x1021,
        init: 0x0000,
        refin: false,
        refout: false,
        xorout: 0x0000,
        name: 'ZMODEM',
        returnAs: 'number'
    },
    "CRC17CANFD": {
        width: 17,
        poly: 0x1685b,
        init: 0x00000,
        refin: false,
        refout: false,
        xorout: 0x00000,
        name: 'CRC-17/CAN-FD',
        returnAs: 'number'
    },
    "CRC21CANFD": {
        width: 21,
        poly: 0x102899,
        init: 0x000000,
        refin: false,
        refout: false,
        xorout: 0x000000,
        name: 'CRC-21/CAN-FD',
        returnAs: 'number'
    },
    "CRC24BLE": {
        width: 24,
        poly: 0x00065b,
        init: 0x555555,
        refin: true,
        refout: true,
        xorout: 0x000000,
        name: 'CRC-24/BLE',
        returnAs: 'number'
    },
    "CRC24FLEXRAYA": {
        width: 24,
        poly: 0x5d6dcb,
        init: 0xfedcba,
        refin: false,
        refout: false,
        xorout: 0x000000,
        name: 'CRC-24/FLEXRAY-A',
        returnAs: 'number'
    },
    "CRC24FLEXRAyb": {
        width: 24,
        poly: 0x5d6dcb,
        init: 0xabcdef,
        refin: false,
        refout: false,
        xorout: 0x000000,
        name: 'CRC-24/FLEXRAY-B',
        returnAs: 'number'
    },
    "CRC24INTERLAKEN": {
        width: 24,
        poly: 0x328b63,
        init: 0xffffff,
        refin: false,
        refout: false,
        xorout: 0xffffff,
        name: 'CRC-24/INTERLAKEN',
        returnAs: 'number'
    },
    "CRC24LTEA": {
        width: 24,
        poly: 0x864cfb,
        init: 0x000000,
        refin: false,
        refout: false,
        xorout: 0x000000,
        name: 'CRC-24/LTE-A',
        returnAs: 'number'
    },
    "CRC24LTEB": {
        width: 24,
        poly: 0x800063,
        init: 0x000000,
        refin: false,
        refout: false,
        xorout: 0x000000,
        name: 'CRC-24/LTE-B',
        returnAs: 'number'
    },
    "CRC24OPENPGP": {
        width: 24,
        poly: 0x864cfb,
        init: 0xb704ce,
        refin: false,
        refout: false,
        xorout: 0x000000,
        name: 'CRC-24/OPENPGP',
        returnAs: 'number'
    },
    "CRC24": {
        width: 24,
        poly: 0x864cfb,
        init: 0xb704ce,
        refin: false,
        refout: false,
        xorout: 0x000000,
        name: 'CRC-24',
        returnAs: 'number'
    },
    "CRC24OS9": {
        width: 24,
        poly: 0x800063,
        init: 0xffffff,
        refin: false,
        refout: false,
        xorout: 0xffffff,
        name: 'CRC-24/OS-9',
        returnAs: 'number'
    },
    "CRC30CDMA": {
        width: 30,
        poly: 0x2030b9c7,
        init: 0x3fffffff,
        refin: false,
        refout: false,
        xorout: 0x3fffffff,
        name: 'CRC-30/CDMA',
        returnAs: 'number'
    },
    "CRC31PHILIPS": {
        width: 31,
        poly: 0x04c11db7,
        init: 0x7fffffff,
        refin: false,
        refout: false,
        xorout: 0x7fffffff,
        name: 'CRC-31/PHILIPS',
        returnAs: 'number'
    },
    "CRC32AIXM": {
        width: 32,
        poly: 0x814141ab,
        init: 0x00000000,
        refin: false,
        refout: false,
        xorout: 0x00000000,
        name: 'CRC-32/AIXM',
        returnAs: 'number'
    },
    "CRC32Q": {
        width: 32,
        poly: 0x814141ab,
        init: 0x00000000,
        refin: false,
        refout: false,
        xorout: 0x00000000,
        name: 'CRC-32Q',
        returnAs: 'number'
    },
    "CRC32AUTOSAR": {
        width: 32,
        poly: 0xf4acfb13,
        init: 0xffffffff,
        refin: true,
        refout: true,
        xorout: 0xffffffff,
        name: 'CRC-32/AUTOSAR',
        returnAs: 'number'
    },
    "CRC32BASE91D": {
        width: 32,
        poly: 0xa833982b,
        init: 0xffffffff,
        refin: true,
        refout: true,
        xorout: 0xffffffff,
        name: 'CRC-32/BASE91-D',
        returnAs: 'number'
    },
    "CRC32D": {
        width: 32,
        poly: 0xa833982b,
        init: 0xffffffff,
        refin: true,
        refout: true,
        xorout: 0xffffffff,
        name: 'CRC-32D',
        returnAs: 'number'
    },
    "CRC32BZIP2": {
        width: 32,
        poly: 0x04c11db7,
        init: 0xffffffff,
        refin: false,
        refout: false,
        xorout: 0xffffffff,
        name: 'CRC-32/BZIP2',
        returnAs: 'number'
    },
    "CRC32AAL5": {
        width: 32,
        poly: 0x04c11db7,
        init: 0xffffffff,
        refin: false,
        refout: false,
        xorout: 0xffffffff,
        name: 'CRC-32/AAL5',
        returnAs: 'number'
    },
    "CRC32DECTB": {
        width: 32,
        poly: 0x04c11db7,
        init: 0xffffffff,
        refin: false,
        refout: false,
        xorout: 0xffffffff,
        name: 'CRC-32/DECT-B',
        returnAs: 'number'
    },
    "BCRC32": {
        width: 32,
        poly: 0x04c11db7,
        init: 0xffffffff,
        refin: false,
        refout: false,
        xorout: 0xffffffff,
        name: 'B-CRC-32',
        returnAs: 'number'
    },
    "CRC32SQENX":{
        width: 32,
        poly: 0x04c11db7,
        init: 0xffffffff,
        refin: false,
        refout: false,
        xorout: 0xffffffff,
        name: 'B-CRC-32',
        returnAs: 'number'
    },
    "CRC32CDROMEDC": {
        width: 32,
        poly: 0x8001801b,
        init: 0x00000000,
        refin: true,
        refout: true,
        xorout: 0x00000000,
        name: 'CRC-32/CD-ROM-EDC',
        returnAs: 'number'
    },
    "CRC32CKSUM": {
        width: 32,
        poly: 0x04c11db7,
        init: 0xffffffff,
        refin: false,
        refout: false,
        xorout: 0xffffffff,
        name: 'CRC-32/CKSUM',
        returnAs: 'number'
    },
    "CKSUM": {
        width: 32,
        poly: 0x04c11db7,
        init: 0xffffffff,
        refin: false,
        refout: false,
        xorout: 0xffffffff,
        name: 'CKSUM',
        returnAs: 'number'
    },
    "CRC32POSIX": {
        width: 32,
        poly: 0x04c11db7,
        init: 0xffffffff,
        refin: false,
        refout: false,
        xorout: 0xffffffff,
        name: 'CRC-32/POSIX',
        returnAs: 'number'
    },
    "CRC32ISCSI": {
        width: 32,
        poly: 0x1edc6f41,
        init: 0xffffffff,
        refin: true,
        refout: true,
        xorout: 0xffffffff,
        name: 'CRC-32/ISCSI',
        returnAs: 'number'
    },
    "CRC32BASE91C": {
        width: 32,
        poly: 0x1edc6f41,
        init: 0xffffffff,
        refin: true,
        refout: true,
        xorout: 0xffffffff,
        name: 'CRC-32/BASE91-C',
        returnAs: 'number'
    },
    "CRC32CASTAGNOLI": {
        width: 32,
        poly: 0x1edc6f41,
        init: 0xffffffff,
        refin: true,
        refout: true,
        xorout: 0xffffffff,
        name: 'CRC-32/CASTAGNOLI',
        returnAs: 'number'
    },
    "CRC32INTERLAKEN": {
        width: 32,
        poly: 0x1edc6f41,
        init: 0xffffffff,
        refin: true,
        refout: true,
        xorout: 0xffffffff,
        name: 'CRC-32/INTERLAKEN',
        returnAs: 'number'
    },
    "CRC32C": {
        width: 32,
        poly: 0x1edc6f41,
        init: 0xffffffff,
        refin: true,
        refout: true,
        xorout: 0xffffffff,
        name: 'CRC-32C',
        returnAs: 'number'
    },
    "CRC32NVME": {
        width: 32,
        poly: 0x1edc6f41,
        init: 0xffffffff,
        refin: true,
        refout: true,
        xorout: 0xffffffff,
        name: 'CRC-32/NVME',
        returnAs: 'number'
    },
    "CRC32ISOHDLC": {
        width: 32,
        poly: 0x04c11db7,
        init: 0xffffffff,
        refin: true,
        refout: true,
        xorout: 0xffffffff,
        name: 'CRC-32/ISO-HDLC',
        returnAs: 'number'
    },
    "CRC32": {
        width: 32,
        poly: 0x04c11db7,
        init: 0xffffffff,
        refin: true,
        refout: true,
        xorout: 0xffffffff,
        name: 'CRC-32',
        returnAs: 'number'
    },
    "CRC32ADCCP": {
        width: 32,
        poly: 0x04c11db7,
        init: 0xffffffff,
        refin: true,
        refout: true,
        xorout: 0xffffffff,
        name: 'CRC-32/ADCCP',
        returnAs: 'number'
    },
    "CRC32V42": {
        width: 32,
        poly: 0x04c11db7,
        init: 0xffffffff,
        refin: true,
        refout: true,
        xorout: 0xffffffff,
        name: 'CRC-32/V-42',
        returnAs: 'number'
    },
    "CRC32XZ": {
        width: 32,
        poly: 0x04c11db7,
        init: 0xffffffff,
        refin: true,
        refout: true,
        xorout: 0xffffffff,
        name: 'CRC-32/XZ',
        returnAs: 'number'
    },
    "PKZIP": {
        width: 32,
        poly: 0x04c11db7,
        init: 0xffffffff,
        refin: true,
        refout: true,
        xorout: 0x00000000,
        name: 'PKZIP',
        returnAs: 'number'
    },
    "CRC32JAMCRC": {
        width: 32,
        poly: 0x04c11db7,
        init: 0xffffffff,
        refin: true,
        refout: true,
        xorout: 0x00000000,
        name: 'CRC-32/JAMCRC',
        returnAs: 'number'
    },
    "JAMCRC": {
        width: 32,
        poly: 0x04c11db7,
        init: 0xffffffff,
        refin: true,
        refout: true,
        xorout: 0x00000000,
        name: 'JAMCRC',
        returnAs: 'number'
    },
    "CRC32MEF": {
        width: 32,
        poly: 0x741b8cd7,
        init: 0xffffffff,
        refin: true,
        refout: true,
        xorout: 0x00000000,
        name: 'CRC-32/MEF',
        returnAs: 'number'
    },
    "CRC32MPEG2": {
        width: 32,
        poly: 0x04c11db7,
        init: 0xffffffff,
        refin: false,
        refout: false,
        xorout: 0x00000000,
        name: 'CRC-32/MPEG-2',
        returnAs: 'number'
    },
    "CRC32XFER": {
        width: 32,
        poly: 0x000000af,
        init: 0x00000000,
        refin: false,
        refout: false,
        xorout: 0x00000000,
        name: 'CRC-32/XFER',
        returnAs: 'number'
    },
    "XFER": {
        width: 32,
        poly: 0x000000af,
        init: 0x00000000,
        refin: false,
        refout: false,
        xorout: 0x00000000,
        name: 'XFER',
        returnAs: 'number'
    },
    "CRC40GSM": {
        width: 40,
        poly: [0x00, 0x04820009],
        init: [0x00, 0x00000000],
        refin: false,
        refout: false,
        xorout: [0xff, 0xffffffff],
        name: 'CRC-40/GSM',
        returnAs: 'bigint'
    },
    "CRC64": {
        width: 64,
        poly: [0x42f0e1eb, 0xa9ea3693],
        init: [0, 0],
        refin: false,
        refout: false,
        xorout: [0, 0],
        name: 'CRC-64',
        returnAs: 'bigint'
    },
    "CRC64ECMA182": {
        width: 64,
        poly: [0x42f0e1eb, 0xa9ea3693],
        init: [0, 0],
        refin: false,
        refout: false,
        xorout: [0, 0],
        name: 'CRC-64/ECMA-182',
        returnAs: 'bigint'
    },
    "CRC64GOISO": {
        width: 64,
        poly: [0x00000000, 0x0000001b],
        init: [0xffffffff, 0xffffffff],
        refin: true,
        refout: true,
        xorout: [0xffffffff, 0xffffffff],
        name: 'CRC-64/GO-ISO',
        returnAs: 'bigint'
    },
    "CRC64MS": {
        width: 64,
        poly: [0x259c84cb, 0xa6426349],
        init: [0xffffffff, 0xffffffff],
        refin: true,
        refout: true,
        xorout: [0, 0],
        name: 'CRC-64/MS',
        returnAs: 'bigint'
    },
    "CRC64NVMEN": {
        width: 64,
        poly: [0xad93d235, 0x94c93659],
        init: [0xffffffff, 0xffffffff],
        refin: true,
        refout: true,
        xorout: [0xffffffff, 0xffffffff],
        name: 'CRC-64/NVME',
        returnAs: 'bigint'
    },
    "CRC64REDIS": {
        width: 64,
        poly: [0xad93d235, 0x94c935a9],
        init: [0, 0],
        refin: true,
        refout: true,
        xorout: [0, 0],
        name: 'CRC-64/REDIS',
        returnAs: 'bigint'
    },
    "CRC64WE": {
        width: 64,
        poly: [0x42f0e1eb, 0xa9ea3693],
        init: [0xffffffff, 0xffffffff],
        refin: false,
        refout: false,
        xorout: [0xffffffff, 0xffffffff],
        name: 'CRC-64/WE',
        returnAs: 'bigint'
    },
    "CRC64XZ": {
        width: 64,
        poly: [0x42f0e1eb, 0xa9ea3693],
        init: [0xffffffff, 0xffffffff],
        refin: true,
        refout: true,
        xorout: [0xffffffff, 0xffffffff],
        name: 'CRC-64/XZ',
        returnAs: 'bigint'
    },
    "CRC64GOECMA": {
        width: 64,
        poly: [0x42f0e1eb, 0xa9ea3693],
        init: [0xffffffff, 0xffffffff],
        refin: true,
        refout: true,
        xorout: [0xffffffff, 0xffffffff],
        name: 'CRC-64/GO-ECMA',
        returnAs: 'bigint'
    },
    "CRC82DARC": {
        width: 82,
        poly: [0x0308c, 0x01110114, 0x01440411],
        init: [0, 0, 0],
        refin: true,
        refout: true,
        xorout: [0, 0, 0],
        name: 'CRC-82/DARC',
        returnAs: 'array'
    }
}

/**
 * Static class of CRC functions
 */
export class CRC {
    private static Compute(crc: CrcCalculator, data: Buffer | Uint8Array | string, offset?: number, length?: number): number | bigint | number[] | string {
        if (typeof data == "string") {
            data = strToUint8Array(data);
        }

        const { actualOffset, actualLength } = CRC.ensureLength(data, offset, length);

        return crc.update(data.subarray(actualOffset, actualOffset + actualLength))[crc.returnAs ?? "number"]();
    }

    private static ensureLength(data: Buffer | Uint8Array | string, offset?: number, length?: number): { actualOffset: number, actualLength: number } {
        var actualOffset = offset ?? 0;
        var actualLength = length ?? data.length;

        // Check if offset is defined and valid
        if (offset !== undefined) {
            if (offset < 0) {
                // Offset must be a non-negative integer
                actualOffset = 0;
            }

            if (actualOffset >= data.length) {
                // Offset must be less than data length
                return { actualOffset: 0, actualLength: 0 };
            }
        }

        // Check if length is defined and valid
        if (length !== undefined) {
            if (length <= 0) {
                // Length must be a positive integer
                return { actualOffset: 0, actualLength: 0 };
            }

            if (actualOffset + actualLength > data.length) {
                // Offset + length exceeds data length
                actualLength = data.length - actualOffset;
            }
        }

        // If using defaults, ensure the effective range is valid
        if (actualOffset + actualLength > data.length) {
            // Effective range exceeds data length
            actualLength = data.length - actualOffset;
        }

        return { actualOffset, actualLength };
    }

    static CrcCalculator = CrcCalculator;

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
    static CRC(options: CRCOptions, data: Buffer | Uint8Array | string, offset?: number, length?: number) {
        const crc = new CrcCalculator(
            options
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }

    /**
     * CRC-3
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC3(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC3']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }

    /**
     * CRC-3/GSM
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC3GSM(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC3GSM']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }

    /**
     * CRC-3/ROHC
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC3ROHC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC3ROHC']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }

    /**
     * CRC-4/G-704
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC4G704(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC4G704']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }

    /**
     * CRC-4/ITU
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC4ITU(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC4ITU']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }

    /**
     * CRC-5/EPC-C1G2
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC5EPCC1G2(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC5EPCC1G2']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }

    /**
     * CRC-5/EPC
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC5EPC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC5EPC']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }

    /**
     * CRC-5/G-704
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC5G704(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC5G704']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }

    /**
     * CRC-5/ITU
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC5ITU(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC5ITU']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }

    /**
     * CRC-5/USB
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC5USB(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC5USB']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }

    /**
     * CRC-6/CDMA2000-A
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC6CDMA2000A(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC6CDMA2000A']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-6/CDMA2000-B
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC6CDMA2000B(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC6CDMA2000B']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-6/DARC
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC6DARC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC6DARC']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-6/G-704
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC6G704(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC6G704']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-6/ITU
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC6ITU(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC6ITU']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-6/GSM
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC6GSM(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC6GSM']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-7
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC7(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC7']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-7/MMC
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC7MMC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC7MMC']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-7/ROHC
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC7ROHC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC7ROHC']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-7/UMTS
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC7UMTS(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC7UMTS']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-8/AUTOSAR
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8AUTOSAR(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC8AUTOSAR']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-8/BLUETOOTH
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8BLUETOOTH(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC8BLUETOOTH']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-8/CDMA2000
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8CDMA2000(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC8CDMA2000']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-8/DARC
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8DARC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC8DARC']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-8/DVB-S2
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8DVBS2(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC8DVBS2']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-8/GSM-A
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8GSMA(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC8GSMA']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-8/GSM-B
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8GSMB(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC8GSMB']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-8/HITAG
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8HITAG(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC8HITAG']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-8/I-432-1
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8I4321(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC8I4321']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-8/ITU
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8ITU(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC8ITU']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-8/I-CODE
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8ICODE(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC8ICODE']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-8/LTE
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8LTE(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC8LTE']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-8/MAXIM-DOW
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8MAXIMDOW(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC8MAXIMDOW']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-8/MAXIM
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8MAXIM(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC8MAXIM']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * DOW-CRC
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static DOWCRC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['DOWCRC']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-8/MIFARE-MAD
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8MIFAREMAD(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC8MIFAREMAD']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-8/NRSC-5
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8NRSC5(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC8NRSC5']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-8/OPENSAFETY
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8OPENSAFETY(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC8OPENSAFETY']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-8/ROHC
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8ROHC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC8ROHC']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-8/SAE-J1850
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8SAEJ1850(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC8SAEJ1850']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-8
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC8']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-8/SMBUS
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8SMBUS(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC8SMBUS']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-8/TECH-3250
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8TECH3250(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC8TECH3250']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-8/AES
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8AES(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC8AES']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-8/EBU
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8EBU(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC8EBU']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-8/WCDMA
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC8WCDMA(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC8WCDMA']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-10/ATM
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC10ATM(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC10ATM']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-10
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC10(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC10']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-10/I-610
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC10I610(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC10I610']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-10/CDMA2000
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC10CDMA2000(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC10CDMA2000']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-10/GSM
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC10GSM(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC10GSM']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-11/FLEXRAY
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC11FLEXRAY(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC11FLEXRAY']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-11
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC11(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC11']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-11/UMTS
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC11UMTS(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC11UMTS']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-12/CDMA2000
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC12CDMA2000(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC12CDMA2000']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-12/DECT
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC12DECT(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC12DECT']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * X-CRC-12
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static XCRC12(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['XCRC12']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-12/GSM
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC12GSM(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC12GSM']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-12/UMTS
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC12UMTS(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC12UMTS']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-12/3GPP
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC123GPP(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC123GPP']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-13/BBC
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC13BBC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC13BBC']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-14/DARC
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC14DARC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC14DARC']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-14/GSM
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC14GSM(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC14GSM']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-15/CAN
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC15CAN(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC15CAN']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-15
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC15(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC15']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-15/MPT1327
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC15MPT1327(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC15MPT1327']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/ARC
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16ARC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16ARC']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * ARC
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static ARC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['ARC']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/LHA
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16LHA(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16LHA']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-IBM
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRCIBM(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRCIBM']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/CDMA2000
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16CDMA2000(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16CDMA2000']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/CMS
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16CMS(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16CMS']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/DDS-110
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16DDS110(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16DDS110']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/DECT-R
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16DECTR(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16DECTR']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * R-CRC-16
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static RCRC16(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['RCRC16']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/DECT-X
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16DECTX(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16DECTX']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * X-CRC-16
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static XCRC16(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['XCRC16']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/DNP
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16DNP(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16DNP']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/EN-13757
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16EN13757(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16EN13757']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/GENIBUS
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16GENIBUS(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16GENIBUS']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/DARC
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16DARC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16DARC']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/EPC
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16EPC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16EPC']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/EPC-C1G2
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16EPCC1G2(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16EPCC1G2']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/I-CODE
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16ICODE(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16ICODE']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/GSM
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16GSM(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16GSM']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/IBM-3740
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16IBM3740(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16IBM3740']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/AUTOSAR
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16AUTOSAR(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16AUTOSAR']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/CCITT-FALSE
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16CCITTFALSE(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16CCITTFALSE']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/IBM-SDLC
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16IBMSDLC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16IBMSDLC']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/ISO-HDLC
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16ISOHDLC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16ISOHDLC']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/ISO-IEC-14443-3-B
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16ISOIEC144433B(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16ISOIEC144433B']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/X-25
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16X25(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16X25']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/B
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRCB(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRCB']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * X-25
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static X25(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['X25']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/ISO-IEC-14443-3-A
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16ISOIEC144433A(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16ISOIEC144433A']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-A
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRCA(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRCA']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/KERMIT
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16KERMIT(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16KERMIT']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/BLUETOOTH
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16BLUETOOTH(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16BLUETOOTH']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/CCITT
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16CCITT(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16CCITT']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/CCITT-TRUE
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16CCITTTRUE(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16CCITTTRUE']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/V-41-LSB
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16V41LSB(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16V41LSB']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-CCITT
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRCCCITT(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRCCCITT']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * KERMIT
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static KERMIT(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['KERMIT']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/LJ1200
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16LJ1200(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16LJ1200']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/M17
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16M17(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16M17']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/MAXIM-DOW
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16MAXIMDOW(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16MAXIMDOW']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/MAXIM
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16MAXIM(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16MAXIM']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/MCRF4XX
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16MCRF4XX(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16MCRF4XX']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/MODBUS
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16MODBUS(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16MODBUS']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * MODBUS
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static MODBUS(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['MODBUS']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/NRSC-5
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16NRSC5(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16NRSC5']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/OPENSAFETY-A
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16OPENSAFETYA(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16OPENSAFETYA']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/OPENSAFETY-B
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16OPENSAFETYB(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16OPENSAFETYB']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/PROFIBUS
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16PROFIBUS(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16PROFIBUS']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/IEC-61158-2
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16IEC611582(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16IEC611582']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/RIELLO
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16RIELLO(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16RIELLO']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/SPI-FUJITSU
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16SPIFUJITSU(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16SPIFUJITSU']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/AUG-CCITT
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16AUGCCITT(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16AUGCCITT']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/T10-DIF
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16T10DIF(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16T10DIF']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/TELEDISK
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16TELEDISK(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16TELEDISK']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/TMS37157
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16TMS37157(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16TMS37157']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/UMTS
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16UMTS(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16UMTS']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/BUYPASS
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16BUYPASS(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16BUYPASS']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/VERIFONE
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16VERIFONE(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16VERIFONE']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/USB
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16USB(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16USB']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/XMODEM
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16XMODEM(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16XMODEM']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/ACORN
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16ACORN(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16ACORN']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/LTE
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16LTE(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16LTE']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-16/V-41-MSB
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC16V41MSB(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC16V41MSB']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * XMODEM
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static XMODEM(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['XMODEM']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * ZMODEM
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static ZMODEM(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['ZMODEM']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-17/CAN-FD
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC17CANFD(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC17CANFD']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-21/CAN-FD
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC21CANFD(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC21CANFD']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-24/BLE
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC24BLE(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC24BLE']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-24/FLEXRAY-A
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC24FLEXRAYA(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC24FLEXRAYA']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-24/FLEXRAY-B
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC24FLEXRAyb(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC24FLEXRAyb']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-24/INTERLAKEN
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC24INTERLAKEN(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC24INTERLAKEN']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-24/LTE-A
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC24LTEA(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC24LTEA']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-24/LTE-B
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC24LTEB(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC24LTEB']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-24/OPENPGP
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC24OPENPGP(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC24OPENPGP']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-24
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC24(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC24']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-24/OS-9
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC24OS9(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC24OS9']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-30/CDMA
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC30CDMA(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC30CDMA']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-31/PHILIPS
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC31PHILIPS(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC31PHILIPS']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-32/AIXM
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32AIXM(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC32AIXM']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-32Q
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32Q(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC32Q']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-32/AUTOSAR
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32AUTOSAR(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC32AUTOSAR']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-32/BASE91-D
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32BASE91D(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC32BASE91D']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-32D
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32D(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC32D']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-32/BZIP2
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32BZIP2(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC32BZIP2']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-32/AAL5
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32AAL5(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC32AAL5']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-32/DECT-B
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32DECTB(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC32DECTB']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * B-CRC-32
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static BCRC32(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['BCRC32']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }

    /**
     * CRC-32/SqEnx
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32SQENX(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        data = formatMessage(data);

        const { actualLength, actualOffset } = CRC.ensureLength(data, offset, length);

        var pbBuffer = data.subarray(actualOffset, actualOffset + actualLength);

        const crc_table_0f085d0 = new Int32Array([
            0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3, 0x0EDB8832,
            0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91, 0x1DB71064, 0x6AB020F2,
            0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7, 0x136C9856, 0x646BA8C0, 0xFD62F97A,
            0x8A65C9EC, 0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5, 0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
            0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B, 0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940, 0x32D86CE3,
            0x45DF5C75, 0xDCD60DCF, 0xABD13D59, 0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423,
            0xCFBA9599, 0xB8BDA50F, 0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 0x2F6F7C87, 0x58684C11, 0xC1611DAB,
            0xB6662D3D, 0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
            0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01, 0x6B6B51F4,
            0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457, 0x65B0D9C6, 0x12B7E950,
            0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65, 0x4DB26158, 0x3AB551CE, 0xA3BC0074,
            0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB, 0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
            0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9, 0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 0x5768B525,
            0x206F85B3, 0xB966D409, 0xCE61E49F, 0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81,
            0xB7BD5C3B, 0xC0BA6CAD, 0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 0xEAD54739, 0x9DD277AF, 0x04DB2615,
            0x73DC1683, 0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
            0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7, 0xFED41B76,
            0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5, 0xD6D6A3E8, 0xA1D1937E,
            0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B, 0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6,
            0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79, 0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
            0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F, 0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7,
            0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D, 0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F,
            0x72076785, 0x05005713, 0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38, 0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7,
            0x0BDBDF21, 0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
            0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45, 0xA00AE278,
            0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB, 0xAED16A4A, 0xD9D65ADC,
            0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9, 0xBDBDF21C, 0xCABAC28A, 0x53B39330,
            0x24B4A3A6, 0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF, 0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
            0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
        ]);

        const crc_table_0f089d0 = new Int32Array([
            0x00000000, 0x191B3141, 0x32366282, 0x2B2D53C3, 0x646CC504, 0x7D77F445, 0x565AA786, 0x4F4196C7, 0xC8D98A08,
            0xD1C2BB49, 0xFAEFE88A, 0xE3F4D9CB, 0xACB54F0C, 0xB5AE7E4D, 0x9E832D8E, 0x87981CCF, 0x4AC21251, 0x53D92310,
            0x78F470D3, 0x61EF4192, 0x2EAED755, 0x37B5E614, 0x1C98B5D7, 0x05838496, 0x821B9859, 0x9B00A918, 0xB02DFADB,
            0xA936CB9A, 0xE6775D5D, 0xFF6C6C1C, 0xD4413FDF, 0xCD5A0E9E, 0x958424A2, 0x8C9F15E3, 0xA7B24620, 0xBEA97761,
            0xF1E8E1A6, 0xE8F3D0E7, 0xC3DE8324, 0xDAC5B265, 0x5D5DAEAA, 0x44469FEB, 0x6F6BCC28, 0x7670FD69, 0x39316BAE,
            0x202A5AEF, 0x0B07092C, 0x121C386D, 0xDF4636F3, 0xC65D07B2, 0xED705471, 0xF46B6530, 0xBB2AF3F7, 0xA231C2B6,
            0x891C9175, 0x9007A034, 0x179FBCFB, 0x0E848DBA, 0x25A9DE79, 0x3CB2EF38, 0x73F379FF, 0x6AE848BE, 0x41C51B7D,
            0x58DE2A3C, 0xF0794F05, 0xE9627E44, 0xC24F2D87, 0xDB541CC6, 0x94158A01, 0x8D0EBB40, 0xA623E883, 0xBF38D9C2,
            0x38A0C50D, 0x21BBF44C, 0x0A96A78F, 0x138D96CE, 0x5CCC0009, 0x45D73148, 0x6EFA628B, 0x77E153CA, 0xBABB5D54,
            0xA3A06C15, 0x888D3FD6, 0x91960E97, 0xDED79850, 0xC7CCA911, 0xECE1FAD2, 0xF5FACB93, 0x7262D75C, 0x6B79E61D,
            0x4054B5DE, 0x594F849F, 0x160E1258, 0x0F152319, 0x243870DA, 0x3D23419B, 0x65FD6BA7, 0x7CE65AE6, 0x57CB0925,
            0x4ED03864, 0x0191AEA3, 0x188A9FE2, 0x33A7CC21, 0x2ABCFD60, 0xAD24E1AF, 0xB43FD0EE, 0x9F12832D, 0x8609B26C,
            0xC94824AB, 0xD05315EA, 0xFB7E4629, 0xE2657768, 0x2F3F79F6, 0x362448B7, 0x1D091B74, 0x04122A35, 0x4B53BCF2,
            0x52488DB3, 0x7965DE70, 0x607EEF31, 0xE7E6F3FE, 0xFEFDC2BF, 0xD5D0917C, 0xCCCBA03D, 0x838A36FA, 0x9A9107BB,
            0xB1BC5478, 0xA8A76539, 0x3B83984B, 0x2298A90A, 0x09B5FAC9, 0x10AECB88, 0x5FEF5D4F, 0x46F46C0E, 0x6DD93FCD,
            0x74C20E8C, 0xF35A1243, 0xEA412302, 0xC16C70C1, 0xD8774180, 0x9736D747, 0x8E2DE606, 0xA500B5C5, 0xBC1B8484,
            0x71418A1A, 0x685ABB5B, 0x4377E898, 0x5A6CD9D9, 0x152D4F1E, 0x0C367E5F, 0x271B2D9C, 0x3E001CDD, 0xB9980012,
            0xA0833153, 0x8BAE6290, 0x92B553D1, 0xDDF4C516, 0xC4EFF457, 0xEFC2A794, 0xF6D996D5, 0xAE07BCE9, 0xB71C8DA8,
            0x9C31DE6B, 0x852AEF2A, 0xCA6B79ED, 0xD37048AC, 0xF85D1B6F, 0xE1462A2E, 0x66DE36E1, 0x7FC507A0, 0x54E85463,
            0x4DF36522, 0x02B2F3E5, 0x1BA9C2A4, 0x30849167, 0x299FA026, 0xE4C5AEB8, 0xFDDE9FF9, 0xD6F3CC3A, 0xCFE8FD7B,
            0x80A96BBC, 0x99B25AFD, 0xB29F093E, 0xAB84387F, 0x2C1C24B0, 0x350715F1, 0x1E2A4632, 0x07317773, 0x4870E1B4,
            0x516BD0F5, 0x7A468336, 0x635DB277, 0xCBFAD74E, 0xD2E1E60F, 0xF9CCB5CC, 0xE0D7848D, 0xAF96124A, 0xB68D230B,
            0x9DA070C8, 0x84BB4189, 0x03235D46, 0x1A386C07, 0x31153FC4, 0x280E0E85, 0x674F9842, 0x7E54A903, 0x5579FAC0,
            0x4C62CB81, 0x8138C51F, 0x9823F45E, 0xB30EA79D, 0xAA1596DC, 0xE554001B, 0xFC4F315A, 0xD7626299, 0xCE7953D8,
            0x49E14F17, 0x50FA7E56, 0x7BD72D95, 0x62CC1CD4, 0x2D8D8A13, 0x3496BB52, 0x1FBBE891, 0x06A0D9D0, 0x5E7EF3EC,
            0x4765C2AD, 0x6C48916E, 0x7553A02F, 0x3A1236E8, 0x230907A9, 0x0824546A, 0x113F652B, 0x96A779E4, 0x8FBC48A5,
            0xA4911B66, 0xBD8A2A27, 0xF2CBBCE0, 0xEBD08DA1, 0xC0FDDE62, 0xD9E6EF23, 0x14BCE1BD, 0x0DA7D0FC, 0x268A833F,
            0x3F91B27E, 0x70D024B9, 0x69CB15F8, 0x42E6463B, 0x5BFD777A, 0xDC656BB5, 0xC57E5AF4, 0xEE530937, 0xF7483876,
            0xB809AEB1, 0xA1129FF0, 0x8A3FCC33, 0x9324FD72
        ]);

        const crc_table_0f08dd0 = new Int32Array([
            0x00000000, 0x01C26A37, 0x0384D46E, 0x0246BE59, 0x0709A8DC, 0x06CBC2EB, 0x048D7CB2, 0x054F1685, 0x0E1351B8,
            0x0FD13B8F, 0x0D9785D6, 0x0C55EFE1, 0x091AF964, 0x08D89353, 0x0A9E2D0A, 0x0B5C473D, 0x1C26A370, 0x1DE4C947,
            0x1FA2771E, 0x1E601D29, 0x1B2F0BAC, 0x1AED619B, 0x18ABDFC2, 0x1969B5F5, 0x1235F2C8, 0x13F798FF, 0x11B126A6,
            0x10734C91, 0x153C5A14, 0x14FE3023, 0x16B88E7A, 0x177AE44D, 0x384D46E0, 0x398F2CD7, 0x3BC9928E, 0x3A0BF8B9,
            0x3F44EE3C, 0x3E86840B, 0x3CC03A52, 0x3D025065, 0x365E1758, 0x379C7D6F, 0x35DAC336, 0x3418A901, 0x3157BF84,
            0x3095D5B3, 0x32D36BEA, 0x331101DD, 0x246BE590, 0x25A98FA7, 0x27EF31FE, 0x262D5BC9, 0x23624D4C, 0x22A0277B,
            0x20E69922, 0x2124F315, 0x2A78B428, 0x2BBADE1F, 0x29FC6046, 0x283E0A71, 0x2D711CF4, 0x2CB376C3, 0x2EF5C89A,
            0x2F37A2AD, 0x709A8DC0, 0x7158E7F7, 0x731E59AE, 0x72DC3399, 0x7793251C, 0x76514F2B, 0x7417F172, 0x75D59B45,
            0x7E89DC78, 0x7F4BB64F, 0x7D0D0816, 0x7CCF6221, 0x798074A4, 0x78421E93, 0x7A04A0CA, 0x7BC6CAFD, 0x6CBC2EB0,
            0x6D7E4487, 0x6F38FADE, 0x6EFA90E9, 0x6BB5866C, 0x6A77EC5B, 0x68315202, 0x69F33835, 0x62AF7F08, 0x636D153F,
            0x612BAB66, 0x60E9C151, 0x65A6D7D4, 0x6464BDE3, 0x662203BA, 0x67E0698D, 0x48D7CB20, 0x4915A117, 0x4B531F4E,
            0x4A917579, 0x4FDE63FC, 0x4E1C09CB, 0x4C5AB792, 0x4D98DDA5, 0x46C49A98, 0x4706F0AF, 0x45404EF6, 0x448224C1,
            0x41CD3244, 0x400F5873, 0x4249E62A, 0x438B8C1D, 0x54F16850, 0x55330267, 0x5775BC3E, 0x56B7D609, 0x53F8C08C,
            0x523AAABB, 0x507C14E2, 0x51BE7ED5, 0x5AE239E8, 0x5B2053DF, 0x5966ED86, 0x58A487B1, 0x5DEB9134, 0x5C29FB03,
            0x5E6F455A, 0x5FAD2F6D, 0xE1351B80, 0xE0F771B7, 0xE2B1CFEE, 0xE373A5D9, 0xE63CB35C, 0xE7FED96B, 0xE5B86732,
            0xE47A0D05, 0xEF264A38, 0xEEE4200F, 0xECA29E56, 0xED60F461, 0xE82FE2E4, 0xE9ED88D3, 0xEBAB368A, 0xEA695CBD,
            0xFD13B8F0, 0xFCD1D2C7, 0xFE976C9E, 0xFF5506A9, 0xFA1A102C, 0xFBD87A1B, 0xF99EC442, 0xF85CAE75, 0xF300E948,
            0xF2C2837F, 0xF0843D26, 0xF1465711, 0xF4094194, 0xF5CB2BA3, 0xF78D95FA, 0xF64FFFCD, 0xD9785D60, 0xD8BA3757,
            0xDAFC890E, 0xDB3EE339, 0xDE71F5BC, 0xDFB39F8B, 0xDDF521D2, 0xDC374BE5, 0xD76B0CD8, 0xD6A966EF, 0xD4EFD8B6,
            0xD52DB281, 0xD062A404, 0xD1A0CE33, 0xD3E6706A, 0xD2241A5D, 0xC55EFE10, 0xC49C9427, 0xC6DA2A7E, 0xC7184049,
            0xC25756CC, 0xC3953CFB, 0xC1D382A2, 0xC011E895, 0xCB4DAFA8, 0xCA8FC59F, 0xC8C97BC6, 0xC90B11F1, 0xCC440774,
            0xCD866D43, 0xCFC0D31A, 0xCE02B92D, 0x91AF9640, 0x906DFC77, 0x922B422E, 0x93E92819, 0x96A63E9C, 0x976454AB,
            0x9522EAF2, 0x94E080C5, 0x9FBCC7F8, 0x9E7EADCF, 0x9C381396, 0x9DFA79A1, 0x98B56F24, 0x99770513, 0x9B31BB4A,
            0x9AF3D17D, 0x8D893530, 0x8C4B5F07, 0x8E0DE15E, 0x8FCF8B69, 0x8A809DEC, 0x8B42F7DB, 0x89044982, 0x88C623B5,
            0x839A6488, 0x82580EBF, 0x801EB0E6, 0x81DCDAD1, 0x8493CC54, 0x8551A663, 0x8717183A, 0x86D5720D, 0xA9E2D0A0,
            0xA820BA97, 0xAA6604CE, 0xABA46EF9, 0xAEEB787C, 0xAF29124B, 0xAD6FAC12, 0xACADC625, 0xA7F18118, 0xA633EB2F,
            0xA4755576, 0xA5B73F41, 0xA0F829C4, 0xA13A43F3, 0xA37CFDAA, 0xA2BE979D, 0xB5C473D0, 0xB40619E7, 0xB640A7BE,
            0xB782CD89, 0xB2CDDB0C, 0xB30FB13B, 0xB1490F62, 0xB08B6555, 0xBBD72268, 0xBA15485F, 0xB853F606, 0xB9919C31,
            0xBCDE8AB4, 0xBD1CE083, 0xBF5A5EDA, 0xBE9834ED
        ]);

        const crc_table_0f091d0 = new Int32Array([
            0x00000000, 0xB8BC6765, 0xAA09C88B, 0x12B5AFEE, 0x8F629757, 0x37DEF032, 0x256B5FDC, 0x9DD738B9, 0xC5B428EF,
            0x7D084F8A, 0x6FBDE064, 0xD7018701, 0x4AD6BFB8, 0xF26AD8DD, 0xE0DF7733, 0x58631056, 0x5019579F, 0xE8A530FA,
            0xFA109F14, 0x42ACF871, 0xDF7BC0C8, 0x67C7A7AD, 0x75720843, 0xCDCE6F26, 0x95AD7F70, 0x2D111815, 0x3FA4B7FB,
            0x8718D09E, 0x1ACFE827, 0xA2738F42, 0xB0C620AC, 0x087A47C9, 0xA032AF3E, 0x188EC85B, 0x0A3B67B5, 0xB28700D0,
            0x2F503869, 0x97EC5F0C, 0x8559F0E2, 0x3DE59787, 0x658687D1, 0xDD3AE0B4, 0xCF8F4F5A, 0x7733283F, 0xEAE41086,
            0x525877E3, 0x40EDD80D, 0xF851BF68, 0xF02BF8A1, 0x48979FC4, 0x5A22302A, 0xE29E574F, 0x7F496FF6, 0xC7F50893,
            0xD540A77D, 0x6DFCC018, 0x359FD04E, 0x8D23B72B, 0x9F9618C5, 0x272A7FA0, 0xBAFD4719, 0x0241207C, 0x10F48F92,
            0xA848E8F7, 0x9B14583D, 0x23A83F58, 0x311D90B6, 0x89A1F7D3, 0x1476CF6A, 0xACCAA80F, 0xBE7F07E1, 0x06C36084,
            0x5EA070D2, 0xE61C17B7, 0xF4A9B859, 0x4C15DF3C, 0xD1C2E785, 0x697E80E0, 0x7BCB2F0E, 0xC377486B, 0xCB0D0FA2,
            0x73B168C7, 0x6104C729, 0xD9B8A04C, 0x446F98F5, 0xFCD3FF90, 0xEE66507E, 0x56DA371B, 0x0EB9274D, 0xB6054028,
            0xA4B0EFC6, 0x1C0C88A3, 0x81DBB01A, 0x3967D77F, 0x2BD27891, 0x936E1FF4, 0x3B26F703, 0x839A9066, 0x912F3F88,
            0x299358ED, 0xB4446054, 0x0CF80731, 0x1E4DA8DF, 0xA6F1CFBA, 0xFE92DFEC, 0x462EB889, 0x549B1767, 0xEC277002,
            0x71F048BB, 0xC94C2FDE, 0xDBF98030, 0x6345E755, 0x6B3FA09C, 0xD383C7F9, 0xC1366817, 0x798A0F72, 0xE45D37CB,
            0x5CE150AE, 0x4E54FF40, 0xF6E89825, 0xAE8B8873, 0x1637EF16, 0x048240F8, 0xBC3E279D, 0x21E91F24, 0x99557841,
            0x8BE0D7AF, 0x335CB0CA, 0xED59B63B, 0x55E5D15E, 0x47507EB0, 0xFFEC19D5, 0x623B216C, 0xDA874609, 0xC832E9E7,
            0x708E8E82, 0x28ED9ED4, 0x9051F9B1, 0x82E4565F, 0x3A58313A, 0xA78F0983, 0x1F336EE6, 0x0D86C108, 0xB53AA66D,
            0xBD40E1A4, 0x05FC86C1, 0x1749292F, 0xAFF54E4A, 0x322276F3, 0x8A9E1196, 0x982BBE78, 0x2097D91D, 0x78F4C94B,
            0xC048AE2E, 0xD2FD01C0, 0x6A4166A5, 0xF7965E1C, 0x4F2A3979, 0x5D9F9697, 0xE523F1F2, 0x4D6B1905, 0xF5D77E60,
            0xE762D18E, 0x5FDEB6EB, 0xC2098E52, 0x7AB5E937, 0x680046D9, 0xD0BC21BC, 0x88DF31EA, 0x3063568F, 0x22D6F961,
            0x9A6A9E04, 0x07BDA6BD, 0xBF01C1D8, 0xADB46E36, 0x15080953, 0x1D724E9A, 0xA5CE29FF, 0xB77B8611, 0x0FC7E174,
            0x9210D9CD, 0x2AACBEA8, 0x38191146, 0x80A57623, 0xD8C66675, 0x607A0110, 0x72CFAEFE, 0xCA73C99B, 0x57A4F122,
            0xEF189647, 0xFDAD39A9, 0x45115ECC, 0x764DEE06, 0xCEF18963, 0xDC44268D, 0x64F841E8, 0xF92F7951, 0x41931E34,
            0x5326B1DA, 0xEB9AD6BF, 0xB3F9C6E9, 0x0B45A18C, 0x19F00E62, 0xA14C6907, 0x3C9B51BE, 0x842736DB, 0x96929935,
            0x2E2EFE50, 0x2654B999, 0x9EE8DEFC, 0x8C5D7112, 0x34E11677, 0xA9362ECE, 0x118A49AB, 0x033FE645, 0xBB838120,
            0xE3E09176, 0x5B5CF613, 0x49E959FD, 0xF1553E98, 0x6C820621, 0xD43E6144, 0xC68BCEAA, 0x7E37A9CF, 0xD67F4138,
            0x6EC3265D, 0x7C7689B3, 0xC4CAEED6, 0x591DD66F, 0xE1A1B10A, 0xF3141EE4, 0x4BA87981, 0x13CB69D7, 0xAB770EB2,
            0xB9C2A15C, 0x017EC639, 0x9CA9FE80, 0x241599E5, 0x36A0360B, 0x8E1C516E, 0x866616A7, 0x3EDA71C2, 0x2C6FDE2C,
            0x94D3B949, 0x090481F0, 0xB1B8E695, 0xA30D497B, 0x1BB12E1E, 0x43D23E48, 0xFB6E592D, 0xE9DBF6C3, 0x516791A6,
            0xCCB0A91F, 0x740CCE7A, 0x66B96194, 0xDE0506F1
        ]);

        function getInt32LE(array: Buffer | Uint8Array, offset: number) {
            const value =
                array[offset] |
                (array[offset + 1] << 8) |
                (array[offset + 2] << 16) |
                (array[offset + 3] << 24);
            return value;
        }

        var cbLength = pbBuffer.length;
        var dwCRC = -1;

        const cbRunningLength = ((cbLength < 4) ? 0 : (((cbLength) / 4) >>> 0) * 4);

        const cbEndUnalignedBytes = cbLength - cbRunningLength;

        var loc = 0;

        for (let i = 0; i < cbRunningLength / 4; ++i) {
            dwCRC ^= getInt32LE(pbBuffer, loc);

            loc = loc + 4;

            dwCRC = crc_table_0f091d0[dwCRC & 0x000000FF] ^
                crc_table_0f08dd0[(dwCRC >>> 8) & 0x000000FF] ^
                crc_table_0f089d0[(dwCRC >>> 16) & 0x000000FF] ^
                crc_table_0f085d0[(dwCRC >>> 24) & 0x000000FF];
        }

        for (let i = 0; i < cbEndUnalignedBytes; ++i) {
            dwCRC = crc_table_0f085d0[(dwCRC ^ pbBuffer[loc++]) & 0x000000FF] ^ (dwCRC >>> 8);
        }

        return dwCRC >>> 0;
    }

    /**
     * CRC-32/CD-ROM-EDC
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32CDROMEDC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC32CDROMEDC']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-32/CKSUM
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32CKSUM(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC32CKSUM']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CKSUM
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CKSUM(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CKSUM']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-32/POSIX
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32POSIX(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC32POSIX']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-32/ISCSI
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32ISCSI(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC32ISCSI']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-32/BASE91-C
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32BASE91C(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC32BASE91C']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-32/CASTAGNOLI
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32CASTAGNOLI(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC32CASTAGNOLI']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-32/INTERLAKEN
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32INTERLAKEN(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC32INTERLAKEN']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-32C
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32C(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC32C']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-32/NVME
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32NVME(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC32NVME']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-32/ISO-HDLC
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32ISOHDLC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC32ISOHDLC']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-32
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC32']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-32/ADCCP
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32ADCCP(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC32ADCCP']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-32/V-42
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32V42(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC32V42']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-32/XZ
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32XZ(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC32XZ']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * PKZIP
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static PKZIP(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['PKZIP']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-32/JAMCRC
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32JAMCRC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC32JAMCRC']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * JAMCRC
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static JAMCRC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['JAMCRC']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-32/MEF
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32MEF(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC32MEF']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-32/MPEG-2
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32MPEG2(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC32MPEG2']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-32/XFER
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static CRC32XFER(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['CRC32XFER']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * XFER
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number`
     */
    static XFER(data: Buffer | Uint8Array | string, offset?: number, length?: number): number {
        const crc = new CrcCalculator(
            CrcTypes['XFER']
        );
        return CRC.Compute(crc, data, offset, length) as number;
    }


    /**
     * CRC-40/GSM
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `bigint`
     */
    static CRC40GSM(data: Buffer | Uint8Array | string, offset?: number, length?: number): bigint {
        const crc = new CrcCalculator(
            CrcTypes['CRC40GSM']
        );
        return CRC.Compute(crc, data, offset, length) as bigint;
    }


    /**
     * CRC-64
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `bigint`
     */
    static CRC64(data: Buffer | Uint8Array | string, offset?: number, length?: number): bigint {
        const crc = new CrcCalculator(
            CrcTypes['CRC64']
        );
        return CRC.Compute(crc, data, offset, length) as bigint;
    }


    /**
     * CRC-64/ECMA-182
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `bigint`
     */
    static CRC64ECMA182(data: Buffer | Uint8Array | string, offset?: number, length?: number): bigint {
        const crc = new CrcCalculator(
            CrcTypes['CRC64ECMA182']
        );
        return CRC.Compute(crc, data, offset, length) as bigint;
    }


    /**
     * CRC-64/GO-ISO
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `bigint`
     */
    static CRC64GOISO(data: Buffer | Uint8Array | string, offset?: number, length?: number): bigint {
        const crc = new CrcCalculator(
            CrcTypes['CRC64GOISO']
        );
        return CRC.Compute(crc, data, offset, length) as bigint;
    }


    /**
     * CRC-64/MS
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `bigint`
     */
    static CRC64MS(data: Buffer | Uint8Array | string, offset?: number, length?: number): bigint {
        const crc = new CrcCalculator(
            CrcTypes['CRC64MS']
        );
        return CRC.Compute(crc, data, offset, length) as bigint;
    }


    /**
     * CRC-64/NVME
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `bigint`
     */
    static CRC64NVMEN(data: Buffer | Uint8Array | string, offset?: number, length?: number): bigint {
        const crc = new CrcCalculator(
            CrcTypes['CRC64NVMEN']
        );
        return CRC.Compute(crc, data, offset, length) as bigint;
    }


    /**
     * CRC-64/REDIS
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `bigint`
     */
    static CRC64REDIS(data: Buffer | Uint8Array | string, offset?: number, length?: number): bigint {
        const crc = new CrcCalculator(
            CrcTypes['CRC64REDIS']
        );
        return CRC.Compute(crc, data, offset, length) as bigint;
    }


    /**
     * CRC-64/WE
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `bigint`
     */
    static CRC64WE(data: Buffer | Uint8Array | string, offset?: number, length?: number): bigint {
        const crc = new CrcCalculator(
            CrcTypes['CRC64WE']
        );
        return CRC.Compute(crc, data, offset, length) as bigint;
    }


    /**
     * CRC-64/XZ
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `bigint`
     */
    static CRC64XZ(data: Buffer | Uint8Array | string, offset?: number, length?: number): bigint {
        const crc = new CrcCalculator(
            CrcTypes['CRC64XZ']
        );
        return CRC.Compute(crc, data, offset, length) as bigint;
    }


    /**
     * CRC-64/GO-ECMA
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `bigint`
     */
    static CRC64GOECMA(data: Buffer | Uint8Array | string, offset?: number, length?: number): bigint {
        const crc = new CrcCalculator(
            CrcTypes['CRC64GOECMA']
        );
        return CRC.Compute(crc, data, offset, length) as bigint;
    }


    /**
     * CRC-82/DARC
     * 
     * @param {Buffer|Uint8Array|string} data - source
     * @param {number?} offset - Offset to start in data
     * @param {number?} length - amount of data from the offset to read
     * @returns `number[]`
     */
    static CRC82DARC(data: Buffer | Uint8Array | string, offset?: number, length?: number): number[] {
        const crc = new CrcCalculator(
            CrcTypes['CRC82DARC']
        );
        return CRC.Compute(crc, data, offset, length) as number[];
    }

    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST(){
        return Object.keys(CrcTypes);
    };
};