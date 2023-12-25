class RANDOMXORSHIFT {
    constructor(seed) {
        var s;
        const mt = [0, 0, 0, 0];
        if (seed == undefined) {
            seed = new Date().getTime();
        }
        if (typeof Buffer !== 'undefined' && seed instanceof Buffer) {
            if (seed.length < 4) {
                throw new Error("Must be a seed Buffer of 4 bytes");
            }
            mt[0] = seed.readUInt32LE() >>> 0;
        }
        else if (seed instanceof Uint8Array) {
            if (seed.length < 4) {
                throw new Error("Must be a seed Uint8Array of 4 bytes");
            }
            mt[0] = ((seed[3] << 24) | (seed[2] << 16) | (seed[1] << 8) | seed[0]);
        }
        else if (typeof seed == "number") {
            mt[0] = seed >>> 0;
        }
        for (var i = 1; i < 5; i++) {
            s = mt[i - 1] ^ (mt[i - 1] >>> 30);
            mt[i] =
                (((((s & 0xffff0000) >>> 16) * 1812433253) << 16) + (s & 0x0000ffff) * 1812433253) + (i - 1);
            mt[i] >>>= 0;
        }
        mt.shift();
        var result = new Uint8Array(16);
        mt.forEach((e, i) => {
            result[(i * 4)] = e & 0xFF;
            result[(i * 4) + 1] = (e >> 8) & 0xFF;
            result[(i * 4) + 2] = (e >> 16) & 0xFF;
            result[(i * 4) + 3] = (e >> 24) & 0xFF;
        });
        this.mt = result;
    }
    /**
     * Generate a random unsigned 32 bit integer
     * @returns number
     */
    random_int() {
        let v1 = ((this.mt[3] << 24) | (this.mt[2] << 16) | (this.mt[1] << 8) | this.mt[0]);
        let v4 = ((this.mt[15] << 24) | (this.mt[14] << 16) | (this.mt[13] << 8) | this.mt[12]);
        let comp_1 = (v4 ^ (v4 >>> 19) ^ v1 ^ (v1 << 11) ^ ((v1 ^ (v1 << 11)) >>> 8)) >>> 0;
        let new_value = new Uint8Array(4);
        new_value[0] = comp_1 & 0xFF;
        new_value[1] = (comp_1 >> 8) & 0xFF;
        new_value[2] = (comp_1 >> 16) & 0xFF;
        new_value[3] = (comp_1 >> 24) & 0xFF;
        const shift = this.mt.subarray(4, 16);
        var newBuffer = new Uint8Array([...shift, ...new_value]);
        this.mt = newBuffer;
        return comp_1;
    }
}
function getMachineHostname() {
    // Check if the code is running in a Node.js environment
    if (typeof process !== 'undefined' && process.release.name === 'node') {
        const os = require('os');
        return os.hostname();
    }
    else if (typeof window !== 'undefined') {
        // Check if the code is running in a browser
        return window.location.hostname;
    }
    else {
        // Handle other environments or defaults
        return 'Unknwn';
    }
}
function camp(number) {
    if (number < 1) {
        return 1;
    }
    else if (number > 5) {
        return 5;
    }
    else if (number == undefined) {
        return 4;
    }
    else {
        return number;
    }
}
function hexStringToUint8Array(hexString) {
    hexString = hexString.replace(/-/g, "");
    // Check if the hex string has an odd length, and pad it with a leading "0" if needed.
    if (hexString.length % 2 !== 0) {
        hexString = "0" + hexString;
    }
    // Create a Uint8Array of the correct length.
    const uint8Array = new Uint8Array(hexString.length / 2);
    // Parse the hex string and populate the Uint8Array.
    for (let i = 0; i < hexString.length; i += 2) {
        const byte = parseInt(hexString.substr(i, 2), 16);
        uint8Array[i / 2] = byte;
    }
    return uint8Array;
}
function hexStringToBuffer(hexString) {
    hexString = hexString.replace(/-/g, "");
    // Check if the hex string has an odd length, and pad it with a leading "0" if needed.
    if (hexString.length % 2 !== 0) {
        hexString = "0" + hexString;
    }
    // Create a Buffer of the correct length.
    const buffer = Buffer.alloc(hexString.length / 2);
    // Parse the hex string and populate the Uint8Array.
    for (let i = 0; i < hexString.length; i += 2) {
        const byte = parseInt(hexString.substr(i, 2), 16);
        buffer[i / 2] = byte;
    }
    return buffer;
}
/**
 * Generates a UUID as Uint8Array, Buffer or Hex string (default).
 *
 * @param {number} version - UUID version 1-5 (default 4)
 * @param {Options} options - Object with asBuffer, asArray or asHex as true (default is number). If seeding is needed, use ``{seed: seed}``.If a mac ID is needed., use ``{mac: mac}``. Must be UInt8Array or Buffer of 16 bytes.
 * @returns string
 */
export function UUID(version, options) {
    var buff;
    const seed = options && options.seed;
    const mac = options && options.mac;
    const asBuffer = options && options.asBuffer;
    const asArray = options && options.asArray;
    if (seed && (seed instanceof Buffer || seed instanceof Uint8Array)) {
        if (seed.length < 16) {
            throw new Error("Seed array must be at least 16 bytes");
        }
        else {
            buff = seed;
        }
    }
    else {
        const random_mt = new RANDOMXORSHIFT();
        buff = new Uint8Array(16);
        for (let i = 0; i < 16; i++) {
            buff[i] = random_mt.random_int();
        }
    }
    if (mac != undefined) {
        if (mac && !(mac instanceof Buffer || mac instanceof Uint8Array)) {
            throw new Error("Mac array must Uint8Array or Buffer");
        }
        if (mac.length != 6) {
            throw new Error("Mac array must be at least 6 bytes");
        }
    }
    var ver = version != undefined ? camp(version) : 4;
    var output = "00000000-0000-0000-0000-000000000000";
    switch (ver) {
        case 1:
        case 2:
        case 3:
        case 5:
            var fakeMacBytes = new Uint8Array(6);
            if (mac != undefined) {
                fakeMacBytes = mac;
            }
            else {
                var fakeMac = getMachineHostname() || "1234";
                var string_add = "\0";
                if (fakeMac.length < 6) {
                    for (let i = fakeMac.length; i < 6; i++) {
                        fakeMac += string_add;
                    }
                }
                var fakeMacBytes = new TextEncoder().encode(fakeMac.slice(0, 6));
            }
            var uuidTemplate = `llllllll-mmmm-${ver}hhh-yxxx-zzzzzzzzzzzz`;
            var number = 0;
            var numbernib = 0;
            var macnumber = 0;
            var macnnib = 0;
            output = uuidTemplate.replace(/[lmhxyz]/g, function (c) {
                var r = buff[number] & 0xFF;
                var v = (r & 0x0F);
                switch (c) {
                    case "l":
                        if (numbernib == 0) {
                            v = r >>> 4;
                            numbernib += 1;
                        }
                        else {
                            v = r & 0xF;
                            number += 1;
                            numbernib = 0;
                        }
                        break;
                    case "m":
                        if (numbernib == 0) {
                            v = r >>> 4;
                            numbernib += 1;
                        }
                        else {
                            v = r & 0xF;
                            number += 1;
                            numbernib = 0;
                        }
                        break;
                    case "h":
                        if (numbernib == 0) {
                            v = r >>> 4;
                            numbernib += 1;
                        }
                        else {
                            v = r & 0xF;
                            number += 1;
                            numbernib = 0;
                        }
                        break;
                    case "x":
                        if (numbernib == 0) {
                            v = r >>> 4;
                            numbernib += 1;
                        }
                        else {
                            v = r & 0xF;
                            number += 1;
                            numbernib = 0;
                        }
                        break;
                    case "z":
                        r = fakeMacBytes[macnumber] & 0xff;
                        if (macnnib == 0) {
                            v = r >>> 4;
                            macnnib += 1;
                        }
                        else {
                            v = r & 0xF;
                            macnumber += 1;
                            macnnib = 0;
                        }
                        break;
                    case "y":
                        if (numbernib == 0) {
                            v = ((r >>> 4) & 0x3 | 0x8);
                            numbernib += 1;
                        }
                        else {
                            v = ((r & 0xF) & 0x3 | 0x8);
                            number += 1;
                            numbernib = 0;
                        }
                        break;
                    default:
                        if (numbernib == 0) {
                            v = r >>> 4;
                            numbernib += 1;
                        }
                        else {
                            v = r & 0xF;
                            number += 1;
                            numbernib = 0;
                        }
                        break;
                }
                return v.toString(16);
            });
            break;
        case 4:
            var number = 0;
            var numbernib = 0;
            var uuidTemplate = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx';
            output = uuidTemplate.replace(/[xy]/g, function (c) {
                var r = buff[number] & 0xFF;
                if (numbernib == 0) {
                    r = r >>> 4;
                    numbernib += 1;
                }
                else {
                    r = r & 0xF;
                    number += 1;
                    numbernib = 0;
                }
                const v = c === 'x' ? r : (r & 0x3 | 0x8);
                return v.toString(16);
            });
            break;
        default:
            break;
    }
    if (asBuffer) {
        return hexStringToBuffer(output);
    }
    if (asArray) {
        return hexStringToUint8Array(output);
    }
    return output;
}
//# sourceMappingURL=UUID.js.map