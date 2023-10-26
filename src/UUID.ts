import {MERSENNETWISTER as mt} from './MERSENNETWISTER'

function getMachineHostname(): string {
    // Check if the code is running in a Node.js environment
    if (typeof process !== 'undefined' && process.release.name === 'node') {
      const os = require('os');
      return os.hostname();
    } else if (typeof window !== 'undefined') {
      // Check if the code is running in a browser
      return window.location.hostname;
    } else {
      // Handle other environments or defaults
      return 'Unknwn';
    }
}
function camp(number:number){
    if(number < 1){
        return 1
    } else
    if(number > 5){
        return 5
    } else 
    if (number == undefined){
        return 4
    } else {
        return number
    }
}

/**
 * Generates a UUID. 
 * @param {number} version - UUID version 1-5 (default 4)
 * @param {Uint8Array|Buffer} seed - If seeding is needed
 * @param {Uint8Array|Buffer} mac - if a mac ID can be supplied, else is generated 
 * @returns string
 */
export function generateUUID(version?:number, seed?:Uint8Array|Buffer, mac?:Uint8Array|Buffer):string {
    var buff = seed as Uint8Array
    if(seed && (seed instanceof Buffer || seed instanceof Uint8Array)){
        if(seed.length < 16){
            throw new Error("Seed array must be at least 16 bytes")
        } else {
            buff = seed as Uint8Array
        }
    } else {
        const random_mt = new mt();
        buff = new Uint8Array(16)
        for (let i = 0; i < 16; i++) {
            buff[i] = random_mt.random_int()
        }
    }
    if(mac != undefined){
        if(mac && !(mac instanceof Buffer || mac instanceof Uint8Array)){
            throw new Error("Mac array must Uint8Array or Buffer")
        }
        if(mac.length != 6){
            throw new Error("Mac array must be at least 6 bytes")
        }
    }
    var ver = version != undefined ? camp(version as number) : 4
    var output:string = "00000000-0000-0000-0000-000000000000";
    switch (ver) {
        case 1:
        case 2:
        case 3:
        case 5:
            var fakeMacBytes = new Uint8Array(6)
            if(mac != undefined){
                fakeMacBytes = mac
            } else {
                var fakeMac:string = getMachineHostname() || "1234"
                var string_add = "\0"
                if(fakeMac.length < 6){
                    for (let i = fakeMac.length; i < 6; i++) {
                        fakeMac += string_add;
                    }
                }
                var fakeMacBytes = new TextEncoder().encode(fakeMac.slice(0,6))
            }
            var uuidTemplate = `llllllll-mmmm-${ver}hhh-yxxx-zzzzzzzzzzzz`;
            var number = 0
            var numbernib = 0
            var macnumber = 0;
            var macnnib = 0;
            output = uuidTemplate.replace(/[lmhxyz]/g, function (c) {
                var r = buff[number] & 0xFF;
                var v = (r & 0x0F);
                switch (c) {
                    case "l":
                        if(numbernib == 0){
                            v = r >>> 4
                            numbernib+=1
                        } else {
                            v = r & 0xF
                            number+=1
                            numbernib = 0
                        } 
                        break;
                    case "m":
                        if(numbernib == 0){
                            v = r >>> 4
                            numbernib+=1
                        } else {
                            v = r & 0xF
                            number+=1
                            numbernib = 0
                        } 
                        break;
                    case "h":
                        if(numbernib == 0){
                            v = r >>> 4
                            numbernib+=1
                        } else {
                            v = r & 0xF
                            number+=1
                            numbernib = 0
                        } 
                        break;
                    case "x":
                        if(numbernib == 0){
                            v = r >>> 4
                            numbernib+=1
                        } else {
                            v = r & 0xF
                            number+=1
                            numbernib = 0
                        } 
                        break;
                    case "z":
                        r = fakeMacBytes[macnumber] & 0xff
                        if(macnnib == 0){
                            v = r >>> 4
                            macnnib+=1
                        } else {
                            v = r & 0xF
                            macnumber+=1
                            macnnib = 0
                        }                        
                        break;
                    case "y":
                        if(numbernib == 0){
                            v = ((r >>> 4) & 0x3 | 0x8)
                            numbernib+=1
                        } else {
                            v = ((r & 0xF) & 0x3 | 0x8)
                            number+=1
                            numbernib = 0
                        } 
                        break;
                    default:
                        if(numbernib == 0){
                            v = r >>> 4
                            numbernib+=1
                        } else {
                            v = r & 0xF
                            number+=1
                            numbernib = 0
                        } 
                        break;
                }
                return v.toString(16)
            });
            break;
        case 4:
            var number = 0
            var numbernib = 0
            var uuidTemplate = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx';
            output = uuidTemplate.replace(/[xy]/g, function (c) {
                var r = buff[number] & 0xFF;
                if(numbernib == 0){
                    r = r >>> 4
                    numbernib+=1
                } else {
                    r = r & 0xF
                    number+=1
                    numbernib = 0
                }
                const v = c === 'x' ? r  : (r & 0x3 | 0x8);
                return v.toString(16)
            });
            break;
        default:
            break;
    }
    return output
}