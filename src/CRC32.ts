interface Options {
    asBuffer:boolean,
    asArray:boolean,
    asHex:boolean,
    asNumber:boolean
}
/**
 * Cyclic Redundancy Check 32
 * @param {string|Uint8Array|Buffer} message - Message as string, Uint8Array or Buffer
 * @returns number
 */
export function CRC32(message:string|Uint8Array|Buffer, options?:Options):number|string|Uint8Array|Buffer{
    var bytes:any
    if(typeof message == "string"){
        bytes = stringToBytes(message)
    } else if(arraybuffcheck(message as Uint8Array|Buffer)){
        bytes = message
    } else {
        throw new Error("Message must be either String, Buffer or Uint8Array")
    }

    const divisor = 0xEDB88320;
    let crc = 0xFFFFFFFF;
    for (const byte of bytes) {
        crc = (crc ^ byte);
        for (let i = 0; i < 8; i++) {
            if (crc & 1) {
                crc = (crc >>> 1) ^ divisor;
            } else {
                crc = crc >>> 1;
            }
        }
    }
    crc = toUnsignedInt32(crc ^ 0xFFFFFFFF);
    if(options && options.asBuffer){
        const buff = Buffer.alloc(4)
        buff[0] = (crc >> 24) & 0xFF;
        buff[1] = (crc >> 16) & 0xFF;
        buff[2] = (crc >> 8) & 0xFF;
        buff[3] = crc & 0xFF;
        return buff
    } else
    if(options && options.asArray){
        const buff = new Uint8Array(4)
        buff[0] = (crc >> 24) & 0xFF;
        buff[1] = (crc >> 16) & 0xFF;
        buff[2] = (crc >> 8) & 0xFF;
        buff[3] = crc & 0xFF;
        return buff
    } else
    if(options && options.asHex){
        const buff = new Uint8Array(4)
        buff[0] = (crc >> 24) & 0xFF;
        buff[1] = (crc >> 16) & 0xFF;
        buff[2] = (crc >> 8) & 0xFF;
        buff[3] = crc & 0xFF;
        return bytesToHex(<unknown> buff as number[])
    }
    return crc
}

/**
 * Cyclic Redundancy Check 3
 * @param {string|Uint8Array|Buffer} message - Message as string, Uint8Array or Buffer
 * @returns number
 */
export function CRC3(message:string|Uint8Array|Buffer, options?:Options):number|string|Uint8Array|Buffer{
    var bytes:any
    if(typeof message == "string"){
        bytes = stringToBytes(message)
    } else if(arraybuffcheck(message as Uint8Array|Buffer)){
        bytes = message
    } else {
        throw new Error("Message must be either String, Buffer or Uint8Array")
    }

    const divisor = 0b111;
    let crc = 0b000;

    for (const byte of bytes) {
        let reminder = byte;
        for (let i = 0; i < 8; i++) {
            if (reminder & 1) {
                reminder = (reminder >>> 1) ^ divisor;
            } else {
                reminder = reminder >>> 1;
            }
        }

        // final division
        crc = crc ^ reminder;
    }
 
    if(options && options.asBuffer){
        const buff = Buffer.alloc(1)
        buff[0] = crc & 0xFF;
    } else
    if(options && options.asArray){
        const buff = new Uint8Array(1)
        buff[0] = crc & 0xFF;
        return buff
    } else
    if(options && options.asHex){
        const buff = new Uint8Array(1)
        buff[0] = crc & 0xFF;
        return bytesToHex(<unknown> buff as number[])
    }
    return crc;
}

/**
 * Cyclic Redundancy Check 16
 * @param {string|Uint8Array|Buffer} message - Message as string, Uint8Array or Buffer
 * @returns number
 */
export function CRC16(message:string|Uint8Array|Buffer, options?:Options):number|string|Uint8Array|Buffer{
    var bytes:any
    const crc_tab16 = new Uint16Array(256);
    if(typeof message == "string"){
        bytes = stringToBytes(message)
    } else if(arraybuffcheck(message as Uint8Array|Buffer)){
        bytes = message
    } else {
        throw new Error("Message must be either String, Buffer or Uint8Array")
    }

    var crc = new Uint16Array(1);
    const c = new Uint16Array(1);

    for (var i=0; i<256; i++) {

        crc[0] = 0;
        c[0]   = i;

        for (var j=0; j<8; j++) {

            if ( (crc[0] ^ c[0]) & 0x0001 ) crc[0] = ( crc[0] >> 1 ) ^ 0xA001;
            else                      crc[0] =   crc[0] >> 1;

            c[0] = c[0] >> 1;
        }

        crc_tab16[i] = crc[0];
    }

    var num_bytes = bytes.length;

	crc[0] = 0x0000;
	var ptr = 0;

	for (var a=0; a < num_bytes; a++) {
		crc[0] = (crc[0] >> 8) ^ crc_tab16[ (crc[0] ^ bytes[ptr]) & 0x00FF ];
        ptr++
	}
   
    if(options && options.asBuffer){
        const buff = Buffer.alloc(2)
        buff[0] = (crc[0] >> 8) & 0xFF;
        buff[1] = crc[0] & 0xFF;
    } else
    if(options && options.asArray){
        const buff = new Uint8Array(2)
        buff[0] = (crc[0] >> 8) & 0xFF;
        buff[1] = crc[0] & 0xFF;
        return buff
    } else
    if(options && options.asHex){
        const buff = new Uint8Array(2)
        buff[0] = (crc[0] >> 8) & 0xFF;
        buff[1] = crc[0] & 0xFF;
        return bytesToHex(<unknown> buff as number[])
    }
    return crc[0];
}

function bytesToHex(bytes:number[]):string {
    for (var hex:string[] = [], i = 0; i < bytes.length; i++) {
        hex.push((bytes[i] >>> 4).toString(16));
        hex.push((bytes[i] & 0xF).toString(16));
    }
    return hex.join("");
}

function toUnsignedInt32 (n: number): number {
    if (n >= 0) {
      return n;
    }
    return 0xFFFFFFFF - (n * -1) + 1;
}

function stringToBytes(str:string):number[] {
    for (var bytes:number[] = [], i = 0; i < str.length; i++){
        bytes.push(str.charCodeAt(i) & 0xFF);
    }
    return bytes;
}

function isBuffer(obj: Buffer|Uint8Array): boolean {
    return (typeof Buffer !== 'undefined' && obj instanceof Buffer);
}
  
function arraybuffcheck(obj:  Buffer|Uint8Array): boolean {
    return obj instanceof Uint8Array || isBuffer(obj);
}