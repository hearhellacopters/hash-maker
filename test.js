const {MERSENNETWISTER, MD5, randomBytes, RANDOMXORSHIFT, SHA1, SHA256, SHA224, SHA384, SHA512, CRC32, CRC3, CRC16} = require('./lib/cjs/index.js')
const mt = CRC16("123456789")
console.log(mt)