# hash-maker

A collection of checksums, hashes and RNG for Node or Browser in pure JS.

**Note:** *v2.0 has breaking changes with the additional hashes. Please review the new API structure and arguments before upgrading.*

[Checksum](#checksum)
- [General Purpose Hash](#general-purpose-hash) Collection of general by-the-byte checksums hashes.
- [Math](#math) - Creates a Xor or Sum checksum of a message.
- [CRC](#crc) - Creates a CRC checksum of a message.
- [Adler](#adler) - Creates a Adler32 checksum of a message.
- [BSD](#bsd) - Creates a Berkeley Software Distribution checksum of a message.
- [Fletcher](#fletcher) - Creates a Fletcher 16 - 32 checksum of a message.
- [LCR](#lcr) - Creates a LCR checksum of a message.
- [BCC](#bcc) - Creates a BCC (Unix) checksum of a message.
- [SYSV](#sysv) - Creates a SYSV (Unix) checksum of a message.
- [SFH](#super-fast-hash) - Creates a Super Fast Hash checksum of a message.
- [BuzHash](#buzhash) - Creates a BuzHash checksum of a message.

[Hashes](#hashes)
- [SHA](#sha) - Creates a SHA0 - SHA3 hash of a message.
- [Keccak](#keccak) - Creates a Keccak hash of a message.
- [KMAC](#kmac) - Creates a KMAC keyed hash of a message.
- [SHAKE](#shake) - Creates a SHAKE hash of a message.
- [cSHAKE](#cshake) - Creates a cSHAKE hash of a message.
- [MD](#md) - Creates a MD2 - MD6 hash of a message.
- [BLAKE](#blake) - Creates a BLAKE - BLAKE3 hash of a message.
- [RIPEMD](#ripemd) - Creates a RipeMD hash of a message.
- [SM3](#sm3) - Creates a SM3 hash of a message.
- [Whirlpool](#whirlpool) - Creates a Whirlpool 0 - T hash of a message.
- [Snefru](#snefru) - Creates a Snefru 128 / 256 hash of a message.
- [Tiger](#tiger) - Creates a Tiger 128 - 192 hash of a message.
- [BMW](#bmw) - Creates a Blue Midnight Wish (BMW) hash of the message.
- [FNV](#fnv) - Creates a Fowler/Noll/Vo FNV hash of the message.
- [HAS160](#has160) - Creates a HAS-160 hash of a message.
- [Pearson](#pearson) - Creates a Pearson hash of a message.
- [Jenkins](#jenkins) - Creates a One At A Time, Lookup2, Lookup3 and Spooky hash of a message.
- [CubeHash](#cubehash) - Creates a Cube Hash of the message.
- [PANAMA](#panama) - Creates a PANAMA hash of the message.
- [ECHO](#echo) - Creates a ECHO224 - 512 hash of the message.
- [Fugue](#fugue) - Creates a Fugue224 - 512 hash of the message.
- [Groestl](#groestl) - Creates a Grøstl224 - 512 hash of the message.
- [Hamsi](#hamsi) - Creates a Hamsi224 - 512 hash of the message.
- [HAVAL](#haval) - Creates a HAVEL128 - 256 hash of the message.
- [JH](#jh) - Creates a Hongjun Wu's JH hash of the message.
- [RadioGatún](#radiogatún) - Creates a RadioGatún32/64 hash of the message.
- [LUFFA](#luffa) - Creates a LUFFA224 - 512 hash of the message.
- [SHABAL](#shabal) - Creates a SHABAL192 - 512 hash of the message.
- [SHAvite](#shavite) - Creates a SHAvite224 - 512 hash of the message.
- [Skein](#skein) - Creates a Skein224 - 512 hash of the message.
- [SIMD](#simd) - creates a SIP32 - 128 hash of the message.
- [SIP](#sip) - Creates a SIP32 - 128 hash of the message.
- [Highway](#highway) - Creates a Highway64 - 256 hash of the message.
- [LSH](#lsh) - Creates a Locality-Sensitive Hashing (LSH) 256 - 512 hash of the message.
- [Murmur](#murmur) - Creates a Murmur 1 - 3 hash of the message.
- [Argon2](#argon2) - Creates a Argon2d/i/id/u hash of the message.

[RNG](#rng)
- [Mersenne Twister](#mersenne-twister) - Random number generator that can be seaded. Create 32 bit signed, unsigned or float values.
- [Random Xor Shift](#random-xor-shift) - Random number generator that can be seaded. Creates unsigned 32 bit values.
- [Random Bytes](#random-bytes) - Random bytes of a supplied length (based on Mersenne Twister)
- [UUID](#uuid) - Create UUIDs verisons 1 - 5.

## Installation

```npm install hash-maker```

Provides both CommonJS and ES modules.

# Checksum

Functions that generally return a `number` or `bigint` value of a small fixed bit length. Not used for cryptographic means.

## General Purpose Hash

General Purpose Hashes (GPH) that are largely by-the-byte checksums type hashes.

Can be imported as:

```javascript
const { GPH } = require('hash-maker'); // common
// or
import { GPH } from 'hash-maker'; // esm
/*---*/
console.log(GPH.FUNCTION_LIST): // get the full list
const hash = GPH.RSHash("123456789");
```

| Functions                | Params                               |
| :---                     | :---                                 |
| RSHash(message)          | Robert Sedgwicks hash. Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Will return as `number`. **Note: Can't be seeded,**|
| JSHash(message)          | Justin Sobel hash. Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Will return as `number`. **Note: Can't be seeded**|
| PJWHash(message, seed?)  | Peter J. Weinberger hash. Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Will return as `number`. |
| ELFHash(message, seed?)  | Executable and Linkable Format (ELF file format) hash. Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Will return as `number`.|
| BKDRHash(message, seed?) | Brian Kernighan and Dennis Ritchie hash. Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Will return as `number`.|
| SDBMHash(message, seed?) | Simple Database Management hash. Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Will return as `number`.|
| DJBHash(message, seed?)  | Daniel J. Bernstein hash. Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Will return as `number`.| 
| DEKHash(message)         | Donald E. Knuth hash. Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Will return as `number`. **Note: Can't be seeded**|
| BPHash(message, seed?)   | Benjamin Pritchard hash. Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Will return as `number`.|
| APHash(message, seed?)   | Anchor-based Probability hash. Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Will return as `number`. |
| DJB2Hash(message)        | Daniel J. Bernstein 2 hash. Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Will return as `number`. **Note: Can't be seeded**|
| FNVHash(message, seed?)   | Fowler/Noll/Vo (basic) hash. Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Will return as `number`.|
| Fast32Hash(message, seed?)   | Zilong Tan Fast Hash. Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Will return as `number`.|
| Fast64Hash(message, seed?)   | Zilong Tan Fast Hash. Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Will return as `bigint`.|

## Math

Xor8 - 32 or Sum 8 - 32 bit checksum function class. Returns as `number`.

Can be imported as:

```javascript
const { MATH } = require('hash-maker');  // common
// or
import { MATH } from 'hash-maker'; // esm
/*---*/
console.log(MATH.FUNCTION_LIST): // get the full list
const hash = MATH.SUM8("123456789");
```

| Functions                | Params                               |
| :---                     | :---                                 |
| SUM#(message) | Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Will return as `number`.|
| XOR#(message) | Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Will return as `number`.|

## CRC

CRC hash function class. A full list of all CRC hashes can be found in `CRC.FUNCTION_LIST` (currently 187 different hashes). CRC functions are returned as `number`, `bigint`, or `Uint8Array` depending on the bit size. `number` for under 32, `bigint` up to 64 then `Uint8Array` after that. Can create your own with the `CRC.CrcCalculator` class or use `CRC.CRC` for a wrapped function.

Can be imported as:

```javascript
const { CRC } = require('hash-maker'); // esm
// or
import { CRC } from 'hash-maker'; // common
/*---*/
console.log(CRC.FUNCTION_LIST): // get the full list
const hash = CRC.CRC32("123456789");
```

| Functions                | Params                               |
| :---                     | :---                                 |
| CRC##(message, offset? length?) | Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Will return a `number` for less than 32 bit hashes, a `bigint` for values up to 64 bit and a `Uint8Array` for anything over 64 bit.<br>Can set an offset and length of the source message.|

## Adler

Adler32 hash function class. Returns as `number`.

Can be imported as:

```javascript
const { ALDER } = require('hash-maker'); // common
// or
import { ALDER } from 'hash-maker'; // esm
/*---*/
const hash = ALDER.ALDER32("123456789");
```
| Functions                | Params                               |
| :---                     | :---                                 |
| ALDER32(message, seed?)  | Message to be hashed as `string`, `Uint8Array` or `Buffer`. Starting seed value. <br>Will return an 32 bit `number`. |

## BSD

Berkeley Software Distribution (BSD) 16 bit hash function class. Returns as `number`.

Can be imported as:

```javascript
const { BSD } = require('hash-maker'); // common
// or
import { BSD } from 'hash-maker'; // esm
/*---*/
const hash = BSD.BSD("123456789");
```

| Functions                | Params                               |
| :---                     | :---                                 |
| BSD(message, seed?)      | Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Starting seed value. <br>Will return an 16 bit `number`. |

## Fletcher

Fletcher hash function class. Returns as unsigned 8 bit `number`.

Can be imported as:

```javascript
const { FLETCHER } = require('hash-maker'); // common
// or
import { FLETCHER } from 'hash-maker'; // esm
/*---*/
console.log(FLETCHER.FUNCTION_LIST): // get the full list
const hash = FLETCHER.FLETCHER32("123456789");
```

| Functions                          | Params                               |
| :---                               | :---                                 |
| FLETCHER##(message, seed1? seed2?) | Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Any seed values. <br>Will return as a `number`|

## LCR

Longitudinal Redundancy Checksum function class. Returns as unsigned 8 bit `number`.

Can be imported as:

```javascript
const { LCR } = require('hash-maker'); // common
// or
import { LCR } from 'hash-maker'; // esm
/*---*/
const hash = LCR.LCR("123456789");
```

| Functions                          | Params                               |
| :---                               | :---                                 |
|LCR(message, seed?) | Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Starting seed value. <br>Will return an 8 bit `number`.|

## BCC

Block Check Character (Unix) function class. Returns as unsigned 8 bit `number`.

Can be imported as:

```javascript
const { BCC } = require('hash-maker'); // common
// or
import { BCC } from 'hash-maker'; // esm
/*---*/
const hash = BCC.BCC("123456789");
```

| Functions                          | Params                               |
| :---                               | :---                                 |
| BCC(message, seed?) | Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Starting seed value.<br>Will return an 8 bit `number`.|

## SYSV

System V (SYSV) 16 bit hash function class. Returns as `number`.

Can be imported as:

```javascript
const { SYSV } = require('hash-maker'); // common
// or
import { SYSV } from 'hash-maker'; // esm
/*---*/
const hash = SYSV.SYSV("123456789");
```

| Functions                          | Params                               |
| :---                               | :---                                 |
|SYSV(message, seed?) |Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Starting seed value.<br>Will return an 16 bit `number`.|

## Super Fast Hash

Super Fast Hash (SFH) function class. Returns as unsigned 32 bit `number`. Can create your own with the `SFH.SuperFastHash` class.

Can be imported as:

```javascript
const { SFH } = require('hash-maker'); // common
// or
import { SFH } from 'hash-maker'; // esm
/*---*/
const hash = SFH.SFH("123456789");
```

| Functions                          | Params                               |
| :---                               | :---                                 |
|SFH(message) | Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br>Will return an 32 bit `number`.|

## BuzHash

BuzHash function class. Returns as unsigned 32 bit `number`. Can create your own with the `BUZHASH.BuzHash` class.

Can be imported as:

```javascript
const { BUZHASH } = require('hash-maker'); // common
// or
import { BUZHASH } from 'hash-maker'; // esm
/*---*/
const hash = BUZHASH.BUZHASH("123456789");
```

| Functions                          | Params                               |
| :---                               | :---                                 |
|BUZHASH(message, seed?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Starting seed value. <br>Will return an 32 bit `number`. |

# Hashes

Functions that generally return data longer than 32 bits as byte arrays. Can be used for cryptography in some cases.

**Note: The default return `format` will be wil be based on the system you are running when `undefined`. For Node, it will return a `Buffer` as the `"buffer"` option would. For Browsers, it will return a `Uint8Array` as the `"array"` option would.**

## SHA

Secure Hash Algorithm (SHA) hashes. Over 150 different types. A full list of all SHA hashes can be found in `SHA.FUNCTION_LIST`. All SHA functions can be returned as a hex `string`, `Uint8Array` or `Buffer`. Includes keyed `_HMAC` variants as well.

Can be imported as:

```javascript
const { SHA } = require('hash-maker'); // common
// or
import { SHA } from 'hash-maker'; // esm
/*---*/
console.log(SHA.FUNCTION_LIST); // get the full list
const hash = SHA.SHA256("123456789","buffer");
```

| Functions                          | Params                               |
| :---                               | :---                                 |
|SHA###(message, format?) | Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br>Return format type as: `"hex"`, `"array"` or `"buffer"`.| 
|SHA###_HMAC(message, key, format?) | Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br>The hash key as `string`, `Uint8Array` or `Buffer`. <br>Return format type as: `"hex"`, `"array"` or `"buffer"`| 


## Keccak

Keccak hash function class. Can be returned as a hex `string`, `Uint8Array`, or `Buffer`. Includes keyed `_HMAC` variants as well.

Can be imported as:

```javascript
const { KECCAK } = require('hash-maker'); // common
// or
import { KECCAK } from 'hash-maker'; // esm
/*---*/
console.log(KECCAK.FUNCTION_LIST): // gives you the full list
const hash = KECCAK.KECCAK512("123456789", "buffer");
```

| Functions                          | Params                               |
| :---                               | :---                                 |
|KECCAK###(message, format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`.|
|KECCAK###_HMAC(message, key, format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br>Message key as a `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`|

## KMAC

Keccak Message Authentication Code (KMAC) hash function class. Can be returned as a hex `string`, `Uint8Array`, or `Buffer`.

Can be imported as:

```javascript
const { KMAC } = require('hash-maker'); // common
// or 
import { KMAC } from 'hash-maker'; // esm
/*---*/
console.log(KMAC.FUNCTION_LIST): // gives you the full list
const hash = KMAC.KMAC256("123456789", "key", 256, "buffer", "secret");
```

| Functions                          | Params                               |
| :---                               | :---                                 |
|KMAC###(message, key, outputBits, format? secret?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`. <br>Message key as a `string`, `Uint8Array` or `Buffer`. <br>Hash output bit size (default `256` bits or 32 bytes).<br>Return format type as: `"hex"`, `"array"` or `"buffer"`<br>Message secret as a `string`, `Uint8Array` or `Buffer`.|

## SHAKE

Secure Hash Algorithm (SHAKE) hash function class. Can be returned as a hex `string`, `Uint8Array`, or `Buffer`. You can create your own with `SHAKE.SHAKE` wrapped function.

Can be imported as:

```javascript
const { SHAKE } = require('hash-maker'); // common
// or 
import { SHAKE } from 'hash-maker'; // esm
/*---*/
console.log(SHAKE.FUNCTION_LIST): // gives you the full list
const hash = SHAKE.SHAKE256("123456789", 256, "buffer");
```

| Functions                          | Params                               |
| :---                               | :---                                 |
|SHAKE###(message, outputBits, format?)| Message to be hashed as a `string`, `Uint8Array` or `Buffer`. <br>Hash output bit size (default `256` or 32 bytes). <br>Return format type as: `"hex"`, `"array"` or `"buffer"`|

## cSHAKE

Customizable Secure Hash Algorithm (cSHAKE) hash function class. Can be returned as a hex `string`, `Uint8Array`, or `Buffer`.

Can be imported as:

```javascript
const { cSHAKE128 } = require('hash-maker'); // common
// or
import { cSHAKE128 } from 'hash-maker'; // esm
/*---*/
console.log(cSHAKE128.FUNCTION_LIST): // gives you the full list
const hash = cSHAKE128.cSHAKE256("123456789", 256, "buffer", "Bob", "password");
```

| Functions                          | Params                               |
| :---                               | :---                                 |
|cSHAKE###(message, outputBits, format?, name?, secret?) | Message to be hashed as a `string`, `Uint8Array` or `Buffer`. <br>Hash output bit size (default `256` or 32 bytes). <br>Return format type as: `"hex"`, `"array"` or `"buffer"`,<br> Message name as a `string`, `Uint8Array` or `Buffer`.<br> Message password as a `string`, `Uint8Array` or `Buffer`.|

## MD

Message Digest (MD) hash function class version 2 - 6. A full list of all MD hashes can be found in `MD.FUNCTION_LIST`. Can be returned as a hex `string`, `Uint8Array`, or `Buffer`. Includes keyed `_HMAC` variants as well.

Can be imported as:

```javascript
const { MD } = require('hash-maker'); // common
// or 
import { MD } from 'hash-maker'; // esm
/*---*/
console.log(MD.FUNCTION_LIST); // get the full list
const hash = MD.MD4("123456789","buffer")
```

| Functions                          | Params                               |
| :---                               | :---                                 |
|MD#(message, format?) |Message to be hashed as a `string`, `Uint8Array` or `Buffer`. <br>Return format type as: `"hex"`, `"array"` or `"buffer"`|
|MD#_HMAC(message, key, format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br>Message key as a `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`|

## BLAKE

BLAKE hash function class. Can be returned as a hex `string`, `Uint8Array`, or `Buffer`. Can create your own BLAKE3 with `BLAKE.Blake3` class. Includes keyed `_HMAC` variants as well.

Can be imported as:

```javascript
const { BLAKE } = require('hash-maker'); // common
// or
import { BLAKE } from 'hash-maker'; // esm
/*---*/
console.log(BLAKE.FUNCTION_LIST): // gives you the full list
const hash = BLAKE.BLAKE2b("123456789");
```

| Functions                          | Params                               |
| :---                               | :---                                 |
|BLAKE###(message, format?) | Message to be hashed as a `string`, `Uint8Array` or `Buffer`. <br>Return format type as: `"hex"`, `"array"` or `"buffer"`|
|BLAKE###_HMAC(message, key, format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br>Message key as a `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`|
|BLAKE2b###(message, format?, key?, salt?, personal?)| Message to be hashed as a `string`, `Uint8Array` or `Buffer`. <br>Return format type as: `"hex"`, `"array"` or `"buffer"`<br>Message key as a `string`, `Uint8Array` or `Buffer`. <br> Message salt as a `string`, `Uint8Array` or `Buffer`.<br> Message personal as a `string`, `Uint8Array` or `Buffer`.|
|BLAKE2b###_HMAC(message, format?, key?, salt?, personal?)| Message to be hashed as a `string`, `Uint8Array` or `Buffer`. <br>Return format type as: `"hex"`, `"array"` or `"buffer"`<br>Message key as a `string`, `Uint8Array` or `Buffer`. <br> Message salt as a `string`, `Uint8Array` or `Buffer`.<br> Message personal as a `string`, `Uint8Array` or `Buffer`.|
|BLAKE2s###(message, format?)| Message to be hashed as a `string`, `Uint8Array` or `Buffer`. <br>Return format type as: `"hex"`, `"array"` or `"buffer"`|
|BLAKE2s###_HMAC(message, key, format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br>Message key as a `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`|
|BLAKE3(message, format?, outLen?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`<br> Length in bytes of returned hash (default `32` bytes) |
|BLAKE3_HMAC(message, key, format?, outLen?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br>Message key as a `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`<br> Length in bytes of returned hash (default `32` bytes) |
|BLAKE3_DeriveKey(message, key?, format?, outLen?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br>Message key as a `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`<br> Length in bytes of returned hash (default `32` bytes) |

## RIPEMD

RACE Integrity Primitives Evaluation Message Digest (RIPEMD) hash function class. Can be returned as a hex `string`, `Uint8Array`, or `Buffer`. Includes keyed `_HMAC` variants as well. Can create your own with `RIPEMD.Ripemd` class or use `RIPEMD.RIPEMD` or `RIPEMD.RIPEMD_HMAC` for a wrapped functions.

Can be imported as:

```javascript
const { RIPEMD } = require('hash-maker'); // common
// or
import { RIPEMD } from 'hash-maker'; // esm
/*---*/
console.log(RIPEMD.FUNCTION_LIST): // gives you the full list
const hash = RIPEMD.RIPEMD160("123456789", "buffer");
```

| Functions                          | Params                               |
| :---                               | :---                                 |
|RIPEMD###(message, format?) | Message to be hashed as a `string`, `Uint8Array` or `Buffer`. <br>Return format type as: `"hex"`, `"array"` or `"buffer"`|
|RIPEMD###_HMAC(message, key, format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br>Message key as a `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"` |

## SM3

ShangMi 3 (SM3) hash function class. Can be returned as a hex `string`, `Uint8Array`, or `Buffer`. Includes keyed `_HMAC` variants as well. Can create your own with the `SM3.Sm3` class or use `SM3.SM3_HMAC` for a wrapped function.

Can be imported as:

```javascript
const { SM3 } = require('hash-maker'); // common
// or
import { SM3 } from 'hash-maker'; // esm
/*---*/
console.log(SM3.FUNCTION_LIST): // gives you the full list
const hash = SM3.SM3("123456789", "buffer");
```

| Functions                          | Params                               |
| :---                               | :---                                 |
|SM3(message, format?, rounds?) | Message to be hashed as a `string`, `Uint8Array` or `Buffer`. <br>Return format type as: `"hex"`, `"array"` or `"buffer"`<br> Rounds of hashing (default `64`)|
|SM3_HMAC(message, key, format?, rounds?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br>Message key as a `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"` <br> Rounds of hashing (default `64`)|

## Whirlpool

Whirlpool hash function class. Can be returned as a hex `string`, `Uint8Array`, or `Buffer`. Includes keyed `_HMAC` variants as well. Can create your own with the `WHIRLPOOL.Whirlpool` class or use `WHIRLPOOL.WHIRLPOOL_HMAC` for a wrapped function.

Can be imported as:

```javascript
const { WHIRLPOOL } = require('hash-maker'); // common
// or
import { WHIRLPOOL } from 'hash-maker'; // esm
/*---*/
console.log(WHIRLPOOL.FUNCTION_LIST): // gives you the full list
const hash = WHIRLPOOL.WHIRLPOOL0("123456789", "buffer");
```

| Functions                          | Params                               |
| :---                               | :---                                 |
|WHIRLPOOL#(message, format?)| Message to be hashed as a `string`, `Uint8Array` or `Buffer`. <br>Return format type as: `"hex"`, `"array"` or `"buffer"`|
|WHIRLPOOL#_HMAC(message, key, format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br>Message key as a `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`|


## Snefru

Snefru hash function class. Can be returned as a hex `string`, `Uint8Array`, or `Buffer`. Can create your own with the `SNEFRU.Snefru` class.

Can be imported as:

```javascript
const { SNEFRU } = require('hash-maker'); // common
// or
import { SNEFRU } from 'hash-maker'; // esm
/*---*/
console.log(SNEFRU.FUNCTION_LIST): // gives you the full list
const hash = SNEFRU.SNEFRU("123456789", "buffer");
```
| Functions                          | Params                               |
| :---                               | :---                                 |
|SNEFRU###_#(message, format?)| Message to be hashed as a `string`, `Uint8Array` or `Buffer`. <br>Return format type as: `"hex"`, `"array"` or `"buffer"`|

## Tiger

Tiger hash function class. Can be returned as a hex `string`, `Uint8Array`, or `Buffer`. Includes keyed `_HMAC` variants as well. Can create your own with the `TIGER.Tiger` or use `TIGER.TIGER` or `TIGER.TIGER2` for a wrapped function.

Can be imported as:

```javascript
const { TIGER } = require('hash-maker'); // common
// or
import { TIGER } from 'hash-maker'; // esm
/*---*/
console.log(TIGER.FUNCTION_LIST): // gives you the full list
const hash = TIGER.TIGER128("123456789", "buffer");
```

| Functions                          | Params                               |
| :---                               | :---                                 |
|TIGER###(message, format?)| Message to be hashed as a `string`, `Uint8Array` or `Buffer`. <br>Return format type as: `"hex"`, `"array"` or `"buffer"`|
|TIGER###_HMAC(message, key, format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br>Message key as a `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`|

## BMW

Blue Midnight Wish (BMW) hash function class. Can be returned as a hex `string`, `Uint8Array`, or `Buffer`. Includes keyed `_HMAC` variants as well. Can create your own with the `BMW.Bmw` class or use `BMW.BMW`, `BMW.BMW_HMAC` for a wrapped function.

Can be imported as:

```javascript
const { BMW } = require('hash-maker'); // common
// or
import { BMW } from 'hash-maker'; // esm
/*---*/
console.log(BMW.FUNCTION_LIST): // gives you the full list
const hash = BMW.BMW256("123456789", "buffer");
```

| Functions                          | Params                               |
| :---                               | :---                                 |
|BMW###(message, format?)| Message to be hashed as a `string`, `Uint8Array` or `Buffer`. <br>Return format type as: `"hex"`, `"array"` or `"buffer"`|
|BMW###(message, key, format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br>Message key as a `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`|

## FNV

Fowler/Noll/Vo (FNV) hash function class between of 32 - 1024 bits. Can be returned as a hex `string`, `Uint8Array`, or `Buffer`. Includes keyed `_HMAC` variants as well. Can create your own with the `FNV.Fnv` class or use `FNV.FNV` or `FNV.FNV_HMAC` for a wrapped functions.

Can be imported as:

```javascript
const { FNV } = require('hash-maker'); // common
// or
import { FNV } from 'hash-maker'; // esm
/*---*/
console.log(FNV.FUNCTION_LIST): // gives you the full list
const hash = FNV.FNV1A_64("123456789", "buffer");
```

| Functions                          | Params                               |
| :---                               | :---                                 |
|FNV###(message, format?)| Message to be hashed as a `string`, `Uint8Array` or `Buffer`. <br>Return format type as: `"hex"`, `"array"` or `"buffer"`|
|FNV###_HMAC(message, key, format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br>Message key as a `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`|

## HAS160

Hash Algorithm Standard 160 (HAS-160) hash function class. Can be returned as a hex `string`, `Uint8Array`, or `Buffer`. Includes keyed `_HMAC` variants as well. Can create your own with the `HAS160.Has160` class.

Can be imported as:

```javascript
const { HAS160 } = require('hash-maker'); // common
// or
import { HAS160 } from 'hash-maker'; // esm
/*---*/
console.log(HAS160.FUNCTION_LIST): // gives you the full list
const hash = HAS160.HAS160("123456789", "buffer");
```

| Functions                          | Params                               |
| :---                               | :---                                 |
|HAS160(message, format?) | Message to be hashed as a `string`, `Uint8Array` or `Buffer`. <br>Return format type as: `"hex"`, `"array"` or `"buffer"`|
|HAS160_HMAC(message, key, format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br>Message key as a `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`|

## Pearson

Pearson hash function class. Can be returned as a hex `string`, `Uint8Array`, or `Buffer`. Includes keyed `_HMAC` variants as well. Can create your own with the `PEARSON.Pearson` class or the `PEARSON.PEARSON` or `PEARSON.PEARSON_HMAC` for a wrapped functions.

Can be imported as:

```javascript
const { PEARSON } = require('hash-maker'); // common
// or 
import { PEARSON } from 'hash-maker'; // esm
/*---*/
console.log(PEARSON.FUNCTION_LIST): // gives you the full list
const hash = PEARSON.PEARSON32("123456789", "buffer");
```

| Functions                          | Params                               |
| :---                               | :---                                 |
|PEARSON###(message, format?)| Message to be hashed as a `string`, `Uint8Array` or `Buffer`. <br>Return format type as: `"hex"`, `"array"` or `"buffer"`|
|PEARSON###_HMAC(message, key, format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br>Message key as a `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`|

## Jenkins

Bob Jenkin's hash function class for One At A Time, Lookup2, Lookup3 and Spooky hashes. Hshes shorter than 32 bits are return as `number` and 64 bit return as `bigint`. Others can be returned as a hex `string`, `Uint8Array`, or `Buffer`.

Can be imported as:

```javascript
const { JENKINS } = require('hash-maker'); // common
// or 
import { JENKINS } from 'hash-maker'; // esm
/*---*/
console.log(JENKINS.FUNCTION_LIST): // gives you the full list
const hash = JENKINS.ONEATATIME("123456789");
```

| Functions                          | Params                               |
| :---                               | :---                                 |
|ONEATATIME(message?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Returns as unsigned 32 bit `number`.|
|LOOKUP2(message, startingValue?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Starting seed value.<br> Returns as unsigned 32 bit `number`.|
|LOOKUP3_##(message, primaryInitval?, secondaryInitval?) | Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Seed values as unsigned 32 bit `number`.<br> Returns as unsigned 32 bit `number` or 64 bit `bigint`.|
|SPOOKY(message, format?, seed1?, seed2?) | Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`<br> Seed values as 64 bit `bigint`.|

## CubeHash

CubeHash hash function class. Can be returned as a hex `string`, `Uint8Array`, or `Buffer`. Includes keyed `_HMAC` variants as well. Can create your own with the `CUBEHASH.CubeHash###` classes.

Can be imported as:

```javascript
const { CUBEHASH } = require('hash-maker'); // common
// or
import { CUBEHASH } from 'hash-maker'; // esm
/*---*/
console.log(PEARSON.FUNCTION_LIST): // gives you the full list
const hash = CUBEHASH.CUBEHASH128("123456789", "buffer");
```

| Functions                          | Params                               |
| :---                               | :---                                 |
| CUBEHASH###(message, format?) | Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"` |
| CUBEHASH###_HMAC(message, key, format?) | Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br>Message key as a `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`|

## PANAMA

Pearson hash function class. Can be returned as a hex `string`, `Uint8Array`, or `Buffer`. Includes keyed `_HMAC` variants as well. Can create your own with the `PANAMA.Panama` class.

Can be imported as:

```javascript
const { PANAMA } = require('hash-maker'); // common
// or
import { PANAMA } from 'hash-maker'; // esm
/*---*/
console.log(PANAMA.FUNCTION_LIST): // gives you the full list
const hash = PANAMA.PANAMA("123456789", "buffer");
```

| Functions                          | Params                               |
| :---                               | :---                                 |
|PANAMA(message, format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`|
|PANAMA_HMAC(message, key, format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br>Message key as a `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`|

## PANAMA

ECHO hash function class. Can be returned as a hex `string`, `Uint8Array`, or `Buffer`. Includes keyed `_HMAC` variants as well. Can create your own with the `ECHO.Echo###` class.

Can be imported as:

```javascript
const { ECHO } = require('hash-maker'); // common
// or
import { ECHO } from 'hash-maker'; // esm
/*---*/
console.log(ECHO.FUNCTION_LIST): // gives you the full list
const hash = ECHO.ECHO512("123456789", "buffer");
```

| Functions                          | Params                               |
| :---                               | :---                                 |
|ECHO###(message, format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`|
|ECHO###_HMAC(message, key, format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br>Message key as a `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`|

## Fugue

Fugue hash function class. Can be returned as a hex `string`, `Uint8Array`, or `Buffer`. Can create your own with the `FUGUE.Fugue###` class.

Can be imported as:

```javascript
const { FUGUE } = require('hash-maker'); // common
// or
import { FUGUE } from 'hash-maker'; // esm
/*---*/
console.log(FUGUE.FUNCTION_LIST): // gives you the full list
const hash = FUGUE.FUGUE512("123456789", "buffer");
```

| Functions                          | Params                               |
| :---                               | :---                                 |
|FUGUE###(message, format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`|

## Groestl

Grøstl hash function class. Can be returned as a hex `string`, `Uint8Array`, or `Buffer`. Includes keyed `_HMAC` variants as well. Can create your own with the `GROESTL.Groestl###` classes.

Can be imported as:

```javascript
const { GROESTL } = require('hash-maker'); // common
// or
import { GROESTL } from 'hash-maker'; // esm
/*---*/
console.log(GROESTL.FUNCTION_LIST): // gives you the full list
const hash = GROESTL.GROESTL512("123456789", "buffer");
```

| Functions                          | Params                               |
| :---                               | :---                                 |
|GROESTL###(message, format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`|
|GROESTL###_HMAC(message, key, format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br>Message key as a `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`|

## Hamsi

Hamsi hash function class. Can be returned as a hex `string`, `Uint8Array`, or `Buffer`. Includes keyed `_HMAC` variants as well. Can create your own with the `HAMSI.Hamsi###` classes.

Can be imported as:

```javascript
const { HAMSI } = require('hash-maker'); // common
// or
import { HAMSI } from 'hash-maker'; // esm
/*---*/
console.log(HAMSI.FUNCTION_LIST): // gives you the full list
const hash = HAMSI.HAMSI512("123456789", "buffer");
```

| Functions                          | Params                               |
| :---                               | :---                                 |
|HAMSI###(message, format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`|
|HAMSI###_HMAC(message, key, format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br>Message key as a `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`|

## HAVAL

Hash of Variable Length (HAVAL) hash function class. Can be returned as a hex `string`, `Uint8Array`, or `Buffer`. Includes keyed `_HMAC` variants as well. Can create your own with the `HAVAL.HAVAL` wrapped function or `HAVAL.Haval###` classes.

Can be imported as:

```javascript
const { HAMSI } = require('hash-maker'); // common
// or
import { HAMSI } from 'hash-maker'; // esm
/*---*/
console.log(HAMSI.FUNCTION_LIST): // gives you the full list
const hash = HAMSI.HAVAL256_3("123456789", "buffer");
```

| Functions                          | Params                               |
| :---                               | :---                                 |
|HAVAL###_#(message, format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`|
|HAVAL###(message, rounds? format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Rounds of hashing. (default `3`)<br> Return format type as: `"hex"`, `"array"` or `"buffer"`|
|HAVAL###_#_HMAC(message, key, format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br>Message key as a `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`|
|HAVAL###_HMAC(message, key, rounds?, format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Message key as a `string`, `Uint8Array` or `Buffer`.<br> Rounds of hashing. (default `3`)<br> Return format type as: `"hex"`, `"array"` or `"buffer"`|

## JH

Hongjun Wu's JH hash function class. Can be returned as a hex `string`, `Uint8Array`, or `Buffer`. Includes keyed `_HMAC` variants as well. Can create your own with the `JH.Jh` wrapped function or `JH.JH###` classes.

Can be imported as:

```javascript
const { JH } = require('hash-maker'); // common
// or
import { JH } from 'hash-maker'; // esm
/*---*/
console.log(JH.FUNCTION_LIST): // gives you the full list
const hash = JH.JH256("123456789", "buffer");
```

| Functions                          | Params                               |
| :---                               | :---                                 |
|JS###(message, format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`|
|JS###_HMAC(message, key, format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br>Message key as a `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`|

## RadioGatún

RadioGatún hash function class. *Note that the naming of 32 / 64 hashes are not the hash size, but the bit size it processes in.* Can be returned as a hex `string`, `Uint8Array`, or `Buffer`. Can create your own with the `RADIOGATUN.RadioGatun##` classes.

Can be imported as:

```javascript
const { RADIOGATUN } = require('hash-maker'); // common
// or
import { RADIOGATUN } from 'hash-maker'; // esm
/*---*/
console.log(RADIOGATUN.FUNCTION_LIST): // gives you the full list
const hash = RADIOGATUN.RADIOGATUN32("123456789", "buffer");
```

| Functions                          | Params                               |
| :---                               | :---                                 |
|RADIOGATUN##(message, format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`|

## LUFFA

LUFFA hash function class. Can be returned as a hex `string`, `Uint8Array`, or `Buffer`. Includes keyed `_HMAC` variants as well. Can create your own with the `LUFFA.LUFFA` wrapped function or `LUFFA.Luffa###` classes.

Can be imported as:

```javascript
const { LUFFA } = require('hash-maker'); // common
// or
import { LUFFA } from 'hash-maker'; // esm
/*---*/
console.log(LUFFA.FUNCTION_LIST): // gives you the full list
const hash = LUFFA.LUFFA256("123456789", "buffer");
```

| Functions                          | Params                               |
| :---                               | :---                                 |
|LUFFA###(message, format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`|
|LUFFA###_HMAC(message, key, format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br>Message key as a `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`|

## SHABAL

SHABAL hash function class. Can be returned as a hex `string`, `Uint8Array`, or `Buffer`. Includes keyed `_HMAC` variants as well. Can create your own with the `SHABAL.SHABAL` wrapped function or `SHABAL.Shabal###` classes.

Can be imported as:

```javascript
const { SHABAL } = require('hash-maker'); // common
// or
import { SHABAL } from 'hash-maker'; // esm
/*---*/
console.log(SHABAL.FUNCTION_LIST): // gives you the full list
const hash = SHABAL.SHABAL256("123456789", "buffer");
```

| Functions                          | Params                               |
| :---                               | :---                                 |
|SHABAL###(message, format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`|
|SHABAL###_HMAC(message, key, format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br>Message key as a `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`|

## SHAvite

SHAvite hash function class. Can be returned as a hex `string`, `Uint8Array`, or `Buffer`. Includes keyed `_HMAC` variants as well. Can create your own with the `SHAVITE.SHAVITE` wrapped function or `SHAVITE.SHAvite###` classes.

Can be imported as:

```javascript
const { SHAVITE } = require('hash-maker'); // common
// or
import { SHAVITE } from 'hash-maker'; // esm
/*---*/
console.log(SHAVITE.FUNCTION_LIST): // gives you the full list
const hash = SHAVITE.SHAVITE256("123456789", "buffer");
```

| Functions                          | Params                               |
| :---                               | :---                                 |
|SHAVITE###(message, format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`|
|SHAVITE###_HMAC(message, key, format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br>Message key as a `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`|

## Skein

Skein hash function class. Can be returned as a hex `string`, `Uint8Array`, or `Buffer`. Includes keyed `_HMAC` variants as well. Can create your own with the `SKEIN.SKEIN` wrapped function or `SKEIN.Skein###` classes.

Can be imported as:

```javascript
const { SKEIN } = require('hash-maker'); // common
// or
import { SKEIN } from 'hash-maker'; // esm
/*---*/
console.log(SKEIN.FUNCTION_LIST): // gives you the full list
const hash = SKEIN.SKEIN256("123456789", "buffer");
```

| Functions                          | Params                               |
| :---                               | :---                                 |
|SKEIN###(message, format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`|
|SKEIN###_HMAC(message, key, format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br>Message key as a `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`|

## SIMD

Single Instruction, Multiple Data (SIMD) hash function class. Can be returned as a hex `string`, `Uint8Array`, or `Buffer`. Includes keyed `_HMAC` variants as well. Can create your own with the `SIMD.SIMD` wrapped function or `SIMD.Simd###` classes.

Can be imported as:

```javascript
const { SIMD } = require('hash-maker'); // common
// or
import { SIMD } from 'hash-maker'; // esm
/*---*/
console.log(SIMD.FUNCTION_LIST): // gives you the full list
const hash = SIMD.SIMD256("123456789", "buffer");
```

| Functions                          | Params                               |
| :---                               | :---                                 |
|SKEIN###(message, format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`|
|SKEIN###_HMAC(message, key, format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br>Message key as a `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`|

## SIP

SIP hash function class. Can be returned as a hex `string`, `Uint8Array`, or `Buffer`. Includes keyed `_HMAC` variants as well. Can create your own with the `SIP.SIP` wrapped function.

Can be imported as:

```javascript
const { SIP } = require('hash-maker'); // common
// or
import { SIP } from 'hash-maker'; // esm
/*---*/
console.log(SIP.FUNCTION_LIST): // gives you the full list
const hash = SIP.SIP128("123456789", "key", "buffer");
```

| Functions                          | Params                               |
| :---                               | :---                                 |
|SIP###(message, key?, format?, cROUNDS?, dROUNDS?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br>Message key as a `string`, `Uint8Array` or `Buffer`. <br> Return format type as: `"hex"`, `"array"` or `"buffer"`.<br> Primary rounds. (default `2`) <br>Secondary rounds. (default `4`)|

## Highway

Highway hash function class. Can be returned as a hex `string`, `Uint8Array`, or `Buffer`. Can create your own with the `HIGHWAY.HIGHWAY` wrapped function or `HIGHWAY.Highway` class.

Can be imported as:

```javascript
const { HIGHWAY } = require('hash-maker'); // common
// or
import { HIGHWAY } from 'hash-maker'; // esm
/*---*/
console.log(HIGHWAY.FUNCTION_LIST): // gives you the full list
const hash = HIGHWAY.HIGHWAY128("123456789", "key", "buffer");
```

| Functions                          | Params                               |
| :---                               | :---                                 |
|HIGHWAY###(message, key?, format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`.<br>Message key as a `string`, `Uint8Array` or `Buffer`. <br> Return format type as: `"hex"`, `"array"` or `"buffer"`.|

## LSH

Locality-Sensitive Hashing (LSH) hash function class. Can be returned as a hex `string`, `Uint8Array`, or `Buffer`. Includes keyed `_HMAC` variants as well. Can create your own with the `LSH.LSH` wrapped function or `LSH.Lsh###` class.

Can be imported as:

```javascript
const { LSH } = require('hash-maker'); // common
// or
import { LSH } from 'hash-maker'; // esm
/*---*/
console.log(LSH.FUNCTION_LIST): // gives you the full list
const hash = LSH.LSH512_512("123456789", "buffer");
```

| Functions                          | Params                               |
| :---                               | :---                                 |
|LSH###(message, format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`. <br> Return format type as: `"hex"`, `"array"` or `"buffer"`.|
|LSH###_HMAC(message, key, format?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`. <br>Message key as a `string`, `Uint8Array` or `Buffer`.<br> Return format type as: `"hex"`, `"array"` or `"buffer"`.|

## MurMur

MurMur hash function class. 128 bit functions can be returned as a hex `string`, `Uint8Array`, or `Buffer`. Others return as `number` or `bigint` depending on the hash size. 

Can be imported as:

```javascript
const { MURMUR } = require('hash-maker'); // common
// or
import { MURMUR } from 'hash-maker'; // esm
/*---*/
console.log(MURMUR.FUNCTION_LIST): // gives you the full list
const hash = MURMUR.MURMUR3_X86_128("123456789");
```

| Functions                          | Params                               |
| :---                               | :---                                 |
|MURMUR#(message, seed?)| Message to be hashed as `string`, `Uint8Array` or `Buffer`. <br> Return format type as: `"hex"`, `"array"` or `"buffer"` for 128 bit functions, `number` and `bigint` for the others depending on hash size.|

## Argon2

Argon2 password hash function class. Can be returned as an Agron2 `encoded` string, a hex `string`, `Uint8Array`, or `Buffer`. Can create your own with the `ARGON2.ARGON2` wrapped function. 

**Note**: This function uses WebAssembly. If run on a browser, it must support WebAssembly.

Can be imported as:

```javascript
const { ARGON2 } = require('hash-maker'); // common
// or
import { ARGON2 } from 'hash-maker'; // esm
/*---*/
console.log(ARGON2.FUNCTION_LIST): // gives you the full list
const hash = ARGON2.ARGON2U("pasword", "somesalt", "encoded"); // $argon2d$v=19$m=1024,t=1,p=1$c29tZXNhbHQ$Li5eBf5XrCz0cuzQRe9oflYqmA/VAzmzichw4ZYrvEU
```

| Functions                          | Params                               |
| :---                               | :---                                 |
|ARGON2##(password, salt, format?, time?, memory?, hashLen?, parallelism?)| Password and salt to be hashed (minimum 8 bytes each or will be padded) as `string`, `Uint8Array` or `Buffer`. <br> Return format type as: `"encoded"`, `"hex"`, `"array"` or `"buffer"`.<br> Argon2 params: <br> - time: default `1`<br> - memory: default `1024` (in KiB)<br> - hashLen: default `32`<br> - parallelism: default `1`|

# RNG

Random number generators.

## Mersenne Twister

Mersenne Twister number generator class. Can be seeded with a `number` or `Uint32Array`.

Can be imported as:

```javascript
const { RNG } = require('hash-maker').; // common
// or
import { RNG } from 'hash-maker'; // esm
/*---*/
const { MersenneTwister } = RNG;
const seed = 0x1337; // number or Uint32Array if needed
const mt = new MersenneTwister(seed);
const unsignedInt = mt.random_int() // or mt.RandTwisterUnsigned() mt.genrand_int32()
```

| Functions                          | Params / Returns                              |
| :---                               | :---                                 |
|new MersenneTwister(seed?)| Seed as `number` or `Uint32Array`|
|mt.genrand_int32()<br>mt.RandTwisterUnsigned()<br>mt.random_int()| Returns unsigned 32 bit `number`|
|mt.genrand_int32i()<br>mt.RandTwisterSigned()| Returns signed 32 bit `number` |
|mt.genrand_real1()<br>mt.RandTwisterDouble()| Returns `number` on [0,1]-real-interval |
|mt.genrand_real2()| Returns `number` on [0,1)-real-interval | 
|mt.genrand_real3() | Returns `number` on (0,1)-real-interval|
|mt.genrand_res53()| Returns `number` on [0,1) with 53-bit resolution|

## Random Xor Shift

Random Xor Shift number generator class. Can seeded with a 32 bit `number`, `Uint8Array` or `Buffer` of 4 bytes.

Can be imported as:

```javascript
const { RNG } = require('hash-maker'); // common
// or
import { RNG } from 'hash-maker'; // esm
/*---*/
const { RandomXORShift } = RNG; 
const seed = 0x1337; // number, Uint8Array or Buffer of 4 bytes
const rxs = new RandomXORShift(seed);
const random_int = rxs.random_int(); // unsigned 32 bit number
```

| Functions                          | Params / Returns                     |
| :---                               | :---                                 |
|new RandomXORShift(seed?)| Seed with a 32 bit `number` or a `Uint8Array` or `Buffer` of 4 bytes.|
|rxs.random_int() | Returns unsigned 32 bit `number`|

## Random Bytes

Random byte generator function. Functions can be returned as a hex `string` ,`Buffer` or`Uint8Array`. Numbers generated with the `MersenneTwister`.

Can be imported as:

```javascript
const { RNG } = require('hash-maker'); // common
// or
import { RNG } from 'hash-maker'; // esm
/*---*/
const bytes = RNG.RandomBytes(12, "hex");
```

| Functions                          | Params                     |
| :---                               | :---                       |
|RandomBytes(amount, fromat?)| Return format type as: `"hex"`, `"array"` or `"buffer"`|

## UUID

UUID generator function. UUID functions can create verisons 1 - 5 (default 4) and can be returned as a hex `string`, `Uint8Array` or `Buffer` (default `hex`).

Can be imported as:

```javascript
const { RNG } = require('hash-maker'); // common
// or
import { RNG } from 'hash-maker'; // esm
/*---*/
const id = RNG.UUID(1,"array");
```

| Functions                          | Params                     |
| :---                               | :---                       |
|UUID(verison, format?, seed? mac?) | verison 1 - 5 (default 4)<br>Return format type as: `"hex"`, `"array"` or `"buffer"` (default `"hex"`)<br>Seed value to start, at least a 16 byte `Buffer` or `Uint8Array`<br>Static mac to use of at least a 6 byte `Buffer` or `Uint8Array`.|

## License

MIT

## Disclaimer

I curated this library to implement these functions across different Node environments and have them all match. They do not hold up speed or performance wise against something more direct like a C++ source code, as the goal here was flexible. All libraries are presented *as is*, I take no responsibility for outside use.

**If you plan to implement these hashes for anything other than personal or educational use, please be sure you have the appropriate permissions from the original owner of the cipher.**
