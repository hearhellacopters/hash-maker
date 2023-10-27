# hash-maker

A collection of hash and number generators for Node or Browser in pure JS.

- [SHA](#sha) - Creates a SHA1/224/256/384/512 hash of a message.
- [MD5](#md5) - Creates a MD5 hash of a message.
- [CRC](#crc) - Createsa CRC3/16/32 hash of a message.
- [UUID](#uuid) - Create UUIDs verisons 1 - 5.
- [Random bytes](#random-bytes) - Random bytes of a supplied length (based on Mersenne Twister)
- [Mersenne Twister](#mersenne-twister) - Random number generator that can be seaded. Create 32 bit signed, unsigned or float values.
- [Random Xor Shift](#random-xor-shift) - Random number generator that can be seaded. Creates unsigned 32 bit values.

## Installation

```npm install hash-maker```

Provides both CommonJS and ES modules.

## SHA

SHA hash function. All SHA functions can be returned as a string, Uint8Array, Buffer or Hex string (default).

Can be imported as:

```javascript
const { SHA256 } = require('hash-maker');
//
import { SHA256 } from 'hash-maker';
const hash = SHA256("0123456789",{asArray:true});
```

<table>
<thead>
  <tr>
    <th align="center">Functions</th>
    <th align="left">Params</th>
  </tr>
</thead>
<tbody>
  <tr>
    <td>SHA1(message, options?)<br>SHA224(message, options?)<br>SHA256(message, options?)<br>SHA384(message, options)<br>SHA512(message, options)</td>
    <td>Message to be hashed as string, Uint8Array or Buffer,<br>options: {
  asString: true ||
  asBuffer: true ||
  asArray: true
}</td>
  </tr>
</tbody>
</table>

## MD5

MD5 hash function. MD5 functions can be returned as a string, Uint8Array, Buffer or Hex string (default).

Can be imported as:

```javascript
const { MD5 } = require('hash-maker');
//
import { MD5 } from 'hash-maker';
const hash = MD5("0123456789",{asArray:true})
```

<table>
<thead>
  <tr>
    <th align="center">Functions</th>
    <th align="left">Params</th>
  </tr>
</thead>
<tbody>
  <tr>
    <td>MD5(message, options?)</td>
    <td>Message to be hashed as string, Uint8Array or Buffer,<br>options: {
  asString: true ||
  asBuffer: true ||
  asArray: true
}</td>
  </tr>
</tbody>
</table>

## CRC

CRC hash function. CRC functions can be returned as a Hex string, Uint8Array, Buffer or number (default).

Can be imported as:

```javascript
const { CRC32 } = require('hash-maker');
//
import { CRC32 } from 'hash-maker';
const hash = CRC32("0123456789",{asArray:true});
```

<table>
<thead>
  <tr>
    <th align="center">Functions</th>
    <th align="left">Params</th>
  </tr>
</thead>
<tbody>
  <tr>
    <td>CRC3(message, options?)<br>CRC16(message, options?)<br>CRC32(message, options?)</td>
    <td>Message to be hashed as string, Uint8Array or Buffer,<br>options: {
  asBuffer: true ||
  asArray: true ||
  asHex: true
}</td>
  </tr>
</tbody>
</table>

## UUID

UUID generator function. UUID functions can create verisons 1 - 5 (default 4) and can be returned as a Uint8Array, Buffer or Hex string (default).

Can be imported as:

```javascript
const { UUID } = require('hash-maker');
//
import { UUID } from 'hash-maker';
const id = UUID(1,{asArray:true});
```

<table>
<thead>
  <tr>
    <th align="center">Functions</th>
    <th align="left">Params</th>
  </tr>
</thead>
<tbody>
  <tr>
    <td>UUID(verison, options?)</td>
    <td>verison 1 - 5 (default 4),<br>options: {<br>
    seed: If seeding is needed. Must be UInt8Array or Buffer of 16 bytes,<br>
    mac: If a mac ID is needed. Must be UInt8Array or Buffer of 6 bytes. Else one is generated when needed,<br>
    asBuffer: true ||
    asArray: true 
<br>}</td>
  </tr>
</tbody>
</table>

## Random Bytes

Random byte generator function. Functions can be returned as a Buffer or Uint8Array (default). Numbers generated with the Mersenne Twister (see below).

Can be imported as:

```javascript
const { randomBytes } = require('hash-maker');
//
import { randomBytes } from 'hash-maker';
const bytes = randomBytes(12,true);
```

<table>
<thead>
  <tr>
    <th align="center">Functions</th>
    <th align="left">Params</th>
  </tr>
</thead>
<tbody>
  <tr>
    <td>randomBytes(amount, asBuffer?)</td>
    <td>Bytes neede,<br> true to return as a Buffer
</td>
  </tr>
</tbody>
</table>

## Mersenne Twister

Mersenne Twister number generator class. Can be seeded with a number or Uint32Array.

Can be imported as:

```javascript
const { MERSENNETWISTER } = require('hash-maker');
//
import { MERSENNETWISTER } from 'hash-maker';
const seed; // number or Uint32Array if needed
const mt = new MERSENNETWISTER(seed);
const unsignedInt = mt.genrand_int32() // or mt.RandTwisterUnsigned() mt.random_int()
const signedInt = mt.genrand_int32i() // or mt.RandTwisterSigned()
const unsigned31Int = mt.genrand_int3i() //31 bit number
const double = mt.genrand_real1() // or mt.RandTwisterDouble()
const float1 = mt.genrand_real2() // generates a random number on [0,1)-real-interval
const float2 = mt.genrand_real3() // generates a random number on (0,1)-real-interval
const float3 = mt.genrand_res53() // generates a random number on [0,1) with 53-bit resolution
```

<table>
<thead>
  <tr>
    <th align="center">Functions</th>
    <th align="left">Params / returns</th>
  </tr>
</thead>
<tbody>
  <tr>
    <td>new MERSENNETWISTER(seed?)</td>
    <td>Seed as number or Uint32Array
  </td>
  <tr>
    <td>mt.genrand_int32()<br>mt.RandTwisterUnsigned()<br>mt.random_int()</td>
    <td>unsigned 32 bit number
  </td>
  <tr>
    <td>mt.genrand_int32i()<br>mt.RandTwisterSigned()</td>
    <td>signed 32 bit number
  </td>
  </tr>
  <tr>
    <td>mt.genrand_real1()<br>mt.RandTwisterDouble()</td>
    <td>generates a random number on [0,1]-real-interval
  </td>
  </tr>
  <tr>
    <td>mt.genrand_real2()</td>
    <td>generates a random number on [0,1)-real-interval
  </td>
  </tr>
  <tr>
    <td>mt.genrand_real3()</td>
    <td>generates a random number on (0,1)-real-interval
  </td>
  </tr>
  <tr>
    <td>mt.genrand_real3()</td>
    <td>generates a random number on [0,1) with 53-bit resolution
  </td>
  </tr>
</tbody>
</table>

## Random Xor Shift

Random Xor Shift number generator class. Can seeded with a number or a Uint8Array or Buffer of 4 bytes.

Can be imported as:

```javascript
const { RANDOMXORSHIFT } = require('hash-maker');
//
import { RANDOMXORSHIFT } from 'hash-maker';
const seed; //number, Uint8Array or Buffer of 4 bytes
const rxs = new RANDOMXORSHIFT(seed);
const random_int = rxs.random_int();
```

<table>
<thead>
  <tr>
    <th align="center">Functions</th>
    <th align="left">Params / returns</th>
  </tr>
</thead>
<tbody>
  <tr>
    <td>new RANDOMXORSHIFT(seed?)</td>
    <td>Seed as a number or a Uint8Array or Buffer of 4 bytes.
  </td>
  <tr>
    <td>rxs.random_int()</td>
    <td>unsigned 32 bit number
  </td>
</tbody>
</table>
