# salty-crypto

A TypeScript implementation of the [Noise Protocol Framework](https://noiseprotocol.org/),
intended to be runnable both in the browser and server-side. Also includes just enough minimal
crypto code (partly from [tweetnacl.js](https://github.com/dchest/tweetnacl-js), partly code I
wrote [myself](https://leastfixedpoint.com/) from the RFCs) to get
`Noise_*_25519_ChaChaPoly_BLAKE2s` working.

## Example

The noise protocol needs some way to transport encrypted packets back and forth. This could be
a TCP/IP socket, a WebSocket, or something similar. Let's represent this transport as a pair of
functions:

```typescript
async function writePacket(packet: Uint8Array): Promise<void>;
async function readPacket(): Promise<Uint8Array>;
```

Then, on the initiating ("connecting") side,

```typescript
import { Handshake, Noise_25519_ChaChaPoly_BLAKE2s } from 'salty-crypto';
const I = new Handshake(Noise_25519_ChaChaPoly_BLAKE2s, 'NX', 'initiator');
const { send, recv } = await I.completeHandshake(writePacket, readPacket);
...
await writePacket(send.encrypt(message));
...
const message = rect.decrypt(await readPacket());
...
```

On the responding ("listening") side, the code is exactly the same, except with `'responder'`
instead of `'initiator'`.

If you want to check the peer's static (~identity) key, access the `remoteStaticPublicKey`
field of the `Handshake` object. To supply a long-lived identity keypair when handshaking, pass
in a `HandshakeOptions` structure with a `staticKeypair` member to the `Handshake` constructor.

## Status

Includes (and passes) test vectors from [noise-c](https://github.com/rweather/noise-c/) and
[snow](https://github.com/mcginty/snow/).

## Potential next steps

 - support AESGCM, SHA256, SHA512, perhaps via `Crypto.subtle`?
 - support BLAKE2b, by implementing from the RFC just like BLAKE2s
 - `fallback` pattern modifier

## Code overview

 - [`src/index.ts`](src/index.ts): Main package entrypoint; main API.
 - [`src/aead.ts`](src/aead.ts): Abstract AEAD API.
 - [`src/aead/chacha20poly1305.ts`](src/aead/chacha20poly1305.ts): RFC-8439 ("IETF") ChaCha20-Poly1305 AEAD construction.
 - [`src/bytes.ts`](src/bytes.ts): Uint8Array utilities.
 - [`src/cipher.ts`](src/cipher.ts): Abstract stream-cipher API.
 - [`src/cipher/chacha20.ts`](src/cipher/chacha20.ts): RFC-8439 ("IETF") ChaCha20 cipher.
 - [`src/dh.ts`](src/dh.ts): Abstract key agreement API.
 - [`src/dh/x25519.ts`](src/dh/x25519.ts): Port of [the X25519 key agreement implementation from tweetnacl.js](https://github.com/dchest/tweetnacl-js/blob/6a9594a35a27f9c723c5f1c107e376d1c65c23b3/nacl-fast.js#L852-L1379).
 - [`src/hash.ts`](src/hash.ts): Abstract hash-function API.
 - [`src/hash/blake2s.ts`](src/hash/blake2s.ts): RFC-7693 BLAKE2s hash function.
 - [`src/hash/poly1305.ts`](src/hash/poly1305.ts): Port of [the Poly1305 MAC implementation from tweetnacl.js](https://github.com/dchest/tweetnacl-js/blob/6a9594a35a27f9c723c5f1c107e376d1c65c23b3/nacl-fast.js#L462-L817), which in turn ported [Andrew Moon's Poly1305-donna-16 code](https://github.com/floodyberry/poly1305-donna/blob/e6ad6e091d30d7f4ec2d4f978be1fcfcbce72781/poly1305-donna-16.h).
 - [`src/hkdf.ts`](src/hkdf.ts): Standard HKDF construction.
 - [`src/hmac.ts`](src/hmac.ts): Standard HMAC construction.
 - [`src/noise.ts`](src/noise.ts): Main Noise Protocol API.
 - [`src/noise/algorithms.ts`](src/noise/algorithms.ts): Abstract Noise algorithms API.
 - [`src/noise/cipherstate.ts`](src/noise/cipherstate.ts): Noise Protocol CipherState implementation.
 - [`src/noise/handshake.ts`](src/noise/handshake.ts): Core Noise Protocol Framework handshake implementation.
 - [`src/noise/patterns.ts`](src/noise/patterns.ts): Library of Noise handshake patterns.
 - [`src/noise/profiles.ts`](src/noise/profiles.ts): Profiles of the Noise Protocol Framework. Currently just `Noise_25519_ChaChaPoly_BLAKE2s`.
 - [`src/noise/rekey.ts`](src/noise/rekey.ts): Noise Protocol default rekey function.
 - [`src/nonce.ts`](src/nonce.ts): Representation of 64- (or 96-) bit nonces.
 - [`src/random.ts`](src/random.ts): Port of [the randomness-generation code from tweetnacl.js](https://github.com/dchest/tweetnacl-js/blob/6a9594a35a27f9c723c5f1c107e376d1c65c23b3/nacl-fast.js#L2363-L2389).
 - [`test-vectors`](test-vectors): Contains Noise test vectors (more-or-less in the [standard JSON format](https://github.com/noiseprotocol/noise_wiki/wiki/Test-vectors)) copied from other projects.
 - [`test`](test): Contains a test driver and test code.

## Copyright and License

These libraries are Copyright © 2023 Tony Garnock-Jones `<tonyg@leastfixedpoint.com>`.

They are made available to you under the [MIT license](https://spdx.org/licenses/MIT.html).

    MIT License

    Copyright (c) 2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice (including the next
    paragraph) shall be included in all copies or substantial portions of the
    Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
