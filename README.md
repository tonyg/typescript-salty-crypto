# salty-crypto

A TypeScript implementation of the [Noise Protocol Framework](https://noiseprotocol.org/),
intended to be runnable both in the browser and server-side. Also includes just enough minimal
crypto code (partly from [tweetnacl.js](https://github.com/dchest/tweetnacl-js), partly code I
wrote [myself](https://leastfixedpoint.com/) from the RFCs) to get
`Noise_*_25519_ChaChaPoly_BLAKE2s` working.

## Status

Includes (and passes) test vectors from [noise-c](https://github.com/rweather/noise-c/) and
[snow](https://github.com/mcginty/snow/).

## Potential next steps

 - support AESGCM, SHA256, SHA512, perhaps via `Crypto.subtle`?
 - support BLAKE2b, by implementing from the RFC just like BLAKE2s
 - `fallback` pattern modifier

## Code overview

 - `src` directory:
    - [`aead.ts`](src/aead.ts): RFC-8439 ("IETF") ChaCha20-Poly1305 AEAD construction
    - [`blake2.ts`](src/blake2.ts): RFC-7693 BLAKE2s hash function
    - [`chacha20.ts`](src/chacha20.ts): RFC-8439 ("IETF") ChaCha20 cipher
    - [`noise.ts`](src/noise.ts): Core Noise Protocol Framework handshake and CipherState
      implementation
    - [`patterns.ts`](src/patterns.ts): Library of Noise handshake patterns
    - [`poly1305.ts`](src/poly1305.ts): Port of [the Poly1305 MAC implementation from
      tweetnacl.js](https://github.com/dchest/tweetnacl-js/blob/6a9594a35a27f9c723c5f1c107e376d1c65c23b3/nacl-fast.js#L462-L817),
      which in turn ported [Andrew Moon's Poly1305-donna-16
      code](https://github.com/floodyberry/poly1305-donna/blob/e6ad6e091d30d7f4ec2d4f978be1fcfcbce72781/poly1305-donna-16.h).
    - [`profiles.ts`](src/profiles.ts): Profiles of the Noise Protocol Framework. Currently
      just `Noise_25519_ChaChaPoly_BLAKE2s`.
    - [`random.ts`](src/random.ts): Port of [the randomness-generation code from
      tweetnacl.js](https://github.com/dchest/tweetnacl-js/blob/6a9594a35a27f9c723c5f1c107e376d1c65c23b3/nacl-fast.js#L2363-L2389).
    - [`x25519.ts`](src/x25519.ts): Port of [the X25519 key agreement implementation from
      tweetnacl.js](https://github.com/dchest/tweetnacl-js/blob/6a9594a35a27f9c723c5f1c107e376d1c65c23b3/nacl-fast.js#L852-L1379).
 - `test-vectors` directory: Contains Noise test vectors (more-or-less in the [standard JSON
   format](https://github.com/noiseprotocol/noise_wiki/wiki/Test-vectors)) copied from other
   projects.
 - `test` directory: Contains a test driver and test code.

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
