/// SPDX-License-Identifier: MIT
/// SPDX-FileCopyrightText: Copyright © 2023-2025 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

export * from './aead.js';
export * as Bytes from './bytes.js';
export * from './cipher.js';
export * from './dh.js';
export * from './hash.js';
export * from './hkdf.js';
export * from './hmac.js';
export * as IO from './io.js';
export * from './noise.js';
export * from './nonce.js';
export * from './random.js';

import * as chacha20poly1305 from './aead/chacha20poly1305.js';
import * as chacha20 from './cipher/chacha20.js';
import * as x25519 from './dh/x25519.js';
import * as blake2s from './hash/blake2s.js';
import * as poly1305 from './hash/poly1305.js';
import * as algorithms from './noise/algorithms.js';
import * as cipherstate from './noise/cipherstate.js';
import * as handshake from './noise/handshake.js';
import * as patterns from './noise/patterns.js';
import * as profiles from './noise/profiles.js';
import * as rekey from './noise/rekey.js';

export const INTERNALS = {
    aead: {
        chacha20poly1305,
    },
    cipher: {
        chacha20,
    },
    dh: {
        x25519,
    },
    hash: {
        blake2s,
        poly1305,
    },
    noise: {
        algorithms,
        cipherstate,
        handshake,
        patterns,
        profiles,
        rekey,
    },
};
