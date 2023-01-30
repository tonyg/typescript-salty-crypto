/// SPDX-License-Identifier: MIT
/// SPDX-FileCopyrightText: Copyright © 2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

export * from './aead';
export * as Bytes from './bytes';
export * from './cipher';
export * from './dh';
export * from './hash';
export * from './hkdf';
export * from './hmac';
export * as IO from './io';
export * from './noise';
export * from './nonce';
export * from './random';

import * as chacha20poly1305 from './aead/chacha20poly1305';
import * as chacha20 from './cipher/chacha20';
import * as x25519 from './dh/x25519';
import * as blake2s from './hash/blake2s';
import * as poly1305 from './hash/poly1305';
import * as algorithms from './noise/algorithms';
import * as cipherstate from './noise/cipherstate';
import * as handshake from './noise/handshake';
import * as patterns from './noise/patterns';
import * as profiles from './noise/profiles';
import * as rekey from './noise/rekey';

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
