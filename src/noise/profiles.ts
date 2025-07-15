/// SPDX-License-Identifier: MIT
/// SPDX-FileCopyrightText: Copyright © 2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

import { Algorithms } from './algorithms.js';
import { BLAKE2s } from '../hash.js';
import { ChaCha20Poly1305_RFC8439 } from '../aead.js';
import { X25519 } from '../dh.js';

export const Noise_25519_ChaChaPoly_BLAKE2s: Algorithms = {
    dh: X25519,
    aead: ChaCha20Poly1305_RFC8439,
    hash: BLAKE2s,
};
