/// SPDX-License-Identifier: MIT
/// SPDX-FileCopyrightText: Copyright © 2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

import { Nonce } from './nonce.js';

export interface StreamCipher {
    readonly NAME: string;
    readonly KEYBYTES: number;
    readonly NONCEBYTES: number;
    readonly BLOCKBYTES: number;

    stream_xor(key: DataView,
               nonce: Nonce,
               input: Uint8Array,
               output: Uint8Array,
               initial_counter?: number,
               messagelength?: number): void;
}

export { ChaCha20 } from './cipher/chacha20.js';
