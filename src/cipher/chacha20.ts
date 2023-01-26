/// SPDX-License-Identifier: MIT
/// SPDX-FileCopyrightText: Copyright © 2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

// RFC-8439 ChaCha20.

import { StreamCipher } from '../cipher';
import { Nonce } from '../nonce';

function ROTATE(n: number, bits: number): number {
    return (n << bits) | (n >>> (32 - bits));
}

export function chacha20_quarter_round(s: Uint32Array, a: number, b: number, c: number, d: number) {
    s[a] += s[b]; s[d] ^= s[a]; s[d] = ROTATE(s[d], 16);
    s[c] += s[d]; s[b] ^= s[c]; s[b] = ROTATE(s[b], 12);
    s[a] += s[b]; s[d] ^= s[a]; s[d] = ROTATE(s[d], 8);
    s[c] += s[d]; s[b] ^= s[c]; s[b] = ROTATE(s[b], 7);
}

function fill_state(state: Uint32Array, key: DataView, block: number, nonce: DataView) {
    state[0] += 0x61707865; state[1] += 0x3320646e; state[2] += 0x79622d32; state[3] += 0x6b206574;
    state[4] += key.getUint32(0, true); state[5] += key.getUint32(4, true);
    state[6] += key.getUint32(8, true); state[7] += key.getUint32(12, true);
    state[8] += key.getUint32(16, true); state[9] += key.getUint32(20, true);
    state[10] += key.getUint32(24, true); state[11] += key.getUint32(28, true);
    state[12] += block;
    state[13] += nonce.getUint32(0, true);
    state[14] += nonce.getUint32(4, true);
    state[15] += nonce.getUint32(8, true);
}

export function chacha20_block(key: DataView, block: number, nonce: DataView): Uint32Array {
    const state = new Uint32Array(16);
    fill_state(state, key, block, nonce);
    for (let round = 0; round < 20; round += 2) {
        chacha20_quarter_round(state, 0, 4, 8, 12);
        chacha20_quarter_round(state, 1, 5, 9, 13);
        chacha20_quarter_round(state, 2, 6, 10, 14);
        chacha20_quarter_round(state, 3, 7, 11, 15);
        chacha20_quarter_round(state, 0, 5, 10, 15);
        chacha20_quarter_round(state, 1, 6, 11, 12);
        chacha20_quarter_round(state, 2, 7, 8, 13);
        chacha20_quarter_round(state, 3, 4, 9, 14);
    }
    fill_state(state, key, block, nonce);
    return state;
}

function serializeNonce(n: Nonce): DataView {
    const view = new DataView(new ArrayBuffer(ChaCha20.NONCEBYTES));
    view.setUint32(0, n.extra, true);
    view.setUint32(4, n.lo, true);
    view.setUint32(8, n.hi, true);
    return view;
}

export const ChaCha20: StreamCipher = {
    NAME: 'chacha20',
    KEYBYTES: 32,
    NONCEBYTES: 12,
    BLOCKBYTES: 64,

    stream_xor(key: DataView,
               nonce0: Nonce,
               input: Uint8Array,
               output: Uint8Array,
               initial_counter = 0,
               messagelength = input.byteLength): void
    {
        const nonce = serializeNonce(nonce0);
        const whole_blocks = messagelength >> 6;
        const remaining_bytes = messagelength & 63;
        for (let j = 0; j < whole_blocks; j++) {
            const chunk = chacha20_block(key, initial_counter + j, nonce);
            for (let i = 0; i < 64; i++) {
                output[(j << 6) + i] = input[(j << 6) + i] ^ (chunk[i >> 2] >> ((i & 3) << 3));
            }
        }
        if (remaining_bytes !== 0) {
            const chunk = chacha20_block(key, initial_counter + whole_blocks, nonce);
            for (let i = 0; i < remaining_bytes; i++) {
                output[(whole_blocks << 6) + i] = input[(whole_blocks << 6) + i] ^ (chunk[i >> 2] >> ((i & 3) << 3));
            }
        }
    }
};
