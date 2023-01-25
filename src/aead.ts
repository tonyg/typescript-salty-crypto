/// SPDX-License-Identifier: MIT
/// SPDX-FileCopyrightText: Copyright © 2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

// RFC-8439 AEAD construction.

export const AEAD_CHACHA20_POLY1305_KEYBYTES = 32;
export const AEAD_CHACHA20_POLY1305_NONCEBYTES = 12;
export const AEAD_CHACHA20_POLY1305_TAGBYTES = 16;

import { chacha20 } from './chacha20';
import { Poly1305 } from './poly1305';

const PADDING = new Uint8Array(16);

function pad16(p: Poly1305, unpadded_length: number) {
    const leftover = unpadded_length & 15;
    if (leftover !== 0) p.update(PADDING, 0, 16 - leftover);
}

function aead_tag(tag: Uint8Array,
                  key: DataView,
                  nonce: DataView,
                  ciphertext: Uint8Array,
                  cipherlength: number,
                  associated_data?: Uint8Array)
{
    const mac_key = new Uint8Array(Poly1305.KEYBYTES);
    chacha20(key, nonce, mac_key, mac_key, 0);
    const p = new Poly1305(mac_key);

    if (associated_data !== void 0) {
        p.update(associated_data, 0, associated_data.byteLength);
        pad16(p, associated_data.byteLength);
    }

    p.update(ciphertext, 0, cipherlength);
    pad16(p, cipherlength);

    const L = new Uint8Array(16);
    const Lv = new DataView(L.buffer);
    if (associated_data !== void 0) {
        Lv.setUint32(0, associated_data.byteLength, true);
    }
    Lv.setUint32(8, cipherlength, true);
    p.update(L, 0, L.byteLength);

    p.finish(tag, 0);
}

export function aead_encrypt_detached(plaintext: Uint8Array,
                                      ciphertext: Uint8Array,
                                      messagelength: number,
                                      tag: Uint8Array,
                                      key: DataView,
                                      nonce: DataView,
                                      associated_data?: Uint8Array)
{
    chacha20(key, nonce, plaintext, ciphertext, 1, messagelength);
    aead_tag(tag, key, nonce, ciphertext, messagelength, associated_data);
}

// `verify` from nacl-fast.js
function verify(x: Uint8Array, y: Uint8Array, n: number): number {
    let d = 0;
    for (let i = 0; i < n; i++) d |= x[i]^y[i];
    return (1 & ((d - 1) >>> 8)) - 1;
}

export function aead_decrypt_detached(plaintext: Uint8Array,
                                      ciphertext: Uint8Array,
                                      messagelength: number,
                                      expected_tag: Uint8Array,
                                      key: DataView,
                                      nonce: DataView,
                                      associated_data?: Uint8Array): boolean
{
    const actual_tag = new Uint8Array(AEAD_CHACHA20_POLY1305_TAGBYTES);
    aead_tag(actual_tag, key, nonce, ciphertext, messagelength, associated_data);
    const ok = verify(actual_tag, expected_tag, actual_tag.byteLength) === 0;
    if (ok) {
        chacha20(key, nonce, ciphertext, plaintext, 1, messagelength);
    } else {
        plaintext.fill(0, 0, messagelength);
    }
    return ok;
}
