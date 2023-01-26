/// SPDX-License-Identifier: MIT
/// SPDX-FileCopyrightText: Copyright © 2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

// RFC-8439 AEAD construction.

import { AEAD, _encrypt, _decrypt } from '../aead';
import { Nonce } from '../nonce';

import { ChaCha20 } from '../cipher/chacha20';
import { Poly1305 } from '../hash/poly1305';
import * as Bytes from '../bytes';
import { HashAlgorithm } from '../hash';

const PADDING = new Uint8Array(16);

function pad16(p: HashAlgorithm, unpadded_length: number) {
    const leftover = unpadded_length & 15;
    if (leftover !== 0) p.update(PADDING, 0, 16 - leftover);
}

function aead_tag(tag: Uint8Array,
                  key: DataView,
                  nonce: Nonce,
                  ciphertext: Uint8Array,
                  cipherlength: number,
                  associated_data?: Uint8Array)
{
    const mac_key = new Uint8Array(Poly1305.KEYBYTES);
    ChaCha20.stream_xor(key, nonce, mac_key, mac_key, 0);
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

    p.final(tag);
}

export const ChaCha20Poly1305_RFC8439: AEAD = {
    NAME: 'ChaChaPoly',
    KEYBYTES: 32,
    NONCEBYTES: 12,
    TAGBYTES: 16,

    encrypt_detached(plaintext: Uint8Array,
                     ciphertext: Uint8Array,
                     messagelength: number,
                     tag: Uint8Array,
                     key: DataView,
                     nonce: Nonce,
                     associated_data?: Uint8Array): void {
        ChaCha20.stream_xor(key, nonce, plaintext, ciphertext, 1, messagelength);
        aead_tag(tag, key, nonce, ciphertext, messagelength, associated_data);
    },

    encrypt: _encrypt,

    decrypt_detached(plaintext: Uint8Array,
                     ciphertext: Uint8Array,
                     messagelength: number,
                     expected_tag: Uint8Array,
                     key: DataView,
                     nonce: Nonce,
                     associated_data?: Uint8Array): boolean {
        const actual_tag = new Uint8Array(this.TAGBYTES);
        aead_tag(actual_tag, key, nonce, ciphertext, messagelength, associated_data);
        const ok = Bytes.equal(actual_tag, expected_tag, actual_tag.byteLength);
        if (ok) ChaCha20.stream_xor(key, nonce, ciphertext, plaintext, 1, messagelength);
        return ok;
    },

    decrypt: _decrypt,
};
