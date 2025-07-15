/// SPDX-License-Identifier: MIT
/// SPDX-FileCopyrightText: Copyright © 2023-2025 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

import { Nonce } from '../nonce.js';
import { makeRekey } from './rekey.js';
import { Algorithms } from './algorithms.js';

export class CipherState {
    view: DataView | null = null;
    nonce = new Nonce();
    readonly maxPayload: number;

    constructor (public algorithms: Algorithms,
                 key?: Uint8Array)
    {
        if (key !== void 0) this.view = new DataView(key.buffer);
        this.maxPayload = 65535 - this.algorithms.aead.TAGBYTES;
    }

    encrypt(plaintext: Uint8Array, associated_data?: Uint8Array): Uint8Array {
        if (this.view === null) return plaintext;
        const ciphertext =
            this.algorithms.aead.encrypt(plaintext, this.view, this.nonce, associated_data);
        this.nonce.increment();
        return ciphertext;
    }

    decrypt(ciphertext: Uint8Array, associated_data?: Uint8Array): Uint8Array {
        if (this.view === null) return ciphertext;
        const plaintext =
            this.algorithms.aead.decrypt(ciphertext, this.view, this.nonce, associated_data);
        this.nonce.increment();
        return plaintext;
    }

    rekey() {
        if (this.view === null) return;
        this.view = (this.algorithms.rekey ?? makeRekey(this.algorithms.aead))(this.view);
    }

    encrypt_large(plaintext: Uint8Array): Uint8Array[] {
        if (plaintext.byteLength > this.maxPayload) {
            const pieces = [];
            while (plaintext.byteLength > this.maxPayload) {
                pieces.push(this.encrypt(plaintext.subarray(0, this.maxPayload)));
                plaintext = plaintext.subarray(this.maxPayload);
            }
            if (plaintext.byteLength > 0) {
                pieces.push(this.encrypt(plaintext));
            }
            return pieces;
        } else {
            return [this.encrypt(plaintext)];
        }
    }

    decrypt_large(ciphertexts: Uint8Array[]): Uint8Array {
        const final_len = ciphertexts.reduce(
            (acc, c) => acc + c.byteLength - this.algorithms.aead.TAGBYTES, 0);
        const final = new Uint8Array(final_len);
        let offset = 0;
        ciphertexts.forEach(c => {
            const p = this.decrypt(c);
            final.set(p, offset);
            offset += p.byteLength;
        });
        return final;
    }
}
