/// SPDX-License-Identifier: MIT
/// SPDX-FileCopyrightText: Copyright © 2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

import { Nonce } from '../nonce';
import { makeRekey } from './rekey';
import { Algorithms } from './algorithms';

export class CipherState {
    view: DataView | null = null;
    nonce = new Nonce();

    constructor (public algorithms: Algorithms,
                 key?: Uint8Array)
    {
        if (key !== void 0) this.view = new DataView(key.buffer);
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
}
