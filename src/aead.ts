/// SPDX-License-Identifier: MIT
/// SPDX-FileCopyrightText: Copyright © 2023-2025 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

import { Nonce } from './nonce.js';

export class AuthenticationFailure extends Error {}

export interface AEAD {
    readonly NAME: string;
    readonly KEYBYTES: number;
    readonly NONCEBYTES: number;
    readonly TAGBYTES: number;

    encrypt_detached(plaintext: Uint8Array,
                     ciphertext: Uint8Array,
                     messagelength: number,
                     tag: Uint8Array,
                     key: DataView,
                     nonce: Nonce,
                     associated_data?: Uint8Array): void;

    encrypt(plaintext: Uint8Array,
            key: DataView,
            nonce: Nonce,
            associated_data?: Uint8Array): Uint8Array;

    decrypt_detached(plaintext: Uint8Array,
                     ciphertext: Uint8Array,
                     messagelength: number,
                     expected_tag: Uint8Array,
                     key: DataView,
                     nonce: Nonce,
                     associated_data?: Uint8Array): boolean;

    decrypt(ciphertextAndTag: Uint8Array,
            key: DataView,
            nonce: Nonce,
            associated_data?: Uint8Array): Uint8Array;
}

export function _encrypt(this: AEAD,
                         plaintext: Uint8Array,
                         key: DataView,
                         nonce: Nonce,
                         associated_data?: Uint8Array): Uint8Array
{
    const ciphertextAndTag = new Uint8Array(plaintext.byteLength + this.TAGBYTES);
    this.encrypt_detached(plaintext,
                          ciphertextAndTag,
                          plaintext.byteLength,
                          ciphertextAndTag.subarray(plaintext.byteLength),
                          key,
                          nonce,
                          associated_data);
    return ciphertextAndTag;
}

export function _decrypt(this: AEAD,
                         ciphertextAndTag: Uint8Array,
                         key: DataView,
                         nonce: Nonce,
                         associated_data?: Uint8Array): Uint8Array
{
    const plaintext = new Uint8Array(ciphertextAndTag.byteLength - this.TAGBYTES);
    if (!this.decrypt_detached(plaintext,
                               ciphertextAndTag,
                               plaintext.byteLength,
                               ciphertextAndTag.subarray(plaintext.byteLength),
                               key,
                               nonce,
                               associated_data)) {
        throw new AuthenticationFailure("AEAD authentication failed");
    }
    return plaintext;
}

export { ChaCha20Poly1305_RFC8439 } from './aead/chacha20poly1305.js';
