/// SPDX-License-Identifier: MIT
/// SPDX-FileCopyrightText: Copyright © 2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

import { BLAKE2s } from './blake2';
import { AEAD_CHACHA20_POLY1305_NONCEBYTES, AEAD_CHACHA20_POLY1305_TAGBYTES, aead_decrypt, aead_encrypt } from './aead';
import { DHKeyPair, NoiseProtocolAlgorithms, Nonce } from './noise';
import { randomBytes } from './random';
import { scalarMult, scalarMultBase } from './x25519';

export class Noise_25519_ChaChaPoly_BLAKE2s extends NoiseProtocolAlgorithms {
    constructor () {
        super();
    }

    dhName(): string {
        return '25519';
    }

    generateKeypair(): DHKeyPair {
        const sk = randomBytes(scalarMult.scalarLength);
        const pk = scalarMultBase(sk);
        return { public: pk, secret: sk };
    }

    dh(kp: DHKeyPair, pk: Uint8Array): Uint8Array {
        return scalarMult(kp.secret, pk);
    }

    cipherName(): string {
        return 'ChaChaPoly';
    }

    encrypt(key: DataView, nonce: Nonce, p: Uint8Array, associated_data?: Uint8Array): Uint8Array {
        return aead_encrypt(p, key, serializeNonce(nonce), associated_data);
    }

    decrypt(key: DataView, nonce: Nonce, c: Uint8Array, associated_data?: Uint8Array): Uint8Array {
        return aead_decrypt(c, key, serializeNonce(nonce), associated_data);
    }

    hashName(): string {
        return "BLAKE2s";
    }

    hash(data: Uint8Array): Uint8Array {
        return BLAKE2s.digest(data);
    }

    hashBlocklen(): number {
        return BLAKE2s.BLOCKLEN;
    }
}

function serializeNonce(n: Nonce): DataView {
    const view = new DataView(new ArrayBuffer(AEAD_CHACHA20_POLY1305_NONCEBYTES));
    view.setUint32(4, n.lo, true);
    view.setUint32(8, n.hi, true);
    return view;
}
