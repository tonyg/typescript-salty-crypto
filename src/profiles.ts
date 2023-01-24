import { BLAKE2s } from './blake2';
import { AEAD_CHACHA20_POLY1305_NONCEBYTES, AEAD_CHACHA20_POLY1305_TAGBYTES, aead_decrypt_detached, aead_encrypt_detached } from './aead';
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
        const c = new Uint8Array(p.byteLength + AEAD_CHACHA20_POLY1305_TAGBYTES);
        aead_encrypt_detached(p, c, p.byteLength, c.subarray(p.byteLength), key, this.serializeNonce(nonce), associated_data);
        return c;
    }

    decrypt(key: DataView, nonce: Nonce, c: Uint8Array, associated_data?: Uint8Array): Uint8Array {
        const p = new Uint8Array(c.byteLength - AEAD_CHACHA20_POLY1305_TAGBYTES);
        if (!aead_decrypt_detached(p, c, p.byteLength, c.subarray(p.byteLength), key, this.serializeNonce(nonce), associated_data)) {
            throw new Error("packet decryption failed");
        }
        return p;
    }

    serializeNonce(n: Nonce): DataView {
        const view = new DataView(new ArrayBuffer(AEAD_CHACHA20_POLY1305_NONCEBYTES));
        view.setUint32(4, n.lo, true);
        view.setUint32(8, n.hi, true);
        return view;
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
