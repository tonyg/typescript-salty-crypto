/// SPDX-License-Identifier: MIT
/// SPDX-FileCopyrightText: Copyright © 2023-2025 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

// RFC 7693 BLAKE2s, ported from the C code therein.

import type { Hash, HashAlgorithm } from '../hash.js';

function ROTR32(n: number, bits: number): number {
    return (n >>> bits) | (n << (32 - bits));
}

function B2S_G(v: Uint32Array, a: number, b: number, c: number, d: number, x: number, y: number) {
    v[a] = v[a] + v[b] + x;
    v[d] = ROTR32(v[d] ^ v[a], 16);
    v[c] = v[c] + v[d];
    v[b] = ROTR32(v[b] ^ v[c], 12);
    v[a] = v[a] + v[b] + y;
    v[d] = ROTR32(v[d] ^ v[a], 8);
    v[c] = v[c] + v[d];
    v[b] = ROTR32(v[b] ^ v[c], 7);
}

const blake2s_iv = Uint32Array.from([
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
]);

const _sigma = Uint8Array.from([
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
    11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
    7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
    9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
    2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
    12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
    13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
    6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
    10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
]);

function sigma(i: number, j: number): number {
    return _sigma[(i << 4) + j];
}

export const BLAKE2s = (class BLAKE2s implements HashAlgorithm {
    static readonly NAME = "BLAKE2s";
    static readonly KEYBYTES = 32;
    static readonly OUTBYTES = 32;
    static readonly BLOCKLEN = 64;

    b = new Uint8Array(64);
    bv = new DataView(this.b.buffer);

    h = Uint32Array.from(blake2s_iv);
    t = new Uint32Array(2);
    c = 0;

    static digest(input: Uint8Array, key?: Uint8Array, outlen?: number, ): Uint8Array {
        const p = new BLAKE2s(key, outlen);
        p.update(input);
        return p.final();
    }

    constructor(key?: Uint8Array, public outlen: number = BLAKE2s.OUTBYTES)
    {
        const keylen = key?.byteLength ?? 0;

        if (outlen == 0 || outlen > 32 || keylen > 32) {
            throw new Error("illegal BLAKE2s parameter length(s)");
        }

        this.h[0] ^= 0x01010000 ^ (keylen << 8) ^ outlen;

        if (key && keylen > 0) {
            this.update(key);
            this.c = 64;
        }
    }

    update(input: Uint8Array, offset = 0, length = input.byteLength) {
        for (let i = offset; i < offset + length; i++) {
            if (this.c == 64) {
                this.t[0] += this.c;
                if (this.t[0] < this.c) this.t[1]++;
                this.compress(false);
                this.c = 0;
            }
            this.b[this.c++] = input[i];
        }
    }

    final(output?: Uint8Array): Uint8Array {
        this.t[0] += this.c;
        if (this.t[0] < this.c) this.t[1]++;

        while (this.c < 64) this.b[this.c++] = 0;
        this.compress(true);

        if (output === void 0) output = new Uint8Array(this.outlen);
        for (let i = 0; i < this.outlen; i++) {
            output[i] = (this.h[i >> 2] >> (8 * (i & 3))) & 0xFF;
        }
        return output;
    }

    compress(last: boolean) {
        const v = new Uint32Array(16);
        const m = new Uint32Array(16);

        for (let i = 0; i < 8; i++) {
            v[i] = this.h[i];
            v[i + 8] = blake2s_iv[i];
        }

        v[12] ^= this.t[0];
        v[13] ^= this.t[1];
        if (last) v[14] = ~v[14];

        for (let i = 0; i < 16; i++) {
            m[i] = this.bv.getUint32(i << 2, true);
        }

        for (let i = 0; i < 10; i++) {
            B2S_G(v, 0, 4,  8, 12, m[sigma(i,  0)], m[sigma(i,  1)]);
            B2S_G(v, 1, 5,  9, 13, m[sigma(i,  2)], m[sigma(i,  3)]);
            B2S_G(v, 2, 6, 10, 14, m[sigma(i,  4)], m[sigma(i,  5)]);
            B2S_G(v, 3, 7, 11, 15, m[sigma(i,  6)], m[sigma(i,  7)]);
            B2S_G(v, 0, 5, 10, 15, m[sigma(i,  8)], m[sigma(i,  9)]);
            B2S_G(v, 1, 6, 11, 12, m[sigma(i, 10)], m[sigma(i, 11)]);
            B2S_G(v, 2, 7,  8, 13, m[sigma(i, 12)], m[sigma(i, 13)]);
            B2S_G(v, 3, 4,  9, 14, m[sigma(i, 14)], m[sigma(i, 15)]);
        }

        for (let i = 0; i < 8; i++) {
            this.h[i] ^= v[i] ^ v[i + 8];
        }
    }
}) satisfies Hash;
