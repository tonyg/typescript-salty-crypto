/// SPDX-License-Identifier: MIT
/// SPDX-FileCopyrightText: Copyright © 2023-2025 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

// TypeScript port of the "poly1305" class from nacl-fast.js from tweetnacl.
//
// The comment attached to the class in that file reads as follows:
// /*
// * Port of Andrew Moon's Poly1305-donna-16. Public domain.
// * https://github.com/floodyberry/poly1305-donna
// */

import type { Hash, HashAlgorithm } from '../hash.js';

export const Poly1305 = (class Poly1305 implements HashAlgorithm {
    static readonly NAME = "Poly1305";
    static readonly KEYBYTES = 32;
    static readonly OUTBYTES = 16;
    static readonly BLOCKLEN = 16;

    buffer = new Uint8Array(16);
    r = new Uint16Array(10);
    h = new Uint16Array(10);
    pad = new Uint16Array(8);
    leftover = 0;
    fin = 0;

    static digest(input: Uint8Array, key?: Uint8Array, outlen?: number): Uint8Array {
        const p = new Poly1305(key, outlen);
        p.update(input);
        return p.final();
    }

    constructor(key?: Uint8Array, outlen?: number) {
        if (!key) throw new Error("Poly1305: key required");
        if ((outlen ?? Poly1305.OUTBYTES) !== Poly1305.OUTBYTES) throw new Error("Poly1305: outlen != OUTBYTES");

        const t0 = key[ 0] & 0xff | (key[ 1] & 0xff) << 8; this.r[0] = ( t0                     ) & 0x1fff;
        const t1 = key[ 2] & 0xff | (key[ 3] & 0xff) << 8; this.r[1] = ((t0 >>> 13) | (t1 <<  3)) & 0x1fff;
        const t2 = key[ 4] & 0xff | (key[ 5] & 0xff) << 8; this.r[2] = ((t1 >>> 10) | (t2 <<  6)) & 0x1f03;
        const t3 = key[ 6] & 0xff | (key[ 7] & 0xff) << 8; this.r[3] = ((t2 >>>  7) | (t3 <<  9)) & 0x1fff;
        const t4 = key[ 8] & 0xff | (key[ 9] & 0xff) << 8; this.r[4] = ((t3 >>>  4) | (t4 << 12)) & 0x00ff;
        this.r[5] = ((t4 >>>  1)) & 0x1ffe;
        const t5 = key[10] & 0xff | (key[11] & 0xff) << 8; this.r[6] = ((t4 >>> 14) | (t5 <<  2)) & 0x1fff;
        const t6 = key[12] & 0xff | (key[13] & 0xff) << 8; this.r[7] = ((t5 >>> 11) | (t6 <<  5)) & 0x1f81;
        const t7 = key[14] & 0xff | (key[15] & 0xff) << 8; this.r[8] = ((t6 >>>  8) | (t7 <<  8)) & 0x1fff;
        this.r[9] = ((t7 >>>  5)) & 0x007f;

        this.pad[0] = key[16] & 0xff | (key[17] & 0xff) << 8;
        this.pad[1] = key[18] & 0xff | (key[19] & 0xff) << 8;
        this.pad[2] = key[20] & 0xff | (key[21] & 0xff) << 8;
        this.pad[3] = key[22] & 0xff | (key[23] & 0xff) << 8;
        this.pad[4] = key[24] & 0xff | (key[25] & 0xff) << 8;
        this.pad[5] = key[26] & 0xff | (key[27] & 0xff) << 8;
        this.pad[6] = key[28] & 0xff | (key[29] & 0xff) << 8;
        this.pad[7] = key[30] & 0xff | (key[31] & 0xff) << 8;
    }

    blocks(m: Uint8Array, mpos: number, bytes: number) {
        const hibit = this.fin ? 0 : (1 << 11);

        let h0 = this.h[0];
        let h1 = this.h[1];
        let h2 = this.h[2];
        let h3 = this.h[3];
        let h4 = this.h[4];
        let h5 = this.h[5];
        let h6 = this.h[6];
        let h7 = this.h[7];
        let h8 = this.h[8];
        let h9 = this.h[9];

        let r0 = this.r[0];
        let r1 = this.r[1];
        let r2 = this.r[2];
        let r3 = this.r[3];
        let r4 = this.r[4];
        let r5 = this.r[5];
        let r6 = this.r[6];
        let r7 = this.r[7];
        let r8 = this.r[8];
        let r9 = this.r[9];

        while (bytes >= 16) {
            const t0 = m[mpos + 0] & 0xff | (m[mpos + 1] & 0xff) << 8; h0 += (t0) & 0x1fff;
            const t1 = m[mpos + 2] & 0xff | (m[mpos + 3] & 0xff) << 8; h1 += ((t0 >>> 13) | (t1 << 3)) & 0x1fff;
            const t2 = m[mpos + 4] & 0xff | (m[mpos + 5] & 0xff) << 8; h2 += ((t1 >>> 10) | (t2 << 6)) & 0x1fff;
            const t3 = m[mpos + 6] & 0xff | (m[mpos + 7] & 0xff) << 8; h3 += ((t2 >>> 7) | (t3 << 9)) & 0x1fff;
            const t4 = m[mpos + 8] & 0xff | (m[mpos + 9] & 0xff) << 8; h4 += ((t3 >>> 4) | (t4 << 12)) & 0x1fff;
            h5 += ((t4 >>> 1)) & 0x1fff;
            const t5 = m[mpos + 10] & 0xff | (m[mpos + 11] & 0xff) << 8; h6 += ((t4 >>> 14) | (t5 << 2)) & 0x1fff;
            const t6 = m[mpos + 12] & 0xff | (m[mpos + 13] & 0xff) << 8; h7 += ((t5 >>> 11) | (t6 << 5)) & 0x1fff;
            const t7 = m[mpos + 14] & 0xff | (m[mpos + 15] & 0xff) << 8; h8 += ((t6 >>> 8) | (t7 << 8)) & 0x1fff;
            h9 += ((t7 >>> 5)) | hibit;

            let c = 0;

            let d0 = c;
            d0 += h0 * r0;
            d0 += h1 * (5 * r9);
            d0 += h2 * (5 * r8);
            d0 += h3 * (5 * r7);
            d0 += h4 * (5 * r6);
            c = (d0 >>> 13); d0 &= 0x1fff;
            d0 += h5 * (5 * r5);
            d0 += h6 * (5 * r4);
            d0 += h7 * (5 * r3);
            d0 += h8 * (5 * r2);
            d0 += h9 * (5 * r1);
            c += (d0 >>> 13); d0 &= 0x1fff;

            let d1 = c;
            d1 += h0 * r1;
            d1 += h1 * r0;
            d1 += h2 * (5 * r9);
            d1 += h3 * (5 * r8);
            d1 += h4 * (5 * r7);
            c = (d1 >>> 13); d1 &= 0x1fff;
            d1 += h5 * (5 * r6);
            d1 += h6 * (5 * r5);
            d1 += h7 * (5 * r4);
            d1 += h8 * (5 * r3);
            d1 += h9 * (5 * r2);
            c += (d1 >>> 13); d1 &= 0x1fff;

            let d2 = c;
            d2 += h0 * r2;
            d2 += h1 * r1;
            d2 += h2 * r0;
            d2 += h3 * (5 * r9);
            d2 += h4 * (5 * r8);
            c = (d2 >>> 13); d2 &= 0x1fff;
            d2 += h5 * (5 * r7);
            d2 += h6 * (5 * r6);
            d2 += h7 * (5 * r5);
            d2 += h8 * (5 * r4);
            d2 += h9 * (5 * r3);
            c += (d2 >>> 13); d2 &= 0x1fff;

            let d3 = c;
            d3 += h0 * r3;
            d3 += h1 * r2;
            d3 += h2 * r1;
            d3 += h3 * r0;
            d3 += h4 * (5 * r9);
            c = (d3 >>> 13); d3 &= 0x1fff;
            d3 += h5 * (5 * r8);
            d3 += h6 * (5 * r7);
            d3 += h7 * (5 * r6);
            d3 += h8 * (5 * r5);
            d3 += h9 * (5 * r4);
            c += (d3 >>> 13); d3 &= 0x1fff;

            let d4 = c;
            d4 += h0 * r4;
            d4 += h1 * r3;
            d4 += h2 * r2;
            d4 += h3 * r1;
            d4 += h4 * r0;
            c = (d4 >>> 13); d4 &= 0x1fff;
            d4 += h5 * (5 * r9);
            d4 += h6 * (5 * r8);
            d4 += h7 * (5 * r7);
            d4 += h8 * (5 * r6);
            d4 += h9 * (5 * r5);
            c += (d4 >>> 13); d4 &= 0x1fff;

            let d5 = c;
            d5 += h0 * r5;
            d5 += h1 * r4;
            d5 += h2 * r3;
            d5 += h3 * r2;
            d5 += h4 * r1;
            c = (d5 >>> 13); d5 &= 0x1fff;
            d5 += h5 * r0;
            d5 += h6 * (5 * r9);
            d5 += h7 * (5 * r8);
            d5 += h8 * (5 * r7);
            d5 += h9 * (5 * r6);
            c += (d5 >>> 13); d5 &= 0x1fff;

            let d6 = c;
            d6 += h0 * r6;
            d6 += h1 * r5;
            d6 += h2 * r4;
            d6 += h3 * r3;
            d6 += h4 * r2;
            c = (d6 >>> 13); d6 &= 0x1fff;
            d6 += h5 * r1;
            d6 += h6 * r0;
            d6 += h7 * (5 * r9);
            d6 += h8 * (5 * r8);
            d6 += h9 * (5 * r7);
            c += (d6 >>> 13); d6 &= 0x1fff;

            let d7 = c;
            d7 += h0 * r7;
            d7 += h1 * r6;
            d7 += h2 * r5;
            d7 += h3 * r4;
            d7 += h4 * r3;
            c = (d7 >>> 13); d7 &= 0x1fff;
            d7 += h5 * r2;
            d7 += h6 * r1;
            d7 += h7 * r0;
            d7 += h8 * (5 * r9);
            d7 += h9 * (5 * r8);
            c += (d7 >>> 13); d7 &= 0x1fff;

            let d8 = c;
            d8 += h0 * r8;
            d8 += h1 * r7;
            d8 += h2 * r6;
            d8 += h3 * r5;
            d8 += h4 * r4;
            c = (d8 >>> 13); d8 &= 0x1fff;
            d8 += h5 * r3;
            d8 += h6 * r2;
            d8 += h7 * r1;
            d8 += h8 * r0;
            d8 += h9 * (5 * r9);
            c += (d8 >>> 13); d8 &= 0x1fff;

            let d9 = c;
            d9 += h0 * r9;
            d9 += h1 * r8;
            d9 += h2 * r7;
            d9 += h3 * r6;
            d9 += h4 * r5;
            c = (d9 >>> 13); d9 &= 0x1fff;
            d9 += h5 * r4;
            d9 += h6 * r3;
            d9 += h7 * r2;
            d9 += h8 * r1;
            d9 += h9 * r0;
            c += (d9 >>> 13); d9 &= 0x1fff;

            c = (((c << 2) + c)) | 0;
            c = (c + d0) | 0;
            d0 = c & 0x1fff;
            c = (c >>> 13);
            d1 += c;

            h0 = d0;
            h1 = d1;
            h2 = d2;
            h3 = d3;
            h4 = d4;
            h5 = d5;
            h6 = d6;
            h7 = d7;
            h8 = d8;
            h9 = d9;

            mpos += 16;
            bytes -= 16;
        }

        this.h[0] = h0;
        this.h[1] = h1;
        this.h[2] = h2;
        this.h[3] = h3;
        this.h[4] = h4;
        this.h[5] = h5;
        this.h[6] = h6;
        this.h[7] = h7;
        this.h[8] = h8;
        this.h[9] = h9;
    }

    final(mac?: Uint8Array): Uint8Array {
        if (!mac) mac = new Uint8Array(Poly1305.OUTBYTES);

        if (this.leftover) {
            let i = this.leftover;
            this.buffer[i++] = 1;
            for (; i < 16; i++) this.buffer[i] = 0;
            this.fin = 1;
            this.blocks(this.buffer, 0, 16);
        }

        let c = this.h[1] >>> 13;
        this.h[1] &= 0x1fff;
        for (let i = 2; i < 10; i++) {
            this.h[i] += c;
            c = this.h[i] >>> 13;
            this.h[i] &= 0x1fff;
        }
        this.h[0] += (c * 5);
        c = this.h[0] >>> 13;
        this.h[0] &= 0x1fff;
        this.h[1] += c;
        c = this.h[1] >>> 13;
        this.h[1] &= 0x1fff;
        this.h[2] += c;

        const g = new Uint16Array(10);
        g[0] = this.h[0] + 5;
        c = g[0] >>> 13;
        g[0] &= 0x1fff;
        for (let i = 1; i < 10; i++) {
            g[i] = this.h[i] + c;
            c = g[i] >>> 13;
            g[i] &= 0x1fff;
        }
        g[9] -= (1 << 13);

        let mask = (c ^ 1) - 1;
        for (let i = 0; i < 10; i++) g[i] &= mask;
        mask = ~mask;
        for (let i = 0; i < 10; i++) this.h[i] = (this.h[i] & mask) | g[i];

        this.h[0] = ((this.h[0]) | (this.h[1] << 13)) & 0xffff;
        this.h[1] = ((this.h[1] >>> 3) | (this.h[2] << 10)) & 0xffff;
        this.h[2] = ((this.h[2] >>> 6) | (this.h[3] << 7)) & 0xffff;
        this.h[3] = ((this.h[3] >>> 9) | (this.h[4] << 4)) & 0xffff;
        this.h[4] = ((this.h[4] >>> 12) | (this.h[5] << 1) | (this.h[6] << 14)) & 0xffff;
        this.h[5] = ((this.h[6] >>> 2) | (this.h[7] << 11)) & 0xffff;
        this.h[6] = ((this.h[7] >>> 5) | (this.h[8] << 8)) & 0xffff;
        this.h[7] = ((this.h[8] >>> 8) | (this.h[9] << 5)) & 0xffff;

        let f = this.h[0] + this.pad[0];
        this.h[0] = f & 0xffff;
        for (let i = 1; i < 8; i++) {
            f = (((this.h[i] + this.pad[i]) | 0) + (f >>> 16)) | 0;
            this.h[i] = f & 0xffff;
        }

        mac[0] = (this.h[0] >>> 0) & 0xff;
        mac[1] = (this.h[0] >>> 8) & 0xff;
        mac[2] = (this.h[1] >>> 0) & 0xff;
        mac[3] = (this.h[1] >>> 8) & 0xff;
        mac[4] = (this.h[2] >>> 0) & 0xff;
        mac[5] = (this.h[2] >>> 8) & 0xff;
        mac[6] = (this.h[3] >>> 0) & 0xff;
        mac[7] = (this.h[3] >>> 8) & 0xff;
        mac[8] = (this.h[4] >>> 0) & 0xff;
        mac[9] = (this.h[4] >>> 8) & 0xff;
        mac[10] = (this.h[5] >>> 0) & 0xff;
        mac[11] = (this.h[5] >>> 8) & 0xff;
        mac[12] = (this.h[6] >>> 0) & 0xff;
        mac[13] = (this.h[6] >>> 8) & 0xff;
        mac[14] = (this.h[7] >>> 0) & 0xff;
        mac[15] = (this.h[7] >>> 8) & 0xff;
        return mac;
    };

    update(m: Uint8Array, mpos = 0, bytes = m.byteLength) {
        if (this.leftover) {
            let want = (16 - this.leftover);
            if (want > bytes)
                want = bytes;
            for (let i = 0; i < want; i++)
                this.buffer[this.leftover + i] = m[mpos + i];
            bytes -= want;
            mpos += want;
            this.leftover += want;
            if (this.leftover < 16)
                return;
            this.blocks(this.buffer, 0, 16);
            this.leftover = 0;
        }

        if (bytes >= 16) {
            const want = bytes - (bytes % 16);
            this.blocks(m, mpos, want);
            mpos += want;
            bytes -= want;
        }

        if (bytes) {
            for (let i = 0; i < bytes; i++)
                this.buffer[this.leftover + i] = m[mpos + i];
            this.leftover += bytes;
        }
    }
}) satisfies Hash;
