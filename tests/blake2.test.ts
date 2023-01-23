import { BLAKE2s } from '../src/blake2';

test('Appendix B of RFC 7693', () => {
    expect(BLAKE2s.digest(new TextEncoder().encode("abc"))).toEqual(Uint8Array.from([
        0x50, 0x8C, 0x5E, 0x8C, 0x32, 0x7C, 0x14, 0xE2, 0xE1, 0xA7, 0x2B, 0xA3, 0x4E, 0xEB, 0x45, 0x2F,
        0x37, 0x45, 0x8B, 0x20, 0x9E, 0xD6, 0x3A, 0x29, 0x4D, 0x99, 0x9B, 0x4C, 0x86, 0x67, 0x59, 0x82,
    ]));
});

test('Appendix E of RFC 7693', () => {
    function seq(len: number, seed: number): Uint8Array {
        let a = (0xDEAD4BAD * seed) | 0;
        let b = 1;
        const out = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            const t = (a + b) | 0;
            a = b;
            b = t;
            out[i] = (t >> 24) & 0xff;
        }
        return out;
    }

    const ctx = new BLAKE2s();

    [16, 20, 28, 32].forEach(outlen => {
        [0, 3, 64, 65, 255, 1024].forEach(inlen => {
            const input = seq(inlen, inlen);
            ctx.update(BLAKE2s.digest(input, outlen));
            ctx.update(BLAKE2s.digest(input, outlen, seq(outlen, outlen)));
        });
    });

    expect(ctx.final()).toEqual(Uint8Array.from([
        0x6A, 0x41, 0x1F, 0x08, 0xCE, 0x25, 0xAD, 0xCD,
        0xFB, 0x02, 0xAB, 0xA6, 0x41, 0x45, 0x1C, 0xEC,
        0x53, 0xC5, 0x98, 0xB2, 0x4F, 0x4F, 0xC7, 0x87,
        0xFB, 0xDC, 0x88, 0x79, 0x7F, 0x4C, 0x1D, 0xFE,
    ]));
});
