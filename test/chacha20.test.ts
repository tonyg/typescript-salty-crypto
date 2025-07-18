import { ChaCha20, INTERNALS, Nonce } from '../dist/salty-crypto.js';
const { chacha20_quarter_round, chacha20_block } = INTERNALS.cipher.chacha20;
import { it, expect } from 'vitest';

it('chacha20_quarter_round 1', () => {
    const s = new Uint32Array(4);
    s[0] = 0x11111111;
    s[1] = 0x01020304;
    s[2] = 0x9b8d6f43;
    s[3] = 0x01234567;
    chacha20_quarter_round(s, 0, 1, 2, 3);
    expect(Array.from(s)).toEqual([0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb]);
});

it('chacha20_quarter_round 2', () => {
    const s = Uint32Array.from([
        0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a,
        0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c,
        0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963,
        0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320,
    ]);
    chacha20_quarter_round(s, 2, 7, 8, 13);
    expect(s).toEqual(Uint32Array.from([
        0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a,
        0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0xcfacafd2,
        0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963,
        0x5c971061, 0xccc07c79, 0x2098d9d6, 0x91dbd320,
    ]));
});

it('chacha20_block', () => {
    const key8 = new Uint8Array(ChaCha20.KEYBYTES);
    for (let i = 0; i < key8.length; i++) key8[i] = i;
    const key = new DataView(key8.buffer);

    const nonce8 = new Uint8Array(ChaCha20.NONCEBYTES);
    nonce8[3] = 0x09;
    nonce8[7] = 0x4a;
    const nonce = new DataView(nonce8.buffer);

    const block = 1;

    const output = chacha20_block(key, block, nonce);
    expect(output).toEqual(Uint32Array.from([
        0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
        0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
        0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
        0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2,
    ]));
});

it('chacha20', () => {
    const key8 = new Uint8Array(ChaCha20.KEYBYTES);
    for (let i = 0; i < key8.length; i++) key8[i] = i;
    const key = new DataView(key8.buffer);

    const nonce = new Nonce(0x4a000000, 0, 0);

    const initial_counter = 1;

    const sunscreen_str = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const sunscreen = new TextEncoder().encode(sunscreen_str);
    const output = new Uint8Array(sunscreen.byteLength);

    ChaCha20.stream_xor(key, nonce, sunscreen, output, initial_counter);
    expect(output).toEqual(Uint8Array.from([
        0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
        0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
        0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
        0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
        0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
        0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
        0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
        0x87, 0x4d,
    ]));

    // Test in-place encryption
    ChaCha20.stream_xor(key, nonce, sunscreen, sunscreen, initial_counter);
    expect(sunscreen).toEqual(output);
});
