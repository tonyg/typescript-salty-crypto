import { IO } from '../../dist/salty-crypto.js';
import { describe, it, expect } from '../harness';

describe('basic', async () => {
    const s =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +
        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" +
        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" +
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" +
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
        "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
        "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

    const s64 =
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v" +
        "MDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5f" +
        "YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6P" +
        "kJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/" +
        "wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v" +
        "8PHy8/T19vf4+fr7/P3+/w==";
    const s64_nopadding =
        s64.replace(/=/g, '');

    const bs = new Uint8Array(256);
    for (let i = 0; i < bs.byteLength; i++) bs[i] = i;

    await describe('hex', async () => {
        await it('encode', () => expect(IO.toHex(bs)).toEqual(s));
        await it('decode', () => expect(IO.fromHex(s)).toEqual(bs));
    });

    await describe('base64', async () => {
        await it('encode', () => expect(IO.toBase64(bs)).toEqual(s64));
        await it('encode with padding', () => expect(IO.toBase64(bs, true)).toEqual(s64));
        await it('encode without padding', () => expect(IO.toBase64(bs, false)).toEqual(s64_nopadding));
        await it('decode', () => expect(IO.fromBase64(s64)).toEqual(bs));
        await it('decode without padding', () => expect(IO.fromBase64(s64_nopadding)).toEqual(bs));
    });
});

describe('liberal decoding hex', async () => {
    await it('with spaces', () => expect(IO.fromHex('ab cd ef\n01 23 45')).toEqual(
        Uint8Array.from([171, 205, 239, 1, 35, 69])));
    await it('with odd number of digits', () => expect(() =>
        IO.fromHex('ab cd f\n01 23 45')).toThrow("Hex input contains an odd number of digits"));
    await it('with non-hex garbage', () => expect(IO.fromHex('ab-cd-ef\n01-23-45')).toEqual(
        Uint8Array.from([171, 205, 239, 1, 35, 69])));
});
