/// SPDX-License-Identifier: MIT
/// SPDX-FileCopyrightText: Copyright © 2023-2025 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

export interface Hash {
    readonly NAME: string;
    readonly KEYBYTES: number;
    readonly OUTBYTES: number;
    readonly BLOCKLEN: number;

    digest(input: Uint8Array, key?: Uint8Array, outlen?: number): Uint8Array;

    new(key?: Uint8Array, outlen?: number): HashAlgorithm;
}

export interface HashAlgorithm {
    update(input: Uint8Array, offset?: number, length?: number): void;
    final(output?: Uint8Array): Uint8Array;
}

export { BLAKE2s } from './hash/blake2s.js';
export { Poly1305 } from './hash/poly1305.js';
