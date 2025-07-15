/// SPDX-License-Identifier: MIT
/// SPDX-FileCopyrightText: Copyright © 2023-2025 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

// `verify` from nacl-fast.js
function verify(x: Uint8Array, y: Uint8Array, n: number): number {
    let d = 0;
    for (let i = 0; i < n; i++) d |= x[i]^y[i];
    return (1 & ((d - 1) >>> 8)) - 1;
}

export function equal(x: Uint8Array, y: Uint8Array, n: number): boolean {
    return verify(x, y, n) === 0;
}

export function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
    const len = Math.min(a.byteLength, b.byteLength);
    const r = new Uint8Array(len);
    for (let i = 0; i < len; i++) r[i] = a[i] ^ b[i];
    return r;
}

export function append(a: Uint8Array, b: Uint8Array): Uint8Array {
    const r = new Uint8Array(a.byteLength + b.byteLength);
    r.set(a, 0);
    r.set(b, a.byteLength);
    return r;
}

export const EMPTY = new Uint8Array(0);
