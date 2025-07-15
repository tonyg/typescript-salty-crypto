/// SPDX-License-Identifier: MIT
/// SPDX-FileCopyrightText: Copyright © 2023-2025 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

export function toHex(bs: Uint8Array): string {
    let s = '';
    bs.forEach(b => {
        s = s + '0123456789abcdef'[b >> 4];
        s = s + '0123456789abcdef'[b & 15];
    });
    return s;
}

export function fromHex(s: string): Uint8Array {
    s = s.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
    if (s.length % 2) throw new Error("Hex input contains an odd number of digits");
    const len = Math.floor(s.length / 2);
    const result = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        result[i] = parseInt(s.substring(2*i,2*i+2),16);
    }
    return result;
}

export function toBase64(bs: Uint8Array, withPadding = true): string {
    let r = '';
    bs.forEach(b => r = r + String.fromCharCode(b));
    let s = btoa(r);
    if (!withPadding) s = s.replace(/=/g, '');
    return s;
}

export function fromBase64(s: string): Uint8Array {
    const r = atob(s);
    const result = new Uint8Array(r.length);
    for (let i = 0; i < r.length; i++) result[i] = r.charCodeAt(i);
    return result;
}
