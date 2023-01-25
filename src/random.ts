/// SPDX-License-Identifier: MIT
/// SPDX-FileCopyrightText: Copyright © 2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

// TypeScript port of the randomness-generation code from nacl-fast.js from tweetnacl.
//
// The comment in that file reads as follows:
//
// // Ported in 2014 by Dmitry Chestnykh and Devi Mandiri.
// // Public domain.
// //
// // Implementation derived from TweetNaCl version 20140427.
// // See for details: http://tweetnacl.cr.yp.to/

export const _randomBytes: (out: Uint8Array, n: number) => void = (() => {
    var crypto: any = typeof self !== 'undefined' ? (self.crypto || (self as any).msCrypto) : null;
    if (crypto && crypto.getRandomValues) {
        const QUOTA = 65536;
        return (x: Uint8Array, n: number) => {
            for (let i = 0; i < n; i += QUOTA) {
                crypto.getRandomValues(x.subarray(i, i + Math.min(n - i, QUOTA)));
            }
        };
    } else if (typeof require !== 'undefined') {
        crypto = require('crypto');
        if (crypto && crypto.randomBytes) {
            return (x: Uint8Array, n: number) => x.set(crypto.randomBytes(n));
        }
    }
    throw new Error("No usable randomness source found");
})();

export function randomBytes(n: number): Uint8Array {
    const bs = new Uint8Array(n);
    _randomBytes(bs, n);
    return bs;
}
