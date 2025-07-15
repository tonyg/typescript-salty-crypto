/// SPDX-License-Identifier: MIT
/// SPDX-FileCopyrightText: Copyright © 2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

import { AEAD } from '../aead.js';
import { Hash } from '../hash.js';
import { DH } from '../dh.js';
import { HMAC } from '../hmac.js';
import { HKDF } from '../hkdf.js';

import { Rekey } from './rekey.js';

export interface Algorithms {
    dh: DH,
    aead: AEAD,
    hash: Hash,
    hmac?: HMAC,
    hkdf?: HKDF,
    rekey?: Rekey,
}

export function matchPattern(a: Algorithms, protocol_name: string): string | null {
    const r = new RegExp(`^Noise_([A-Za-z0-9+]+)_${a.dh.NAME}_${a.aead.NAME}_${a.hash.NAME}$`);
    const m = r.exec(protocol_name);
    if (m === null) return null;
    return m[1];
}
