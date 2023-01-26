/// SPDX-License-Identifier: MIT
/// SPDX-FileCopyrightText: Copyright © 2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

import { HMAC } from './hmac';
import * as Bytes from './bytes';

export type HKDF = {
    (chainingKey: Uint8Array, input: Uint8Array, numOutputs: 2): [Uint8Array, Uint8Array];
    (chainingKey: Uint8Array, input: Uint8Array, numOutputs: 3): [Uint8Array, Uint8Array, Uint8Array];
};

export function makeHKDF(hmac: HMAC): HKDF {
    function hkdf(chainingKey: Uint8Array, input: Uint8Array, numOutputs: 2): [Uint8Array, Uint8Array];
    function hkdf(chainingKey: Uint8Array, input: Uint8Array, numOutputs: 3): [Uint8Array, Uint8Array, Uint8Array];
    function hkdf(chainingKey: Uint8Array, input: Uint8Array, numOutputs: 2 | 3): Uint8Array[] {
        const tempKey = hmac(chainingKey, input);
        const o1 = hmac(tempKey, Uint8Array.from([1]));
        const o2 = hmac(tempKey, Bytes.append(o1, Uint8Array.from([2])));
        switch (numOutputs) {
            case 2: return [o1, o2];
            case 3: return [o1, o2, hmac(tempKey, Bytes.append(o2, Uint8Array.from([3])))];
        }
    };
    return hkdf;
}
