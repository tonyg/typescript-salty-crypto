/// SPDX-License-Identifier: MIT
/// SPDX-FileCopyrightText: Copyright © 2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

import { Hash } from './hash.js';
import * as Bytes from './bytes.js';

export type HMAC = {
    (key: Uint8Array, data: Uint8Array): Uint8Array;
    readonly NAME: string;
};

export function makeHMAC(hash: Hash): HMAC {
    const HMAC_IPAD = new Uint8Array(hash.BLOCKLEN); HMAC_IPAD.fill(0x36);
    const HMAC_OPAD = new Uint8Array(hash.BLOCKLEN); HMAC_OPAD.fill(0x5c);
    const hmac = (key0: Uint8Array, data: Uint8Array) => {
        const key1 = key0.byteLength > hash.BLOCKLEN ? hash.digest(key0) : key0;
        const key = Bytes.append(key1, new Uint8Array(hash.BLOCKLEN - key1.byteLength));
        return hash.digest(Bytes.append(Bytes.xor(key, HMAC_OPAD),
                                        hash.digest(Bytes.append(Bytes.xor(key, HMAC_IPAD),
                                                                 data))));
    };
    hmac.NAME = 'HMAC-' + hash.NAME;
    return hmac;
}
