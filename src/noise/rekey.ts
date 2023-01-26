/// SPDX-License-Identifier: MIT
/// SPDX-FileCopyrightText: Copyright © 2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

import { AEAD } from '../aead';
import { Nonce } from '../nonce';

export type Rekey = (k: DataView) => DataView;

export function makeRekey(aead: AEAD): Rekey {
    return (k: DataView): DataView => {
        return new DataView(aead.encrypt(new Uint8Array(32), k, Nonce.MAX).buffer);
    };
}
