/// SPDX-License-Identifier: MIT
/// SPDX-FileCopyrightText: Copyright © 2023-2025 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

import { randomBytes } from "./random.js";
import { scalarMult, scalarMultBase } from "./dh/x25519.js";

export type DHKeyPair = { public: Uint8Array, secret: Uint8Array };

export interface DH {
    readonly NAME: string;
    readonly DHLEN: number;

    generateKeypair(): DHKeyPair;
    dh(kp: DHKeyPair, pk: Uint8Array): Uint8Array;
}

export const X25519: DH = {
    NAME: "25519",
    DHLEN: scalarMult.groupElementLength,

    generateKeypair(): DHKeyPair {
        const sk = randomBytes(scalarMult.scalarLength);
        const pk = scalarMultBase(sk);
        return { public: pk, secret: sk };
    },

    dh(kp: DHKeyPair, pk: Uint8Array): Uint8Array {
        return scalarMult(kp.secret, pk);
    }
};
