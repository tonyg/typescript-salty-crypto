/// SPDX-License-Identifier: MIT
/// SPDX-FileCopyrightText: Copyright © 2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

export class Nonce {
    constructor(public lo = 0, public hi = 0, public extra = 0) {}

    increment() {
        const oldLo = this.lo;
        const newLo = (oldLo + 1) | 0;
        this.lo = newLo;
        if (newLo < oldLo) this.hi = (this.hi + 1) | 0;
    }

    reset(lo = 0, hi = 0, extra = 0) {
        this.lo = lo;
        this.hi = hi;
        this.extra = extra;
    }

    static get MAX(): Nonce {
        return new Nonce(0xffffffff, 0xffffffff);
    }
}
