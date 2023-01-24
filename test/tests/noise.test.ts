import { DHKeyPair, NoiseHandshake, NoiseProtocolAlgorithms, TransportState } from '../../src/noise';
import { isOneWay, lookupPattern } from '../../src/patterns';
import { Noise_25519_ChaChaPoly_BLAKE2s } from '../../src/profiles';
import { scalarMultBase } from '../../src/x25519';
import { describe, it, expect } from '../harness';

import fs from 'fs';
import path from 'path';

type OldTest = {
    name: string,

    init_prologue?: string,
    init_ephemeral?: string,
    init_static?: string,
    init_remote_static?: string,
    init_psk?: string,

    resp_prologue?: string,
    resp_ephemeral?: string,
    resp_static?: string,
    resp_remote_static?: string,
    resp_psk?: string,

    messages: Array<{
        payload: string,
        ciphertext: string,
    }>,
};

type CurrentTest = {
    protocol_name: string,

    init_prologue?: string,
    init_ephemeral?: string,
    init_static?: string,
    init_remote_static?: string,
    init_psks?: string[],

    resp_prologue?: string,
    resp_ephemeral?: string,
    resp_static?: string,
    resp_remote_static?: string,
    resp_psks?: string[],

    messages: Array<{
        payload: string,
        ciphertext: string,
    }>,
};

type Test = OldTest | CurrentTest;

function unhex(s: string): Uint8Array;
function unhex(s: undefined): undefined;
function unhex(s: string | undefined): Uint8Array | undefined;
function unhex(s: string | undefined): Uint8Array | undefined {
    if (s === void 0) return void 0;
    return Uint8Array.from(Buffer.from(s, 'hex'));
}

function hex(bs: Uint8Array): string {
    return Buffer.from(bs).toString('hex');
}

function skToKeypair(sk: Uint8Array | undefined): DHKeyPair | undefined {
    if (sk === void 0) return void 0;
    return {
        public: scalarMultBase(sk),
        secret: sk,
    };
}

const unit = (v: string | undefined): [string] | undefined => v === void 0 ? void 0 : [v];

async function testsuite_test(t: Test, algorithms: NoiseProtocolAlgorithms) {
    const isOld = 'name' in t;
    const patternName = algorithms.matchingPattern(isOld ? t.name : t.protocol_name);
    if (!patternName) return;
    const pattern = lookupPattern(patternName);
    if (!pattern) return;
    const oneWay = isOneWay(pattern);

    await it(pattern.name, async () => {
        const I = new NoiseHandshake(algorithms, pattern, 'initiator', {
            prologue: unhex(t.init_prologue),
            staticKeypair: skToKeypair(unhex(t.init_static)),
            remoteStaticPublicKey: unhex(t.init_remote_static),
            pregeneratedEphemeralKeypair: skToKeypair(unhex(t.init_ephemeral)),
            preSharedKeys: (isOld ? unit(t.init_psk) : t.init_psks)?.map(k => unhex(k)),
        });
        const R = new NoiseHandshake(algorithms, pattern, 'responder', {
            prologue: unhex(t.resp_prologue),
            staticKeypair: skToKeypair(unhex(t.resp_static)),
            remoteStaticPublicKey: unhex(t.resp_remote_static),
            pregeneratedEphemeralKeypair: skToKeypair(unhex(t.resp_ephemeral)),
            preSharedKeys: (isOld ? unit(t.resp_psk) : t.resp_psks)?.map(k => unhex(k)),
        });
        let sender = I;
        let receiver = R;
        let senderCss: TransportState | null = null;
        let receiverCss: TransportState | null = null;
        function swapRoles() {
            const t = sender; sender = receiver; receiver = t;
            const c = senderCss; senderCss = receiverCss; receiverCss = c;
        }
        for (let step = 0; step < t.messages.length; step++) {
            const m = t.messages[step];
            if (senderCss && receiverCss) {
                const actualCiphertext = senderCss.send.encrypt(unhex(m.payload));
                expect(hex(actualCiphertext)).toEqual(m.ciphertext);
                const actualMessage = receiverCss.recv.decrypt(actualCiphertext);
                expect(hex(actualMessage)).toEqual(m.payload);
            } else {
                const { packet: actualCiphertext, finished: senderFinished } =
                    sender.writeMessage(unhex(m.payload));
                expect(hex(actualCiphertext)).toEqual(m.ciphertext);
                const { message: actualMessage, finished: receiverFinished } =
                    receiver.readMessage(actualCiphertext);
                expect(hex(actualMessage)).toEqual(m.payload);
                expect(senderFinished).toEqual(receiverFinished);
                senderCss = senderFinished;
                receiverCss = receiverFinished;
            }
            if (!oneWay) swapRoles();
        };
    });
}

(async () => {
    const algorithms = new Noise_25519_ChaChaPoly_BLAKE2s();
    const load = (n: string) => JSON.parse(fs.readFileSync(path.join('test-vectors', n), 'utf-8'));

    await describe('https://github.com/mcginty/snow/', async () => {
        for (const t of load('snow.txt').vectors as Test[]) {
            await testsuite_test(t, algorithms);
        }
    });
    await describe('https://github.com/rweather/noise-c/', async () => {
        for (const t of load('noise-c-basic.txt').vectors as Test[]) {
            await testsuite_test(t, algorithms);
        }
    });
})();
