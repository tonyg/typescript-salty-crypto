/// SPDX-License-Identifier: MIT
/// SPDX-FileCopyrightText: Copyright © 2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

import { DHKeyPair } from '../dh';
import * as Bytes from '../bytes';

import { Algorithms } from './algorithms';
import { CipherState } from './cipherstate';
import { HandshakePattern, KeyMixToken, Token } from './patterns';
import { HKDF, makeHKDF } from '../hkdf';
import { makeHMAC } from '../hmac';

export type Role = 'initiator' | 'responder';

export type HandshakeOptions = {
    prologue?: Uint8Array,
    staticKeypair?: DHKeyPair,
    remoteStaticPublicKey?: Uint8Array,
    pregeneratedEphemeralKeypair?: DHKeyPair,
    remotePregeneratedEphemeralPublicKey?: Uint8Array,
    preSharedKeys?: Uint8Array[],
};

export type TransportState = { send: CipherState, recv: CipherState };

export class Handshake {
    staticKeypair: DHKeyPair;
    remoteStaticPublicKey: Uint8Array | null;
    ephemeralKeypair: DHKeyPair;
    remoteEphemeralPublicKey: Uint8Array | null;
    preSharedKeys?: Uint8Array[];
    stepIndex = 0;
    cipherState: CipherState;
    chainingKey: Uint8Array;
    handshakeHash: Uint8Array;
    hkdf: HKDF;

    constructor (public algorithms: Algorithms,
                 public pattern: HandshakePattern,
                 public role: Role,
                 options: HandshakeOptions = {})
    {
        this.staticKeypair = options.staticKeypair ?? this.algorithms.dh.generateKeypair();
        this.remoteStaticPublicKey = options.remoteStaticPublicKey ?? null;
        this.ephemeralKeypair = options.pregeneratedEphemeralKeypair ?? this.algorithms.dh.generateKeypair();
        this.remoteEphemeralPublicKey = options.remotePregeneratedEphemeralPublicKey ?? null;
        this.preSharedKeys = options.preSharedKeys;
        if (this.preSharedKeys) {
            this.preSharedKeys = this.preSharedKeys.slice();
            if (this.preSharedKeys.length === 0) this.preSharedKeys = void 0;
        }

        const protocolName = new TextEncoder().encode(
            'Noise_' + this.pattern.name +
                '_' + this.algorithms.dh.NAME +
                '_' + this.algorithms.aead.NAME +
                '_' + this.algorithms.hash.NAME);

        this.cipherState = new CipherState(this.algorithms);
        {
            const ckLen = this.algorithms.hash.OUTBYTES;
            const ckSeed = (protocolName.byteLength > ckLen)
                ? this.algorithms.hash.digest(protocolName)
                : protocolName;
            this.chainingKey = Bytes.append(ckSeed, new Uint8Array(ckLen - ckSeed.byteLength));
        }
        this.handshakeHash = this.chainingKey;

        this.mixHash(options.prologue ?? Bytes.EMPTY);
        this.pattern.initiatorPreMessage.forEach(t => this.mixHash(t === 'e'
            ? (this.isInitiator ? this.ephemeralKeypair.public : this.remoteEphemeralPublicKey!)
            : (this.isInitiator ? this.staticKeypair.public : this.remoteStaticPublicKey!)));
        this.pattern.responderPreMessage.forEach(t => this.mixHash(t === 'e'
            ? (!this.isInitiator ? this.ephemeralKeypair.public : this.remoteEphemeralPublicKey!)
            : (!this.isInitiator ? this.staticKeypair.public : this.remoteStaticPublicKey!)));

        this.hkdf = this.algorithms.hkdf ?? makeHKDF(
            this.algorithms.hmac ?? makeHMAC(this.algorithms.hash));
    }

    get isInitiator(): boolean {
        return this.role === 'initiator';
    }

    mixHash(data: Uint8Array) {
        this.handshakeHash = this.algorithms.hash.digest(Bytes.append(this.handshakeHash, data));
    }

    mixKey(input: Uint8Array) {
        const [newCk, k] = this.hkdf(this.chainingKey, input, 2);
        this.chainingKey = newCk;
        this.cipherState = new CipherState(this.algorithms, k);
    }

    mixKeyAndHashNextPSK() {
        const psk = this.preSharedKeys!.shift()!;
        const [newCk, tempH, k] = this.hkdf(this.chainingKey, psk, 3);
        this.chainingKey = newCk;
        this.mixHash(tempH);
        this.cipherState = new CipherState(this.algorithms, k);
    }

    encryptAndHash(p: Uint8Array) {
        const c = this.cipherState.encrypt(p, this.handshakeHash);
        this.mixHash(c);
        return c;
    }

    decryptAndHash(c: Uint8Array) {
        const p = this.cipherState.decrypt(c, this.handshakeHash);
        this.mixHash(c);
        return p;
    }

    _split(): TransportState | null {
        if (this.stepIndex < this.pattern.messages.length) {
            return null;
        } else {
            let [kI, kR] = this.hkdf(this.chainingKey, Bytes.EMPTY, 2)
                .map(k => new CipherState(this.algorithms, k));
            return this.isInitiator ? { send: kI, recv: kR } : { send: kR, recv: kI };
        }
    }

    _nextStep(): Token[] {
        if (this.stepIndex >= this.pattern.messages.length) {
            throw new Error("Handshake already complete, cannot continue");
        }
        return this.pattern.messages[this.stepIndex++];
    }

    _processKeyMixToken(t: KeyMixToken) {
        switch (t) {
            case 'ee':
                this.mixKey(this.algorithms.dh.dh(this.ephemeralKeypair, this.remoteEphemeralPublicKey!));
                break;

            case 'es':
                this.mixKey(this.isInitiator
                    ? this.algorithms.dh.dh(this.ephemeralKeypair, this.remoteStaticPublicKey!)
                    : this.algorithms.dh.dh(this.staticKeypair, this.remoteEphemeralPublicKey!));
                break;

            case 'se':
                this.mixKey(!this.isInitiator
                    ? this.algorithms.dh.dh(this.ephemeralKeypair, this.remoteStaticPublicKey!)
                    : this.algorithms.dh.dh(this.staticKeypair, this.remoteEphemeralPublicKey!));
                break;

            case 'ss':
                this.mixKey(this.algorithms.dh.dh(this.staticKeypair, this.remoteStaticPublicKey!));
                break;

            case 'psk':
                this.mixKeyAndHashNextPSK();
                break;
        }
    }

    writeMessage(payload: Uint8Array): { packet: Uint8Array, finished: TransportState | null } {
        const pieces = [];
        this._nextStep().forEach(t => {
            switch (t) {
                case 'e':
                    pieces.push(this.ephemeralKeypair.public);
                    this.mixHash(this.ephemeralKeypair.public);
                    if (this.preSharedKeys) this.mixKey(this.ephemeralKeypair.public);
                    break;

                case 's':
                    pieces.push(this.encryptAndHash(this.staticKeypair.public));
                    break;

                default:
                    this._processKeyMixToken(t);
                    break;
            }
        });
        pieces.push(this.encryptAndHash(payload));

        let packet: Uint8Array;
        if (pieces.length === 1) {
            packet = pieces[0];
        } else {
            packet = new Uint8Array(pieces.reduce((ac, p) => ac + p.byteLength, 0));
            let offset = 0;
            pieces.forEach(p => { packet.set(p, offset); offset += p.byteLength; });
        }

        return { packet, finished: this._split() };
    }

    readMessage(packet: Uint8Array): { message: Uint8Array, finished: TransportState | null } {
        const take = (n: number): Uint8Array => {
            const bs = packet.slice(0, n);
            packet = packet.subarray(n);
            return bs;
        };
        this._nextStep().forEach(t => {
            switch (t) {
                case 'e':
                    this.remoteEphemeralPublicKey = take(this.algorithms.dh.DHLEN);
                    this.mixHash(this.remoteEphemeralPublicKey);
                    if (this.preSharedKeys) this.mixKey(this.remoteEphemeralPublicKey);
                    break;

                case 's':
                    this.remoteStaticPublicKey = this.decryptAndHash(take(
                        this.algorithms.dh.DHLEN + (this.cipherState.view ? 16 : 0)));
                    break;

                default:
                    this._processKeyMixToken(t);
                    break;
            }
        });

        const message = this.decryptAndHash(packet);
        return { message, finished: this._split() };
    }

    async completeHandshake(writePacket: (packet: Uint8Array) => Promise<void>,
                            readPacket: () => Promise<Uint8Array>,
                            handleMessage = async (_m: Uint8Array): Promise<void> => {},
                            produceMessage = async (): Promise<Uint8Array> => new Uint8Array(0))
    : Promise<TransportState>
    {
        const W = async (): Promise<TransportState> => {
            const { packet, finished } = this.writeMessage(await produceMessage());
            await writePacket(packet);
            return finished || R();
        };
        const R = async (): Promise<TransportState> => {
            const { message, finished } = this.readMessage(await readPacket());
            await handleMessage(message);
            return finished || W();
        };
        return (this.isInitiator ? W() : R());
    }
}
