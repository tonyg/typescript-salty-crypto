/// SPDX-License-Identifier: MIT
/// SPDX-FileCopyrightText: Copyright © 2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

export type DHKeyPair = { public: Uint8Array, secret: Uint8Array };

export class Nonce {
    constructor(public lo = 0, public hi = 0) {}

    increment() {
        const oldLo = this.lo;
        const newLo = (oldLo + 1) | 0;
        this.lo = newLo;
        if (newLo < oldLo) this.hi = (this.hi + 1) | 0;
    }

    reset(lo = 0, hi = 0) {
        this.lo = lo;
        this.hi = hi;
    }

    static get MAX(): Nonce {
        return new Nonce(0xffffffff, 0xffffffff);
    }
}

export function bytesXor(a: Uint8Array, b: Uint8Array): Uint8Array {
    const len = Math.min(a.byteLength, b.byteLength);
    const r = new Uint8Array(len);
    for (let i = 0; i < len; i++) r[i] = a[i] ^ b[i];
    return r;
}

export function bytesAppend(a: Uint8Array, b: Uint8Array): Uint8Array {
    const r = new Uint8Array(a.byteLength + b.byteLength);
    r.set(a, 0);
    r.set(b, a.byteLength);
    return r;
}

const EMPTY_BYTES = new Uint8Array(0);

export type HMAC = (key: Uint8Array, data: Uint8Array) => Uint8Array;

function makeHMAC(algorithms: NoiseProtocolAlgorithms): HMAC {
    const HMAC_IPAD = new Uint8Array(algorithms.hashBlocklen()); HMAC_IPAD.fill(0x36);
    const HMAC_OPAD = new Uint8Array(algorithms.hashBlocklen()); HMAC_OPAD.fill(0x5c);
    return (key0, data) => {
        const key = algorithms._padOrHash(key0, algorithms.hashBlocklen());
        return algorithms.hash(bytesAppend(bytesXor(key, HMAC_OPAD),
                                           algorithms.hash(bytesAppend(bytesXor(key, HMAC_IPAD),
                                                                       data))));
    };
}

export abstract class NoiseProtocolAlgorithms {
    readonly dhlen: number;
    readonly hmac: HMAC;

    constructor (hmac?: HMAC) {
        const tmp = this.generateKeypair();
        this.dhlen = this.dh(tmp, tmp.public).byteLength;
        this.hmac = hmac ?? makeHMAC(this);
    }

    abstract dhName(): string;
    abstract generateKeypair(): DHKeyPair;
    abstract dh(kp: DHKeyPair, pk: Uint8Array): Uint8Array;

    abstract cipherName(): string;
    abstract encrypt(key: DataView, nonce: Nonce, p: Uint8Array, associated_data?: Uint8Array): Uint8Array;
    abstract decrypt(key: DataView, nonce: Nonce, c: Uint8Array, associated_data?: Uint8Array): Uint8Array;

    abstract hashName(): string;
    abstract hash(data: Uint8Array): Uint8Array;
    abstract hashBlocklen(): number;

    rekey(k: DataView): DataView {
        return new DataView(this.encrypt(k, Nonce.MAX, new Uint8Array(32)).buffer);
    }

    _padOrHash(bs0: Uint8Array, len: number): Uint8Array {
        const bs = bs0.byteLength > len ? this.hash(bs0) : bs0;
        return bytesAppend(bs, new Uint8Array(len - bs.byteLength));
    }

    hkdf(chainingKey: Uint8Array, input: Uint8Array, numOutputs: 2): [Uint8Array, Uint8Array];
    hkdf(chainingKey: Uint8Array, input: Uint8Array, numOutputs: 3): [Uint8Array, Uint8Array, Uint8Array];
    hkdf(chainingKey: Uint8Array, input: Uint8Array, numOutputs: 2 | 3): Uint8Array[] {
        const tempKey = this.hmac(chainingKey, input);
        const o1 = this.hmac(tempKey, Uint8Array.from([1]));
        const o2 = this.hmac(tempKey, bytesAppend(o1, Uint8Array.from([2])));
        switch (numOutputs) {
            case 2: return [o1, o2];
            case 3: return [o1, o2, this.hmac(tempKey, bytesAppend(o2, Uint8Array.from([3])))];
        }
    }

    matchingPattern(protocol_name: string): string | null {
        const r = new RegExp(`^Noise_([A-Za-z0-9+]+)_${this.dhName()}_${this.cipherName()}_${this.hashName()}$`);
        const m = r.exec(protocol_name);
        if (m === null) return null;
        return m[1];
    }
}

export interface HandshakePattern {
    name: string; // e.g. "NNpsk2"
    baseName: string; // e.g. "NN"
    messages: Token[][];
    initiatorPreMessage: PreMessage;
    responderPreMessage: PreMessage;
}

export class CipherState {
    view: DataView | null = null;
    nonce = new Nonce();

    constructor (public algorithms: NoiseProtocolAlgorithms,
                 key?: Uint8Array)
    {
        if (key !== void 0) this.view = new DataView(key.buffer);
    }

    encrypt(plaintext: Uint8Array, associated_data?: Uint8Array): Uint8Array {
        if (this.view === null) return plaintext;
        const ciphertext = this.algorithms.encrypt(this.view, this.nonce, plaintext, associated_data);
        this.nonce.increment();
        return ciphertext;
    }

    decrypt(ciphertext: Uint8Array, associated_data?: Uint8Array): Uint8Array {
        if (this.view === null) return ciphertext;
        const plaintext = this.algorithms.decrypt(this.view, this.nonce, ciphertext, associated_data);
        this.nonce.increment();
        return plaintext;
    }

    rekey() {
        if (this.view === null) return;
        this.view = this.algorithms.rekey(this.view);
    }
}

export type Role = 'initiator' | 'responder';

export type NoiseProtocolOptions = {
    prologue?: Uint8Array,
    staticKeypair?: DHKeyPair,
    remoteStaticPublicKey?: Uint8Array,
    pregeneratedEphemeralKeypair?: DHKeyPair,
    remotePregeneratedEphemeralPublicKey?: Uint8Array,
    preSharedKeys?: Uint8Array[],
};

export type KeyTransferToken = 'e' | 's';
export type KeyMixToken = 'ee' | 'es' | 'se' | 'ss' | 'psk';
export type Token = KeyTransferToken | KeyMixToken;
export type PreMessage = ['e'] | ['s'] | ['e', 's'] | [];

export type TransportState = { send: CipherState, recv: CipherState };

export class NoiseHandshake {
    staticKeypair: DHKeyPair;
    remoteStaticPublicKey: Uint8Array | null;
    ephemeralKeypair: DHKeyPair;
    remoteEphemeralPublicKey: Uint8Array | null;
    preSharedKeys?: Uint8Array[];
    stepIndex = 0;
    cipherState: CipherState;
    chainingKey: Uint8Array;
    handshakeHash: Uint8Array;

    constructor (public algorithms: NoiseProtocolAlgorithms,
                 public pattern: HandshakePattern,
                 public role: Role,
                 options: NoiseProtocolOptions = {})
    {
        this.staticKeypair = options.staticKeypair ?? this.algorithms.generateKeypair();
        this.remoteStaticPublicKey = options.remoteStaticPublicKey ?? null;
        this.ephemeralKeypair = options.pregeneratedEphemeralKeypair ?? this.algorithms.generateKeypair();
        this.remoteEphemeralPublicKey = options.remotePregeneratedEphemeralPublicKey ?? null;
        this.preSharedKeys = options.preSharedKeys;
        if (this.preSharedKeys) {
            this.preSharedKeys = this.preSharedKeys.slice();
            if (this.preSharedKeys.length === 0) this.preSharedKeys = void 0;
        }

        const protocolName = new TextEncoder().encode(
            'Noise_' + this.pattern.name +
                '_' + this.algorithms.dhName() +
                '_' + this.algorithms.cipherName() +
                '_' + this.algorithms.hashName());

        this.cipherState = new CipherState(this.algorithms);
        this.chainingKey = this.algorithms._padOrHash(
            protocolName,
            this.algorithms.hash(EMPTY_BYTES).byteLength);
        this.handshakeHash = this.chainingKey;

        this.mixHash(options.prologue ?? EMPTY_BYTES);
        this.pattern.initiatorPreMessage.forEach(t => this.mixHash(t === 'e'
            ? (this.isInitiator ? this.ephemeralKeypair.public : this.remoteEphemeralPublicKey!)
            : (this.isInitiator ? this.staticKeypair.public : this.remoteStaticPublicKey!)));
        this.pattern.responderPreMessage.forEach(t => this.mixHash(t === 'e'
            ? (!this.isInitiator ? this.ephemeralKeypair.public : this.remoteEphemeralPublicKey!)
            : (!this.isInitiator ? this.staticKeypair.public : this.remoteStaticPublicKey!)));
    }

    get isInitiator(): boolean {
        return this.role === 'initiator';
    }

    mixHash(data: Uint8Array) {
        this.handshakeHash = this.algorithms.hash(bytesAppend(this.handshakeHash, data));
    }

    mixKey(input: Uint8Array) {
        const [newCk, k] = this.algorithms.hkdf(this.chainingKey, input, 2);
        this.chainingKey = newCk;
        this.cipherState = new CipherState(this.algorithms, k);
    }

    mixKeyAndHashNextPSK() {
        const psk = this.preSharedKeys!.shift()!;
        const [newCk, tempH, k] = this.algorithms.hkdf(this.chainingKey, psk, 3);
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
            let [kI, kR] = this.algorithms.hkdf(this.chainingKey, EMPTY_BYTES, 2)
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
                this.mixKey(this.algorithms.dh(this.ephemeralKeypair, this.remoteEphemeralPublicKey!));
                break;

            case 'es':
                this.mixKey(this.isInitiator
                    ? this.algorithms.dh(this.ephemeralKeypair, this.remoteStaticPublicKey!)
                    : this.algorithms.dh(this.staticKeypair, this.remoteEphemeralPublicKey!));
                break;

            case 'se':
                this.mixKey(!this.isInitiator
                    ? this.algorithms.dh(this.ephemeralKeypair, this.remoteStaticPublicKey!)
                    : this.algorithms.dh(this.staticKeypair, this.remoteEphemeralPublicKey!));
                break;

            case 'ss':
                this.mixKey(this.algorithms.dh(this.staticKeypair, this.remoteStaticPublicKey!));
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
                    this.remoteEphemeralPublicKey = take(this.algorithms.dhlen);
                    this.mixHash(this.remoteEphemeralPublicKey);
                    if (this.preSharedKeys) this.mixKey(this.remoteEphemeralPublicKey);
                    break;

                case 's':
                    this.remoteStaticPublicKey = this.decryptAndHash(take(
                        this.algorithms.dhlen + (this.cipherState.view ? 16 : 0)));
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
