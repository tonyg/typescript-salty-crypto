declare class Nonce {
    lo: number;
    hi: number;
    extra: number;
    constructor(lo?: number, hi?: number, extra?: number);
    increment(): void;
    reset(lo?: number, hi?: number, extra?: number): void;
    static get MAX(): Nonce;
}

declare const ChaCha20Poly1305_RFC8439: AEAD;

declare const chacha20poly1305_ChaCha20Poly1305_RFC8439: typeof ChaCha20Poly1305_RFC8439;
declare namespace chacha20poly1305 {
  export {
    chacha20poly1305_ChaCha20Poly1305_RFC8439 as ChaCha20Poly1305_RFC8439,
  };
}

declare class AuthenticationFailure extends Error {
}
interface AEAD {
    readonly NAME: string;
    readonly KEYBYTES: number;
    readonly NONCEBYTES: number;
    readonly TAGBYTES: number;
    encrypt_detached(plaintext: Uint8Array, ciphertext: Uint8Array, messagelength: number, tag: Uint8Array, key: DataView, nonce: Nonce, associated_data?: Uint8Array): void;
    encrypt(plaintext: Uint8Array, key: DataView, nonce: Nonce, associated_data?: Uint8Array): Uint8Array;
    decrypt_detached(plaintext: Uint8Array, ciphertext: Uint8Array, messagelength: number, expected_tag: Uint8Array, key: DataView, nonce: Nonce, associated_data?: Uint8Array): boolean;
    decrypt(ciphertextAndTag: Uint8Array, key: DataView, nonce: Nonce, associated_data?: Uint8Array): Uint8Array;
}
declare function _encrypt(this: AEAD, plaintext: Uint8Array, key: DataView, nonce: Nonce, associated_data?: Uint8Array): Uint8Array;
declare function _decrypt(this: AEAD, ciphertextAndTag: Uint8Array, key: DataView, nonce: Nonce, associated_data?: Uint8Array): Uint8Array;

declare function equal(x: Uint8Array, y: Uint8Array, n: number): boolean;
declare function xor(a: Uint8Array, b: Uint8Array): Uint8Array;
declare function append(a: Uint8Array, b: Uint8Array): Uint8Array;
declare const EMPTY: Uint8Array;

declare const bytes_d_EMPTY: typeof EMPTY;
declare const bytes_d_append: typeof append;
declare const bytes_d_equal: typeof equal;
declare const bytes_d_xor: typeof xor;
declare namespace bytes_d {
  export {
    bytes_d_EMPTY as EMPTY,
    bytes_d_append as append,
    bytes_d_equal as equal,
    bytes_d_xor as xor,
  };
}

declare function chacha20_quarter_round(s: Uint32Array, a: number, b: number, c: number, d: number): void;
declare function chacha20_block(key: DataView, block: number, nonce: DataView): Uint32Array;
declare const ChaCha20: StreamCipher;

declare const chacha20_ChaCha20: typeof ChaCha20;
declare const chacha20_chacha20_block: typeof chacha20_block;
declare const chacha20_chacha20_quarter_round: typeof chacha20_quarter_round;
declare namespace chacha20 {
  export {
    chacha20_ChaCha20 as ChaCha20,
    chacha20_chacha20_block as chacha20_block,
    chacha20_chacha20_quarter_round as chacha20_quarter_round,
  };
}

interface StreamCipher {
    readonly NAME: string;
    readonly KEYBYTES: number;
    readonly NONCEBYTES: number;
    readonly BLOCKBYTES: number;
    stream_xor(key: DataView, nonce: Nonce, input: Uint8Array, output: Uint8Array, initial_counter?: number, messagelength?: number): void;
}

type DHKeyPair = {
    public: Uint8Array;
    secret: Uint8Array;
};
interface DH {
    readonly NAME: string;
    readonly DHLEN: number;
    generateKeypair(): DHKeyPair;
    dh(kp: DHKeyPair, pk: Uint8Array): Uint8Array;
}
declare const X25519: DH;

declare const BLAKE2s: {
    new (key?: Uint8Array, outlen?: number): {
        b: Uint8Array;
        bv: DataView;
        h: Uint32Array;
        t: Uint32Array;
        c: number;
        outlen: number;
        update(input: Uint8Array, offset?: number, length?: number): void;
        final(output?: Uint8Array): Uint8Array;
        compress(last: boolean): void;
    };
    readonly NAME: "BLAKE2s";
    readonly KEYBYTES: 32;
    readonly OUTBYTES: 32;
    readonly BLOCKLEN: 64;
    digest(input: Uint8Array, key?: Uint8Array, outlen?: number): Uint8Array;
};

declare const blake2s_BLAKE2s: typeof BLAKE2s;
declare namespace blake2s {
  export {
    blake2s_BLAKE2s as BLAKE2s,
  };
}

declare const Poly1305: {
    new (key?: Uint8Array, outlen?: number): {
        buffer: Uint8Array;
        r: Uint16Array;
        h: Uint16Array;
        pad: Uint16Array;
        leftover: number;
        fin: number;
        blocks(m: Uint8Array, mpos: number, bytes: number): void;
        final(mac?: Uint8Array): Uint8Array;
        update(m: Uint8Array, mpos?: number, bytes?: number): void;
    };
    readonly NAME: "Poly1305";
    readonly KEYBYTES: 32;
    readonly OUTBYTES: 16;
    readonly BLOCKLEN: 16;
    digest(input: Uint8Array, key?: Uint8Array, outlen?: number): Uint8Array;
};

declare const poly1305_Poly1305: typeof Poly1305;
declare namespace poly1305 {
  export {
    poly1305_Poly1305 as Poly1305,
  };
}

interface Hash {
    readonly NAME: string;
    readonly KEYBYTES: number;
    readonly OUTBYTES: number;
    readonly BLOCKLEN: number;
    digest(input: Uint8Array, key?: Uint8Array, outlen?: number): Uint8Array;
    new (key?: Uint8Array, outlen?: number): HashAlgorithm;
}
interface HashAlgorithm {
    update(input: Uint8Array, offset?: number, length?: number): void;
    final(output?: Uint8Array): Uint8Array;
}

type HMAC = {
    (key: Uint8Array, data: Uint8Array): Uint8Array;
    readonly NAME: string;
};
declare function makeHMAC(hash: Hash): HMAC;

type HKDF = {
    (chainingKey: Uint8Array, input: Uint8Array, numOutputs: 2): [Uint8Array, Uint8Array];
    (chainingKey: Uint8Array, input: Uint8Array, numOutputs: 3): [Uint8Array, Uint8Array, Uint8Array];
};
declare function makeHKDF(hmac: HMAC): HKDF;

type Rekey = (k: DataView) => DataView;
declare function makeRekey(aead: AEAD): Rekey;

type rekey_Rekey = Rekey;
declare const rekey_makeRekey: typeof makeRekey;
declare namespace rekey {
  export {
    rekey_Rekey as Rekey,
    rekey_makeRekey as makeRekey,
  };
}

interface Algorithms {
    dh: DH;
    aead: AEAD;
    hash: Hash;
    hmac?: HMAC;
    hkdf?: HKDF;
    rekey?: Rekey;
}
declare function matchPattern(a: Algorithms, protocol_name: string): string | null;

type algorithms_Algorithms = Algorithms;
declare const algorithms_matchPattern: typeof matchPattern;
declare namespace algorithms {
  export {
    algorithms_Algorithms as Algorithms,
    algorithms_matchPattern as matchPattern,
  };
}

declare class CipherState {
    algorithms: Algorithms;
    view: DataView | null;
    nonce: Nonce;
    constructor(algorithms: Algorithms, key?: Uint8Array);
    encrypt(plaintext: Uint8Array, associated_data?: Uint8Array): Uint8Array;
    decrypt(ciphertext: Uint8Array, associated_data?: Uint8Array): Uint8Array;
    rekey(): void;
}

type cipherstate_CipherState = CipherState;
declare const cipherstate_CipherState: typeof CipherState;
declare namespace cipherstate {
  export {
    cipherstate_CipherState as CipherState,
  };
}

type KeyTransferToken = 'e' | 's';
type KeyMixToken = 'ee' | 'es' | 'se' | 'ss' | 'psk';
type Token = KeyTransferToken | KeyMixToken;
type PreMessage = ['e'] | ['s'] | ['e', 's'] | [];
interface HandshakePattern {
    name: string;
    baseName: string;
    messages: Token[][];
    initiatorPreMessage: PreMessage;
    responderPreMessage: PreMessage;
}
declare const PATTERNS: {
    [key: string]: HandshakePattern;
};
declare function isOneWay(pat: HandshakePattern): boolean;
declare function lookupPattern(name: string): HandshakePattern | null;

type patterns_HandshakePattern = HandshakePattern;
type patterns_KeyMixToken = KeyMixToken;
type patterns_KeyTransferToken = KeyTransferToken;
declare const patterns_PATTERNS: typeof PATTERNS;
type patterns_PreMessage = PreMessage;
type patterns_Token = Token;
declare const patterns_isOneWay: typeof isOneWay;
declare const patterns_lookupPattern: typeof lookupPattern;
declare namespace patterns {
  export {
    patterns_HandshakePattern as HandshakePattern,
    patterns_KeyMixToken as KeyMixToken,
    patterns_KeyTransferToken as KeyTransferToken,
    patterns_PATTERNS as PATTERNS,
    patterns_PreMessage as PreMessage,
    patterns_Token as Token,
    patterns_isOneWay as isOneWay,
    patterns_lookupPattern as lookupPattern,
  };
}

type Role = 'initiator' | 'responder';
type HandshakeOptions = {
    prologue?: Uint8Array;
    staticKeypair?: DHKeyPair;
    remoteStaticPublicKey?: Uint8Array;
    pregeneratedEphemeralKeypair?: DHKeyPair;
    remotePregeneratedEphemeralPublicKey?: Uint8Array;
    preSharedKeys?: Uint8Array[];
};
type TransportState = {
    send: CipherState;
    recv: CipherState;
};
declare class Handshake {
    algorithms: Algorithms;
    pattern: HandshakePattern;
    role: Role;
    staticKeypair: DHKeyPair;
    remoteStaticPublicKey: Uint8Array | null;
    ephemeralKeypair: DHKeyPair;
    remoteEphemeralPublicKey: Uint8Array | null;
    preSharedKeys?: Uint8Array[];
    stepIndex: number;
    cipherState: CipherState;
    chainingKey: Uint8Array;
    handshakeHash: Uint8Array;
    hkdf: HKDF;
    constructor(algorithms: Algorithms, pattern: HandshakePattern, role: Role, options?: HandshakeOptions);
    get isInitiator(): boolean;
    mixHash(data: Uint8Array): void;
    mixKey(input: Uint8Array): void;
    mixKeyAndHashNextPSK(): void;
    encryptAndHash(p: Uint8Array): Uint8Array;
    decryptAndHash(c: Uint8Array): Uint8Array;
    _split(): TransportState | null;
    _nextStep(): Token[];
    _processKeyMixToken(t: KeyMixToken): void;
    writeMessage(payload: Uint8Array): {
        packet: Uint8Array;
        finished: TransportState | null;
    };
    readMessage(packet: Uint8Array): {
        message: Uint8Array;
        finished: TransportState | null;
    };
    completeHandshake(writePacket: (packet: Uint8Array) => Promise<void>, readPacket: () => Promise<Uint8Array>, handleMessage?: (_m: Uint8Array) => Promise<void>, produceMessage?: () => Promise<Uint8Array>): Promise<TransportState>;
}

type handshake_Handshake = Handshake;
declare const handshake_Handshake: typeof Handshake;
type handshake_HandshakeOptions = HandshakeOptions;
type handshake_Role = Role;
type handshake_TransportState = TransportState;
declare namespace handshake {
  export {
    handshake_Handshake as Handshake,
    handshake_HandshakeOptions as HandshakeOptions,
    handshake_Role as Role,
    handshake_TransportState as TransportState,
  };
}

declare const Noise_25519_ChaChaPoly_BLAKE2s: Algorithms;

declare const profiles_Noise_25519_ChaChaPoly_BLAKE2s: typeof Noise_25519_ChaChaPoly_BLAKE2s;
declare namespace profiles {
  export {
    profiles_Noise_25519_ChaChaPoly_BLAKE2s as Noise_25519_ChaChaPoly_BLAKE2s,
  };
}

declare const _randomBytes: (out: Uint8Array, n: number) => void;
declare function randomBytes(n: number): Uint8Array;

declare const crypto_scalarmult_BYTES = 32;
declare const crypto_scalarmult_SCALARBYTES = 32;
declare function crypto_scalarmult(q: Uint8Array, n: Uint8Array, p: Uint8Array): void;
declare function crypto_scalarmult_base(q: Uint8Array, n: Uint8Array): void;
declare function scalarMult(n: Uint8Array, p: Uint8Array): Uint8Array;
declare namespace scalarMult {
    var scalarLength: number;
    var groupElementLength: number;
}
declare function scalarMultBase(n: Uint8Array): Uint8Array;

declare const x25519_crypto_scalarmult: typeof crypto_scalarmult;
declare const x25519_crypto_scalarmult_BYTES: typeof crypto_scalarmult_BYTES;
declare const x25519_crypto_scalarmult_SCALARBYTES: typeof crypto_scalarmult_SCALARBYTES;
declare const x25519_crypto_scalarmult_base: typeof crypto_scalarmult_base;
declare const x25519_scalarMult: typeof scalarMult;
declare const x25519_scalarMultBase: typeof scalarMultBase;
declare namespace x25519 {
  export {
    x25519_crypto_scalarmult as crypto_scalarmult,
    x25519_crypto_scalarmult_BYTES as crypto_scalarmult_BYTES,
    x25519_crypto_scalarmult_SCALARBYTES as crypto_scalarmult_SCALARBYTES,
    x25519_crypto_scalarmult_base as crypto_scalarmult_base,
    x25519_scalarMult as scalarMult,
    x25519_scalarMultBase as scalarMultBase,
  };
}

declare const INTERNALS: {
    aead: {
        chacha20poly1305: typeof chacha20poly1305;
    };
    cipher: {
        chacha20: typeof chacha20;
    };
    dh: {
        x25519: typeof x25519;
    };
    hash: {
        blake2s: typeof blake2s;
        poly1305: typeof poly1305;
    };
    noise: {
        algorithms: typeof algorithms;
        cipherstate: typeof cipherstate;
        handshake: typeof handshake;
        patterns: typeof patterns;
        profiles: typeof profiles;
        rekey: typeof rekey;
    };
};

export { AEAD, Algorithms, AuthenticationFailure, BLAKE2s, bytes_d as Bytes, ChaCha20, ChaCha20Poly1305_RFC8439, CipherState, DH, DHKeyPair, HKDF, HMAC, Handshake, HandshakeOptions, HandshakePattern, Hash, HashAlgorithm, INTERNALS, KeyMixToken, KeyTransferToken, Noise_25519_ChaChaPoly_BLAKE2s, Nonce, PATTERNS, Poly1305, PreMessage, Rekey, Role, StreamCipher, Token, TransportState, X25519, _decrypt, _encrypt, _randomBytes, isOneWay, lookupPattern, makeHKDF, makeHMAC, matchPattern, randomBytes };
