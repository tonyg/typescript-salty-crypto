declare const AEAD_CHACHA20_POLY1305_KEYBYTES = 32;
declare const AEAD_CHACHA20_POLY1305_NONCEBYTES = 12;
declare const AEAD_CHACHA20_POLY1305_TAGBYTES = 16;
declare function aead_encrypt_detached(plaintext: Uint8Array, ciphertext: Uint8Array, messagelength: number, tag: Uint8Array, key: DataView, nonce: DataView, associated_data?: Uint8Array): void;
declare function aead_encrypt(plaintext: Uint8Array, key: DataView, nonce: DataView, associated_data?: Uint8Array): Uint8Array;
declare function aead_decrypt_detached(plaintext: Uint8Array, ciphertext: Uint8Array, messagelength: number, expected_tag: Uint8Array, key: DataView, nonce: DataView, associated_data?: Uint8Array): boolean;
declare class AuthenticationFailure extends Error {
}
declare function aead_decrypt(ciphertextAndTag: Uint8Array, key: DataView, nonce: DataView, associated_data?: Uint8Array): Uint8Array;

declare const aead_d_AEAD_CHACHA20_POLY1305_KEYBYTES: typeof AEAD_CHACHA20_POLY1305_KEYBYTES;
declare const aead_d_AEAD_CHACHA20_POLY1305_NONCEBYTES: typeof AEAD_CHACHA20_POLY1305_NONCEBYTES;
declare const aead_d_AEAD_CHACHA20_POLY1305_TAGBYTES: typeof AEAD_CHACHA20_POLY1305_TAGBYTES;
type aead_d_AuthenticationFailure = AuthenticationFailure;
declare const aead_d_AuthenticationFailure: typeof AuthenticationFailure;
declare const aead_d_aead_decrypt: typeof aead_decrypt;
declare const aead_d_aead_decrypt_detached: typeof aead_decrypt_detached;
declare const aead_d_aead_encrypt: typeof aead_encrypt;
declare const aead_d_aead_encrypt_detached: typeof aead_encrypt_detached;
declare namespace aead_d {
  export {
    aead_d_AEAD_CHACHA20_POLY1305_KEYBYTES as AEAD_CHACHA20_POLY1305_KEYBYTES,
    aead_d_AEAD_CHACHA20_POLY1305_NONCEBYTES as AEAD_CHACHA20_POLY1305_NONCEBYTES,
    aead_d_AEAD_CHACHA20_POLY1305_TAGBYTES as AEAD_CHACHA20_POLY1305_TAGBYTES,
    aead_d_AuthenticationFailure as AuthenticationFailure,
    aead_d_aead_decrypt as aead_decrypt,
    aead_d_aead_decrypt_detached as aead_decrypt_detached,
    aead_d_aead_encrypt as aead_encrypt,
    aead_d_aead_encrypt_detached as aead_encrypt_detached,
  };
}

declare class BLAKE2s {
    outlen: number;
    static readonly KEYBYTES = 32;
    static readonly OUTBYTES = 32;
    static readonly BLOCKLEN = 64;
    b: Uint8Array;
    bv: DataView;
    h: Uint32Array;
    t: Uint32Array;
    c: number;
    static digest(input: Uint8Array, outlen?: number, key?: Uint8Array): Uint8Array;
    constructor(outlen?: number, key?: Uint8Array);
    update(input: Uint8Array): void;
    final(output?: Uint8Array): Uint8Array;
    compress(last: boolean): void;
}

type blake2_d_BLAKE2s = BLAKE2s;
declare const blake2_d_BLAKE2s: typeof BLAKE2s;
declare namespace blake2_d {
  export {
    blake2_d_BLAKE2s as BLAKE2s,
  };
}

declare const CHACHA20_KEYBYTES = 32;
declare const CHACHA20_NONCEBYTES = 12;
declare const CHACHA20_BLOCKBYTES = 64;
declare function chacha20_quarter_round(s: Uint32Array, a: number, b: number, c: number, d: number): void;
declare function chacha20_block(key: DataView, block: number, nonce: DataView): Uint32Array;
declare function chacha20(key: DataView, nonce: DataView, input: Uint8Array, output: Uint8Array, initial_counter?: number, messagelength?: number): void;

declare const chacha20_d_CHACHA20_BLOCKBYTES: typeof CHACHA20_BLOCKBYTES;
declare const chacha20_d_CHACHA20_KEYBYTES: typeof CHACHA20_KEYBYTES;
declare const chacha20_d_CHACHA20_NONCEBYTES: typeof CHACHA20_NONCEBYTES;
declare const chacha20_d_chacha20: typeof chacha20;
declare const chacha20_d_chacha20_block: typeof chacha20_block;
declare const chacha20_d_chacha20_quarter_round: typeof chacha20_quarter_round;
declare namespace chacha20_d {
  export {
    chacha20_d_CHACHA20_BLOCKBYTES as CHACHA20_BLOCKBYTES,
    chacha20_d_CHACHA20_KEYBYTES as CHACHA20_KEYBYTES,
    chacha20_d_CHACHA20_NONCEBYTES as CHACHA20_NONCEBYTES,
    chacha20_d_chacha20 as chacha20,
    chacha20_d_chacha20_block as chacha20_block,
    chacha20_d_chacha20_quarter_round as chacha20_quarter_round,
  };
}

type DHKeyPair = {
    public: Uint8Array;
    secret: Uint8Array;
};
declare class Nonce {
    lo: number;
    hi: number;
    constructor(lo?: number, hi?: number);
    increment(): void;
    reset(lo?: number, hi?: number): void;
    static get MAX(): Nonce;
}
declare function bytesXor(a: Uint8Array, b: Uint8Array): Uint8Array;
declare function bytesAppend(a: Uint8Array, b: Uint8Array): Uint8Array;
type HMAC = (key: Uint8Array, data: Uint8Array) => Uint8Array;
declare abstract class NoiseProtocolAlgorithms {
    readonly dhlen: number;
    readonly hmac: HMAC;
    constructor(hmac?: HMAC);
    abstract dhName(): string;
    abstract generateKeypair(): DHKeyPair;
    abstract dh(kp: DHKeyPair, pk: Uint8Array): Uint8Array;
    abstract cipherName(): string;
    abstract encrypt(key: DataView, nonce: Nonce, p: Uint8Array, associated_data?: Uint8Array): Uint8Array;
    abstract decrypt(key: DataView, nonce: Nonce, c: Uint8Array, associated_data?: Uint8Array): Uint8Array;
    abstract hashName(): string;
    abstract hash(data: Uint8Array): Uint8Array;
    abstract hashBlocklen(): number;
    rekey(k: DataView): DataView;
    _padOrHash(bs0: Uint8Array, len: number): Uint8Array;
    hkdf(chainingKey: Uint8Array, input: Uint8Array, numOutputs: 2): [Uint8Array, Uint8Array];
    hkdf(chainingKey: Uint8Array, input: Uint8Array, numOutputs: 3): [Uint8Array, Uint8Array, Uint8Array];
    matchingPattern(protocol_name: string): string | null;
}
interface HandshakePattern {
    name: string;
    baseName: string;
    messages: Token[][];
    initiatorPreMessage: PreMessage;
    responderPreMessage: PreMessage;
}
declare class CipherState {
    algorithms: NoiseProtocolAlgorithms;
    view: DataView | null;
    nonce: Nonce;
    constructor(algorithms: NoiseProtocolAlgorithms, key?: Uint8Array);
    encrypt(plaintext: Uint8Array, associated_data?: Uint8Array): Uint8Array;
    decrypt(ciphertext: Uint8Array, associated_data?: Uint8Array): Uint8Array;
    rekey(): void;
}
type Role = 'initiator' | 'responder';
type NoiseProtocolOptions = {
    prologue?: Uint8Array;
    staticKeypair?: DHKeyPair;
    remoteStaticPublicKey?: Uint8Array;
    pregeneratedEphemeralKeypair?: DHKeyPair;
    remotePregeneratedEphemeralPublicKey?: Uint8Array;
    preSharedKeys?: Uint8Array[];
};
type KeyTransferToken = 'e' | 's';
type KeyMixToken = 'ee' | 'es' | 'se' | 'ss' | 'psk';
type Token = KeyTransferToken | KeyMixToken;
type PreMessage = ['e'] | ['s'] | ['e', 's'] | [];
type TransportState = {
    send: CipherState;
    recv: CipherState;
};
declare class NoiseHandshake {
    algorithms: NoiseProtocolAlgorithms;
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
    constructor(algorithms: NoiseProtocolAlgorithms, pattern: HandshakePattern, role: Role, options?: NoiseProtocolOptions);
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

type noise_d_CipherState = CipherState;
declare const noise_d_CipherState: typeof CipherState;
type noise_d_DHKeyPair = DHKeyPair;
type noise_d_HMAC = HMAC;
type noise_d_HandshakePattern = HandshakePattern;
type noise_d_KeyMixToken = KeyMixToken;
type noise_d_KeyTransferToken = KeyTransferToken;
type noise_d_NoiseHandshake = NoiseHandshake;
declare const noise_d_NoiseHandshake: typeof NoiseHandshake;
type noise_d_NoiseProtocolAlgorithms = NoiseProtocolAlgorithms;
declare const noise_d_NoiseProtocolAlgorithms: typeof NoiseProtocolAlgorithms;
type noise_d_NoiseProtocolOptions = NoiseProtocolOptions;
type noise_d_Nonce = Nonce;
declare const noise_d_Nonce: typeof Nonce;
type noise_d_PreMessage = PreMessage;
type noise_d_Role = Role;
type noise_d_Token = Token;
type noise_d_TransportState = TransportState;
declare const noise_d_bytesAppend: typeof bytesAppend;
declare const noise_d_bytesXor: typeof bytesXor;
declare namespace noise_d {
  export {
    noise_d_CipherState as CipherState,
    noise_d_DHKeyPair as DHKeyPair,
    noise_d_HMAC as HMAC,
    noise_d_HandshakePattern as HandshakePattern,
    noise_d_KeyMixToken as KeyMixToken,
    noise_d_KeyTransferToken as KeyTransferToken,
    noise_d_NoiseHandshake as NoiseHandshake,
    noise_d_NoiseProtocolAlgorithms as NoiseProtocolAlgorithms,
    noise_d_NoiseProtocolOptions as NoiseProtocolOptions,
    noise_d_Nonce as Nonce,
    noise_d_PreMessage as PreMessage,
    noise_d_Role as Role,
    noise_d_Token as Token,
    noise_d_TransportState as TransportState,
    noise_d_bytesAppend as bytesAppend,
    noise_d_bytesXor as bytesXor,
  };
}

declare const PATTERNS: {
    [key: string]: HandshakePattern;
};
declare function isOneWay(pat: HandshakePattern): boolean;
declare function lookupPattern(name: string): HandshakePattern | null;

declare const patterns_d_PATTERNS: typeof PATTERNS;
declare const patterns_d_isOneWay: typeof isOneWay;
declare const patterns_d_lookupPattern: typeof lookupPattern;
declare namespace patterns_d {
  export {
    patterns_d_PATTERNS as PATTERNS,
    patterns_d_isOneWay as isOneWay,
    patterns_d_lookupPattern as lookupPattern,
  };
}

declare class Poly1305 {
    key: Uint8Array;
    static readonly KEYBYTES = 32;
    static readonly TAGBYTES = 16;
    static readonly BLOCKBYTES = 16;
    buffer: Uint8Array;
    r: Uint16Array;
    h: Uint16Array;
    pad: Uint16Array;
    leftover: number;
    fin: number;
    static digest(key: Uint8Array, input: Uint8Array): Uint8Array;
    constructor(key: Uint8Array);
    blocks(m: Uint8Array, mpos: number, bytes: number): void;
    finish(mac: Uint8Array, macpos: number): void;
    update(m: Uint8Array, mpos: number, bytes: number): void;
}

type poly1305_d_Poly1305 = Poly1305;
declare const poly1305_d_Poly1305: typeof Poly1305;
declare namespace poly1305_d {
  export {
    poly1305_d_Poly1305 as Poly1305,
  };
}

declare class Noise_25519_ChaChaPoly_BLAKE2s extends NoiseProtocolAlgorithms {
    constructor();
    dhName(): string;
    generateKeypair(): DHKeyPair;
    dh(kp: DHKeyPair, pk: Uint8Array): Uint8Array;
    cipherName(): string;
    encrypt(key: DataView, nonce: Nonce, p: Uint8Array, associated_data?: Uint8Array): Uint8Array;
    decrypt(key: DataView, nonce: Nonce, c: Uint8Array, associated_data?: Uint8Array): Uint8Array;
    hashName(): string;
    hash(data: Uint8Array): Uint8Array;
    hashBlocklen(): number;
}

type profiles_d_Noise_25519_ChaChaPoly_BLAKE2s = Noise_25519_ChaChaPoly_BLAKE2s;
declare const profiles_d_Noise_25519_ChaChaPoly_BLAKE2s: typeof Noise_25519_ChaChaPoly_BLAKE2s;
declare namespace profiles_d {
  export {
    profiles_d_Noise_25519_ChaChaPoly_BLAKE2s as Noise_25519_ChaChaPoly_BLAKE2s,
  };
}

declare const _randomBytes: (out: Uint8Array, n: number) => void;
declare function randomBytes(n: number): Uint8Array;

declare const random_d__randomBytes: typeof _randomBytes;
declare const random_d_randomBytes: typeof randomBytes;
declare namespace random_d {
  export {
    random_d__randomBytes as _randomBytes,
    random_d_randomBytes as randomBytes,
  };
}

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

declare const x25519_d_crypto_scalarmult: typeof crypto_scalarmult;
declare const x25519_d_crypto_scalarmult_BYTES: typeof crypto_scalarmult_BYTES;
declare const x25519_d_crypto_scalarmult_SCALARBYTES: typeof crypto_scalarmult_SCALARBYTES;
declare const x25519_d_crypto_scalarmult_base: typeof crypto_scalarmult_base;
declare const x25519_d_scalarMult: typeof scalarMult;
declare const x25519_d_scalarMultBase: typeof scalarMultBase;
declare namespace x25519_d {
  export {
    x25519_d_crypto_scalarmult as crypto_scalarmult,
    x25519_d_crypto_scalarmult_BYTES as crypto_scalarmult_BYTES,
    x25519_d_crypto_scalarmult_SCALARBYTES as crypto_scalarmult_SCALARBYTES,
    x25519_d_crypto_scalarmult_base as crypto_scalarmult_base,
    x25519_d_scalarMult as scalarMult,
    x25519_d_scalarMultBase as scalarMultBase,
  };
}

export { aead_d as AEAD, blake2_d as BLAKE2, chacha20_d as ChaCha20, noise_d as Noise, profiles_d as NoiseProfiles, patterns_d as Patterns, poly1305_d as Poly1305, random_d as Random, x25519_d as X25519 };
