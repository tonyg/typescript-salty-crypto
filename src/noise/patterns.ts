/// SPDX-License-Identifier: MIT
/// SPDX-FileCopyrightText: Copyright © 2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

export type KeyTransferToken = 'e' | 's';
export type KeyMixToken = 'ee' | 'es' | 'se' | 'ss' | 'psk';
export type Token = KeyTransferToken | KeyMixToken;
export type PreMessage = ['e'] | ['s'] | ['e', 's'] | [];

export interface HandshakePattern {
    name: string; // e.g. "NNpsk2"
    baseName: string; // e.g. "NN"
    messages: Token[][];
    initiatorPreMessage: PreMessage;
    responderPreMessage: PreMessage;
}

export const PATTERNS: { [key: string]: HandshakePattern } = {};

function _p(
    name: string,
    messages: Token[][],
    initiatorPreMessage: PreMessage,
    responderPreMessage: PreMessage,
) {
    const pat = { name, baseName: name, messages, initiatorPreMessage, responderPreMessage };
    PATTERNS[pat.name] = pat;
}

_p("I1K1", [["e","s"],["e","ee","es"],["se"]], [], ["s"]);
_p("I1K", [["e","es","s"],["e","ee"],["se"]], [], ["s"]);
_p("I1N", [["e","s"],["e","ee"],["se"]], [], []);
_p("I1X1", [["e","s"],["e","ee","s"],["se","es"]], [], []);
_p("I1X", [["e","s"],["e","ee","s","es"],["se"]], [], []);
_p("IK1", [["e","s"],["e","ee","se","es"]], [], ["s"]);
_p("IK", [["e","es","s","ss"],["e","ee","se"]], [], ["s"]);
_p("IN", [["e","s"],["e","ee","se"]], [], []);
_p("IX1", [["e","s"],["e","ee","se","s"],["es"]], [], []);
_p("IX", [["e","s"],["e","ee","se","s","es"]], [], []);
_p("K1K1", [["e"],["e","ee","es"],["se"]], ["s"], ["s"]);
_p("K1K", [["e","es"],["e","ee"],["se"]], ["s"], ["s"]);
_p("K1N", [["e"],["e","ee"],["se"]], ["s"], []);
_p("K1X1", [["e"],["e","ee","s"],["se","es"]], ["s"], []);
_p("K1X", [["e"],["e","ee","s","es"],["se"]], ["s"], []);
_p("K", [["e","es","ss"]], ["s"], ["s"]);
_p("KK1", [["e"],["e","ee","se","es"]], ["s"], ["s"]);
_p("KK", [["e","es","ss"],["e","ee","se"]], ["s"], ["s"]);
_p("KN", [["e"],["e","ee","se"]], ["s"], []);
_p("KX1", [["e"],["e","ee","se","s"],["es"]], ["s"], []);
_p("KX", [["e"],["e","ee","se","s","es"]], ["s"], []);
_p("N", [["e","es"]], [], ["s"]);
_p("NK1", [["e"],["e","ee","es"]], [], ["s"]);
_p("NK", [["e","es"],["e","ee"]], [], ["s"]);
_p("NN", [["e"],["e","ee"]], [], []);
_p("NX1", [["e"],["e","ee","s"],["es"]], [], []);
_p("NX", [["e"],["e","ee","s","es"]], [], []);
_p("X1K1", [["e"],["e","ee","es"],["s"],["se"]], [], ["s"]);
_p("X1K", [["e","es"],["e","ee"],["s"],["se"]], [], ["s"]);
_p("X1N", [["e"],["e","ee"],["s"],["se"]], [], []);
_p("X1X1", [["e"],["e","ee","s"],["es","s"],["se"]], [], []);
_p("X1X", [["e"],["e","ee","s","es"],["s"],["se"]], [], []);
_p("X", [["e","es","s","ss"]], [], ["s"]);
_p("XK1", [["e"],["e","ee","es"],["s","se"]], [], ["s"]);
_p("XK", [["e","es"],["e","ee"],["s","se"]], [], ["s"]);
_p("XN", [["e"],["e","ee"],["s","se"]], [], []);
_p("XX1", [["e"],["e","ee","s"],["es","s","se"]], [], []);
_p("XX", [["e"],["e","ee","s","es"],["s","se"]], [], []);

export function isOneWay(pat: HandshakePattern): boolean {
    return pat.baseName.length === 1;
}

const NAME_RE = /^([NKX]|[NKXI]1?[NKX]1?)([a-z][a-z0-9]*(\+[a-z][a-z0-9]*)*)?$/;
const PSK_RE = /^psk([0-9]+)$/;

export function lookupPattern(name: string): HandshakePattern | null {
    const m = NAME_RE.exec(name);
    if (m === null) return null;
    const modifiers = m[2]?.split('+') ?? [];
    let pat: HandshakePattern | null = PATTERNS[m[1]] ?? null;
    if (!pat) return null;
    modifiers.forEach(m => pat = pat && applyModifier(pat, m));
    return pat && { ... pat, name };
}

function applyModifier(pat: HandshakePattern, mod: string): HandshakePattern | null {
    const m = PSK_RE.exec(mod);
    if (m === null) return null;
    const n = parseInt(m[1], 10);
    const messages = pat.messages;
    return { ... pat, messages: (n === 0
        ? [["psk", ... messages[0]], ... messages.slice(1)]
        : [... messages.slice(0, n-1), [... messages[n-1], "psk"], ... messages.slice(n)]) };
}
