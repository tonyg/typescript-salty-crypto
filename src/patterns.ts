import type { HandshakePattern, PreMessage, Token } from './noise';

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

_p("N",  [["e", "es"]],                                [], ["s"]);
_p("K",  [["e", "es", "ss"]],                          ["s"], ["s"]);
_p("X",  [["e", "es", "s", "ss"]],                     [], ["s"]);
_p("NN", [["e"], ["e", "ee"]],                         [], []);
_p("NK", [["e", "es"], ["e", "ee"]],                   [], ["s"]);
_p("NX", [["e"], ["e", "ee", "s", "es"]],              [], []);
_p("KN", [["e"], ["e", "ee", "se"]],                   ["s"], []);
_p("KK", [["e", "es", "ss"], ["e", "ee", "se"]],       ["s"], ["s"]);
_p("KX", [["e"], ["e", "ee", "se", "s", "es"]],        ["s"], []);
_p("XN", [["e"], ["e", "ee"], ["s", "se"]],            [], []);
_p("XK", [["e", "es"], ["e", "ee"], ["s", "se"]],      [], ["s"]);
_p("XX", [["e"], ["e", "ee", "s", "es"], ["s", "se"]], [], []);
_p("IN", [["e", "s"], ["e", "ee", "se"]],              [], []);
_p("IK", [["e", "es", "s", "ss"], ["e", "ee", "se"]],  [], ["s"]);
_p("IX", [["e", "s"], ["e", "ee", "se", "s", "es"]],   [], []);

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
