#!/usr/bin/env python3
"""
MSN-GUARD log decoder.

The in-app log is redacted by `LogRedactor.kt` before the user copies it, so
every address, port and subsystem name shows up as a token. Tokens are
DETERMINISTIC: the same node/address yields the same code all session.

This script reverses the REVERSIBLE parts (IPv4, ports) and prints the
codebook for the one-way parts (subsystem names, engine names). It cannot
undo one-way digests (hostnames, file paths, node labels) because those are
FNV-1a hashes — but two identical digests always mean the same original.

USAGE
    python3 log-decode.py msn-guard-log.txt           # full decode
    python3 log-decode.py msn-guard-log.txt --tok N26W5V3   # decode one token
    python3 log-decode.py --codebook                  # print the whole codebook

What is reversible and what is not
----------------------------------
Reversible (this script recovers the exact value):
  * IPv4 address      -> 7-symbol token, e.g. N26W5V3
  * IPv4:port         -> ADDRESS-PORT, e.g. K47L5V3-N823
  * Port              -> 4-symbol token, e.g. N823

One-way (keyed FNV-1a digest, prefix tells you the kind):
  f####   absolute file path        (e.g. fSDVP = a config file path)
  n####   node label / pool entry   (e.g. nCLFG, n5PZM = a SHARD node identity)
  p###    bare channel handle (@...)
  u####   URL
  h####   hostname / library name
  x6####  IPv6 address
  e####   engine version banner

Plain (not tokens at all): timestamps, sizes, RTTs, counts, HTTP status
codes, and words that are not in the codebook.

Literals that stay as-is because they are not secrets: "lo" (127.0.0.1
loopback is kept readable on purpose), "z3"/"z9" are HTTP/3 and QUIC.
"""

import re
import sys

ALPHABET = "3QF7RJ2WXMK9YBDTNAHCLPZG5V4S8E6U"
ADDR_KEY = [0x5B, 0x9F, 0x2E, 0x71]
PORT_KEY = 0x1A2B
DIGEST_KEY = 0x6D5A1F3B

# `LogRedactor.CODEBOOK` — the plain-text word on the left is what the token
# on the right replaced. Order matters when several could match: longest key
# wins. Subsystem names are the ones you actually need to read a log.
CODEBOOK = {
    # subsystems
    "ShardManager/probe": "M7p",
    "ShardManager": "M7",
    "AnyTls/probe": "A2p",
    "AnyTls": "A2",
    "anytls": "A3",
    "ShardSubscription": "S3",
    "ShardSocksFront": "F2",
    "ShardRefreshJob": "R5",
    "ShardHealth": "H4",
    "ShardEdges": "G8",
    "ShardReach": "X6",
    "SmartSplit": "Q9",
    "Smart Split": "Q9",
    "SHARD": "K0",
    "TorSocksFront": "T4",
    "TorManager": "T8",
    "Psiphon": "P6",
    "masque gateway": "V2g",
    "MASQUE": "V2",
    "WireGuard": "W1",
    "WARP": "V3",
    "Watchdog": "wd",
    "Tun2Socks": "t2",
    "tun2socks": "t2",
    # engine and its modules
    "xray SOCKS": "u0",
    "Xray": "E1",
    "xray": "E1",
    "app/dispatcher": "d2",
    "app/proxyman": "d3",
    "app/dns": "d1",
    "app/log": "d6",
    "transport/internet": "d4",
    "infra/conf/serial": "d5",
    "core:": "c0:",
    # method vocabulary
    "subscription": "src",
    "seed list": "src0",
    "udpgw": "g7",
    "SOCKS5": "s5",
    "SOCKS": "s0",
    "winner": "sel",
    "rotations": "sw",
    "rotating": "swap",
    "rotate": "swap",
    "nodes": "nd",
    "node": "nd",
    "pool": "pl",
    "probe": "pb",
    "race": "ph",
    "tunnel": "tn",
    "geosite": "ga",
    "geoip": "ga",
    "geo assets": "ga",
    "reach check": "rc",
    "HTTP/3": "z3",
    "QUIC": "z9",
    "account": "ac",
}

# Reverse lookup: token -> plain word.
REVERSE = {}
for plain, tok in CODEBOOK.items():
    REVERSE.setdefault(tok, plain)

# A reversible address token: exactly 7 symbols from ALPHABET.
ADDR_RE = re.compile(
    r"\b([3QF7RJ2WXMK9YBDTNAHCLPZG5V4S8E6U]{7})(?:-([3QF7RJ2WXMK9YBDTNAHCLPZG5V4S8E6U]{4}))?\b"
)


def tok_to_int(tok):
    """The encoder writes 5 bits per symbol, least-significant FIRST."""
    v = 0
    for i, ch in enumerate(tok):
        v |= ALPHABET.index(ch) << (5 * i)
    return v


def decode_addr(tok):
    v = tok_to_int(tok)
    octets = [(v >> (8 * (3 - i))) & 0xFF for i in range(4)]
    out = [(octets[i] ^ ADDR_KEY[i]) & 0xFF for i in range(4)]
    return "%d.%d.%d.%d" % tuple(out)


def decode_port(tok):
    return tok_to_int(tok) ^ PORT_KEY


def fnv1a(text, key=DIGEST_KEY, width=4):
    """One-way digest — so you can confirm two digests mean the same thing,
    but cannot turn them back into the original string."""
    h = (0x811C9DC5 ^ key) & 0xFFFFFFFF
    for ch in text:
        h = (h ^ ord(ch)) & 0xFFFFFFFF
        h = (h * 16777619) & 0xFFFFFFFF
    return encode(h, width)


def encode(value, width):
    out = []
    v = value & 0xFFFFFFFF
    for _ in range(width):
        out.append(ALPHABET[v & 31])
        v >>= 5
    return "".join(out)


def restore_words(line):
    """Longest token first, mirroring the redactor's CODE_RE."""
    for tok in sorted(REVERSE, key=len, reverse=True):
        line = re.sub(r"\b" + re.escape(tok) + r"\b", REVERSE[tok], line)
    return line


def decode_line(line):
    def sub(m):
        addr = decode_addr(m.group(1))
        if m.group(2):
            return "%s:%d" % (addr, decode_port(m.group(2)))
        return addr

    out = ADDR_RE.sub(sub, line)
    return restore_words(out)


def print_codebook():
    print("=== subsystem / engine tokens (token  ->  real name) ===")
    for plain, tok in sorted(CODEBOOK.items(), key=lambda kv: kv[1]):
        print("  %-6s -> %s" % (tok, plain))
    print()
    print("=== one-way digest prefixes ===")
    print("  f####  absolute file path        n####  node label / pool entry")
    print("  p###   channel handle (@...)     u####  URL")
    print("  h####  hostname / library        x6#### IPv6 address")
    print("  e####  engine version banner")
    print()
    print("=== kept plain on purpose ===")
    print("  lo     127.0.0.1 loopback        z3  HTTP/3        z9  QUIC")
    print("  c1=N c2=N   pool counts (nodes, paths)")
    print("  aN/N       attempt N of N")


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return
    if args[0] in ("-c", "--codebook"):
        print_codebook()
        return
    if args[0] in ("-t", "--tok"):
        for tok in args[1:]:
            tok = tok.split(":")
            if len(tok) == 1:
                print("%s -> %s" % (tok[0], decode_addr(tok[0])))
            else:
                print("%s:%s -> %s:%d" % (tok[0], tok[1], decode_addr(tok[0]), decode_port(tok[1])))
        return

    path = args[0]
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            print(decode_line(line.rstrip("\n")))


if __name__ == "__main__":
    main()
