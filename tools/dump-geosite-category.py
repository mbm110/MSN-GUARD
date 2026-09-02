#!/usr/bin/env python3
"""Dump the domain list of one category out of a trimmed geosite.dat / geoip.dat.

The skill's replica script only reads top-level category NAMES, which answers
"will xray start" but not "does this category actually contain the hostname I
think it does". That second question is the one that matters here: the abuse
interstitial named `https://gemini.google.com/app` together with an Iranian
source address, which can only happen if that hostname was never assigned to
the node in the first place.

geosite.dat wire format (v2ray/xray GeoSiteList):
    GeoSiteList { repeated GeoSite entry = 1; }
    GeoSite     { string country_code = 1; repeated Domain domain = 2; }
    Domain      { Type type = 1; string value = 2; repeated Attribute attr = 3; }
    Type        { Plain = 0; Regex = 1; RootDomain = 2; Full = 3; }
"""
from __future__ import annotations

import sys
from pathlib import Path

TYPE_NAMES = {0: "keyword", 1: "regexp", 2: "domain", 3: "full"}


def varint(buf: bytes, i: int) -> tuple[int, int]:
    r = s = 0
    while True:
        b = buf[i]
        i += 1
        r |= (b & 0x7F) << s
        if not b & 0x80:
            return r, i
        s += 7


def fields(buf: bytes):
    """Yield (field_number, wire_type, payload) for a flat message."""
    i = 0
    while i < len(buf):
        key, i = varint(buf, i)
        fn, wt = key >> 3, key & 7
        if wt == 2:
            ln, i = varint(buf, i)
            yield fn, wt, buf[i:i + ln]
            i += ln
        elif wt == 0:
            v, i = varint(buf, i)
            yield fn, wt, v
        else:
            raise ValueError(f"unsupported wire type {wt}")


def parse_geosite(path: Path) -> dict[str, list[tuple[str, str]]]:
    out: dict[str, list[tuple[str, str]]] = {}
    for fn, _wt, entry in fields(path.read_bytes()):
        if fn != 1:
            continue
        name, domains = None, []
        for efn, ewt, payload in fields(entry):
            if efn == 1 and ewt == 2:
                name = payload.decode("utf-8", "replace")
            elif efn == 2 and ewt == 2:
                dtype, value = 0, ""
                for dfn, dwt, dpay in fields(payload):
                    if dfn == 1 and dwt == 0:
                        dtype = dpay
                    elif dfn == 2 and dwt == 2:
                        value = dpay.decode("utf-8", "replace")
                domains.append((TYPE_NAMES.get(dtype, str(dtype)), value))
        if name:
            out[name] = domains
    return out


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(f"usage: {argv[0]} geosite.dat [CATEGORY ...]")
        return 2
    cats = parse_geosite(Path(argv[1]))
    wanted = [c.upper() for c in argv[2:]] or sorted(cats)
    for c in wanted:
        domains = cats.get(c)
        if domains is None:
            print(f"\n### {c}: NOT PRESENT in this .dat")
            continue
        print(f"\n### {c}  ({len(domains)} entries)")
        for dtype, value in domains:
            print(f"  {dtype:8} {value}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
