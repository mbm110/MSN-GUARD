#!/usr/bin/env python3
"""Shrink Tor's GeoIP database to the countries MSN-GUARD actually offers.

Why this exists
---------------
`ExitNodes {cc}` does not work at all without a GeoIP database: with no country
data Tor cannot map a country to relays, the candidate set comes out empty, and
bootstrap stalls forever. Measured on tor 0.4.6.10, warm cache:

    ExitNodes {fr}, no geoip      -> stalled at 45-50%, never connected
    ExitNodes {fr}, geoip present -> 100% in 4-6s, exit really in FR

That is the bug this fixes. The databases ship inside the Tor source tarball,
but at full size they are 9.5 MB (IPv4) + 16 MB (IPv6) uncompressed.

What it does
------------
Two reductions, both measured:

1. **IPv6 database dropped entirely.** Verified that `ExitNodes {cc}` is honoured
   with the IPv4 file alone — with IPv6 off (FR DE NL RO SE, 5/5) and with the
   app's real `ClientUseIPv6 1` + `ClientPreferIPv6ORPort auto` (FR DE NL SE,
   4/4). A relay's country is derived from its IPv4 address and every relay has
   one, so an empty IPv6 database cannot shrink the candidate set. A comment-only
   stub is written in its place: Tor warns about a missing GeoIPv6File on every
   start, and that warning repeats into a 100-line in-app log. The stub silences
   it for 512 bytes.

2. **IPv4 ranges filtered to the offered countries.** 9.5 MB -> ~6.4 MB on disk,
   1.8 MB in the APK. Ranges for countries the picker does not list are dead
   weight: they can never be named in `ExitNodes`.

The country list is read out of TorRegions.kt rather than duplicated here, so
adding a country to the picker cannot silently ship a database that lacks it.

Usage
-----
    filter-geoip.py <src-geoip> <TorRegions.kt> <out-dir>

Writes <out-dir>/geoip and <out-dir>/geoip6.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path


def offered_countries(tor_regions_kt: Path) -> set[str]:
    """The codes in TorRegions.EXIT_COUNT — the single source of truth.

    Matches the `"US" to 1165,` shape of that map. Deliberately strict: if the
    map is ever reformatted into something this does not match, we want a loud
    failure here rather than a database quietly missing countries.
    """
    text = tor_regions_kt.read_text(encoding="utf-8")
    block = re.search(r"EXIT_COUNT\s*=\s*mapOf\((.*?)\)", text, re.S)
    if not block:
        raise SystemExit(f"{tor_regions_kt}: could not find EXIT_COUNT = mapOf(...)")
    codes = set(re.findall(r'"([A-Z]{2})"\s+to\s+\d+', block.group(1)))
    if len(codes) < 5:
        raise SystemExit(
            f"{tor_regions_kt}: only parsed {len(codes)} country codes from "
            "EXIT_COUNT — the map's format probably changed"
        )
    return codes


def filter_geoip(src: Path, keep: set[str]) -> tuple[str, int, int]:
    """Keep only ranges whose country is in `keep`, preserving the header.

    Tor's format is `#` comment lines followed by `low,high,CC` rows, where the
    addresses are decimal integers. Rows are left byte-identical; only whole
    lines are dropped, so there is no chance of corrupting a range.
    """
    header: list[str] = []
    kept: list[str] = []
    total = 0
    for line in src.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line:
            continue
        if line.startswith("#"):
            if len(header) < 6:
                header.append(line)
            continue
        total += 1
        if line.rsplit(",", 1)[-1].strip().upper() in keep:
            kept.append(line)
    if not kept:
        raise SystemExit(f"{src}: filtering kept zero ranges — wrong input file?")
    note = [
        "# Filtered for MSN-GUARD: only the countries offered by the app's Tor",
        f"# exit-country picker are kept ({len(kept)} of {total} ranges).",
        "# Regenerate with tools/filter-geoip.py; see TorRegions.kt for the list.",
        "#",
    ]
    return "\n".join(note + header + kept) + "\n", total, len(kept)


STUB6 = """\
# MSN-GUARD: intentionally contains no ranges.
#
# ExitNodes {cc} was verified to be honoured with the IPv4 database alone, both
# with IPv6 disabled (FR DE NL RO SE, 5/5) and with the app's real settings of
# ClientUseIPv6 1 + ClientPreferIPv6ORPort auto (FR DE NL SE, 4/4). A relay's
# country comes from its IPv4 address, and every relay has one, so an empty IPv6
# database cannot shrink the candidate set.
#
# This file exists because Tor warns on every start about a missing GeoIPv6File
# and that warning repeats into a 100-line in-app log. Shipping the real 16 MB
# IPv6 database to silence a log line is not a trade worth making.
"""


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    src, regions, out_dir = Path(argv[1]), Path(argv[2]), Path(argv[3])
    out_dir.mkdir(parents=True, exist_ok=True)

    keep = offered_countries(regions)
    text, total, kept = filter_geoip(src, keep)

    (out_dir / "geoip").write_text(text, encoding="utf-8")
    (out_dir / "geoip6").write_text(STUB6, encoding="utf-8")

    src_mb = src.stat().st_size / 1e6
    out_mb = (out_dir / "geoip").stat().st_size / 1e6
    print(f"countries kept : {len(keep)} ({' '.join(sorted(keep))})")
    print(f"ranges         : {kept} of {total}")
    print(f"geoip          : {src_mb:.1f} MB -> {out_mb:.2f} MB")
    print(f"geoip6         : stub, {(out_dir / 'geoip6').stat().st_size} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
