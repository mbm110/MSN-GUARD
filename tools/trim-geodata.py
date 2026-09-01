#!/usr/bin/env python3
"""Trim xray geosite.dat / geoip.dat down to the categories a config names.

Why this exists
---------------
The shipped pair is 11 MB + 17 MB. A real config names a handful of categories;
for Serverless-for-Iran's 12 geosite + 2 geoip tags the honest size is 67 KB.
On Android that is the difference between an APK you can ship the assets in and
one you cannot.

Why no protobuf dependency
--------------------------
Both files are the same trivial shape: a repeated field 1 (wire type 2) at the
top level, one entry per category, and each entry's own field 1 is its name.
So an entry can be kept by copying its raw bytes -- tag, length prefix and
payload -- with no need to understand anything inside it. That keeps this script
stdlib-only and immune to schema changes in the parts we do not touch.

Traps this script exists to catch
--------------------------------
* `geosite:ir` DOES NOT EXIST. Iranian domains are `category-ir`. Asking for IR
  silently yields nothing, which is why missing names are reported and, with
  --strict, are an error.
* A category named in a routing rule but absent from the .dat is a hard xray
  startup failure (`failed to check code X from geosite.dat > EOF`), not a
  warning. Re-run this whenever the rules change.

Usage
-----
    trim-geodata.py geosite.dat out/geosite.dat ir private category-ir openai
    trim-geodata.py --strict geoip.dat out/geoip.dat ir private
    trim-geodata.py --list geosite.dat        # what is in there, by size

Always verify afterwards with the real binary -- but beware the asset fallback:
xray also searches /usr/local/share/xray, /usr/share/xray and /opt/share/xray,
so on a box that has run x-ui a missing file silently reads the system copy and
the test passes for the wrong reason. Hide the fallback to test honestly:

    unshare -m bash -c 'mount -t tmpfs tmpfs /usr/local/share/xray; \
      XRAY_LOCATION_ASSET=out ./xray run -test -c your.json'
"""
from __future__ import annotations

import sys
from pathlib import Path


def read_varint(buf: bytes, i: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        byte = buf[i]
        i += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, i
        shift += 7


def top_level_entries(buf: bytes) -> list[tuple[bytes, bytes]]:
    """[(payload, raw_including_tag_and_length), ...] for each top-level entry."""
    out: list[tuple[bytes, bytes]] = []
    i = 0
    while i < len(buf):
        start = i
        key, i = read_varint(buf, i)
        field, wire = key >> 3, key & 7
        if (field, wire) != (1, 2):
            raise SystemExit(
                f"unexpected field {field} wire {wire} at offset {start} — "
                "this does not look like a geosite/geoip .dat"
            )
        length, j = read_varint(buf, i)
        i = j + length
        out.append((buf[j:i], buf[start:i]))
    return out


def entry_name(payload: bytes) -> str | None:
    """The entry's field 1 (country_code / list name), uppercased by convention."""
    i = 0
    while i < len(payload):
        key, i = read_varint(payload, i)
        field, wire = key >> 3, key & 7
        if wire == 2:
            length, j = read_varint(payload, i)
            value = payload[j : j + length]
            i = j + length
            if field == 1:
                return value.decode("utf-8", "replace")
        elif wire == 0:
            _, i = read_varint(payload, i)
        elif wire == 5:
            i += 4
        elif wire == 1:
            i += 8
        else:
            return None
    return None


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if not a.startswith("--")]
    flags = {a for a in argv[1:] if a.startswith("--")}

    if "--list" in flags:
        if len(args) != 1:
            print(__doc__, file=sys.stderr)
            return 2
        src = Path(args[0])
        entries = top_level_entries(src.read_bytes())
        sized = sorted(
            ((entry_name(p) or "?", len(raw)) for p, raw in entries),
            key=lambda x: -x[1],
        )
        print(f"{src}: {len(entries)} entries, {src.stat().st_size / 1e6:.2f} MB")
        for name, size in sized:
            print(f"  {name:32} {size / 1e6:8.3f} MB")
        return 0

    if len(args) < 3:
        print(__doc__, file=sys.stderr)
        return 2

    src, dst, wanted = Path(args[0]), Path(args[1]), args[2:]
    keep = {w.strip().upper() for w in wanted if w.strip()}

    entries = top_level_entries(src.read_bytes())
    named = [(entry_name(p), raw) for p, raw in entries]
    kept = [raw for name, raw in named if name in keep]
    found = {name for name, _ in named if name in keep}
    missing = sorted(keep - found)

    if not kept:
        raise SystemExit(f"{src}: nothing matched {sorted(keep)} — wrong names?")

    dst.parent.mkdir(parents=True, exist_ok=True)
    blob = b"".join(kept)
    dst.write_bytes(blob)

    print(
        f"{src.name}: {len(entries)} entries {src.stat().st_size / 1e6:.2f} MB "
        f"-> kept {len(kept)} {len(blob) / 1e6:.3f} MB"
    )
    if missing:
        print(f"  MISSING (not in this file): {missing}")
        print("  note: geosite has no 'IR' — Iranian domains are 'CATEGORY-IR'")
        if "--strict" in flags:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
