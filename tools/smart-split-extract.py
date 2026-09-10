#!/usr/bin/env python3
"""Extract fragment profiles from patterniha's Serverless-for-Iran subscription
into the MSN-GUARD mirror format. Used both to build the initial mirror/seed and
(inline) by the smart-split-sync workflow."""
import json, sys, urllib.request, datetime

SUB_URL = ("https://raw.githubusercontent.com/patterniha/Serverless-for-Iran/"
           "refs/heads/main/Subscription/Serverless-for-Iran.json")

def extract(body_text):
    src = json.loads(body_text)
    if not isinstance(src, list):
        raise ValueError("subscription is not a JSON list")
    profiles = []
    for cfg in src:
        if not isinstance(cfg, dict):
            continue
        masks = None
        for ob in cfg.get("outbounds", []):
            if ob.get("tag") == "tcp-fragment-tls":
                fm = (ob.get("streamSettings") or {}).get("finalmask") or {}
                masks = fm.get("tcp")
                break
        if not masks:
            raise ValueError("no tcp-fragment-tls masks in %r"
                             % cfg.get("remarks"))
        for m in masks:  # shape check, not full validation
            if m.get("type") != "fragment" or "settings" not in m:
                raise ValueError("bad mask in %r" % cfg.get("remarks"))
        profiles.append({"name": cfg.get("remarks", ""), "masks": masks})
    if not profiles:
        raise ValueError("no profiles")
    return {
        "version": 1,
        "updated": datetime.datetime.now(datetime.timezone.utc)
                   .strftime("%Y-%m-%dT%H:%MZ"),
        "source": "patterniha/Serverless-for-Iran",
        "profiles": profiles,
    }

if __name__ == "__main__":
    req = urllib.request.Request(SUB_URL, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        mirror = extract(r.read().decode())
    json.dump(mirror, open(sys.argv[1], "w"), indent=2, ensure_ascii=False)
    print("wrote %d profiles: %s" % (len(mirror["profiles"]),
          ", ".join(p["name"] for p in mirror["profiles"])))
