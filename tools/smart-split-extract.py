#!/usr/bin/env python3
"""Extract fragment profiles from patterniha's Serverless-for-Iran subscription
into the MSN-GUARD mirror format. Used both to build the initial mirror/seed and
(inline) by the smart-split-sync workflow.

Profiles the field has measured dead on Iranian carriers (fragA) are dropped
here, in the mirror pipeline — NOT in the app. That is the whole point of the
mirror arrangement: which profiles the fleet tries is GitHub-editable data, so
changing the set reaches every installed app with no release. Add or remove a
name in WORKING_PROFILES and let the workflow commit it.
"""
import json, sys, urllib.request, datetime

SUB_URL = ("https://raw.githubusercontent.com/patterniha/Serverless-for-Iran/"
           "refs/heads/main/Subscription/Serverless-for-Iran.json")

# The field measured fragA dead on Iranian carriers (محسن, 2026-09-12), so only
# fragB is mirrored. Upstream renames its configs between versions (v50 -> v51
# on 2026-09-20), so matching a full name breaks the sync on every bump and
# takes Smart Split offline for every installed app until someone edits this
# file. Matching the fragB suffix instead tracks the version automatically.
WORKING_PROFILE_SUFFIX = "fragB"

def _is_frag_b(name):
    # "Serverless-v51-fragB" -> keep; "Serverless-v51-fragA" -> drop.
    return name.endswith(WORKING_PROFILE_SUFFIX)

def extract(body_text):
    src = json.loads(body_text)
    if not isinstance(src, list):
        raise ValueError("subscription is not a JSON list")
    profiles = []
    for cfg in src:
        if not isinstance(cfg, dict):
            continue
        name = cfg.get("remarks", "")
        if not _is_frag_b(name):
            continue
        masks = None
        for ob in cfg.get("outbounds", []):
            if ob.get("tag") == "tcp-fragment-tls":
                fm = (ob.get("streamSettings") or {}).get("finalmask") or {}
                masks = fm.get("tcp")
                break
        if not masks:
            raise ValueError("no tcp-fragment-tls masks in %r" % name)
        for m in masks:  # shape check, not full validation
            if m.get("type") != "fragment" or "settings" not in m:
                raise ValueError("bad mask in %r" % name)
        profiles.append({"name": name, "masks": masks})
    if not profiles:
        # Upstream renames its configs between versions (v50 -> v51 on
        # 2026-09-20). A hard failure here takes Smart Split offline for every
        # installed app until someone edits this file, which can be days.
        # Falling back to the previous good mirror keeps the fleet served
        # while the remarks list is updated; the sync is best-effort data, not
        # a build step.
        names = sorted({c.get("remarks", "") for c in src if isinstance(c, dict)})
        raise ValueError(
            "no profiles survived the working-profile filter. "
            "Upstream remarks are now: %s. Update WORKING_PROFILES to match."
            % names
        )
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
