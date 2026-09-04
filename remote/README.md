# remote/policy.json

Two lists the app fetches at runtime instead of having them compiled in. Editing
this file changes behaviour on every installed copy within six hours. **No build,
no release, no version bump.**

Read by `RemotePolicy.kt`. The URL is pinned to the `master` branch of this repo:

```
https://raw.githubusercontent.com/mbm110/MSN-GUARD/master/remote/policy.json
```

## Fields

| field | what it is |
|---|---|
| `edges` | Cloudflare edge IPv4 addresses every node is fanned out across. This is what dies when a carrier blackholes an address. |
| `geoblocked` | Hostnames that refuse an Iranian source IP, so they must leave through the node. |
| `sanctioned` | **Extra** names to route through the node, on top of the ones compiled in. For a service that answers 403 to an Iranian address — a new AI site, say. |
| `version`, `updated` | Ignored by the app. For humans reading the diff. |

## Rules the app enforces

Every list is validated before use, and anything that fails is skipped:

* `edges` — must be a dotted-quad IPv4 **inside Cloudflare's published ranges**.
  An address outside them is rejected, so this file can never point the pool's
  TLS at an arbitrary host. Max 24.
* `geoblocked` — bare hostnames only. No `geosite:`, no `domain:`, no `full:`,
  no `/`, no `:`, no `*`. The app adds the `full:` prefix itself. Max 64.
  List `example.com` and `www.example.com` separately — `full:` matches one exact
  name, which is deliberate (see `ShardConfigs.geoBlockedRuleHosts`).
* `sanctioned` — bare hostnames, plus one optional `*.` prefix:
  * `claude.ai` → that exact name.
  * `*.perplexity.ai` → the name and every subdomain.

  Nothing else: `*` anywhere but the front, two `*`, a `:` or a `/` all fail.
  Max 64. This list **adds to** the compiled-in one and cannot replace or remove
  from it, because that list is mostly whole categories (`geosite:openai` and
  friends) which this file is not allowed to write.

If the whole file is unparsable, or every entry in every list fails validation,
the app keeps what it had: previous cache first, then the values compiled into
the APK. **A bad edit degrades to the old behaviour, it does not break the
tunnel.** That is why the built-in fallbacks still exist.

## Editing

GitHub web editor is fine. Commit to `master`. Then:

* new installs pick it up on first launch;
* running installs on the next app resume, next SHARD connect, or the periodic
  job — whichever comes first, with a six-hour floor between fetches;
* to see it immediately on a phone: Settings ▸ SHARD ▸ **Node list** (that tap
  forces both this file and the node list).

Requests are conditional (`ETag`), so an unchanged file costs a few hundred
bytes.

## Adding a geo-blocked site

Add the exact hostnames the page loads from. Prefer the apex plus `www.`, and
add asset hosts only when the page will not render without them — every entry is
a routing rule evaluated per connection, and everything listed here gets slower
by going through the node.

## Replacing a dead edge

When the publisher reports an address dead, delete it and add the replacement.
Keep at least two. There is no need to remove an address that is merely slow:
`ShardHealth` learns per-edge latency on each network and stops racing the slow
ones by itself.

## Adding a sanctioned service

Put the hostname in `sanctioned`. Use `*.name.com` when the site loads assets and
API calls from subdomains — which most do — and the bare name when you want
exactly one host. Unlike `geoblocked`, these names also move their DNS lookups to
the node: a sanctioned service resolves differently for an Iranian resolver, and
that lookup costs about 900 ms, which is why the two lists are separate.
