#!/bin/sh
set -eu

trust_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
blocked_roots=${BLOCKED_ROOTS_FILE:-$trust_dir/blocked-roots.sha256}
[ -s "$blocked_roots" ] || { printf 'missing distrust policy: %s\n' "$blocked_roots" >&2; exit 1; }
bundle=${1:?usage: verify-bundle.sh CA_BUNDLE}
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

awk -v directory="$temporary" '
    /-----BEGIN CERTIFICATE-----/ { count++; output = directory "/" count ".pem" }
    output != "" { print > output }
    /-----END CERTIFICATE-----/ { close(output); output = "" }
' "$bundle"

count=0
for certificate in "$temporary"/*.pem; do
    [ -f "$certificate" ] || continue
    count=$((count + 1))
    fingerprint=$(openssl x509 -in "$certificate" -noout -sha256 -fingerprint)
    fingerprint=$(printf '%s' "${fingerprint#*=}" | tr -d ':')
    if grep -Fxq "$fingerprint" "$blocked_roots"; then
        printf 'blocked root in %s: %s\n' "$bundle" "$fingerprint" >&2
        exit 1
    fi
done
[ "$count" -gt 0 ] || { printf 'empty CA bundle: %s\n' "$bundle" >&2; exit 1; }
