#!/bin/sh
set -eu

trust_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
blocked_roots=${BLOCKED_ROOTS_FILE:-$trust_dir/blocked-roots.sha256}
[ -s "$blocked_roots" ] || { printf 'missing distrust policy: %s\n' "$blocked_roots" >&2; exit 1; }
config=/etc/ca-certificates.conf
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

# Disable sources by certificate fingerprint, including alternate package filenames.
while IFS= read -r entry || [ -n "$entry" ]; do
    case "$entry" in
        ''|'#'*|'!'*) printf '%s\n' "$entry"; continue ;;
    esac
    certificate="/usr/share/ca-certificates/$entry"
    if [ ! -f "$certificate" ]; then
        printf 'missing certificate source: %s\n' "$certificate" >&2
        exit 1
    fi
    fingerprint=$(openssl x509 -in "$certificate" -noout -sha256 -fingerprint)
    fingerprint=$(printf '%s' "${fingerprint#*=}" | tr -d ':')
    if grep -Fxq "$fingerprint" "$blocked_roots"; then
        printf '!%s\n' "$entry"
    else
        printf '%s\n' "$entry"
    fi
done < "$config" > "$temporary/ca-certificates.conf"

cat "$temporary/ca-certificates.conf" > "$config"
update-ca-certificates --fresh
sh "$trust_dir/verify-bundle.sh" /etc/ssl/certs/ca-certificates.crt
