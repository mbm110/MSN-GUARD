#!/bin/bash
# List artifacts for a given MSN-GUARD Actions run id.
# Token is read from .git/config inside the script so it never reaches agent output.
set -euo pipefail
cd /root/MSN-VPN-Fresh
RUN_ID="${1:?usage: ci-artifacts.sh <run_id>}"
URL=$(git config --get remote.guard.url)
TOKEN=$(printf '%s' "$URL" | sed -E 's#https://([^@]*)@github.*#\1#' | sed -E 's#^[^:]*:##')
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://api.github.com/repos/mbm110/MSN-GUARD/actions/runs/${RUN_ID}/artifacts" \
  | python3 -c '
import json,sys
d=json.load(sys.stdin)
for a in d.get("artifacts",[]):
    print(a["name"], round(a["size_in_bytes"]/1048576,1), "MB", a["expired"])
'
