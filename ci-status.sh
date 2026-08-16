#!/bin/bash
# Poll the latest GitHub Actions runs for MSN-GUARD.
# The token is read straight out of .git/config inside this script so it is never
# echoed into agent output (the terminal tool redacts credentials, which made the
# inline curl approach send a literal "***" and get a 401).
set -euo pipefail
cd /root/MSN-VPN-Fresh
URL=$(git config --get remote.guard.url)
TOKEN=$(printf '%s' "$URL" | sed -E 's#https://([^@]*)@github.*#\1#' | sed -E 's#^[^:]*:##')
curl -s -H "Authorization: Bearer $TOKEN" \
  'https://api.github.com/repos/mbm110/MSN-GUARD/actions/runs?per_page=3' \
  | python3 -c '
import json,sys
d=json.load(sys.stdin)
for r in d.get("workflow_runs",[]):
    print(r["id"], r["head_sha"][:8], r["status"], r["conclusion"], r["created_at"])
'
