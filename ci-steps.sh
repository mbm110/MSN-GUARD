#!/bin/bash
# Print failed step logs for a run id.
cd /root/MSN-VPN-Fresh || exit 1
URL=$(git config --get remote.guard.url)
CRED=${URL#https://}; CRED=${CRED%%@*}
TOK=${CRED##*:}
API=https://api.github.com/repos/mbm110/MSN-GUARD
RUN=$1
echo "=== jobs / step conclusions ==="
curl -s -H "Authorization: Bearer $TOK" "$API/actions/runs/$RUN/jobs" \
| python3 -c '
import json,sys
d=json.load(sys.stdin)
for j in d["jobs"]:
    print("JOB", j["id"], j["conclusion"])
    for s in j["steps"]:
        mark = "FAIL" if s["conclusion"]=="failure" else s["conclusion"]
        print("   ", mark, s["name"])
'
