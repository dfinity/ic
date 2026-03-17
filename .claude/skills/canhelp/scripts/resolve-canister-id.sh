#!/bin/bash
set -euo pipefail

INPUT="${1:?Usage: resolve-canister-id.sh <canister-id-or-name>}"

# Principal: Base32(CRC32 · blob) grouped into 5-char chunks separated by dashes.
# Each group is exactly 5 lowercase alphanumeric chars, except the last which is 1-5.
# Max 63 chars (29-byte blob → 53 base32 chars + 10 dashes). Must have at least 2 groups.
if [[ "$INPUT" =~ ^[a-z2-7]{5}(-[a-z2-7]{5})*(-[a-z2-7]{1,5})$ ]]; then
    echo "$INPUT"
    exit 0
fi

# Otherwise, query IC Dashboard API for name-based lookup
QUERY=$(python3 -c "import urllib.parse, sys; print(urllib.parse.quote(sys.argv[1]))" "$INPUT")
RESPONSE=$(curl -sf "https://ic-api.internetcomputer.org/api/v4/canisters?format=json&has_name=true&query=${QUERY}&limit=50")

python3 -c "
import sys, json
data = json.load(sys.stdin)
entries = data.get('data', [])
if not entries:
    print('Error: no canister found matching \"$INPUT\"', file=sys.stderr)
    sys.exit(1)
for e in entries:
    print(f\"{e['canister_id']}  {e.get('name', 'N/A')}\")
" <<< "$RESPONSE"
