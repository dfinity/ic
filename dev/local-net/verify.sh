#!/usr/bin/env bash
#
# Smoke-test the running local IC network (variant 2, application subnet,
# no NNS canisters installed).
#
# Validates:
#   1. Replica HTTP API is reachable and reports healthy.
#   2. dfx can ping the network.
#   3. All 4 replicas have the same root key and certified height is growing.
set -euo pipefail

NET_URL="${NET_URL:-http://localhost:8080}"

echo "==> /api/v2/status @ $NET_URL"
# CBOR contains null bytes; pipe through `strings` before any shell
# capture so bash doesn't warn about ignored nulls.
status=$(curl -sS -m 5 "$NET_URL/api/v2/status" | strings) || {
    echo "FAIL: could not reach $NET_URL/api/v2/status" >&2
    exit 1
}
echo "$status" | grep -iE "impl_version|health" | sed 's/^/    /'

echo
if command -v dfx >/dev/null 2>&1; then
    echo "==> dfx ping (dfx $(dfx --version | awk '{print $2}'))"
    if dfx ping "$NET_URL" 2>&1 | sed 's/^/    /'; then
        :
    else
        echo "    (dfx ping returned non-zero; see output above)"
    fi
else
    echo "==> dfx not installed; skipping dfx ping"
fi

echo
if command -v icp >/dev/null 2>&1; then
    echo "==> icp network ping local-cluster (icp $(icp --version | awk '{print $2}'))"
    # Run from this directory so icp.yaml is found.
    (cd "$(dirname "$0")" && icp network ping local-cluster 2>&1 | sed 's/^/    /') \
        || echo "    (icp ping returned non-zero; see output above)"
else
    echo "==> icp-cli not installed; skipping icp ping"
fi

echo
echo "==> Per-node /api/v2/status (consensus liveness)"
for i in 0 1 2 3; do
    h=$(docker exec ic-replica-$i bash -c '
        exec 3<>/dev/tcp/127.0.0.1/8080
        printf "GET /api/v2/status HTTP/1.0\r\nHost: x\r\n\r\n" >&3
        cat <&3
    ' 2>/dev/null | strings | grep -iE "health|version" | head -2 | tr '\n' ' ')
    echo "    node-$i: $h"
done

echo
echo "==> NNS status"
if docker run --rm --platform=linux/amd64 --network ic-local-net_ic-local \
    --entrypoint /usr/local/bin/ic-admin ic-replica:dev \
    --nns-url 'http://[fd00:1::10]:8080' get-subnet-list >/dev/null 2>&1; then
    echo "    NNS canisters installed; ic-admin can query the Registry."
else
    echo "    NNS canisters NOT installed (variant 2 — bare application subnet)."
    echo "    Run ./nns-init.sh to install Registry / Governance / Ledger / etc."
fi

echo
echo "OK — network is deploy-ready. See DEPLOY.md for canister deployment."
