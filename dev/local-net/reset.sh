#!/usr/bin/env bash
#
# Full reset to a fresh genesis: nuke containers, named volumes, bootstrap.
# Re-generate prep and bring up the network.
#
# Use when:
#   - you want to start from height 0 again
#   - the registry or crypto material is stale
#   - you've changed topology in prep.sh (number of nodes, IPs, ports)
set -euo pipefail

LOCAL_NET_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$LOCAL_NET_DIR"

echo "==> docker compose down -v"
docker compose down -v 2>&1 | tail -5

echo "==> rm -rf bootstrap"
rm -rf bootstrap

echo "==> ./prep.sh"
./prep.sh >/dev/null
echo "    prep done"

echo "==> docker compose up -d"
docker compose up -d 2>&1 | tail -5

echo
echo "Waiting for healthy (up to 60s)..."
deadline=$(($(date +%s) + 60))
while [ "$(date +%s)" -lt "$deadline" ]; do
    healthy=0
    for i in 0 1 2 3; do
        if [ "$(docker inspect -f '{{.State.Health.Status}}' "ic-replica-$i" 2>/dev/null)" = "healthy" ]; then
            healthy=$((healthy + 1))
        fi
    done
    if [ "$healthy" -eq 4 ]; then
        echo "    4/4 healthy"
        break
    fi
    sleep 2
done

docker compose ps --format "table {{.Name}}\t{{.Status}}"
