#!/usr/bin/env bash
#
# Tear down everything created by this setup.
#
#   ./clean.sh            # network + builder
#   ./clean.sh --all      # also wipes bootstrap, out, and bazel cache
#   ./clean.sh --cache    # also wipes bazel cache (the slow-to-rebuild bit)
#
# After `clean.sh`, the next `./build.sh` is a cold build.
set -euo pipefail

LOCAL_NET_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$LOCAL_NET_DIR"

WIPE_ARTIFACTS=0
WIPE_CACHE=0
for arg in "$@"; do
    case "$arg" in
        --all)
            WIPE_ARTIFACTS=1
            WIPE_CACHE=1
            ;;
        --cache) WIPE_CACHE=1 ;;
        --help | -h)
            sed -n '3,9p' "$0"
            exit 0
            ;;
    esac
done

echo "==> docker compose down -v"
docker compose down -v 2>&1 | tail -3 || true

if docker container inspect ic-builder >/dev/null 2>&1; then
    echo "==> docker rm -f ic-builder"
    docker rm -f ic-builder >/dev/null
fi

if [ "$WIPE_ARTIFACTS" = "1" ]; then
    echo "==> rm -rf bootstrap out"
    rm -rf bootstrap out
fi

if [ "$WIPE_CACHE" = "1" ]; then
    echo "==> rm -rf cache  (next build is full cold)"
    rm -rf cache
fi

echo
echo "OK. To bring it back up:"
echo "    ./build.sh && ./prep.sh && docker compose up -d"
