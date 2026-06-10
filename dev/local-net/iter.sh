#!/usr/bin/env bash
#
# Edit-rebuild-restart iteration for the local 4-node network.
#
# Workflow:
#   1. Run `bazel build` for the named targets inside the Rosetta builder
#      (default: just the replica binary). Bazel disk cache makes incremental
#      builds fast after the first one.
#   2. Re-extract the binaries to ./out/.
#   3. Restart the named services. The bind-mounted ./out/ → /usr/local/bin
#      means the containers pick up the new binaries on restart, with no
#      image rebuild and no state loss.
#   4. Optionally tail logs.
#
# Usage:
#   ./iter.sh                                # rebuild replica, restart all 4
#   ./iter.sh replica-0                      # restart only node-0
#   ./iter.sh --tail                         # rebuild, restart, then tail logs
#   TARGETS="//rs/p2p/quic_transport:..."    # custom bazel targets
#     ./iter.sh
#
# Resets vs iter:
#   iter.sh   = keep registry + crypto + state; just swap binaries
#   reset.sh  = nuke everything, regen from genesis
set -euo pipefail

LOCAL_NET_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$LOCAL_NET_DIR"

IC_REPO="${IC_REPO:-$(cd "$LOCAL_NET_DIR/../.." && pwd)}"
BUILDER_NAME="ic-builder"
CACHE_DIR="$LOCAL_NET_DIR/cache"
OUT_DIR="$LOCAL_NET_DIR/out"

TAIL=0
SERVICES=()
for arg in "$@"; do
    case "$arg" in
        --tail | -t) TAIL=1 ;;
        --help | -h)
            sed -n '3,20p' "$0"
            exit 0
            ;;
        *) SERVICES+=("$arg") ;;
    esac
done

# Default to just the replica binary; user can override with TARGETS=...
: "${TARGETS:=//rs/replica:replica}"

# Spin up a long-running builder container if one isn't around. The point
# is to keep the bazel JVM warm across iterations — repeated `docker run
# --rm` pays for analysis (~60-120s) every time.
ensure_builder() {
    if docker container inspect "$BUILDER_NAME" >/dev/null 2>&1; then
        if [ "$(docker inspect -f '{{.State.Running}}' "$BUILDER_NAME")" != "true" ]; then
            docker start "$BUILDER_NAME" >/dev/null
        fi
        return
    fi
    local builder_tag
    builder_tag="$(cat "$IC_REPO/ci/container/TAG")"
    echo "    (spinning up persistent builder: $BUILDER_NAME)"
    docker run -d \
        --platform=linux/amd64 \
        --name "$BUILDER_NAME" \
        -v "$IC_REPO:/ic" \
        -v "$CACHE_DIR:/cache" \
        -v "$OUT_DIR:/out" \
        -w /ic \
        "ghcr.io/dfinity/ic-build:${builder_tag}" \
        sleep infinity >/dev/null
}

t0=$(date +%s)
echo "==> bazel build  ($TARGETS)"
ensure_builder

docker exec "$BUILDER_NAME" bash -eu -o pipefail -c "
    bazel build \
        --disk_cache=/cache/bazel-disk \
        --repository_cache=/cache/bazel-repo \
        $TARGETS 2>&1 | tail -20
    for label in $TARGETS; do
        pkg=\${label#//}; pkg=\${pkg%%:*}
        name=\${label##*:}
        src=bazel-bin/\$pkg/\$name
        if [ ! -f \"\$src\" ]; then
            alt=\$(echo \"\$src\" | tr '-' '_')
            [ -f \"\$alt\" ] && src=\"\$alt\"
        fi
        out_name=\$name
        [ \"\$name\" = replica ] && out_name=ic-replica
        cp -L \"\$src\" \"/out/\$out_name\"
        chmod 0755 \"/out/\$out_name\"
    done
" 2>&1 | grep -vE "^WARNING: Remote Cache" | tail -10
t1=$(date +%s)
echo "    (bazel: $((t1 - t0))s)"

echo
echo "==> docker compose restart  (${SERVICES[*]:-all 4 replicas})"
if [ ${#SERVICES[@]} -eq 0 ]; then
    docker compose restart 2>&1 | tail -6
else
    docker compose restart "${SERVICES[@]}" 2>&1 | tail -6
fi

# Wait for at least one replica to be healthy again so we know consensus
# resumed.
echo
echo "==> waiting for replicas to be healthy"
deadline=$(($(date +%s) + 60))
while [ "$(date +%s)" -lt "$deadline" ]; do
    healthy=0
    for i in 0 1 2 3; do
        if [ "$(docker inspect -f '{{.State.Health.Status}}' "ic-replica-$i" 2>/dev/null)" = "healthy" ]; then
            healthy=$((healthy + 1))
        fi
    done
    if [ "$healthy" -ge 3 ]; then
        echo "    $healthy/4 replicas healthy"
        break
    fi
    sleep 2
done

t2=$(date +%s)
echo "    (total iter: $((t2 - t0))s)"

if [ "$TAIL" = "1" ]; then
    echo
    echo "==> docker compose logs -f --tail=10"
    exec docker compose logs -f --tail=10
fi
