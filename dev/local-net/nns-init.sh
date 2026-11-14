#!/usr/bin/env bash
#
# Install the NNS canisters on top of the running local network.
#
# Variant 1: turns the bare application subnet into a full NNS-enabled
# subnet. Adds Registry, Governance, Root, Lifeline, Cycles-Minting,
# Ledger, GTC, SNS-WASM, etc. as canisters.
#
# Prerequisites:
#   - ./build.sh has run (we use the persistent ic-builder)
#   - ./prep.sh has produced bootstrap/
#   - docker compose is up and the 4 replicas are healthy
#
# What this does:
#   1. Builds the NNS canister WASMs via bazel (cached after the first time).
#   2. Lays them out at ./out/wasms/ with the filenames ic-nns-init expects.
#   3. Runs ic-nns-init in a one-shot container against replica-0.
#   4. Verifies installation by querying the Registry canister.
set -euo pipefail

LOCAL_NET_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$LOCAL_NET_DIR"

IC_REPO="${IC_REPO:-$(cd "$LOCAL_NET_DIR/../.." && pwd)}"
BUILDER_NAME="ic-builder"
WASMS_DIR="$LOCAL_NET_DIR/out/wasms"

# NNS_CANISTER_WASMS in rs/nns/constants/src/lib.rs lists 15 entries that
# ic-nns-init's set_up_env_vars_for_all_canisters() looks up in --wasm-dir
# — if any are missing the binary panics. The list below maps each
# expected output filename to the bazel target that produces it.
#
# Format: "<bazel-target>|<output-filename-under-out/wasms>"
# Watch out for two name mismatches between bazel and ic-nns-init:
#   - test variants are bazel-named `-canister-test` but the wasm file
#     wants `-canister_test` (underscore).
#   - ledger's bazel target is `ledger-canister-wasm` but its output
#     file is `ledger-canister.wasm.gz`.
NNS_CANISTERS=(
    "//rs/registry/canister:registry-canister|registry-canister.wasm.gz"
    "//rs/registry/canister:registry-canister-test|registry-canister_test.wasm.gz"
    "//rs/nns/governance:governance-canister|governance-canister.wasm.gz"
    "//rs/nns/governance:governance-canister-test|governance-canister_test.wasm.gz"
    "//rs/ledger_suite/icp/ledger:ledger-canister-wasm|ledger-canister.wasm.gz"
    "//rs/nns/handlers/root/impl:root-canister|root-canister.wasm.gz"
    "//rs/nns/cmc:cycles-minting-canister|cycles-minting-canister.wasm.gz"
    "//rs/nns/handlers/lifeline/impl:lifeline_canister|lifeline_canister.wasm.gz"
    "//rs/nns/gtc:genesis-token-canister|genesis-token-canister.wasm.gz"
    "//rs/nns/identity:identity-canister|identity-canister.wasm.gz"
    "//rs/nns/nns-ui:nns-ui-canister|nns-ui-canister.wasm.gz"
    "//rs/nns/sns-wasm:sns-wasm-canister|sns-wasm-canister.wasm.gz"
    "//rs/ledger_suite/icrc1/ledger:ledger_canister|ic-icrc1-ledger.wasm.gz"
    "//rs/bitcoin/ckbtc/minter:ckbtc_minter|ic-ckbtc-minter.wasm.gz"
    "//rs/migration_canister:migration-canister|migration-canister.wasm.gz"
)

# --- preflight ---
if ! docker container inspect ic-replica-0 >/dev/null 2>&1; then
    echo "ERROR: ic-replica-0 not running. Run 'docker compose up -d' first." >&2
    exit 1
fi
if [ ! -d "$LOCAL_NET_DIR/bootstrap/ic_registry_local_store" ]; then
    echo "ERROR: bootstrap/ic_registry_local_store missing. Run ./prep.sh first." >&2
    exit 1
fi

# --- spin up persistent builder if needed ---
ensure_builder() {
    if docker container inspect "$BUILDER_NAME" >/dev/null 2>&1; then
        [ "$(docker inspect -f '{{.State.Running}}' "$BUILDER_NAME")" = "true" ] \
            || docker start "$BUILDER_NAME" >/dev/null
        return
    fi
    local tag
    tag="$(cat "$IC_REPO/ci/container/TAG")"
    echo "    (spinning up persistent builder: $BUILDER_NAME)"
    docker run -d \
        --platform=linux/amd64 \
        --name "$BUILDER_NAME" \
        -v "$IC_REPO:/ic" \
        -v "$LOCAL_NET_DIR/cache:/cache" \
        -v "$LOCAL_NET_DIR/out:/out" \
        -w /ic \
        "ghcr.io/dfinity/ic-build:${tag}" \
        sleep infinity >/dev/null
}

# --- build all canister WASMs ---
echo "==> Building NNS canister WASMs (${#NNS_CANISTERS[@]} targets)"
ensure_builder

TARGETS=()
for entry in "${NNS_CANISTERS[@]}"; do
    TARGETS+=("${entry%%|*}")
done

t0=$(date +%s)
docker exec "$BUILDER_NAME" bash -eu -o pipefail -c "
    bazel build \
        --disk_cache=/cache/bazel-disk \
        --repository_cache=/cache/bazel-repo \
        ${TARGETS[*]} 2>&1 | tail -10
" 2>&1 | grep -vE "^WARNING: Remote Cache" | tail -10
t1=$(date +%s)
echo "    (bazel: $((t1 - t0))s)"

# --- collect into out/wasms/ with the canonical names ic-nns-init expects ---
echo
echo "==> Collecting WASMs into out/wasms/"
mkdir -p "$WASMS_DIR"

# Pass src/dst pairs as positional args to avoid shell-quoting headaches
# (the `|` separator in the original array breaks pipe parsing inside the
# inner shell).
COPY_ARGS=()
for entry in "${NNS_CANISTERS[@]}"; do
    target="${entry%%|*}"
    outname="${entry##*|}"
    pkg="${target#//}"
    pkg="${pkg%%:*}"
    name="${target##*:}"
    COPY_ARGS+=("$pkg/$name" "$outname")
done

docker exec "$BUILDER_NAME" bash -eu -o pipefail -c '
    mkdir -p /out/wasms
    while [ $# -gt 0 ]; do
        src_base=$1
        dst=$2
        shift 2
        found=
        for ext in .wasm.gz .wasm; do
            if [ -f "bazel-bin/${src_base}${ext}" ]; then
                found="bazel-bin/${src_base}${ext}"
                break
            fi
        done
        if [ -z "$found" ]; then
            echo "  MISSING: ${src_base}" >&2
            exit 1
        fi
        cp -L "$found" "/out/wasms/${dst}"
        printf "  %-42s  %s\n" "$dst" "$(du -h "$found" | awk "{print \$1}")"
    done
' bash "${COPY_ARGS[@]}"

# --- run ic-nns-init against replica-0 ---
echo
echo "==> Running ic-nns-init"
echo "    URL:      http://[fd00:1::10]:8080"
echo "    wasms:    /wasm-dir (mounted from $WASMS_DIR)"
echo "    registry: /registry (mounted from bootstrap/ic_registry_local_store)"
echo

t2=$(date +%s)
docker run --rm \
    --platform=linux/amd64 \
    --network ic-local-net_ic-local \
    -v "$WASMS_DIR:/wasm-dir:ro" \
    -v "$LOCAL_NET_DIR/bootstrap/ic_registry_local_store:/registry:ro" \
    --entrypoint /usr/local/bin/ic-nns-init \
    ic-replica:dev \
    --url "http://[fd00:1::10]:8080" \
    --wasm-dir /wasm-dir \
    --registry-local-store-dir /registry \
    --pass-specified-id 2>&1 | tail -30
t3=$(date +%s)
echo "    (ic-nns-init: $((t3 - t2))s)"

# --- verify ---
echo
echo "==> Verify: registry canister responds"
docker run --rm \
    --platform=linux/amd64 \
    --network ic-local-net_ic-local \
    --entrypoint /usr/local/bin/ic-admin \
    ic-replica:dev \
    --nns-url "http://[fd00:1::10]:8080" get-subnet-list 2>&1 | head -10

echo
echo "OK — NNS is installed."
echo
echo "Try:"
echo "    docker run --rm --network ic-local-net_ic-local --platform=linux/amd64 \\"
echo "        --entrypoint /usr/local/bin/ic-admin ic-replica:dev \\"
echo "        --nns-url http://[fd00:1::10]:8080 get-topology | head -40"
