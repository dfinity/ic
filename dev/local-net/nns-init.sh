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

# Cycles ledger canister IDs (from rs/nns/constants/src/lib.rs)
# um5iw-rqaaa-aaaaq-qaaba-cai = 0x_0210_0002
CYCLES_LEDGER_CANISTER_ID="um5iw-rqaaa-aaaaq-qaaba-cai"
# ul4oc-4iaaa-aaaaq-qaabq-cai = 0x_0210_0003
CYCLES_LEDGER_INDEX_CANISTER_ID="ul4oc-4iaaa-aaaaq-qaabq-cai"

# Path to a local cycles-ledger checkout (must be main branch; initial_balances
# was never released). Defaults to a sibling of the IC repo.
CYCLES_LEDGER_SRC="${CYCLES_LEDGER_SRC:-$(cd "$IC_REPO/.." && pwd)/cycles-ledger}"

# Pre-encoded Candid init args produced by:
#   didc encode -d "$CYCLES_LEDGER_SRC/cycles-ledger/cycles-ledger.did" \
#     '(variant { Init = record { max_blocks_per_request=50:nat64;
#        index_id=opt principal "ul4oc-4iaaa-aaaaq-qaabq-cai";
#        initial_balances=opt vec { record {
#          record { owner=principal "2vxsx-fae"; subaccount=null };
#          1_000_000_000_000_000:nat } } } })'
CYCLES_LEDGER_INIT_HEX="4449444c076b01b0ced18403016c03b2a4dab20502a89cb2b50c06afe0ff870d786e036d046c020005017d6c02b3b0dac30368ad86ca83057f6e68010000010101010480809aa6eaafe30101010a000000000210000301013200000000000000"
#   didc encode -d index-ng.did \
#     '(opt variant { Init = record { ledger_id=principal
#        "um5iw-rqaaa-aaaaq-qaaba-cai"; ... } })'
CYCLES_LEDGER_INDEX_INIT_HEX="4449444c036e016b01b0ced18403026c04f1f7fcf70668dcb79b830b7fe9bbd2a50e7f97b3c9a90e7f01000100010a00000000021000020101"

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
        sleep infinity
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
        ${TARGETS[*]} 2>&1
" 2>&1 | tee "$LOCAL_NET_DIR"/ic_nns_init.log | grep -vE "^WARNING: Remote Cache" | tail -10
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

# --- build cycles-ledger WASM from source + build index WASM ---
echo
echo "==> Building cycles-ledger WASM from source"
if [ ! -d "$CYCLES_LEDGER_SRC" ]; then
    echo "ERROR: CYCLES_LEDGER_SRC=$CYCLES_LEDGER_SRC not found." >&2
    echo "       Clone https://github.com/dfinity/cycles-ledger alongside the IC repo" >&2
    echo "       or set CYCLES_LEDGER_SRC to its path." >&2
    exit 1
fi
# dfx build --check produces the optimised wasm.gz without deploying
(cd "$CYCLES_LEDGER_SRC" && dfx build --check cycles-ledger 2>&1 | tail -5)
cp "$CYCLES_LEDGER_SRC/.dfx/local/canisters/cycles-ledger/cycles-ledger.wasm.gz" \
    "$WASMS_DIR/cycles-ledger.wasm.gz"
echo "    cycles-ledger.wasm.gz OK ($(du -h "$WASMS_DIR/cycles-ledger.wasm.gz" | awk '{print $1}'))"

echo "==> Building cycles-ledger-index WASM"
docker exec "$BUILDER_NAME" bash -eu -o pipefail -c "
    bazel build \
        --disk_cache=/cache/bazel-disk \
        --repository_cache=/cache/bazel-repo \
        //rs/ledger_suite/icrc1/index-ng:index_ng_canister_u256.wasm.gz 2>&1
" 2>&1 | grep -vE "^WARNING: Remote Cache" | tail -5
docker exec "$BUILDER_NAME" bash -eu -o pipefail -c '
    src=bazel-bin/rs/ledger_suite/icrc1/index-ng/index_ng_canister_u256.wasm.gz
    cp -L "$src" /out/wasms/cycles-ledger-index.wasm.gz
    printf "  %-42s  %s\n" "cycles-ledger-index.wasm.gz" "$(du -h "$src" | awk "{print \$1}")"
'

# --- verify ---
echo
echo "==> Verify: registry canister responds"
docker run --rm \
    --platform=linux/amd64 \
    --network ic-local-net_ic-local \
    --entrypoint /usr/local/bin/ic-admin \
    ic-replica:dev \
    --nns-url "http://[fd00:1::10]:8080" get-subnet-list 2>&1 | head -10

# --- deploy cycles ledger + index via dfx on the host ---
#
# Uses the provisional canister creation API (whitelist = ["*"] in prep.sh)
# and a throw-away dfx project so we can pass --specified-id without touching
# any existing dfx project. Requires dfx on PATH and localhost:8080 reachable.
echo
echo "==> Deploying cycles ledger and index"

_dfx_deploy_canister() {
    local canister_name="$1" specified_id="$2" wasm="$3" init_hex="$4"

    local tmpdir
    tmpdir=$(mktemp -d)
    # shellcheck disable=SC2064
    trap "rm -rf '$tmpdir'" RETURN

    # Minimal dfx.json — wasm/candid placeholders are ignored because we
    # provide --wasm explicitly and skip candid checking with --argument-type raw.
    cat > "$tmpdir/dfx.json" << DFXJSON
{
  "version": 1,
  "canisters": {
    "$canister_name": { "type": "custom", "wasm": "ph.wasm", "candid": "ph.did" }
  }
}
DFXJSON
    touch "$tmpdir/ph.wasm" "$tmpdir/ph.did"

    pushd "$tmpdir" >/dev/null

    dfx canister create "$canister_name" \
        --specified-id "$specified_id" \
        --no-wallet \
        --network http://localhost:8080 2>&1

    # --argument-type raw accepts the Candid binary as a hex string (dfx 0.26+)
    dfx canister install "$canister_name" \
        --wasm "$wasm" \
        --argument-type raw \
        --argument "$init_hex" \
        --mode install \
        --network http://localhost:8080 2>&1

    popd >/dev/null
}

_dfx_deploy_canister \
    "cycles-ledger" "$CYCLES_LEDGER_CANISTER_ID" \
    "$WASMS_DIR/cycles-ledger.wasm.gz" "$CYCLES_LEDGER_INIT_HEX"
echo "    cycles-ledger:       $CYCLES_LEDGER_CANISTER_ID"

_dfx_deploy_canister \
    "cycles-ledger-index" "$CYCLES_LEDGER_INDEX_CANISTER_ID" \
    "$WASMS_DIR/cycles-ledger-index.wasm.gz" "$CYCLES_LEDGER_INDEX_INIT_HEX"
echo "    cycles-ledger-index: $CYCLES_LEDGER_INDEX_CANISTER_ID"

# --- authorize the subnet on the CMC so cycles-ledger can create canisters ---
#
# The CMC only creates canisters on subnets in its authorized list, which is
# governed by NNS. propose-to-set-authorized-subnetworks with
# --test-neuron-proposer submits, auto-votes, and waits for execution.
# No --who means the default list (available to all principals / cycles-ledger).
echo
echo "==> Authorizing subnet on CMC"
SUBNET_ID=$(docker run --rm \
    --platform=linux/amd64 \
    --network ic-local-net_ic-local \
    --entrypoint /usr/local/bin/ic-admin \
    ic-replica:dev \
    --nns-url "http://[fd00:1::10]:8080" get-subnet-list 2>/dev/null \
    | jq -r '.[0]')
echo "    subnet: $SUBNET_ID"
docker run --rm \
    --platform=linux/amd64 \
    --network ic-local-net_ic-local \
    --entrypoint /usr/local/bin/ic-admin \
    ic-replica:dev \
    --nns-url "http://[fd00:1::10]:8080" \
    propose-to-set-authorized-subnetworks \
    --test-neuron-proposer \
    --summary "Authorize local-net subnet for cycles-ledger canister creation" \
    --subnets "$SUBNET_ID" 2>&1

echo
echo "OK — NNS and cycles ledger are installed."
echo
echo "Try:"
echo "    docker run --rm --network ic-local-net_ic-local --platform=linux/amd64 \\"
echo "        --entrypoint /usr/local/bin/ic-admin ic-replica:dev \\"
echo "        --nns-url http://[fd00:1::10]:8080 get-topology | head -40"
