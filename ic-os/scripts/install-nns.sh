#!/usr/bin/env bash

function error() {
    echo $1
    exit 1
}

TMPDIR=$1

[[ -d "$TMPDIR" ]] || error "Please specify temporary directory from boot-single-machine-nns.sh as argument"

VPN_IP6=::1

NNS_URL=$2
NNS_URL="${NNS_URL:=http://[::1]:8080}"
GIT_REV=$(git rev-parse --verify master)
REPO_ROOT="$(
    cd "$(dirname "$0")"
    git rev-parse --show-toplevel
)"

function download_registry_canisters() {
    "${REPO_ROOT}"/gitlab-ci/src/artifacts/rclone_download.py \
        --git-rev $GIT_REV --remote-path canisters --out "${TMPDIR}/canisters"

    for f in "${IC_PREP_DIR}"/*.gz; do
        gunzip -f "$f"
    done
}

function download_binaries() {
    "${REPO_ROOT}"/gitlab-ci/src/artifacts/rclone_download.py \
        --git-rev $GIT_REV --remote-path release --out "${IC_PREP_DIR}"

    for f in "${IC_PREP_DIR}"/*.gz; do
        gunzip -f "$f"
        chmod +x "${IC_PREP_DIR}/$(basename $f .gz)"
    done
}

# Ensure we can reach the canister
curl $NNS_URL/api/v2/status --output - >/dev/null || error "Could not reach replica to install NNS no"

# We are deploying the NNS subnetwork
SUBNET_IDX=0

download_binaries

download_registry_canisters

#echo "Ensuring NNS is not yet installed"
#($TMPDIR/ic-admin --nns-url $NNS_URL get-subnet 0 2>&1 | grep "Canister rwlgt-iiaaa-aaaaa-aaaaa-cai not found" ) || error "NNS is already installed, aborting"

echo "Installing NNS"
time $TMPDIR/ic-nns-init \
    --url $NNS_URL \
    --registry-local-store-dir $TMPDIR/ic_registry_local_store \
    --wasm-dir "$TMPDIR/canisters"

echo "Test NNS is installed"
$TMPDIR/ic-admin --nns-url $NNS_URL get-subnet 0
