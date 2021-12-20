#!/usr/bin/env bash

function error() {
    echo $1
    exit 1
}

TMPDIR=$1
GIT_REV=$(git rev-parse --verify master)
REPO_ROOT=$(git rev-parse --show-toplevel)

[[ -d "$TMPDIR" ]] || error "Please specify temporary directory as first argument"

function download_registry_canisters() {
    "${REPO_ROOT}"/gitlab-ci/src/artifacts/rclone_download.py \
        --git-rev "$GIT_REVISION" --remote-path=release --out="$TMPDIR" \
        --include="{replica,orchestrator}.gz"

    for f in "${IC_PREP_DIR}"/*.gz; do
        gunzip -f "$f"
    done
}

download_registry_canisters
