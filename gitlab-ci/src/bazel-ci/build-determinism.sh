#!/usr/bin/env bash

set -eExuo pipefail
if [[ "${CI_PIPELINE_SOURCE:-}" == "merge_request_event"  && "${CI_MERGE_REQUEST_EVENT_TYPE:-}" != "merge_train" ]] && [[ "${CI_MERGE_REQUEST_TARGET_BRANCH_NAME:-}" != "rc--"* ]]; then
    # we only run the test if the path exists in both builds
    export BAZEL_COMMAND="build"
    TARGETS=$("$CI_PROJECT_DIR"/gitlab-ci/src/bazel-ci/diff.sh)

    # target taken from build-ic.sh
    declare -A ARTEFACTS_PATHS
    ARTEFACTS_PATHS["release"]="//publish/binaries"
    ARTEFACTS_PATHS["canisters"]="//publish/canisters"
    ARTEFACTS_PATHS["guest-os/update-img"]="//ic-os/guestos/envs/prod"
    ARTEFACTS_PATHS["host-os/update-img"]="//ic-os/hostos/envs/prod"
    ARTEFACTS_PATHS["setup-os/disk-img"]="//ic-os/setupos/envs/prod"

    # check if ARTEFACTS_PATHS[$PATH0] exists in TARGETS
    if ! echo "$TARGETS" | grep -q "${ARTEFACTS_PATHS[$PATH0]}"; then
        echo "Skipping build-determinism for $PATH0"
        exit 0
    fi
fi

"$CI_PROJECT_DIR"/gitlab-ci/tools/build-diff.sh "$PATH0" "$PATH1"
