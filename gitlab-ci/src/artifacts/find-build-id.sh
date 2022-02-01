#!/usr/bin/env bash
#
# Finds the Build ID by calculating the sha's of all inputs listed in Capsule.toml under 'build-id'.

set -eu

# TODO: "broken-blockmaster" condition is a hack to fix the broken hack of !2067.
if [[ "${CI_PARENT_PIPELINE_SOURCE:-}" = "merge_request_event" && "${CI_COMMIT_REF_NAME:-}" != "broken-blockmaker" ]]; then
    cd "${CI_PROJECT_DIR}"
    placebo -c build-id --inputs_hash
else
    git rev-parse --verify HEAD
fi
