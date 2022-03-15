#!/usr/bin/env bash
#
# Finds the Build ID by calculating the sha's of all inputs listed in Capsule.toml under 'build-id'.

set -eux

# TODO: "broken-blockmaster" condition is a hack to fix the broken hack of !2067.
# TODO: CI_MERGE_REQUEST_TITLE conditional is a stopgap solution for IDX-2123.
if [[ "${CI_PARENT_PIPELINE_SOURCE:-}" = "merge_request_event" && "${CI_COMMIT_REF_NAME:-}" != "broken-blockmaker" && ! "${CI_MERGE_REQUEST_TITLE}" =~ \[rc\]|\[benchmark\] ]]; then
    cd "${CI_PROJECT_DIR}"
    placebo -c build-id --inputs_hash
else
    git rev-parse --verify HEAD
fi
