#!/usr/bin/env bash
#
# Finds the Build ID by calculating the sha's of all inputs listed in Capsule.toml under 'build-id'.

set -eu

if [ "${CI_PARENT_PIPELINE_SOURCE:-}" = "merge_request_event" ]; then
    cd "${CI_PROJECT_DIR}"
    placebo -c build-id --inputs_hash
else
    git rev-parse --verify HEAD
fi
