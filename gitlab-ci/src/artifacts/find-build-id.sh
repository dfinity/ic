#!/usr/bin/env bash
#
# Finds the Build ID by calculating the sha's of all inputs listed in Capsule.toml under 'build-id'.

set -eu

if [ "${CI_PARENT_PIPELINE_SOURCE:-}" = "merge_request_event" ]; then
    build_id_file="$(mktemp)"
    cd "${CI_PROJECT_DIR}"
    # We use a dummy backend as we don't need to talk to S3 here.
    placebo -c build-id -b dummy -- \
        bash -c "[[ -z \"\${CAPSULE_INPUTS_HASH}\" ]] && exit 1; echo \"\${CAPSULE_INPUTS_HASH}\" > ${build_id_file}" >/dev/null
    cat "${build_id_file}"
else
    git rev-parse --verify HEAD
fi
