#!/usr/bin/env bash

set -euo pipefail

# RUN_SCRIPT_ variables are meant for this script only and shouldn't be forwarded
# to the test driver
export -n \
    RUN_SCRIPT_ICOS_IMAGES \
    RUN_SCRIPT_UPLOAD_SYSTEST_DEP \
    RUN_SCRIPT_TEST_EXECUTABLE \
    RUN_SCRIPT_ENV_VAR_FILES \
    RUN_SCRIPT_DRIVER_EXTRA_ARGS

# RUN_SCRIPT_ICOS_IMAGES:
# For every ic-os image specified, first ensure it's in remote
# storage, then export its download URL and HASH as environment variables.
if [ -n "${RUN_SCRIPT_ICOS_IMAGES:-}" ]; then
    # split the ";"-delimited list of "env_prefix:filepath;env_prefix2:filepath2;..."
    # into an array
    IFS=';' read -ra icos_images <<<"$RUN_SCRIPT_ICOS_IMAGES"
    for image in "${icos_images[@]}"; do
        # split "envvar:filepath"
        image_var_prefix=${image%:*}
        image_filename=${image#*:}

        # ensure the dep is uploaded
        image_download_url=$("$RUN_SCRIPT_UPLOAD_SYSTEST_DEP" "$image_filename")
        echo "  -> $image_filename=$image_download_url" >&2

        # Since this is a CAS url, we assume the last URL path part is the sha256
        image_download_hash="${image_download_url##*/}"
        # set the environment variables for the test
        export "${image_var_prefix}_URL=$image_download_url"
        export "${image_var_prefix}_HASH=$image_download_hash"
    done
fi

# RUN_SCRIPT_ENV_VAR_FILES:
# For every env var set via file, read the file and set the environment variable
if [ -n "${RUN_SCRIPT_ENV_VAR_FILES:-}" ]; then
    IFS=';' read -ra env_var_files <<<"$RUN_SCRIPT_ENV_VAR_FILES"
    for env_var_file in "${env_var_files[@]}"; do
        # split "<envvar>:<path-of-contents>"
        export "${env_var_file%:*}=$(cat "${env_var_file#*:}")"
    done
fi

mkdir "$TEST_TMPDIR/root_env" # farm needs this directory to exist

# prepare the args for the test driver
read -ra test_driver_extra_args <<<"${RUN_SCRIPT_DRIVER_EXTRA_ARGS:-}"

# We export RUNFILES such that the from_location_specified_by_env_var() function in
# rs/rust_canisters/canister_test/src/canister.rs can find canisters
# relative to the $RUNFILES directory.
exec \
    env RUNFILES="$PWD" \
    "$RUN_SCRIPT_TEST_EXECUTABLE" \
    --working-dir "$TEST_TMPDIR" \
    "${test_driver_extra_args[@]}" \
    "$@" run
