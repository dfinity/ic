#!/usr/bin/env bash

set -euo pipefail

# RUN_SCRIPT_ variables are meant for this script only and shouldn't be forwarded
# to the test driver
export -n \
  RUN_SCRIPT_ICOS_IMAGES \
  RUN_SCRIPT_UPLOAD_SYSTEST_DEP \
  RUN_SCRIPT_INFO_FILE_VARS \
  RUN_SCRIPT_TEST_EXECUTABLE \
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

# RUN_SCRIPT_INFO_FILE_VARS:
# For every var specified, pull the value from info_file, and
# expose it to the test plus the given suffix.
if [ -n "${RUN_SCRIPT_INFO_FILE_VARS:-}" ]; then
    # split the ";"-delimited list of "env_var:info_var:suffix;env_var2:info_var2:suffix;..."
    # into an array
    IFS=';' read -ra vars <<<"$RUN_SCRIPT_INFO_FILE_VARS"
    for var in "${vars[@]}"; do
        # split "envvar:infovar:suffix"
        IFS=':' read -ra parts <<<"$var"
        env_var_name="${parts[0]}"
        info_var_name="${parts[1]}"
        suffix="${parts[2]:-}"

        # Expose the variable to the test.
        export "${env_var_name}"="$(grep <"${FARM_METADATA_PATH}" -e "${info_var_name}" | cut -d' ' -f2)${suffix}"
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
