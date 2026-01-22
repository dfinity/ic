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
# rs/rust_canisters/canister_test/src/canister.rs and get_dependency_path()
# can find runtime dependencies relative to the $RUNFILES directory.
export RUNFILES="$TEST_TMPDIR/runfiles"

# Create symlinks under "$RUNFILES" pointing to the runtime dependencies in runtime_deps
# and reset the env vars pointing to the new location using relative paths.
export ORIG_RUNFILES="$PWD"
mkdir "$RUNFILES"
IFS=';' read -ra runtime_dep_env_vars <<<"$RUNTIME_DEP_ENV_VARS"
for env_var in "${runtime_dep_env_vars[@]}"; do
    relative_dep_path="${!env_var}"

    # We want folks to reference runtime dependencies using environment variables defined by runtime_deps.
    # To make it less likely folks reference dependencies via paths we replace all '/'s by '-'s.
    # This additionally fixes an issue with Bazel >= 8 where
    # $(rootpath @some_repo//some_target) can point outside the runfiles directory,
    # as in, the path will contain '..'s.
    sanitized_relative_dep_path="$(sed 's|/|-|g' <<<"$relative_dep_path")"

    ln -s "$ORIG_RUNFILES/$relative_dep_path" \
          "$RUNFILES/$sanitized_relative_dep_path"
    export "$env_var=$sanitized_relative_dep_path"
done

exec \
    env -C "$TEST_TMPDIR" \
    "$ORIG_RUNFILES/$RUN_SCRIPT_TEST_EXECUTABLE" \
    --working-dir "$TEST_TMPDIR" \
    "${test_driver_extra_args[@]}" \
    "$@" run
