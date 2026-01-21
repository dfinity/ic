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

# Copy all runtime_deps into "$TEST_TMPDIR/runfiles"
# and reset the env vars pointing to the new location using absolute paths.
ORIG_RUNFILES="$PWD"
RUNFILES="$TEST_TMPDIR/runfiles"
mkdir "$RUNFILES"
IFS=';' read -ra runtime_dep_env_vars <<<"$RUNTIME_DEP_ENV_VARS"
for env_var in "${runtime_dep_env_vars[@]}"; do
    relative_dep_path="${!env_var}"

    # In bazel-8 $relative_dep_path may contain .. parent references.
    # Those will clash with the following mkdir and cp commands.
    # So we sanitize them here by creating a mirror structure of the parent paths under $RUNFILES.
    sanitized_relative_dep_path="$(sed 's|\.\.|__parent__|g' <<<"$relative_dep_path")"

    mkdir -p "$(dirname "$RUNFILES/$sanitized_relative_dep_path")"
    cp --symbolic-link "$ORIG_RUNFILES/$relative_dep_path" "$RUNFILES/$sanitized_relative_dep_path"
    export "$env_var=$RUNFILES/$sanitized_relative_dep_path"
done

# TODO: remove the following comment
# and adapt from_location_specified_by_env_var() and get_dependency_path()
# to not read the $RUNFILES env var.
#
# We export RUNFILES such that the from_location_specified_by_env_var() function in
# rs/rust_canisters/canister_test/src/canister.rs and get_dependency_path()
# can find runtime dependencies relative to the $RUNFILES directory.

# Change current working directory to be different than $RUNFILES
# to ensure the test accesses all its runtime dependencies via environment variables
# instead of via hard-code paths relative to $RUNFILES.
cd "$TEST_TMPDIR"

exec \
    "$ORIG_RUNFILES/$RUN_SCRIPT_TEST_EXECUTABLE" \
    --working-dir "$TEST_TMPDIR" \
    "${test_driver_extra_args[@]}" \
    "$@" run
