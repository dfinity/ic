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

# The folllowing accomplishes several goals:
# * We want to ensure all runtime dependencies are specified using the `runtime_deps` argument of the system_test bazel macro.
# * Furthermore, we want to make it less likely tests reference their runtime dependencies using hard-coded paths.
# * Finally, in case of a colocated test, we want to ensure that all runtime dependencies can be easily copied to the colocated test-driver VM
#   (for both bazel < 8 and >= 8) and that the environment variables specified in runtime_deps keep working for the colocated test.
#
# To implement the above we:
# 1) Execute the test ($RUN_SCRIPT_TEST_EXECUTABLE) in a different directory than $PWD (we use $TEST_TMPDIR)
#    to ensure hard-coded relative path references to Bazel's standard runfiles don't work
#    and have to be replaced by reading an environment variable specified in runtime_deps.
# 2) Create a "runfiles" directory in $TEST_TMPDIR containing symlinks to all runtime dependencies specified via runtime_deps.
# 3) Re-export the environment variables from runtime_deps to point to the new location under runfiles/.
# 4) How to name the symlinks? We could have recreated the same directory hierarchy under runfiles/ as Bazel's runfiles tree.
#    However, in bazel >= 8 runtime dependencies to external repos are not stored under $PWD anymore,
#    as in $(rootpath @repo//target) yields a path containing `..`s.
#    This would have made recreating the directory hierarchy impossible.
#    So instead we create a flat directory under runfiles/ where the name of each symlink is
#    the path to the dependency with `/` replaced by `-`. For example:
#
#    runfiles/ic-os-guestos-envs-dev-launch-measurements.json -> $RUNFILES_DIR/_main/ic-os/guestos/envs/dev/launch-measurements.json
#    runfiles/rs-tests-cross_chain-btc_uvm_config_image.zst -> $RUNFILES_DIR/_main/rs/tests/cross_chain/btc_uvm_config_image.zst
#    runfiles/external-_main~_repo_rules~btc_canister-file-ic-btc-canister.wasm.gz -> $RUNFILES_DIR/_main/external/_main~_repo_rules~btc_canister/file/ic-btc-canister.wasm.gz
#
#    With Bazel >= 8 that last symlink will be:
#    runfiles/..-+_repo_rules2+btc_canister-file-ic-btc-canister.wasm.gz -> $RUNFILES_DIR/_main/../+_repo_rules2+btc_canister/file/ic-btc-canister.wasm.gz
#
RUNFILES="$TEST_TMPDIR/runfiles"
mkdir "$RUNFILES"
IFS=';' read -ra runtime_dep_env_vars <<<"$RUNTIME_DEP_ENV_VARS"
for env_var in "${runtime_dep_env_vars[@]}"; do
    old_dep="${!env_var}"
    new_dep="$(sed 's|/|-|g' <<<"$old_dep")"
    ln -sf "$PWD/$old_dep" "$RUNFILES/$new_dep"
    export "$env_var=runfiles/$new_dep"
done

if [ -n "${COLOCATE_UVM_CONFIG_IMAGE_PATH:-}" ]; then
    export COLOCATE_UVM_CONFIG_IMAGE_PATH="$PWD/$COLOCATE_UVM_CONFIG_IMAGE_PATH"
fi

exec \
    env -C "$TEST_TMPDIR" \
    "$PWD/$RUN_SCRIPT_TEST_EXECUTABLE" \
    --working-dir "$TEST_TMPDIR" \
    "${test_driver_extra_args[@]}" \
    "$@" run
