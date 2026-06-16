#!/usr/bin/env bash

set -euo pipefail

# RUN_SCRIPT_ variables are meant for this script only and shouldn't be forwarded
# to the test driver
export -n \
    RUN_SCRIPT_ICOS_IMAGES \
    RUN_SCRIPT_UPLOAD_SYSTEST_DEP \
    RUN_SCRIPT_TEST_EXECUTABLE \
    RUN_SCRIPT_ENV_VAR_FILES \
    RUN_SCRIPT_DRIVER_EXTRA_ARGS \
    RUN_SCRIPT_RUNTIME_DEP_ENV_VARS \
    RUN_SCRIPT_VOLATILE_STATUS_PATH

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

# To force system-tests to specify all their runtime dependencies using the runtime_deps parameter
# we execute the test in $TEST_TMPDIR such that relative paths to bazel's runfiles directory fail to work.
# Instead we create a $TEST_TMPDIR/runtime_deps directory, symlink all runtime dependencies there
# and reset the runtime_deps environment variables to point (absolutely) to the symlinks.
runtime_deps="$TEST_TMPDIR/runtime_deps"
mkdir "$runtime_deps"
runtime_dep_base="$runtime_deps"
# In colocated tests the runtime deps exists in the container on the UVM
# so we need to adjust the base path accordingly.
if [ -n "${COLOCATED_UVM_CONFIG_IMAGE_PATH:-}" ]; then
    export COLOCATED_UVM_CONFIG_IMAGE_PATH="$(realpath $COLOCATED_UVM_CONFIG_IMAGE_PATH)"
    runtime_dep_base="/home/root/test/runtime_deps"
fi
IFS=';' read -ra runtime_dep_env_vars <<<"$RUN_SCRIPT_RUNTIME_DEP_ENV_VARS"
for env_var in "${runtime_dep_env_vars[@]}"; do
    old_dep="${!env_var}"
    # The name of the symlink contains the hash of the $old_dep path to avoid name clashes.
    old_dep_hash="$(sha256sum <<<"$old_dep" | cut -d' ' -f1)"
    old_dep_name="$(basename "$old_dep")"
    new_dep="$old_dep_hash-$old_dep_name"
    old_dep_abs="$(realpath $old_dep)"
    echo "Linking runtime dependency for $env_var: $runtime_dep_base/$new_dep -> $old_dep_abs" >&2
    ln -sf "$old_dep_abs" "$runtime_deps/$new_dep"
    export "$env_var=$runtime_dep_base/$new_dep"
done

# Set environment variables based on volatile status variables:
export FARM_METADATA="$(grep '^FARM_METADATA ' "$RUN_SCRIPT_VOLATILE_STATUS_PATH" | cut -d' ' -f2-)"
DC="$(grep '^DC ' "$RUN_SCRIPT_VOLATILE_STATUS_PATH" | cut -d' ' -f2- || true)"
if [ -n "$DC" ]; then
    export DC
fi

# Optionally sync Grafana dashboards from the dfinity-ops/k8s repo so they can be
# provisioned on the Prometheus VM (see prometheus_vm.rs). This is enabled by setting
# IC_DASHBOARDS_BRANCH to the desired branch of the k8s repo. The resulting directory is
# exported as IC_DASHBOARDS_DIR which is read by the test driver (and forwarded to the
# colocated UVM by colocate_test.rs). If IC_DASHBOARDS_DIR is already set (e.g. pointing
# at a local clone) we use that directly and skip the checkout.
if [ -z "${IC_DASHBOARDS_DIR:-}" ] && [ -n "${IC_DASHBOARDS_BRANCH:-}" ]; then
    dashboards_repo="$TEST_TMPDIR/k8s_dashboards"
    rm -rf "$dashboards_repo"
    echo "Syncing Grafana dashboards from k8s branch '$IC_DASHBOARDS_BRANCH' ..." >&2
    if git clone --filter=blob:none --no-checkout --branch "$IC_DASHBOARDS_BRANCH" \
        git@github.com:dfinity-ops/k8s.git "$dashboards_repo" \
        && git -C "$dashboards_repo" config core.sparseCheckout true \
        && echo "bases/apps/ic-dashboards" >>"$dashboards_repo/.git/info/sparse-checkout" \
        && git -C "$dashboards_repo" checkout HEAD; then
        export IC_DASHBOARDS_DIR="$dashboards_repo/bases/apps/ic-dashboards"
        echo "Synced Grafana dashboards to $IC_DASHBOARDS_DIR" >&2
    else
        echo "WARNING: failed to sync Grafana dashboards from k8s branch '$IC_DASHBOARDS_BRANCH'; continuing without them" >&2
    fi
fi

exec \
    env -C "$TEST_TMPDIR" \
    "$(realpath $RUN_SCRIPT_TEST_EXECUTABLE)" \
    --working-dir "$TEST_TMPDIR" \
    "${test_driver_extra_args[@]}" \
    "$@" run
