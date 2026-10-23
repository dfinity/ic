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

if [ "${SYSTEM_TEST_BACKEND:-}" != "local" ]; then
    # To eliminate unstable inter-DC network traffic, we want:
    #
    #   * Testnets of Farm-based system-tests to be allocated to the Farm DC
    #     in which the K8s cluster is hosted that is running the test
    #     either from CI or from a devenv
    #     unless overridden by the DC environment variable.
    #   * IC-OS images needed by that testnet to be served from that same K8s cluster.
    #
    # The name of the K8s cluster is extracted from the in-cluster K8s API server certificate SAN.
    cluster=$(timeout 15 openssl s_client -connect kubernetes.default.svc:443 </dev/null 2>/dev/null \
        | openssl x509 -noout -text 2>/dev/null \
        | grep -m1 -oE 'api\.[a-z0-9][a-z0-9-]*\.dfinity\.network' \
        | sed -E 's/^api\.(.*)\.dfinity\.network$/\1/')
    export DC="${DC:-${cluster%%-*}}"
fi

# RUN_SCRIPT_ICOS_IMAGES:
# For every ic-os image specified, export its HASH. When not using the local
# backend we first ensure the image is in remote storage and also export its
# download URL. Under the local backend the image is served from a local file
# by the test driver's file server (see `serve_files_task`), so only the HASH is
# needed here; the driver derives the (content-addressed) URL itself.
if [ -n "${RUN_SCRIPT_ICOS_IMAGES:-}" ]; then
    # split the ";"-delimited list of "env_prefix:filepath;env_prefix2:filepath2;..."
    # into an array
    IFS=';' read -ra icos_images <<<"$RUN_SCRIPT_ICOS_IMAGES"
    for image in "${icos_images[@]}"; do
        # split "envvar:filepath"
        image_var_prefix=${image%:*}
        image_filename=${image#*:}

        if [ "${SYSTEM_TEST_BACKEND:-}" = "local" ]; then
            # The image is served locally from its file path; compute its sha256
            # so the test driver can advertise it under a content-addressed URL.
            image_download_hash="$(sha256sum "$image_filename" | cut -d' ' -f1)"
            export "${image_var_prefix}_HASH=$image_download_hash"
        else
            # ensure the dep is uploaded
            image_download_url=$("$RUN_SCRIPT_UPLOAD_SYSTEST_DEP" "$image_filename" "$cluster")
            echo "  -> $image_filename=$image_download_url" >&2

            # Since this is a CAS url, we assume the last URL path part is the sha256
            image_download_hash="${image_download_url##*/}"
            # set the environment variables for the test
            export "${image_var_prefix}_URL=$image_download_url"
            export "${image_var_prefix}_HASH=$image_download_hash"
        fi
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
    # mcopy/mlabel are mtools applets that dispatch on argv[0], so their symlink
    # must keep the exact basename; skip the disambiguating hash prefix for them.
    case "$old_dep_name" in
        mcopy | mlabel) new_dep="$old_dep_name" ;;
    esac
    old_dep_abs="$(realpath $old_dep)"
    ln -sf "$old_dep_abs" "$runtime_deps/$new_dep"

    # Most deps resolve at $runtime_dep_base (the in-container path for colocated
    # tests, the local path otherwise). MKFS_FAT/MCOPY are an exception: the
    # colocated *wrapper* itself dereferences them on the host (UniversalVm::start
    # builds the driver VM's config image locally), so they must resolve locally;
    # colocate_test.rs rewrites them to the in-container path in the environment
    # it forwards to the inner test driver.
    dep_base="$runtime_dep_base"
    case "$env_var" in
        MKFS_FAT | MCOPY) dep_base="$runtime_deps" ;;
    esac
    echo "Linking runtime dependency for $env_var: $dep_base/$new_dep -> $old_dep_abs" >&2
    export "$env_var=$dep_base/$new_dep"
done

# Set environment variables based on volatile status variables:
export FARM_METADATA="$(grep '^FARM_METADATA ' "$RUN_SCRIPT_VOLATILE_STATUS_PATH" | cut -d' ' -f2-)"

# Optionally sync Grafana dashboards from the dfinity-ops/k8s repo so they can be
# provisioned on the Prometheus VM (see prometheus_vm.rs). This is enabled by setting
# IC_DASHBOARDS_BRANCH to the desired branch of the k8s repo. The resulting directory is
# exported as IC_DASHBOARDS_DIR which is read by the test driver (and forwarded to the
# colocated UVM by colocate_test.rs). If IC_DASHBOARDS_DIR is already set (e.g. pointing
# at a local clone) we use that directly and skip the checkout.
if [ -n "${IC_DASHBOARDS_DIR:-}" ]; then
    # A dashboards directory was provided directly. The driver is later executed with
    # `env -C "$TEST_TMPDIR"`, so normalize a relative path to an absolute one now;
    # otherwise it would be resolved against $TEST_TMPDIR and the dashboards wouldn't
    # be found. Keep the original value if realpath fails (best-effort, non-fatal).
    export IC_DASHBOARDS_DIR="$(realpath "$IC_DASHBOARDS_DIR" 2>/dev/null || echo "$IC_DASHBOARDS_DIR")"
elif [ -n "${IC_DASHBOARDS_BRANCH:-}" ]; then
    dashboards_repo="$TEST_TMPDIR/k8s_dashboards"
    rm -rf "$dashboards_repo" || true
    echo "Syncing Grafana dashboards from k8s branch '$IC_DASHBOARDS_BRANCH' ..." >&2
    # Keep the clone fully non-interactive so it can't hang a Bazel run:
    # - BatchMode disables password/passphrase prompts.
    # - StrictHostKeyChecking=accept-new auto-accepts the host key on first contact
    #   (but still rejects a changed key) instead of prompting to confirm it.
    # - An isolated UserKnownHostsFile under $TEST_TMPDIR avoids touching or locking
    #   the user's ~/.ssh/known_hosts. Its value is single-quoted because git runs
    #   GIT_SSH_COMMAND through a shell, so a $TEST_TMPDIR containing spaces would
    #   otherwise be split into multiple arguments.
    # - ConnectTimeout + a single ConnectionAttempt bound how long we wait on
    #   network/DNS issues so this best-effort sync fails fast instead of stalling.
    if GIT_SSH_COMMAND="ssh -oBatchMode=yes -oStrictHostKeyChecking=accept-new -oUserKnownHostsFile='$TEST_TMPDIR/k8s_known_hosts' -oConnectTimeout=15 -oConnectionAttempts=1" \
        git clone --depth 1 --filter=blob:none --no-checkout --branch "$IC_DASHBOARDS_BRANCH" \
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
