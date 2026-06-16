#!/usr/bin/env bash

set -euo pipefail

# Uploads a dependency to the local cluster's bazel-remote cache and returns the
# download URL.
#
# The path to the dependency should be specified as the first (and only) argument.
#
# The download URL is printed to stdout.

# NOTE: This script uses bazel-remote as the CAS storage (implementation detail).

# The local cluster's bazel-remote, reachable in-cluster both from CI runners and
# from devenvs. We talk to it directly instead of going through the (cross-cluster)
# redirect server: we only ever check & upload to the *local* cluster's cache.
BAZEL_REMOTE_URL="http://server.bazel-remote.svc.cluster.local:8080"

# Returns 0 if the CAS key (provided as $1) already exists in the local
# bazel-remote cache, 1 if it does not. Exits the script on unexpected responses.
dep_in_cache() {
    local key="$1"
    local url="$BAZEL_REMOTE_URL/cas/$key"
    local code
    if ! code=$(curl --silent --show-error --max-time 30 \
        -o /dev/null -w '%{http_code}' --head "$url"); then
        echo "Failed to reach bazel-remote at '$url'" >&2
        exit 1
    fi

    case "$code" in
        200) return 0 ;;
        404) return 1 ;;
        *)
            echo "Unexpected HTTP code '$code' when looking up dependency '$key' at '$url'" >&2
            exit 1
            ;;
    esac
}

# Determines the name of the local cluster (e.g. "zh1-idx1"), used to build the
# download URL served at artifacts.<cluster>.dfinity.network.
resolve_cluster() {
    # A valid cluster name (e.g. "zh1-idx1"): lowercase alphanumerics and
    # hyphens, with no leading/trailing hyphen. We validate against this because
    # the name is interpolated into the artifacts.<cluster>.dfinity.network URL,
    # so unexpected characters would produce an invalid/unsafe URL.
    local cluster_re='^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'

    # Allow an explicit override (e.g. for manual runs or unusual environments).
    if [ -n "${SYSTEST_UPLOAD_CLUSTER:-}" ]; then
        if [[ ! "$SYSTEST_UPLOAD_CLUSTER" =~ $cluster_re ]]; then
            echo "SYSTEST_UPLOAD_CLUSTER='$SYSTEST_UPLOAD_CLUSTER' is not a valid cluster name (expected e.g. 'zh1-idx1')" >&2
            exit 1
        fi
        echo "$SYSTEST_UPLOAD_CLUSTER"
        return
    fi

    # Otherwise auto-detect from the in-cluster Kubernetes API server certificate,
    # which carries a SAN of the form 'api.<cluster>.dfinity.network'. This works
    # both on CI runners and in devenvs, and yields the exact cluster name.
    if ! command -v openssl >/dev/null; then
        echo "openssl not found; cannot auto-detect the cluster name, set SYSTEST_UPLOAD_CLUSTER explicitly" >&2
        exit 1
    fi

    # Note: we deliberately don't check openssl s_client's exit status (it can
    # reflect verification of the internal CA rather than connectivity) and
    # instead validate the extracted name below. The `timeout` bounds DNS or
    # network stalls so we fail fast instead of hanging CI.
    local cluster=""
    cluster=$(timeout 15 openssl s_client -connect kubernetes.default.svc:443 </dev/null 2>/dev/null \
        | openssl x509 -noout -text 2>/dev/null \
        | grep -m1 -oE 'api\.[a-z0-9][a-z0-9-]*\.dfinity\.network' \
        | sed -E 's/^api\.(.*)\.dfinity\.network$/\1/') || true

    if [[ ! "$cluster" =~ $cluster_re ]]; then
        echo "could not determine the local cluster name from the API server certificate; set SYSTEST_UPLOAD_CLUSTER explicitly" >&2
        exit 1
    fi

    echo "$cluster"
}

dep_filename="${1:?Dependency not specified}"
dep_sha256=$(sha256sum "$dep_filename" | cut -d' ' -f1)

echo "Found dep to upload $dep_filename ($dep_sha256)" >&2

# Determine the local cluster up front so we fail fast (before any upload) if it
# cannot be determined.
cluster=$(resolve_cluster)
echo "dep '$dep_filename': local cluster is '$cluster'" >&2

# Figure out _if_ the dep should be uploaded (no point re-uploading several GBs
# if it's already in the local cache).
if dep_in_cache "$dep_sha256"; then
    echo "dep '$dep_filename': already uploaded" >&2
else
    echo "dep '$dep_filename': not uploaded yet" >&2

    # Upload the dep to the local cluster's bazel-remote (used as CAS storage).
    dep_upload_url="$BAZEL_REMOTE_URL/cas/$dep_sha256"
    echo "Using upload URL: '$dep_upload_url'" >&2
    curl_out=$(mktemp)
    curl --silent --show-error --fail --retry 3 "$dep_upload_url" --upload-file "$dep_filename" -w '%{size_upload} %{time_total} %{speed_upload}\n' | tee "$curl_out" >&2
    # read & pretty print 3 metrics: upload size, upload time & upload speed
    if read -ra metrics <"$curl_out"; then
        echo "Uploaded $(numfmt --to=iec-i --suffix=B "${metrics[0]}") in ${metrics[1]}s ($(numfmt --to=iec-i --suffix=B "${metrics[2]}")/s)" >&2
    fi

    rm "$curl_out"

    # Check that it was actually uploaded and can be served (this sometimes takes a moment)
    attempt=1
    while ! dep_in_cache "$dep_sha256"; do
        echo "attempt $attempt: dep not served yet" >&2
        if [ "$attempt" -ge 10 ]; then
            echo "  giving up" >&2
            exit 1
        fi

        echo "  will retry in 1s" >&2
        sleep 1

        attempt=$((attempt + 1))
    done
fi

# Use the DC-local bazel cache directly, without going through the redirect server.
dep_download_url="https://artifacts.$cluster.dfinity.network/cas/$dep_sha256"
echo "dep '$dep_filename': download_url: '$dep_download_url'" >&2
echo "$dep_download_url"
