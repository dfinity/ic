#!/usr/bin/env bash

set -euo pipefail

# Uploads a dependency to shared storage and returns the download URL.
#
# The path to the dependency should be specified as the first (and only) argument.
#
# The download URL is printed to stdout.

# NOTE: This script uses bazel-remote as the CAS storage (implementation detail).

# Look up a CAS key (provided as $1) through the redirect server.
# If the key exists, then then download URL is returned (through stdout).
# If the key does not exist, the empty string is returned.
lookup_dep_url() {
    REDIRECT_SERVER_URL="https://artifacts.idx.dfinity.network"
    local redirect_url="$REDIRECT_SERVER_URL/cas/$1"
    local result
    result=$(curl --silent --head \
        -w '%{http_code} %{redirect_url}' \
        "$redirect_url" \
        | tail -n1)

    local result_code
    result_code=$(cut -d' ' -f1 <<<"$result")
    if [ "$result_code" == "404" ]; then
        # The key was not found
        return
    fi

    if [ "$result_code" != "307" ]; then
        echo "Expected 404 or 307 when looking up dependency '$1', got '$result_code'" >&2
        exit 1
    fi

    local result_url
    result_url=$(cut -d' ' -f2 <<<"$result")
    if [ -z "$result_url" ]; then
        echo "Looking up dependency '$1' did not return a URL, got: '$result'" >&2
        exit 1
    fi

    echo "$result_url"
}

dep_filename="${1:?Dependency not specified}"
dep_sha256=$(sha256sum "$dep_filename" | cut -d' ' -f1)

echo "Found dep to upload $dep_filename ($dep_sha256)" >&2
result_url=$(lookup_dep_url "$dep_sha256")

# First, figure out _if_ the dep should be uploaded (no point re-uploading several GBs
# if it's been uploaded already)
if [ -n "$result_url" ]; then
    echo "dep '$dep_filename': already uploaded" >&2
else
    echo "dep '$dep_filename': not uploaded yet" >&2

    # We use bazel-remote as a CAS storage
    UPLOAD_URL="http://server.bazel-remote.svc.cluster.local:8080/cas"

    # Upload the dep
    dep_upload_url="$UPLOAD_URL/$dep_sha256"
    echo "Using upload URL: '$dep_upload_url'" >&2
    curl_out=$(mktemp)
    curl --silent --show-error --fail --retry 3 "$dep_upload_url" --upload-file "$dep_filename" -w '%{size_upload} %{time_total} %{speed_upload}\n' | tee "$curl_out" >&2
    # read & pretty print 3 metrics: upload size, upload time & upload speed
    if read -ra metrics <"$curl_out"; then
        echo "Uploaded $(numfmt --to=iec-i --suffix=B "${metrics[0]}") in ${metrics[1]}s ($(numfmt --to=iec-i --suffix=B "${metrics[2]}")/s)" >&2
    fi

    rm "$curl_out"

    # Check that it was actually uploaded and can be served (this sometimes takes a minute)
    attempt=1
    result_url=
    while true; do
        result_url=$(lookup_dep_url "$dep_sha256")

        if [ -n "$result_url" ]; then
            break
        fi

        echo "attempt $attempt failed" >&2
        if [ "$attempt" -ge 10 ]; then
            echo "  giving up" >&2
            exit 1
        fi

        echo "  will retry in 1s" >&2
        sleep 1

        attempt=$((attempt + 1))
    done
fi

# extract cluster
# NOTE: this assumes the result URL is https://artifacts.<CLUSTER>.dfinity.network/...
cluster=$(sed <<<"$result_url" -n -E 's$^https://artifacts.([^.]+).*$\1$p')
if [ -z "$cluster" ]; then
    echo "could not read cluster from '$result_url'" >&2
    exit 1
fi

echo "dep '$dep_filename': cluster is '$cluster'" >&2

# Use the direct URL, without going through the redirect server
dep_download_url="http://$cluster.artifacts.proxy-global.dfinity.network:8080/cas/$dep_sha256"
echo "dep '$dep_filename': download_url: '$dep_download_url'" >&2
echo "$dep_download_url"
