#!/usr/bin/env bash
#
# Usage: mainnet-icos-download.sh URL SHA256 OUT
#
# Build-time, sha256-verified download of one mainnet ICOS image. Called from the
# genrules that //bazel:mainnet-icos-images.bzl writes into the @mainnet_*_images
# repositories; see that file for why the images are downloaded at build time
# rather than while the repository is fetched.
#
# The action runs under --incompatible_strict_action_env, i.e. with
# PATH=/bin:/usr/bin:/usr/local/bin and without the client's proxy variables.
# An environment that needs a proxy to reach download.dfinity.systems has to
# pass it explicitly, e.g. `--action_env=HTTPS_PROXY=...`.
set -euo pipefail

url="$1"
sha256="$2"
out="$3"

# Download into a temp file next to the output and rename it only after the
# checksum matched, so an interrupted action never leaves a truncated $out.
part="$out.part"
trap 'rm -f "$part"' EXIT

verify() {
    echo "$sha256  $part" | sha256sum --check --status
}

# Two independent budgets: up to 5 failed transfers (network trouble) and up to
# 2 complete transfers with the wrong checksum. Keeping them apart guarantees the
# one clean re-download after a checksum mismatch, even when the mismatch happens
# on the last of the 5 transfer attempts.
failures=0
mismatches=0
while true; do
    # --continue-at - resumes whatever an earlier attempt left in $part. curl's
    # own --retry handles short blips in-process; --speed-limit/--speed-time turn
    # a stalled connection (< 100 KB/s for 120 s) into a retryable error instead
    # of a hang. No --max-time: a multi-GB image legitimately takes minutes.
    curl_status=0
    curl --fail --silent --show-error --location --proto '=https' \
        --retry 5 --retry-all-errors --retry-delay 5 \
        --speed-limit 102400 --speed-time 120 \
        --continue-at - --output "$part" "$url" || curl_status=$?

    # Verify even after a curl error: a transfer that completed but reported a
    # late error still verifies (this also covers a resume of an already complete
    # $part).
    if [ -f "$part" ] && verify; then
        mv -f "$part" "$out" # same directory: atomic
        trap - EXIT
        exit 0
    fi

    if [ "$curl_status" -eq 0 ]; then
        # Complete transfer, wrong content. Retry once from scratch to rule out a
        # corrupted resume, then fail: the JSON pin and the CDN disagree.
        mismatches=$((mismatches + 1))
        echo "$url: sha256 mismatch: expected $sha256, got $(sha256sum "$part" | cut -d' ' -f1)" >&2
        rm -f "$part"
        if [ "$mismatches" -ge 2 ]; then
            echo "ERROR: $url does not match the sha256 recorded in mainnet-icos-revisions.json" >&2
            exit 1
        fi
    else
        failures=$((failures + 1))
        if [ "$failures" -ge 5 ]; then
            echo "ERROR: giving up on $url after $failures failed download attempts" >&2
            exit 1
        fi
        echo "$url: download attempt $failures failed (curl exit $curl_status); retrying" >&2
        sleep $((failures * 10))
    fi
done
