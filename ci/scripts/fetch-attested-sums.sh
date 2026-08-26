#!/usr/bin/env bash
#
# Download a directory's SHA256SUMS file from the CDN and verify it against
# the build-provenance attestation created by the `attest-uploads` job of the
# pipeline that built <commit> (see .github/actions/attest-uploads).
#
# The CDN (download.dfinity.systems, S3 + Cloudflare R2) is not a trust
# anchor: whoever can write to the buckets can replace artifacts and their
# SHA256SUMS alike (security finding 3618194). The attestation is stored by
# GitHub, signed via Sigstore with the workflow's OIDC identity, and covers
# the SHA256SUMS file's digest, so a substituted or tampered SHA256SUMS fails
# verification here. `--source-digest` pins the attestation to the exact
# commit, so a SHA256SUMS legitimately attested for some other commit fails
# too. Callers then verify each downloaded artifact against the verified sums
# with `sha256sum --check`; nothing other than SHA256SUMS files ever needs
# attestation verification.
#
# Usage:
#   fetch-attested-sums.sh <commit> <cdn-subdir> <signer-workflow> <out-file>
#
#   <commit>          40-hex git commit id whose artifacts to fetch
#   <cdn-subdir>      directory under ic/<commit>/ on the CDN,
#                     e.g. "canisters", "binaries/x86_64-linux",
#                     "guest-os/update-img-dev"
#   <signer-workflow> workflow whose attest-uploads job must have attested the
#                     upload, e.g.
#                       dfinity/ic/.github/workflows/ci-kickoff.yml
#                         (master commits)
#                       dfinity/ic/.github/workflows/release-testing.yml
#                         (rc--*/hotfix-* commits)
#   <out-file>        where to write the verified SHA256SUMS
#
# Requires the `gh` CLI (>= 2.61 for --source-digest) authenticated with any
# token able to read the public dfinity/ic attestations (in GitHub Actions,
# export GH_TOKEN="${{ github.token }}").
#
# Negative tests (documented per the house style for download verification):
# flipping one hex char in the downloaded SHA256SUMS, or passing the commit of
# a different build, makes `gh attestation verify` exit non-zero and this
# script abort before the file is used.

set -euo pipefail

if [ "$#" -ne 4 ]; then
    echo "usage: $0 <commit> <cdn-subdir> <signer-workflow> <out-file>" >&2
    exit 1
fi

commit="$1"
subdir="$2"
signer_workflow="$3"
out_file="$4"

# The repository whose attestation store anchors the artifacts. Builds from
# dfinity/ic-private are not attested; their commits gain attestations once
# the branch is pushed to dfinity/ic and rebuilt there.
repo="dfinity/ic"

if ! [[ "$commit" =~ ^[0-9a-f]{40}$ ]]; then
    echo "ERROR: commit must be a 40-character lowercase hex git commit id, got: $commit" >&2
    exit 1
fi

# One or more [A-Za-z0-9._-]+ segments separated by single slashes; then
# explicitly reject '.' and '..' segments so the subdir cannot escape the
# ic/<commit>/ prefix or alias another path.
if ! [[ "$subdir" =~ ^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$ ]] || [[ "/$subdir/" == *"/./"* ]] || [[ "/$subdir/" == *"/../"* ]]; then
    echo "ERROR: invalid cdn-subdir: $subdir" >&2
    exit 1
fi

if ! [[ "$signer_workflow" =~ ^[A-Za-z0-9._/-]+$ ]]; then
    echo "ERROR: invalid signer-workflow: $signer_workflow" >&2
    exit 1
fi

url="https://download.dfinity.systems/ic/${commit}/${subdir}/SHA256SUMS"

# Download to the target file, then verify BEFORE anything reads it. --fail
# ensures an HTTP error page fails here rather than as a verification error.
echo "Fetching $url" >&2
curl -fsSL --retry 3 "$url" -o "$out_file"

echo "Verifying attestation of $subdir/SHA256SUMS for commit $commit" >&2
gh attestation verify "$out_file" \
    --repo "$repo" \
    --signer-workflow "$signer_workflow" \
    --source-digest "$commit" \
    >&2
