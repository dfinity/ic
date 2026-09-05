#!/usr/bin/env bash
#
# Download a directory's SHA256SUMS file from the CDN and verify it against
# the build-provenance attestation created by the `attest-uploads` job of the
# pipeline that built <commit> (see .github/actions/attest-uploads).
#
# The CDN (download.dfinity.systems, S3 + Cloudflare R2) is not a trust
# anchor: whoever can write to the buckets can replace artifacts and their
# SHA256SUMS alike. The attestation is stored by
# GitHub, signed via Sigstore with the workflow's OIDC identity, and covers
# the SHA256SUMS file's digest, so a substituted or tampered SHA256SUMS fails
# verification here. `--source-digest` pins the attestation to the exact
# commit, so a SHA256SUMS legitimately attested for some other commit fails
# too. Callers then verify each downloaded artifact against the verified sums
# with `sha256sum --check`; nothing other than SHA256SUMS files ever needs
# attestation verification.
#
# Usage:
#   fetch-attested-sums.sh <commit> <cdn-subdir> <signer-workflow> \
#       <source-ref-regex> <out-file>
#
#   <commit>           40-hex git commit id whose artifacts to fetch
#   <cdn-subdir>       directory under ic/<commit>/ on the CDN,
#                      e.g. "canisters", "binaries/x86_64-linux",
#                      "guest-os/update-img-dev"
#   <signer-workflow>  workflow whose attest-uploads job must have attested
#                      the upload, e.g.
#                        dfinity/ic/.github/workflows/ci-kickoff.yml
#                          (master commits)
#                        dfinity/ic/.github/workflows/release-testing.yml
#                          (rc--*/hotfix-* commits)
#   <source-ref-regex> regex (anchored by this script) that the attestation's
#                      source git ref must match, e.g.
#                        refs/heads/master
#                          (master commits)
#                        refs/heads/(rc--|hotfix-)[^/]+
#                          (release-qualification branches)
#                      The signer-workflow pin alone fixes WHICH workflow
#                      signed, not from which ref it ran: those workflows can
#                      be dispatched on arbitrary branches (and ci-kickoff
#                      also runs for dev-gh-* pushes and PRs), so without
#                      this binding anyone able to trigger a release build of
#                      an unreviewed branch could mint an acceptable
#                      attestation. The ref regex confines acceptance to
#                      branches whose content is controlled (branch
#                      protection on master; release process on rc/hotfix).
#   <out-file>         where to write the verified SHA256SUMS
#
# Requires the `gh` CLI (>= 2.61 for --source-digest) authenticated with any
# token able to read the public dfinity/ic attestations (in GitHub Actions,
# export GH_TOKEN="${{ github.token }}"), and `jq`.
#
# Beyond `gh attestation verify` (which proves "SOME file of this build has
# this digest"), the script also requires the verified attestation to record
# the file's digest under the subject name "ic/<commit>/<cdn-subdir>/SHA256SUMS".
# One attestation covers every file a build uploaded, so without this
# subject-name binding a CDN writer could serve one directory's (legitimately
# attested) SHA256SUMS at another directory's path — e.g. the prod update-img
# sums at the update-img-dev path — and have consumers record a valid build
# hash for the wrong artifact. The subject names are trustworthy because the
# pinned --signer-workflow's attest-uploads job generates them from its own
# upload manifest.

set -euo pipefail

if [ "$#" -ne 5 ]; then
    echo "usage: $0 <commit> <cdn-subdir> <signer-workflow> <source-ref-regex> <out-file>" >&2
    exit 1
fi

commit="$1"
subdir="$2"
signer_workflow="$3"
source_ref_regex="$4"
out_file="$5"

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

# An invalid regex is not a bypass — jq's test() errors out and this script
# exits non-zero — but reject the empty string, which would anchor to ^()$
# and match nothing while looking like a configuration rather than a failure.
if [ -z "$source_ref_regex" ]; then
    echo "ERROR: source-ref-regex must not be empty" >&2
    exit 1
fi

expected_subject="ic/${commit}/${subdir}/SHA256SUMS"
url="https://download.dfinity.systems/${expected_subject}"

# Download to the target file, then verify BEFORE anything reads it. --fail
# ensures an HTTP error page fails here rather than as a verification error.
echo "Fetching $url" >&2
curl -fsSL --retry 3 "$url" -o "$out_file"

echo "Verifying attestation of $expected_subject" >&2
verify_output="$(mktemp)"
trap 'rm -f "$verify_output"' EXIT
gh attestation verify "$out_file" \
    --repo "$repo" \
    --signer-workflow "$signer_workflow" \
    --source-digest "$commit" \
    --format json \
    >"$verify_output"

# Bind the digest to THIS directory's path and the attestation to the
# expected source ref: at least one verified attestation must BOTH have been
# minted from a ref matching <source-ref-regex> (sourceRepositoryRef in its
# Sigstore certificate) AND list the file's digest under the expected subject
# name. Both conditions are checked on the same attestation entry — an
# attacker must not be able to satisfy them with two different attestations.
digest="$(sha256sum "$out_file" | cut -d' ' -f1)"
jq -e \
    --arg name "$expected_subject" \
    --arg digest "$digest" \
    --arg refRegex "^(${source_ref_regex})\$" \
    '[.[]
      | select(.verificationResult.signature.certificate.sourceRepositoryRef // ""
               | test($refRegex))
      | .verificationResult.statement.subject[]?
      | select(.name == $name and .digest.sha256 == $digest)]
     | length > 0' \
    "$verify_output" >/dev/null || {
    echo "ERROR: no verified attestation minted from a ref matching '${source_ref_regex}' records digest $digest under subject '$expected_subject'." >&2
    echo "The file served at $url is either attested from an unexpected ref (unqualified build?) or not as this directory's SHA256SUMS (cross-directory substitution?)." >&2
    exit 1
}

echo "Verified $expected_subject ($digest)" >&2
