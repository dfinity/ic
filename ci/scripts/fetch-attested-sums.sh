#!/usr/bin/env bash
#
# Download a directory's SHA256SUMS file from the CDN and verify it against the
# build-provenance attestation minted by the CI run that built <commit> (the
# Attest steps of .github/workflows/ci-main.yml, called by ci-kickoff.yml for
# master commits or release-testing.yml for rc--*/hotfix-* commits).
#
# The CDN (download.dfinity.systems, S3 + Cloudflare R2) is not a trust anchor:
# whoever can write to the buckets can replace artifacts and their SHA256SUMS
# alike. The attestation is stored by GitHub, signed via Sigstore with the
# workflow's OIDC identity, and covers the SHA256SUMS file's digest, so a
# substituted or tampered SHA256SUMS fails verification here. `--source-digest`
# pins the attestation to the exact commit, so a SHA256SUMS legitimately
# attested for some other commit fails too. Callers then verify each downloaded
# artifact against the verified sums with `sha256sum --check`; nothing other
# than SHA256SUMS files ever needs attestation verification.
#
# Usage:
#   fetch-attested-sums.sh <commit> <cdn-subdir> <build-workflow> <source-ref-regex> <out-file>
#
#   <commit>           40-hex git commit id whose artifacts to fetch
#   <cdn-subdir>       directory under ic/<commit>/ on the CDN,
#                      e.g. "canisters", "binaries/x86_64-linux", "guest-os/update-img"
#   <build-workflow>   top-level workflow of the CI run that must have uploaded and
#                      attested the artifacts, e.g.
#                        dfinity/ic/.github/workflows/ci-kickoff.yml (master commits)
#                        dfinity/ic/.github/workflows/release-testing.yml (rc--*/hotfix-* commits)
#                      Both of these call ci-main.yml as a reusable workflow and it is
#                      ci-main.yml's upload jobs that attest, so ci-main.yml is always
#                      the SIGNER (pinned below, invariant across pipelines) while the
#                      calling pipeline shows up only in the certificate's Build Config
#                      URI (OID 1.3.6.1.4.1.57264.1.18). `gh` has no flag for that
#                      field, so it is enforced in the jq filter further down.
#   <source-ref-regex> regex (anchored by this script) that the attestation's
#                      source git ref must match, e.g.
#                        refs/heads/master (master commits)
#                        refs/heads/(rc--|hotfix-)[^/]+ (release-qualification branches)
#                      The build-workflow pin alone fixes WHICH pipeline ran,
#                      not from which ref it ran: those workflows can
#                      be dispatched on arbitrary branches (and ci-kickoff
#                      also runs for dev-gh-* pushes and PRs), so without
#                      this binding anyone able to trigger a release build of
#                      an unreviewed branch could mint an acceptable
#                      attestation. The ref regex confines acceptance to
#                      branches whose content is controlled (branch
#                      protection on master; release process on rc/hotfix).
#   <out-file>         where to write the verified SHA256SUMS
#
# Beyond `gh attestation verify` (which proves "SOME file of this build has
# this digest"), the script also requires the verified attestation to record
# the file's digest under the subject name "ic/<commit>/<cdn-subdir>/SHA256SUMS".
# Each attestation covers every file its uploading job uploaded (a release build
# mints one per uploading job), so without this subject-name binding a CDN writer
# could serve one directory's (legitimately attested) SHA256SUMS at another
# directory's path — e.g. the prod update-img sums at the update-img-dev path —
# and have consumers record a valid build hash for the wrong artifact. The
# subject names are trustworthy because the pinned signer workflow's upload jobs
# generate them from their own upload manifests.
#
# Attestations minted between #11323 and #11569 were signed by the calling
# workflow itself (ci-kickoff.yml / release-testing.yml) rather than by
# ci-main.yml, and are rejected here by design. They cannot be re-minted: a
# workflow_dispatch on such a commit's branch runs that branch's tree.

set -euo pipefail

if [ "$#" -ne 5 ]; then
    echo "usage: $0 <commit> <cdn-subdir> <build-workflow> <source-ref-regex> <out-file>" >&2
    exit 1
fi

commit="$1"
subdir="$2"
build_workflow="$3"
source_ref_regex="$4"
out_file="$5"

# The repository whose attestation store anchors the artifacts. Builds from
# dfinity/ic-private are not attested; their commits gain attestations once
# the (hotfix-*) branch is pushed to dfinity/ic and rebuilt there.
repo="dfinity/ic"

# The reusable workflow whose upload jobs mint the attestation, and hence the
# certificate SAN (Build Signer URI) of every attestation this script accepts.
# It is the same for every pipeline: see <build-workflow> above.
signer_workflow="dfinity/ic/.github/workflows/ci-main.yml"

if ! [[ "$commit" =~ ^[0-9a-f]{40}$ ]]; then
    echo "ERROR: commit must be a 40-character lowercase hex git commit id, got: $commit" >&2
    exit 1
fi

# One or more [A-Za-z0-9._-]+ segments separated by single slashes; then
# explicitly reject '.' and '..' segments so the subdir cannot escape the
# ic/<commit>/ prefix or alias another path.
if ! [[ "$subdir" =~ ^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$ ]] \
    || [[ "/$subdir/" == *"/./"* ]] \
    || [[ "/$subdir/" == *"/../"* ]]; then
    echo "ERROR: invalid cdn-subdir: $subdir" >&2
    exit 1
fi

if ! [[ "$build_workflow" =~ ^dfinity/ic/\.github/workflows/[A-Za-z0-9_-]+\.yml$ ]]; then
    echo "ERROR: invalid build-workflow (expected dfinity/ic/.github/workflows/<name>.yml): $build_workflow" >&2
    exit 1
fi

if [ -z "$source_ref_regex" ]; then
    echo "ERROR: source-ref-regex must not be empty" >&2
    exit 1
fi

expected_subject="ic/${commit}/${subdir}/SHA256SUMS"
url="https://download.dfinity.systems/${expected_subject}"

# Download to the target file, then verify BEFORE anything reads it.
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

# Bind, on the SAME verified attestation entry: (1) the top-level workflow of
# the run that minted it (buildConfigURI, OID 1.3.6.1.4.1.57264.1.18) to
# <build-workflow>, (2) the ref it ran from (sourceRepositoryRef) to
# <source-ref-regex>, and (3) the file's digest to THIS directory's subject
# name. (1) and (2) are certificate fields Fulcio populates from the run's OIDC
# token; (3) is statement data, trustworthy only because --signer-workflow above
# pins who produced it. All three are checked on one entry — an attacker must
# not be able to satisfy them with three different attestations.
#
# The buildConfigURI is "<workflow path>@<ref>"; the prefix match includes the
# trailing '@' so it can only match at the end of the workflow path, never at a
# workflow whose name merely extends <build-workflow>'s.
digest="$(sha256sum "$out_file" | cut -d' ' -f1)"
jq -e \
    --arg name "$expected_subject" \
    --arg digest "$digest" \
    --arg refRegex "^(${source_ref_regex})\$" \
    --arg buildConfigPrefix "https://github.com/${build_workflow}@" \
    '[.[]
      | .verificationResult.signature.certificate as $cert
      | select(($cert.buildConfigURI // "") | startswith($buildConfigPrefix))
      | select(($cert.sourceRepositoryRef // "") | test($refRegex))
      | .verificationResult.statement.subject[]?
      | select(.name == $name and .digest.sha256 == $digest)]
     | length > 0' \
    "$verify_output" >/dev/null || {
    echo "ERROR: no verified attestation from a '${build_workflow}' run on a ref matching '${source_ref_regex}' records digest $digest under subject '$expected_subject'." >&2
    echo "The file served at $url is either attested by an unexpected pipeline, attested from an unexpected ref (unqualified build?), or not attested as this directory's SHA256SUMS (cross-directory substitution?)." >&2
    echo "Note: attestations minted between #11323 and #11569 were signed by the calling workflow rather than by ci-main.yml and are rejected here by design." >&2
    exit 1
}

echo "Verified $expected_subject ($digest)" >&2
