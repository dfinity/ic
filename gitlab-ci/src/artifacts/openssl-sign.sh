#!/usr/bin/env bash
#
# Sign build artifacts with openssl
#

set -eEuo pipefail

if (($# < 1)); then
    echo >&2 "Usage: openssl-sign.sh <folder>"
    exit 1
fi

folder=${1:-}
cd "$folder"

# Ensure there is no leftover SHA256SUMS file, having it in the file list will
# break the signing process
rm -f SHA256SUMS
(
    GLOBIGNORE="SHA256SUMS"
    sha256sum -b * | tee SHA256SUMS
)

cp SHA256SUMS sign-input.txt
git rev-parse --verify HEAD >>sign-input.txt

openssl dgst -sha256 -hex -sign /openssl/private.pem -out "sign.sig" sign-input.txt

echo "CI_COMMIT_REF_PROTECTED: ${CI_COMMIT_REF_PROTECTED:-}"
if [[ "${CI_COMMIT_REF_PROTECTED:-}" == "true" ]]; then
    # On protected branches ensure that signatures we just created can be verified
    "$CI_PROJECT_DIR"/gitlab-ci/src/artifacts/openssl-verify.sh .
fi
