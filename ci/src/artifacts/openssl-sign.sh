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
rm -f SHA256SUMS sign-input.txt sign.sig sign.sig.bin
(
    GLOBIGNORE="SHA256SUMS"
    shasum --algorithm 256 --binary * | tee SHA256SUMS
)
