#!/usr/bin/env bash
#
# Verify signed build artifacts with openssl
#

set -eEuo pipefail

if (($# < 1)); then
    echo >&2 "Usage: openssl-verify.sh <folder>"
    exit 1
fi

BASEDIR=$(
    cd "$(dirname "${BASH_SOURCE[0]}")"
    pwd
)

folder=${1:-}
cd "$folder"

echo
echo "# Verifying the SHA256 sums of the build artifacts"
echo
sed -e '$d' sign-input.txt >SHA256SUMS
sha256sum -c SHA256SUMS

echo
echo "# Verifying the validity of the sign-input.txt"
echo
# verify the signature
cat sign.sig | sed -e 's/.*= \(.*\)$/\1/' | xxd -r -p >sign.sig.bin
openssl dgst -sha256 -verify $BASEDIR/trusted-builders-public.key -signature "sign.sig.bin" sign-input.txt

echo
echo "***** Verified the trusted build of revision $(tail -n 1 sign-input.txt) ******"
echo
