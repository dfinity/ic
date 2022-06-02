#!/usr/bin/env bash
#
# Script for comparing artifacts in AWS S3 that are produced from our CI
#
# We build and push artifacts to S3:
# * cargo-build-canisters            -> ic/<sha256>/canisters
# * cargo-build-release-linux-native -> ic/<sha256>/binaries
# * guest-os-updateimg               -> ic/<sha256>/guest-os/update-img
# We build the same set of artifacts:
# * docker-build-ic                  -> ic/<sha256>/docker-build-ic/canisters
#                                    -> ic/<sha256>/docker-build-ic/binaries
#                                    -> ic/<sha256>/docker-build-ic/icos/guest-os/update-img
#
# This script compares SHA256SUMS file [diff] and also the actual artifacts [diffoscope]

usage() {
    echo -e "Usage: $0 <path-0> <path-1> [<git-revision>]"
    echo -e ""
    echo -e "HEAD revision:"
    echo -e ""
    echo -e "\t$0 docker-build-ic/canisters canisters [diff]"
    echo -e "\t$0 docker-build-ic/release release [diff]"
    echo -e "\t$0 docker-build-ic/release/replica.gz release/replica.gz [diffoscope]"
    echo -e "\t$0 docker-build-ic/guest-os/update-img guest-os/update-img [diff/diffoscope]"
    echo -e ""
    echo -e "Specific revision:"
    echo -e ""
    echo -e "\t$0 /<sha256>/docker-build-ic/release release [diff]"
    echo -e "\t$0 /<sha256>/docker-build-ic/release /<sha256'>/release [diff]"
    echo -e "\t$0 /<sha256>/docker-build-ic/guest-os/update-img /<sha256>/guest-os/update-img [diff/diffoscope]"
    echo -e ""
    echo -e "Note: <sha256>/<sha256'> is git revision and must be full, 40 char string."
}

diffoscope_check() {
    if ! which diffoscope; then
        if grep -q Ubuntu /etc/os-release; then
            sudo apt-get update && sudo apt-get --no-install-recommends --yes install \
                "linux-image-$(uname -r)" diffoscope \
                python3-tlsh libguestfs-tools python3-guestfs squashfs-tools
        else
            echo "No diffoscope found!" && exit 1
        fi
    fi
}

if [ $# -lt 2 ]; then
    usage
    exit 1
fi

set -exuo pipefail

PATH0=$1
PATH1=$2
VERSION=${3:-$(git rev-parse HEAD)}

# relative path doesn't include sha256
if [[ ${PATH0::1} != '/' ]]; then
    PATH0="${VERSION}/${PATH0}"
else
    PATH0="${PATH0:1}"
fi

# relative path doesn't include sha256
if [[ ${PATH1::1} != '/' ]]; then
    PATH1="${VERSION}/${PATH1}"
else
    PATH1="${PATH1:1}"
fi

if [[ $PATH0 == *".gz" && $PATH1 == *".gz" ]]; then
    mkdir -p "$(dirname /tmp/$PATH0)"
    mkdir -p "$(dirname /tmp/$PATH1)"

    curl -sfS --retry 5 --retry-delay 10 \
        "https://download.dfinity.systems/ic/$PATH0" \
        -o "/tmp/$PATH0"
    curl -sfS --retry 5 --retry-delay 10 \
        "https://download.dfinity.systems/ic/$PATH1" \
        -o "/tmp/$PATH1"

    diffoscope_check
    diffoscope "/tmp/$PATH0" "/tmp/$PATH1"

    exit 0
fi

curl -sfS --retry 5 --retry-delay 10 \
    "https://download.dfinity.systems/ic/$PATH0/SHA256SUMS" \
    -o SHA256SUMS-0
curl -sfS --retry 5 --retry-delay 10 \
    "https://download.dfinity.systems/ic/$PATH1/SHA256SUMS" \
    -o SHA256SUMS-1

echo "$PATH0/SHA256SUMS:"
cat SHA256SUMS-0
echo "$PATH1/SHA256SUMS:"
cat SHA256SUMS-1

# XXX(marko): we ignore panics and sns-test-dapp-canister
sed -i -E '/(panics.wasm|sns-test-dapp-canister.wasm)/d' SHA256SUMS-*

if ! diff -u SHA256SUMS-0 SHA256SUMS-1; then
    set +x
    echo -e "\nThis script compares artifacts built from separate CI jobs"
    set -x

    if grep -q "update-img" SHA256SUMS-*; then
        echo "Running diffoscope for update-img"
        diffoscope_check

        ARTIFACT="update-img.tar.gz"
        if grep -q "host-update-img" SHA256SUMS-*; then
            ARTIFACT="host-update-img.tar.gz"
        fi

        mkdir -p "$PATH0" "$PATH1" artifacts
        curl -sfS --retry 5 --retry-delay 10 \
            "https://download.dfinity.systems/ic/$PATH0/$ARTIFACT" \
            -o "$PATH0/update-img.tar.gz"
        curl -sfS --retry 5 --retry-delay 10 \
            "https://download.dfinity.systems/ic/$PATH1/$ARTIFACT" \
            -o "$PATH1/update-img.tar.gz"

        cd "$PATH0"
        tar -xzf "$ARTIFACT"
        cd ..
        cd "$PATH1"
        tar -xzf "$ARTIFACT"
        cd ..

        # we give diffoscope 20min to find the diff
        timeout 20m sudo diffoscope \
            "$PATH0/boot.img" \
            "$PATH1/boot.img" \
            --html artifacts/output-boot.html --text -
        timeout 20m sudo diffoscope \
            "$PATH0/root.img" \
            "$PATH1/root.img" \
            --html artifacts/output-root.html --text -
    else
        set +x
        echo -e "Investigate with diffoscope [\xF0\x9F\x99\x8F]:"
        echo "  BIN=ic-admin.gz # (specify the right artifact)"
        echo "  $0 /${PATH0}/\$BIN /${PATH1}/\$BIN $VERSION"
        set -x
        exit 1
    fi
else
    echo "Build Determinism Check Successful"
fi
