#!/usr/bin/env bash
#
# Script for comparing artifacts in AWS S3 that are produced from our CI
#
# We build and push artifacts to S3:
# * [bazel] //publish/canister      -> ic/<sha256>/canisters
# * [bazel] //publish/binaries      -> ic/<sha256>/binaries
# * [bazel] //ic-os/guestos/envs/prod:*  -> ic/<sha256>/guest-os/update-img
# We build the same set of artifacts:
# * build-ic                        -> ic/<sha256>/build-ic/canisters
#                                   -> ic/<sha256>/build-ic/binaries
#                                   -> ic/<sha256>/build-ic/icos/guest-os/update-img
#
# This script compares SHA256SUMS file [diff] and also the actual artifacts [diffoscope]

RED='\033[0;31m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'
NOCOLOR='\033[0m'

echo_red() { echo -e "${RED}${1}${NOCOLOR}"; }
echo_blue() { echo -e "${BLUE}${1}${NOCOLOR}"; }
echo_green() { echo -e "${GREEN}${1}${NOCOLOR}"; }

usage() {
    echo -e "Usage: $0 <path-0> <path-1> [<git-revision>]"
    echo -e ""
    echo -e "HEAD revision:"
    echo -e ""
    echo -e "\t$0 build-ic/canisters canisters [diff]"
    echo -e "\t$0 build-ic/release release [diff]"
    echo -e "\t$0 build-ic/release/replica.gz release/replica.gz [diffoscope]"
    echo -e "\t$0 build-ic/guest-os/update-img guest-os/update-img [diff/diffoscope]"
    echo -e ""
    echo -e "Specific revision:"
    echo -e ""
    echo -e "\t$0 /<sha256>/build-ic/release release [diff]"
    echo -e "\t$0 /<sha256>/build-ic/release /<sha256'>/release [diff]"
    echo -e "\t$0 /<sha256>/build-ic/guest-os/update-img /<sha256>/guest-os/update-img [diff/diffoscope]"
    echo -e ""
    echo -e "Note: <sha256>/<sha256'> is git revision and must be full, 40 char string."
}

alert() {
    # no alert if this is not a scheduled CI job!
    if [ ${CI_PIPELINE_SOURCE:-} != "schedule" ]; then
        exit 1
    fi

    MESSAGE="Release Build Reproducibility Failure in <$CI_JOB_URL|$CI_JOB_NAME>! "
    MESSAGE+="Follow <http://go/reproducible-builds-incident-runbook|this run-book>! "
    MESSAGE+="<!subteam^S022UEH2AKE>"
    # https://stackoverflow.com/questions/54284389/mention-users-group-via-slack-api

    ./ci/src/notify_slack/notify_slack.py \
        "$MESSAGE" --channel "#eng-idx-alerts"

    exit 1
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

if [[ $PATH0 == *".zst" && $PATH1 == *".zst" ]]; then
    mkdir -p "$(dirname /tmp/$PATH0)"
    mkdir -p "$(dirname /tmp/$PATH1)"

    curl -sfS --retry 5 --retry-delay 10 \
        "https://download.dfinity.systems/ic/$PATH0" \
        -o "/tmp/$PATH0"
    curl -sfS --retry 5 --retry-delay 10 \
        "https://download.dfinity.systems/ic/$PATH1" \
        -o "/tmp/$PATH1"

    diffoscope --text - --html-dir "diffoscope-${VERSION}" "/tmp/$PATH0" "/tmp/$PATH1"

    exit 0
fi

TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT
SHA256SUMS0="$TMPDIR/SHA256SUMS0"
SHA256SUMS1="$TMPDIR/SHA256SUMS01"
rm -f $SHA256SUMS0 $SHA256SUMS1

curl -sfS --retry 5 --retry-delay 10 \
    "https://download.dfinity.systems/ic/$PATH0/SHA256SUMS" \
    -o $SHA256SUMS0
curl -sfS --retry 5 --retry-delay 10 \
    "https://download.dfinity.systems/ic/$PATH1/SHA256SUMS" \
    -o $SHA256SUMS1

echo "$PATH0/SHA256SUMS:"
cat $SHA256SUMS0
echo "$PATH1/SHA256SUMS:"
cat $SHA256SUMS1

# ignore *.wasm.gz.did files
sed -i -e '/.wasm.gz.did/d' $SHA256SUMS0 $SHA256SUMS1

echo "Full diff before dropping artifacts allowed non-determinism"
diff -u "$SHA256SUMS0" "$SHA256SUMS1" || true

# TODO:(IDX-3050) remove after BD issue is resolved
sed -i -e '/json.wasm.gz/d' -e '/http_counter.wasm.gz/d' $SHA256SUMS0 $SHA256SUMS1

# Most of the time, we only want to check update images so we strip out any
# disk images. When checking SetupOS, do the opposite.
SETUPOS_FLAG="${SETUPOS_FLAG:=}"
if [ "${SETUPOS_FLAG}" != "" ]; then
    sed -i -e '/update-img/d' $SHA256SUMS0 $SHA256SUMS1
else
    sed -i -e '/disk-img/d' $SHA256SUMS0 $SHA256SUMS1
fi

if ! diff -u $SHA256SUMS0 $SHA256SUMS1; then
    set +x
    echo_green "Investigate with diffoscope [\xF0\x9F\x99\x8F]:\n"
    if grep -q "img.tar.zst" $SHA256SUMS0; then
        echo_blue "# Download IC-OS image:\n"

        if grep -q "update-img.tar.zst" $SHA256SUMS0; then
            ARTIFACT="update-img.tar.zst"
        else
            ARTIFACT="disk-img.tar.zst"
        fi

        echo "rm -rf /tmp/$PATH0 && mkdir -p /tmp/$PATH0"
        echo "rm -rf /tmp/$PATH1 && mkdir -p /tmp/$PATH1"
        echo "curl -sfS https://download.dfinity.systems/ic/$PATH0/$ARTIFACT -o /tmp/$PATH0/$ARTIFACT"
        echo "curl -sfS https://download.dfinity.systems/ic/$PATH1/$ARTIFACT -o /tmp/$PATH1/$ARTIFACT"

        if grep -q "update-img.tar.zst" $SHA256SUMS0; then
            echo_blue "# Mount IC-OS boot & root image as loop devices:\n"
            echo "pushd /tmp/$PATH0"
            echo "tar -xzf $ARTIFACT"
            echo "DEV00=\$(sudo losetup --show -f -P root.img)"
            echo "mkdir -p root.img.mnt"
            echo "sudo mount \$DEV00 root.img.mnt"
            echo "DEV01=\$(sudo losetup --show -f -P boot.img)"
            echo "mkdir -p boot.img.mnt"
            echo "sudo mount \$DEV01 boot.img.mnt"
            echo "popd"

            echo "pushd /tmp/$PATH1"
            echo "tar -xzf $ARTIFACT"
            echo "DEV10=\$(sudo losetup --show -f -P root.img)"
            echo "mkdir -p root.img.mnt"
            echo "sudo mount \$DEV10 root.img.mnt"
            echo "DEV11=\$(sudo losetup --show -f -P boot.img)"
            echo "mkdir -p boot.img.mnt"
            echo "sudo mount \$DEV11 boot.img.mnt"
            echo "popd"

            echo_blue "# Run diffoscope:\n"
            echo "sudo diffoscope /tmp/$PATH0/root.img.mnt /tmp/$PATH1/root.img.mnt"
            echo "sudo diffoscope /tmp/$PATH0/boot.img.mnt /tmp/$PATH1/boot.img.mnt"

            echo_blue "# Unmount and detach all loop devices:\n"
            echo "sudo umount -d \$DEV00 \$DEV01 \$DEV10 \$DEV11"
        else
            echo_blue "# Mount IC-OS image partitions as loop devices:\n"
            # TODO: handle lvm2 partition of host-os image
            echo "pushd /tmp/$PATH0"
            echo "tar -xzf $ARTIFACT"
            echo "DEV0=\$(sudo losetup --show -f -P disk.img)"
            echo "mkdir -p disk.img.mnt"
            echo "sudo partx --show -g \$DEV0 | cut -d' ' -f2 | xargs -I{} mkdir -p disk.img.mnt/{}"
            echo "sudo partx --show -g \$DEV0 | cut -d' ' -f2 | xargs -I{} sudo mount \${DEV0}p{} disk.img.mnt/{}"
            echo "popd"

            echo "pushd /tmp/$PATH1"
            echo "tar -xzf $ARTIFACT"
            echo "DEV1=\$(sudo losetup --show -f -P disk.img)"
            echo "mkdir -p disk.img.mnt"
            echo "sudo partx --show -g \$DEV1 | cut -d' ' -f2 | xargs -I{} mkdir -p disk.img.mnt/{}"
            echo "sudo partx --show -g \$DEV1 | cut -d' ' -f2 | xargs -I{} sudo mount \${DEV1}p{} disk.img.mnt/{}"
            echo "popd"

            echo_blue "# Run diffoscope:\n"
            echo "sudo diffoscope /tmp/$PATH0/disk.img.mnt /tmp/$PATH1/disk.img.mnt"

            echo_blue "# Unmount and detach all loop devices:\n"
            echo "sudo umount -d \${DEV0}p* \${DEV1}p*"
        fi
        echo_red "# Instructions above might be outdated and rather serve as a guideline!\n"
    else
        echo_blue "# Re-run $0 as shown below:\n"
        echo "  BIN=ic-admin.gz # (specify the right artifact)"
        echo "  $0 /${PATH0}/\$BIN /${PATH1}/\$BIN $VERSION"
    fi
    alert
    set -x
else
    echo "Build Determinism Check Successful"
fi
