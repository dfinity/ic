#!/usr/bin/env bash

GET_GUEST_OS_DEFAULT=1
GET_GUEST_OS=${GET_GUEST_OS-$GET_GUEST_OS_DEFAULT}
GET_HOST_OS_DEFAULT=0
GET_HOST_OS=${GET_HOST_OS-$GET_HOST_OS_DEFAULT}
GET_SETUP_OS_DEFAULT=0
GET_SETUP_OS=${GET_SETUP_OS-$GET_SETUP_OS_DEFAULT}

DEFAULT=$(git rev-parse HEAD)
GIT=${GIT-$DEFAULT}

CI_PROJECT_DIR=$(dirname "$0")/../..
cd "${CI_PROJECT_DIR}"
echo "➡️  Downloading artifacts for revision $GIT"
set -x
./ci/src/artifacts/rclone_download.py --git-rev $GIT --out=artifacts/canisters --remote-path canisters --latest-to
./ci/src/artifacts/rclone_download.py --git-rev $GIT --out=artifacts/release --remote-path release --latest-to
(
    cd artifacts/canisters
    for f in *.gz; do gunzip -f $f; done
)
(
    cd artifacts/release
    for f in *.gz; do gunzip -f $f; done
    chmod u+x *
)

if [[ $GET_GUEST_OS -eq 1 ]]; then
    ./ci/src/artifacts/rclone_download.py --git-rev $GIT --out=artifacts/guest-os --remote-path guest-os --latest-to
    (
        cd artifacts/guest-os/disk-img
        for f in *.gz; do gunzip -f $f; done
    )
    (
        cd artifacts/guest-os/disk-img
        for f in *.tar; do tar --sparse -xf $f; done
    )
fi

if [[ $GET_HOST_OS -eq 1 ]]; then
    ./ci/src/artifacts/rclone_download.py --git-rev $GIT --out=artifacts/host-os --remote-path host-os --latest-to
    (
        cd artifacts/host-os/disk-img
        for f in *.gz; do gunzip -f $f; done
    )
    (
        cd artifacts/host-os/disk-img
        for f in *.tar; do tar --sparse -xf $f; done
    )
fi

if [[ $GET_SETUP_OS -eq 1 ]]; then
    ./ci/src/artifacts/rclone_download.py --git-rev $GIT --out=artifacts/setup-os --remote-path setup-os --latest-to
    (
        cd artifacts/setup-os/disk-img
        for f in *.gz; do gunzip -f $f; done
    )
    (
        cd artifacts/setup-os/disk-img
        for f in *.tar; do tar --sparse -xf $f; done
    )
fi
