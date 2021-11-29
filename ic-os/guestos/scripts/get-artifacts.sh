#!/usr/bin/env bash

GET_GUEST_OS_DEFAULT=1
GET_GUEST_OS=${GET_GUEST_OS-$GET_GUEST_OS_DEFAULT}

DEFAULT=$(git rev-parse HEAD)
GIT=${GIT-$DEFAULT}

CI_PROJECT_DIR=$(dirname "$0")/../../..
cd "${CI_PROJECT_DIR}"
echo "➡️  Downloading artifacts for revision $GIT"
set -x
./gitlab-ci/src/artifacts/rclone_download.py --git-rev $GIT --out=artifacts/canisters --remote-path canisters --latest-to
./gitlab-ci/src/artifacts/rclone_download.py --git-rev $GIT --out=artifacts/release --remote-path release --latest-to
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
    ./gitlab-ci/src/artifacts/rclone_download.py --git-rev $GIT --out=artifacts/guest-os --remote-path guest-os --latest-to
    (
        cd artifacts/guest-os/disk-img
        for f in *.gz; do gunzip -f $f; done
    )
    (
        cd artifacts/guest-os/disk-img
        for f in *.tar; do tar --sparse -xf $f; done
    )

    DEFAULT=$(git rev-parse HEAD)
    GIT_REV=${GIT_REV-$DEFAULT}
    echo "➡️  Downloading artifacts for revision $GIT_REV (as upgrade target)"
    ./gitlab-ci/src/artifacts/rclone_download.py --git-rev $GIT_REV --out=artifacts/guest-os-master --remote-path guest-os --latest-to
    (
        cd artifacts/guest-os-master/disk-img
        for f in *.gz; do gunzip -f $f; done
    )
    (
        cd artifacts/guest-os-master/disk-img
        for f in *.tar; do tar --sparse -xf $f; done
    )
fi
