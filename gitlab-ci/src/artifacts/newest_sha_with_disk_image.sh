#!/usr/bin/env bash
#
# Return the newest Git SHA on the provided branch for which a disk image has been built on the CI
#

if (($# < 1)); then
    echo >&2 "Usage: newest_sha_with_artifacts.sh <branch_name> [<count>]"
    exit 1
fi

function disk_image_exists() {
    local GIT_SHA=$1

    URLS=(
        "https://download.dfinity.systems/blessed/ic/${GIT_SHA}/guest-os/disk-img/disk-img.tar.gz"
        "https://download.dfinity.systems/blessed/ic/${GIT_SHA}/guest-os/disk-img/disk-img.tar.zst"
        "https://download.dfinity.systems/ic/${GIT_SHA}/guest-os/disk-img.tar.gz"
        "https://download.dfinity.systems/ic/${GIT_SHA}/guest-os/disk-img.tar.zst"
        "https://download.dfinity.systems/ic/${GIT_SHA}/guest-os/disk-img/disk-img.tar.gz"
        "https://download.dfinity.systems/ic/${GIT_SHA}/guest-os/disk-img/disk-img.tar.zst"
    )

    for url in ${URLS[@]}; do
        curl -sL -I --fail "${url}" -o /dev/null
        if [[ "$?" == "0" ]]; then
            return 0
        fi
    done

    return 1
}

branch_name=${1:-}
count=${2:-1}

for git_sha in $(git log --format=format:%H "$branch_name" --max-count=50); do
    test "$count" = 0 && exit 0
    if disk_image_exists $git_sha; then
        echo $git_sha
        count=$((count - 1))
    fi
done

echo >&2 "No artifacts could be found for <branch_name>"
exit 1
