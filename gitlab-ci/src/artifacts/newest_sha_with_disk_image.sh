#!/usr/bin/env bash
#
# Return the newest Git SHA on the provided branch for which a disk image has been built on the CI
#

if (($# < 1)); then
    echo >&2 "Usage: newest_sha_with_artifacts.sh <branch_name> [<count>]"
    exit 1
fi

branch_name=${1:-}
count=${2:-1}

function disk_image_exists() {
    git_sha=$1
    curl --output /dev/null --silent --head --fail \
        "https://download.dfinity.systems/blessed/ic/$git_sha/guest-os/disk-img/disk-img.tar.gz" \
        || curl --output /dev/null --silent --head --fail \
            "https://download.dfinity.systems/ic/$git_sha/guest-os/disk-img/disk-img.tar.gz" \
        || curl --output /dev/null --silent --head --fail \
            "https://download.dfinity.systems/ic/$git_sha/guest-os/disk-img.tar.gz" \
        || curl --output /dev/null --silent --head --fail \
            "https://download.dfinity.systems/blessed/ic/$git_sha/guest-os/disk-img/disk-img.tar.zst" \
        || curl --output /dev/null --silent --head --fail \
            "https://download.dfinity.systems/ic/$git_sha/guest-os/disk-img/disk-img.tar.zst" \
        || curl --output /dev/null --silent --head --fail \
            "https://download.dfinity.systems/ic/$git_sha/guest-os/disk-img.tar.zst"
}

for git_sha in $(git log --format=format:%H "$branch_name" --max-count=50); do
    test "$count" = 0 && exit 0
    if disk_image_exists $git_sha; then
        echo $git_sha
        count=$((count - 1))
    fi
done

echo >&2 "No artifacts could be found for <branch_name>"
exit 1
