#!/usr/bin/env bash

set -euo pipefail

print_usage() {
    cat >&2 <<-USAGE
    This script builds and diffs the update image between CI and docker-build-ic
    options:
    -h	this help message
    -n	dry run mode, do not build local dev image
    -c	git revision to use, defaults to the current commit
USAGE
}

build_dev=1
while getopts 'nhc:' flag; do
    case "${flag}" in
        c) git_hash="${OPTARG}" ;;
        n) build_dev=0 ;;
        h)
            print_usage
            exit 1
            ;;
        *)
            print_usage
            exit 1
            ;;
    esac
done

git_hash=${git_hash:-$(git rev-parse HEAD)}

OUT="$HOME/disk-images/$git_hash"
CI_OUT="$OUT/ci-img"
DEV_OUT="$OUT/dev-img"

mkdir -p "$CI_OUT"
mkdir -p "$DEV_OUT"

if ! which diffoscope; then
    echo "Please install diffoscope: sudo apt install diffoscope"
    read -p "Should I do this for you [yn]?" yn
    case $yn in
        [Yy]*)
            sudo apt install diffoscope
            break
            ;;
        [Nn]*) exit 1 ;;
        *) echo "Please answer yes or no." ;;
    esac
fi

pushd "$(git rev-parse --show-toplevel)"
if ! ./gitlab-ci/src/artifacts/rclone_download.py --git-rev=$git_hash --out="$CI_OUT" --remote-path guest-os/update-img; then
    echo "please either create *DRAFT* merge request pipeline for this commit sha:$git_hash or make sure that GitLab is running a pipeline against this commit SHA"
    echo "Note that this script does not work on older branches which use build id instead of the git commit sha"
    echo "e.g. any commits before eab9be79c53a88627881258b399ac9967aae7a60"
    read -p "Confirm OK to continue [yn]" yn
    case $yn in
        [Yy]*) break ;;
        [Nn]*) exit 1 ;;
        *) echo "Please answer yes or no." ;;
    esac
fi

echo "images will be saved in $OUT"

cwd=$(pwd)
# fetch the commit from upstream here while in the users IC directory
# otherwise we would have to configure git remotes in the temp dir.
git fetch --quiet origin "$git_hash"

tmp=$(mktemp -d)
trap "rm -fr $tmp" EXIT

pushd "$tmp"
git clone --quiet "$cwd" .
git checkout --quiet "$git_hash"

if [ "$build_dev" -eq "1" ]; then
    ./gitlab-ci/tools/docker-build-ic
    mv artifacts/docker-build-ic/icos/update-img.tar.gz "$DEV_OUT"
fi

if [ ! -f "$CI_OUT/update-img.tar.gz" ]; then
    ./gitlab-ci/src/artifacts/rclone_download.py --git-rev="$git_hash" --out="$CI_OUT" --remote-path guest-os/update-img
fi

tar -xzf "$CI_OUT/update-img.tar.gz" -C "$CI_OUT"
tar -xzf "$DEV_OUT/update-img.tar.gz" -C "$DEV_OUT"

echo ""
echo "sh256sum of CI contents"
find $CI_OUT -name *.img -type f -exec sha256sum {} \;

echo ""
echo "sh256sum of Dev contents"
find $DEV_OUT -name *.img -type f -exec sha256sum {} \;

echo ""
echo "diffoscope"
sudo diffoscope "$CI_OUT/boot.img" "$DEV_OUT/boot.img" || true

echo ""
sudo diffoscope "$CI_OUT/root.img" "$DEV_OUT/root.img" || true

echo "disk images saved to $OUT"
