#!/usr/bin/env bash
set -euo pipefail

[ -n "${DEBUG:-}" ] && set -x

usage() {
    cat <<EOF
Utility script for building IC.

Usage: $0 -b -c -i

    -b  Build IC Binaries
    -c  Build IC Canisters
    -i  Build IC-OS Image
    -h  Print help
EOF
}

RED='\033[0;31m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'
NOCOLOR='\033[0m'

echo_red() { echo -e "${RED}${1}${NOCOLOR}"; }
echo_blue() { echo -e "${BLUE}${1}${NOCOLOR}"; }
echo_green() { echo -e "${GREEN}${1}${NOCOLOR}"; }

export BUILD_BIN=false
export BUILD_CAN=false
export BUILD_IMG=false
export BUILD_DEBUG_IMG=false
export BUILD_STATIC_SSL=false


if [ "$#" == 0 ]; then
    echo_red "ERROR: Please specify one of '-b', '-c' or '-i'" >&2
    echo ""
    usage && exit 1
fi

while getopts ':bcidsh' opt; do
    case "$opt" in
        b) BUILD_BIN=true ;;
        c) BUILD_CAN=true ;;
        i) BUILD_IMG=true ;;
        d) BUILD_DEBUG_IMG=true ;;
        s) BUILD_STATIC_SSL=true ;;
        h) usage && exit 0 ;;
        :) echo_red "Option requires an argument.\n" && usage && exit 1 ;;
        ?) echo_red "Invalid command option.\n" && usage && exit 1 ;;
    esac
done
shift "$(($OPTIND - 1))"

export ROOT_DIR="$(git rev-parse --show-toplevel)"
export VERSION="$(git rev-parse HEAD)"
export IC_VERSION_RC_ONLY="0000000000000000000000000000000000000000"

# fetch all protected branches
#git fetch origin 'refs/heads/master:refs/remotes/origin/master'
#git fetch origin 'refs/heads/rc--*:refs/remotes/origin/rc--*'
# check if $VERSION is in any protected branch
BRANCHES_REGEX='(origin/master|origin/rc--20)'
if git branch -r --contains $VERSION | grep -qE "$BRANCHES_REGEX"; then
    IC_VERSION_RC_ONLY="$VERSION"
fi

export BINARIES_DIR=artifacts/release
export CANISTERS_DIR=artifacts/canisters
export DISK_DIR=artifacts/icos
export BINARIES_DIR_FULL="$ROOT_DIR/$BINARIES_DIR"
export CANISTERS_DIR_FULL="$ROOT_DIR/$CANISTERS_DIR"
export DISK_DIR_FULL="$ROOT_DIR/$DISK_DIR"

is_inside_container() {
    [ -e /.dockerenv ] || [ -e /run/.containerenv ] || [ -n "${CI_JOB_URL:-}" ]
}

validate_build_env() {
    function not_supported_prompt() {
        echo_red "$1"
        read -t 7 -r -s -p $'Press ENTER to continue the build anyway...\n'
    }

    if [ -n "$(git status --porcelain)" ]; then
        echo_red "Git working directory is not clean! Clean it and retry."
       # exit 1
    fi

    if [ "$(uname)" != "Linux" ]; then
        not_supported_prompt "This script is only supported on Linux!"
    elif ! grep -q 'Ubuntu' /etc/os-release; then
        not_supported_prompt "Build reproducibility is only supported on Ubuntu!"
    fi
}

echo_green "Validating build environment"
validate_build_env

echo_blue "Purging artifact directories"
rm -rf "$BINARIES_DIR_FULL"
rm -rf "$CANISTERS_DIR_FULL"
rm -rf "$DISK_DIR_FULL"

if [[ $BUILD_STATIC_SSL ]]
then
    SSL_OPT="DFINITY_OPENSSL_STATIC=1 "
else
    SSL_OPT=""
fi

BAZEL_ENV="CARGO_BAZEL_REPIN=true"
echo_green "Building selected IC artifacts"
BAZEL_CMD="$BAZEL_ENV bazel build --config=local --ic_version='$VERSION' --ic_version_rc_only='$IC_VERSION_RC_ONLY'"
BUILD_BINARIES_CMD=$(
    cat <<-END
    # build binaries
    mkdir -p "$BINARIES_DIR"
    $SSL_OPT $BAZEL_CMD //publish/binaries
    bazel cquery --output=files //publish/binaries | xargs -I {} cp {} "$BINARIES_DIR"
END
)

BUILD_CANISTERS_CMD=$(
    cat <<-END
    # build canisters
    mkdir -p "$CANISTERS_DIR"
    $BAZEL_CMD //publish/canisters
    bazel cquery --output=files //publish/canisters | xargs -I {} cp {} "$CANISTERS_DIR"
END
)

if [[ $BUILD_DEBUG_IMG ]]
then
    IMG_TYPE=dev
else
    IMG_TYPE=prod
fi

BUILD_IMAGES_CMD=$(
    cat <<-END
    # build ic-os images
    mkdir -p "$DISK_DIR"
    $BAZEL_CMD //ic-os/guestos/${IMG_TYPE}
    bazel cquery --output=files //ic-os/guestos/${IMG_TYPE} | xargs -I {} cp {} "$DISK_DIR"
END
)
BUILD_CMD=""

if "$BUILD_BIN"; then BUILD_CMD="${BUILD_CMD}${BUILD_BINARIES_CMD}"; fi
if "$BUILD_CAN"; then BUILD_CMD="${BUILD_CMD}${BUILD_CANISTERS_CMD}"; fi
if "$BUILD_IMG"; then BUILD_CMD="${BUILD_CMD}${BUILD_IMAGES_CMD}"; fi

if is_inside_container; then
    echo_blue "Building already inside a container"
    eval "$BUILD_CMD"
else
    echo_blue "Building by using a new container"
    "$ROOT_DIR"/gitlab-ci/container/container-run.sh bash -c "$BUILD_CMD"
fi

if "$BUILD_BIN"; then
    echo_green "##### Binaries SHA256SUMS #####"
    pushd "$BINARIES_DIR_FULL"
    GLOBIGNORE="SHA256SUMS"
    # shellcheck disable=SC2035
    sha256sum -b *.gz | tee SHA256SUMS
    popd
fi

if "$BUILD_CAN"; then
    echo_green "##### Canisters SHA256SUMS #####"
    pushd "$CANISTERS_DIR_FULL"
    # shellcheck disable=SC2035
    sha256sum -b *.gz | tee SHA256SUMS
    # neuron voters need to verify against the unzipped SHA256SUM
    TMP="$(mktemp -d)"
    cp *.gz "$TMP/"
    cd "$TMP"
    gunzip *
    # shellcheck disable=SC2035
    sha256sum *
    popd
    rm -fr "$TMP"
fi

if "$BUILD_IMG"; then
    echo_green "##### IC-OS SHA256SUMS #####"
    pushd "$DISK_DIR_FULL"
    # shellcheck disable=SC2035
    sha256sum -b *.tar.* | tee SHA256SUMS
    popd
fi

echo_green "Build complete for revision $(git rev-parse HEAD)"
