#!/usr/bin/env bash
set -euo pipefail

[ -n "${DEBUG:-}" ] && set -x

usage() {
    cat <<EOF
Utility script for building IC.

Usage: $0 [ --binaries | -b ] [ --canisters | -c ] [ --icos | -i ] [--no-release | -n ]

    --binaries   | -b   Build IC Binaries
    --canisters  | -c   Build IC Canisters
    --icos       | -i   Build IC-OS Images
    --no-release | -n   Non-Release Build
    --help       | -h   Print help

Non-Release Build, is for non-protected branches (revision is not in rc--* or master).

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
export RELEASE=true

if [ "$#" == 0 ]; then
    echo_red "ERROR: Please specify one of '-b', '-c' or '-i'" >&2
    echo ""
    usage && exit 1
fi

while getopts ':bcinh-:' OPT; do
    if [ "$OPT" = "-" ]; then
        OPT="${OPTARG%%=*}"
        OPTARG="${OPTARG#$OPT}"
        OPTARG="${OPTARG#=}"
    fi
    case "$OPT" in
        h | help) usage && exit 0 ;;
        b | binaries) BUILD_BIN=true ;;
        c | canisters) BUILD_CAN=true ;;
        i | icos) BUILD_IMG=true ;;
        n | non-release | no-release | norelease) RELEASE=false ;;
        ??*) echo_red "Invalid option --$OPT" && usage && exit 1 ;;
        ?) echo_red "Invalid command option.\n" && usage && exit 1 ;;
    esac
done
shift "$(($OPTIND - 1))"

if ! "$BUILD_BIN" && ! "$BUILD_CAN" && ! "$BUILD_IMG"; then
    echo_red "ERROR: Please specify one of '-b', '-c' or '-i'" >&2
    echo ""
    usage && exit 1
fi

export ROOT_DIR="$(git rev-parse --show-toplevel)"
export VERSION="$(git rev-parse HEAD)"

if "$RELEASE"; then
    export IC_VERSION_RC_ONLY="$VERSION"
    echo_red "\nBuilding release revision (master or rc--*)! Use '--no-release' for non-release revision!\n" && sleep 2
else
    export IC_VERSION_RC_ONLY="0000000000000000000000000000000000000000"
    echo_red "\nBuilding non-release revision!\n" && sleep 2
fi

export BINARIES_DIR=artifacts/release
export CANISTERS_DIR=artifacts/canisters
export DISK_DIR=artifacts/icos
export BINARIES_DIR_FULL="$ROOT_DIR/$BINARIES_DIR"
export CANISTERS_DIR_FULL="$ROOT_DIR/$CANISTERS_DIR"
export DISK_DIR_FULL="$ROOT_DIR/$DISK_DIR"

is_inside_DFINITY_container() {
    [ -e /home/ubuntu/.DFINITY-TAG ] && ([ -e /.dockerenv ] || [ -e /run/.containerenv ] || [ -n "${CI_JOB_NAME:-}" ])
}

validate_build_env() {
    function not_supported_prompt() {
        echo_red "$1"
        read -t 7 -r -s -p $'Press ENTER to continue the build anyway...\n'
    }

    if [ -n "$(git status --porcelain)" ]; then
        echo_red "Git working directory is not clean! Clean it and retry."
        exit 1
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

echo_green "Building selected IC artifacts"
BAZEL_CMD="bazel build --config=local --ic_version='$VERSION' --ic_version_rc_only='$IC_VERSION_RC_ONLY'"
BUILD_BINARIES_CMD=$(
    cat <<-END
    # build binaries
    mkdir -p "$BINARIES_DIR"
    $BAZEL_CMD //publish/binaries
    bazel cquery --config=local --output=files //publish/binaries | xargs -I {} cp {} "$BINARIES_DIR"
END
)

BUILD_CANISTERS_CMD=$(
    cat <<-END
    # build canisters
    mkdir -p "$CANISTERS_DIR"
    $BAZEL_CMD //publish/canisters
    bazel cquery --config=local --output=files //publish/canisters | xargs -I {} cp {} "$CANISTERS_DIR"
END
)

BUILD_IMAGES_CMD=$(
    cat <<-END
    # build guestos images
    mkdir -p "${DISK_DIR}/guestos"
    $BAZEL_CMD //ic-os/guestos/envs/prod
    bazel cquery --config=local --output=files //ic-os/guestos/envs/prod | xargs -I {} cp {} "${DISK_DIR}/guestos"
    # build hostos images
    mkdir -p "${DISK_DIR}/hostos"
    $BAZEL_CMD //ic-os/hostos/envs/prod
    bazel cquery --config=local --output=files //ic-os/hostos/envs/prod | xargs -I {} cp {} "${DISK_DIR}/hostos"
    # build setupos images
    mkdir -p "${DISK_DIR}/setupos"
    $BAZEL_CMD //ic-os/setupos/envs/prod
    bazel cquery --config=local --output=files //ic-os/setupos/envs/prod | xargs -I {} cp {} "${DISK_DIR}/setupos"
END
)
BUILD_CMD=""

if "$BUILD_BIN"; then BUILD_CMD="${BUILD_CMD}${BUILD_BINARIES_CMD}"; fi
if "$BUILD_CAN"; then BUILD_CMD="${BUILD_CMD}${BUILD_CANISTERS_CMD}"; fi
if "$BUILD_IMG"; then BUILD_CMD="${BUILD_CMD}${BUILD_IMAGES_CMD}"; fi

if is_inside_DFINITY_container; then
    echo_blue "Building already inside a DFINITY container or CI"
    eval "$BUILD_CMD"
else
    echo_blue "Building by using a new DFINITY container"
    "$ROOT_DIR"/ci/container/container-run.sh bash -c "$BUILD_CMD"
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
    echo_green "##### GUESTOS SHA256SUMS #####"
    pushd "$DISK_DIR_FULL/guestos"
    # shellcheck disable=SC2035
    sha256sum -b *.tar.* | tee SHA256SUMS
    popd
    echo_green "##### HOSTOS SHA256SUMS #####"
    pushd "$DISK_DIR_FULL/hostos"
    # shellcheck disable=SC2035
    sha256sum -b *.tar.* | tee SHA256SUMS
    popd
    echo_green "##### SETUPOS SHA256SUMS #####"
    pushd "$DISK_DIR_FULL/setupos"
    # shellcheck disable=SC2035
    sha256sum -b *.tar.* | tee SHA256SUMS
    popd
fi

echo_green "Build complete for revision $(git rev-parse HEAD)"
