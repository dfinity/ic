#!/usr/bin/env bash
set -euo pipefail

# Check if the script is nested (more than once). If so,
# something went wrong with the "inside container" detection
# and we abort to avoid an infinite loop.
if [ "${BUILD_IC_NESTED:-}" == 1 ]; then
    echo "$0 nested, aborting"
    exit 1
fi
export BUILD_IC_NESTED=1

export ROOT_DIR="$(git rev-parse --show-toplevel)"

# Drop into the container if we're not already inside it. This ensures
# we run in a predictable environment (Ubuntu with known deps).
if ! ([ -e /home/ubuntu/.DFINITY-TAG ] && ([ -e /.dockerenv ] || [ -e /run/.containerenv ] || [ -n "${CI_JOB_NAME:-}" ])); then
    echo dropping into container
    exec "$ROOT_DIR"/ci/container/container-run.sh bash "$0" "$@"
fi

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

# Color helpers
tp() { tput -T xterm "$@"; }
echo_red() {
    tp setaf 1
    echo "$1"
    tp sgr0
}
echo_green() {
    tp setaf 2
    echo "$1"
    tp sgr0
}
echo_blue() {
    tp setaf 4
    echo "$1"
    tp sgr0
}

# Join a bash array with a string
# https://stackoverflow.com/a/17841619
function join_by {
    local IFS="$1"
    shift
    echo "$*"
}

export BUILD_BIN=false
export BUILD_CAN=false
export BUILD_IMG=false
release_build=true

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
        n | non-release | no-release | norelease) release_build=false ;;
        ??*) echo_red "Invalid option --$OPT" && usage && exit 1 ;;
        ?) echo_red "Invalid command option." && usage && exit 1 ;;
    esac
done
shift "$(($OPTIND - 1))"

if ! "$BUILD_BIN" && ! "$BUILD_CAN" && ! "$BUILD_IMG"; then
    echo_red "ERROR: Please specify one of '-b', '-c' or '-i'" >&2
    echo ""
    usage && exit 1
fi

# Ensure working dir is clean
if [ -n "$(git status --porcelain)" ]; then
    echo_red "Git working directory is not clean! Clean it and retry."
    exit 1
fi

export VERSION="$(git rev-parse HEAD)"

BAZEL_TARGETS=()

BAZEL_COMMON_ARGS=(
    --config=local
    --color=yes
)

if [[ $release_build == true ]]; then
    echo_red "Building release revision (master or rc--*)! Use '--no-release' for non-release revision!" && sleep 2
    BAZEL_COMMON_ARGS+=(--config=stamped)
else
    echo_red "Building non-release revision!" && sleep 2
fi

export BINARIES_DIR=artifacts/release
export CANISTERS_DIR=artifacts/canisters
export DISK_DIR=artifacts/icos
export BINARIES_DIR_FULL="$ROOT_DIR/$BINARIES_DIR"
export CANISTERS_DIR_FULL="$ROOT_DIR/$CANISTERS_DIR"
export DISK_DIR_FULL="$ROOT_DIR/$DISK_DIR"

echo_blue "Purging artifact directories"
rm -rf "$BINARIES_DIR_FULL"
rm -rf "$CANISTERS_DIR_FULL"
rm -rf "$DISK_DIR_FULL"

if "$BUILD_BIN"; then BAZEL_TARGETS+=("//publish/binaries:bundle"); fi
if "$BUILD_CAN"; then BAZEL_TARGETS+=("//publish/canisters:bundle"); fi
if "$BUILD_IMG"; then BAZEL_TARGETS+=(
    "//ic-os/guestos/envs/prod:bundle-update"
    "//ic-os/hostos/envs/prod:bundle-update"
    "//ic-os/setupos/envs/prod:bundle"
    "//ic-os/guestos/envs/recovery:bundle-update"
); fi

echo_blue "Bazel targets: ${BAZEL_TARGETS[*]}"

bazel build "${BAZEL_COMMON_ARGS[@]}" "${BAZEL_TARGETS[@]}"

query="$(join_by "+" "${BAZEL_TARGETS[@]}")"

for artifact in $(bazel cquery "${BAZEL_COMMON_ARGS[@]}" --output=files "$query"); do
    target_dir=
    case "$artifact" in
        *guestos*disk)
            target_dir="$DISK_DIR/guestos/disk"
            ;;
        *guestos*recovery*)
            target_dir="$DISK_DIR/guestos/update-img-recovery"
            ;;
        *guestos*update)
            target_dir="$DISK_DIR/guestos/update"
            ;;
        *hostos*disk)
            target_dir="$DISK_DIR/hostos/disk"
            ;;
        *hostos*update)
            target_dir="$DISK_DIR/hostos/update"
            ;;
        *setupos*)
            target_dir="$DISK_DIR/setupos"
            ;;
        *binaries*)
            target_dir="$BINARIES_DIR"
            ;;
        *canisters*)
            target_dir="$CANISTERS_DIR"
            ;;
        *)
            echo "don't know where to put artifact '$artifact'"
            exit 1
            ;;
    esac

    mkdir -p "$target_dir"

    # We use -L so that find dereferences symlinks (artifacts are not
    # necessarily duplicated in the build)
    find -L "$artifact" -type f -exec cp {} "$target_dir" \;
done

if "$BUILD_BIN"; then
    echo_green "##### Binaries SHA256SUMS #####"
    pushd "$BINARIES_DIR_FULL" >/dev/null
    cat SHA256SUMS
    popd >/dev/null
fi

if "$BUILD_CAN"; then
    echo_green "##### Canisters SHA256SUMS #####"
    pushd "$CANISTERS_DIR_FULL"
    cat SHA256SUMS
    popd
fi

if "$BUILD_IMG"; then
    echo_green "##### GUESTOS SHA256SUMS #####"
    pushd "$DISK_DIR_FULL/guestos/update" >/dev/null
    cat SHA256SUMS
    popd >/dev/null
    echo_green "##### HOSTOS SHA256SUMS #####"
    pushd "$DISK_DIR_FULL/hostos/update" >/dev/null
    cat SHA256SUMS
    popd >/dev/null
    echo_green "##### SETUPOS SHA256SUMS #####"
    pushd "$DISK_DIR_FULL/setupos" >/dev/null
    cat SHA256SUMS
    popd >/dev/null
    echo_green "##### RECOVERY SHA256SUMS #####"
    pushd "$DISK_DIR_FULL/guestos/update-img-recovery" >/dev/null
    cat SHA256SUMS
    popd >/dev/null
fi

echo_green "Build complete for revision $VERSION"
