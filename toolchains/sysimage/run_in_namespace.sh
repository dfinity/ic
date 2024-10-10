#!/bin/bash

set -euo pipefail

# Wrapper around unshare and chroot that does some extra setup e.g. mounts
# /dev, /proc. and other API filesystems.
#
# The implementation is based on run_with_chroot
# (https://github.com/archlinux/arch-install-scripts/blob/master/run_with_chroot.in)

shopt -s extglob

# shellcheck disable=SC2059 # $1 and $2 can contain the printf modifiers
out() { printf "$1 $2\n" "${@:3}"; }
error() { out "==> ERROR:" "$@"; } >&2
warning() { out "==> WARNING:" "$@"; } >&2
die() {
    error "$@"
    exit 1
}

chroot_add_mount() {
    mount "$@" && CHROOT_ACTIVE_MOUNTS=("$2" "${CHROOT_ACTIVE_MOUNTS[@]}")
}

chroot_teardown() {
    if ((${#CHROOT_ACTIVE_MOUNTS[@]})); then
        umount "${CHROOT_ACTIVE_MOUNTS[@]}"
    fi
    unset CHROOT_ACTIVE_MOUNTS
}

chroot_add_mount_lazy() {
    mount "$@" && CHROOT_ACTIVE_LAZY=("$2" "${CHROOT_ACTIVE_LAZY[@]}")
}

chroot_bind_device() {
    touch "$2" && CHROOT_ACTIVE_FILES=("$2" "${CHROOT_ACTIVE_FILES[@]}")
    chroot_add_mount "$1" "$2" --bind
}

chroot_add_link() {
    ln -sf "$1" "$2" && CHROOT_ACTIVE_FILES=("$2" "${CHROOT_ACTIVE_FILES[@]}")
}

unshare_setup() {
    CHROOT_ACTIVE_MOUNTS=()
    CHROOT_ACTIVE_LAZY=()
    CHROOT_ACTIVE_FILES=()
    [[ $(trap -p EXIT) ]] && die "(BUG): attempting to overwrite existing EXIT trap"
    trap "unshare_teardown" EXIT

    chroot_add_mount_lazy "$1" "$1" --bind \
        && chroot_add_mount proc "$1/proc" -t proc -o nosuid,noexec,nodev \
        && chroot_add_mount_lazy /sys "$1/sys" --rbind \
        && chroot_add_link /proc/self/fd "$1/dev/fd" \
        && chroot_add_link /proc/self/fd/0 "$1/dev/stdin" \
        && chroot_add_link /proc/self/fd/1 "$1/dev/stdout" \
        && chroot_add_link /proc/self/fd/2 "$1/dev/stderr" \
        && chroot_bind_device /dev/full "$1/dev/full" \
        && chroot_bind_device /dev/null "$1/dev/null" \
        && chroot_bind_device /dev/random "$1/dev/random" \
        && chroot_bind_device /dev/tty "$1/dev/tty" \
        && chroot_bind_device /dev/urandom "$1/dev/urandom" \
        && chroot_bind_device /dev/zero "$1/dev/zero" \
        && chroot_add_mount run "$1/run" -t tmpfs -o nosuid,nodev,mode=0755 \
        && chroot_add_mount tmp "$1/tmp" -t tmpfs -o mode=1777,strictatime,nodev,nosuid
}

unshare_teardown() {
    chroot_teardown

    if ((${#CHROOT_ACTIVE_LAZY[@]})); then
        umount --lazy "${CHROOT_ACTIVE_LAZY[@]}"
    fi
    unset CHROOT_ACTIVE_LAZY

    if ((${#CHROOT_ACTIVE_FILES[@]})); then
        rm "${CHROOT_ACTIVE_FILES[@]}"
    fi
    unset CHROOT_ACTIVE_FILES
}

# This outputs code for declaring all variables to stdout. For example, if
# FOO=BAR, then running
#     declare -p FOO
# will result in the output
#     declare -- FOO="bar"
# This function may be used to re-declare all currently used variables and
# functions in a new shell.
declare_all() {
    # Remove read-only variables to avoid warnings. Unfortunately, declare +r -p
    # doesn't work like it looks like it should (declaring only read-write
    # variables). However, declare -rp will print out read-only variables, which
    # we can then use to remove those definitions.
    declare -p | grep -Fvf <(declare -rp)
    # Then declare functions
    declare -pf
}

resolve_link() {
    local target=$1
    local root=$2

    # If a root was given, make sure it ends in a slash.
    [[ -n $root && $root != */ ]] && root=$root/

    while [[ -L $target ]]; do
        target=$(readlink -m "$target")
        # If a root was given, make sure the target is under it.
        # Make sure to strip any leading slash from target first.
        [[ -n $root && $target != $root* ]] && target=$root${target#/}
    done

    printf %s "$target"
}

MOUNT=false
CHROOT_DIR=""
COMMAND=""

pid_unshare="unshare --fork --pid"
mount_unshare="$pid_unshare --mount --map-auto --map-root-user --setuid 0 --setgid 0"

run_with_chroot() {
    ((EUID == 0)) || die "This script must be run with root privileges"

    if [[ $MOUNT = true ]]; then
        unshare_setup "$CHROOT_DIR" || die "failed to setup mounts under $CHROOT_DIR"
    fi

    if ! mountpoint -q "$CHROOT_DIR"; then
        warning "$CHROOT_DIR is not a mountpoint. This may have undesirable side effects."
    fi

    $pid_unshare /usr/sbin/chroot "$CHROOT_DIR" "${COMMAND[@]}"
}

run_without_chroot() {
    "${COMMAND[@]}"
}

usage() {
    echo "Usage: $0 [--mount] [--chroot <directory>] <command>"
    echo "Runs <command> in a separate namespace optionally under chroot."
    echo "This tool is only supported within the build container."
    echo "  --mount                Set up system mount points (eg. /dev and /proc). Requires --chroot"
    echo "  --chroot <directory>   Specify the directory to chroot into."
    echo "  <command>              Command to run."
    exit 1
}

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --mount)
            MOUNT=true
            shift
            ;;
        --chroot)
            if [[ -z "$2" || "$2" == --* ]]; then
                echo "Error: --chroot requires a directory as an argument."
                usage
            fi
            CHROOT_DIR="$2"
            shift 2
            ;;
        --*)
            echo "Unknown argument: $1"
            usage
            ;;
        *)
            COMMAND=("$@")
            break
            ;;
    esac
done

if [[ -z "$COMMAND" ]]; then
    echo "Error: Missing command."
    usage
fi

if [[ $MOUNT = true && -z $CHROOT_DIR ]]; then
    echo "Error: Cannot use --mount option without specifying --chroot dir."
    usage
fi

if [[ -n "$CHROOT_DIR" ]]; then
    [[ -d "$CHROOT_DIR" ]] || die "Error: $CHROOT_DIR is not a valid directory."
    $mount_unshare /bin/bash -c "$(declare_all); run_with_chroot"
else
    echo "$(declare_all); ${COMMAND[@]}"
    $mount_unshare /bin/bash -c "$(declare_all); run_without_chroot"
fi
