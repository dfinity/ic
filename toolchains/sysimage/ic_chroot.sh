#!/bin/bash

# Wrapper around chroot while ensuring that important functionality is available, e.g. mounting /dev/, /proc and other
# API filesystems.
#
# The implementation is a slightly modified version of arch-chroot
# (https://github.com/archlinux/arch-install-scripts/blob/master/arch-chroot.in)

shopt -s extglob

# shellcheck disable=SC2059 # $1 and $2 can contain the printf modifiers
out() { printf "$1 $2\n" "${@:3}"; }
error() { out "==> ERROR:" "$@"; } >&2
warning() { out "==> WARNING:" "$@"; } >&2
msg() { out "==>" "$@"; }
die() {
  error "$@"
  exit 1
}

ignore_error() {
  "$@" 2>/dev/null
  return 0
}

chroot_add_mount() {
  mount "$@" && CHROOT_ACTIVE_MOUNTS=("$2" "${CHROOT_ACTIVE_MOUNTS[@]}")
}

chroot_maybe_add_mount() {
  local cond=$1
  shift
  if eval "$cond"; then
    chroot_add_mount "$@"
  fi
}

chroot_setup() {
  CHROOT_ACTIVE_MOUNTS=()
  [[ $(trap -p EXIT) ]] && die '(BUG): attempting to overwrite existing EXIT trap'
  trap 'chroot_teardown' EXIT

  chroot_add_mount proc "$1/proc" -t proc -o nosuid,noexec,nodev &&
    chroot_add_mount sys "$1/sys" -t sysfs -o nosuid,noexec,nodev,ro &&
    ignore_error chroot_maybe_add_mount "[[ -d '$1/sys/firmware/efi/efivars' ]]" \
      efivarfs "$1/sys/firmware/efi/efivars" -t efivarfs -o nosuid,noexec,nodev &&
    chroot_add_mount udev "$1/dev" -t devtmpfs -o mode=0755,nosuid &&
    chroot_add_mount devpts "$1/dev/pts" -t devpts -o mode=0620,gid=5,nosuid,noexec &&
    chroot_add_mount shm "$1/dev/shm" -t tmpfs -o mode=1777,nosuid,nodev &&
    chroot_add_mount /run "$1/run" --bind --make-private &&
    chroot_add_mount tmp "$1/tmp" -t tmpfs -o mode=1777,strictatime,nodev,nosuid
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
  [[ $(trap -p EXIT) ]] && die '(BUG): attempting to overwrite existing EXIT trap'
  trap 'unshare_teardown' EXIT

  chroot_add_mount_lazy "$1" "$1" --bind &&
    chroot_add_mount proc "$1/proc" -t proc -o nosuid,noexec,nodev &&
    chroot_add_mount_lazy /sys "$1/sys" --rbind &&
    chroot_add_link /proc/self/fd "$1/dev/fd" &&
    chroot_add_link /proc/self/fd/0 "$1/dev/stdin" &&
    chroot_add_link /proc/self/fd/1 "$1/dev/stdout" &&
    chroot_add_link /proc/self/fd/2 "$1/dev/stderr" &&
    chroot_bind_device /dev/full "$1/dev/full" &&
    chroot_bind_device /dev/null "$1/dev/null" &&
    chroot_bind_device /dev/random "$1/dev/random" &&
    chroot_bind_device /dev/tty "$1/dev/tty" &&
    chroot_bind_device /dev/urandom "$1/dev/urandom" &&
    chroot_bind_device /dev/zero "$1/dev/zero" &&
    chroot_add_mount run "$1/run" -t tmpfs -o nosuid,nodev,mode=0755 &&
    chroot_add_mount tmp "$1/tmp" -t tmpfs -o mode=1777,strictatime,nodev,nosuid
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

pid_unshare="unshare --fork --pid"
mount_unshare="$pid_unshare --mount --map-auto --map-root-user --setuid 0 --setgid 0"

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

usage() {
  cat <<EOF
usage: ${0##*/} chroot-dir [command] [arguments...]

    -h                  Print this help message
    -u <user>[:group]   Specify non-root user and optional group to use

If 'command' is unspecified, ${0##*/} will launch /bin/bash.

Note that when using arch-chroot, the target chroot directory *should* be a
mountpoint. This ensures that tools such as pacman(8) or findmnt(8) have an
accurate hierarchy of the mounted filesystems within the chroot.

If your chroot target is not a mountpoint, you can bind mount the directory on
itself to make it a mountpoint, i.e. 'mount --bind /your/chroot /your/chroot'.

EOF
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

arch-chroot() {
  ((EUID == 0)) || die 'This script must be run with root privileges'

  [[ -d $chrootdir ]] || die "Can't create chroot on non-directory %s" "$chrootdir"

  if [[ $setup != "" ]]; then
    $setup "$chrootdir" || die "failed to setup chroot %s" "$chrootdir"
  fi

  if ! mountpoint -q "$chrootdir"; then
    warning "$chrootdir is not a mountpoint. This may have undesirable side effects."
  fi

  chroot_args=()
  [[ $userspec ]] && chroot_args+=(--userspec "$userspec")

  SHELL=/bin/bash $pid_unshare /usr/sbin/chroot "${chroot_args[@]}" -- "$chrootdir" "${args[@]}"
}

unshare_only=
setup=unshare_setup

while getopts ':hu:no' flag; do
  case $flag in
  h)
    usage
    exit 0
    ;;
  u)
    userspec=$OPTARG
    ;;
  o)
    unshare_only=true
    ;;
  n)
    setup=""
    ;;
  :)
    die '%s: option requires an argument -- '\''%s'\' "${0##*/}" "$OPTARG"
    ;;
  ?)
    die '%s: invalid option -- '\''%s'\' "${0##*/}" "$OPTARG"
    ;;
  esac
done
shift $((OPTIND - 1))

(($#)) || die 'No chroot directory specified'
chrootdir=$1
shift

args=("$@")
if [[ $unshare_only ]]; then
  SHELL=/bin/bash $mount_unshare "${args[@]}"
else
  $mount_unshare bash -c "$(declare_all); arch-chroot"
fi
