#!/bin/bash

# Shared utilities for directories that hold persistent private keys. Meant to
# be sourced by scripts that run as root with "set -e".
#
# With TEE, such directories are kept in the SEV-encrypted store, in
# /var/lib/ic/data. That directory is owned by ic-replica, which can thus
# rename or replace any entry in it. A key directory there is therefore only
# trusted if it is private: a root-owned directory with mode 0700, on the same
# filesystem as its parent, holding root-owned regular files. Only root can
# create such a directory there, and only root can modify its contents. (The
# filesystem check rules out root-owned private directories elsewhere, e.g.
# ones that sudo-able root scripts create in /tmp.)
#
# Some root-run scripts chown fixed paths under /var/lib/ic/data recursively to
# ic-replica (bootstrap-ic-node, and setup-permissions.sh for e.g.
# "orchestrator"). So ic-replica can get a key directory chowned to itself, by
# renaming it to such a path, and then read the keys in it. Such a directory
# fails the checks below, and only root could make it pass them again. Its keys
# are thus replaced, and never used again.
#
# The checks and the use of a directory are done from inside it (cd -P), so
# that it cannot be swapped for another one in between.

# Succeeds if the current directory is private (see above), given its parent.
#
# Args:
#   $1: The parent directory.
_cwd_is_private_key_dir() {
    [ "$(stat -c '%u %a %d' .)" = "0 700 $(stat -c '%d' "$1")" ]
}

# Copies the given files from a key directory to a destination directory, if
# the key directory is private and holds all of them as root-owned regular
# files. Fails without copying anything otherwise.
#
# Args:
#   $1: The key directory.
#   $2: The destination directory.
#   $3...: The names of the files to copy.
copy_from_trusted_key_dir() {
    local KEY_DIR="$1"
    local DEST_DIR="$2"
    shift 2
    (
        cd -P "${KEY_DIR}" 2>/dev/null || exit 1
        _cwd_is_private_key_dir "$(dirname "${KEY_DIR}")" || exit 1
        for FILE in "$@"; do
            if [ ! -f "${FILE}" ] || [ -L "${FILE}" ] || [ "$(stat -c '%u' "${FILE}")" != 0 ]; then
                exit 1
            fi
        done
        # --remove-destination: create new files with the source's mode, rather
        # than writing into existing ones (e.g. world-readable placeholders).
        cp --remove-destination "$@" "${DEST_DIR}/"
    )
}

# Replaces a key directory with a new private one, populated by running the
# given command inside it. The new directory is populated under an
# unpredictable name and then moved into place, so that an interrupted run
# leaves no partial key set behind.
#
# Args:
#   $1: The key directory.
#   $2...: The command (and its arguments) that generates the keys into the
#          current directory.
create_key_dir() {
    local KEY_DIR="$1"
    shift
    local NEW_DIR
    # Remove leftovers of interrupted runs. rm does not follow symlinks.
    rm -rf "${KEY_DIR}".??????
    NEW_DIR=$(mktemp -d "${KEY_DIR}.XXXXXX")
    (
        cd -P "${NEW_DIR}"
        _cwd_is_private_key_dir "$(dirname "${KEY_DIR}")"
        "$@"
        sync . ./*
    )
    rm -rf "${KEY_DIR}"
    # -T: fail, rather than move into a directory created at KEY_DIR meanwhile.
    mv -T "${NEW_DIR}" "${KEY_DIR}"
    # Make the rename durable, so that the keys survive a power loss.
    sync "$(dirname "${KEY_DIR}")"
}
