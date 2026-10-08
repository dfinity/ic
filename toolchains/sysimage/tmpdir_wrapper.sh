#!/usr/bin/env bash

# Process wrapper for the ic-os build commands that don't run podman.
# Usage:
# ./tmpdir_wrapper.sh COMMAND
#
# Unlike proc_wrapper.sh it needs no user namespaces, no /tmp/containers and no
# sudo: the wrapped commands only operate on plain image files (via fakeroot,
# mke2fs, e2fsdroid, veritysetup, sfdisk, ...). That's why the actions using it
# can run in the Bazel sandbox and on remote executors.

set -euo pipefail

# fakeroot first tries the real chown and only ignores EPERM. In the user
# namespace of Bazel's linux-sandbox, chown to an unmapped uid fails with EINVAL
# instead, which fakeroot passes on. Ownership is recorded in fakeroot's state
# file either way (a non-root chown never succeeded), so skip the real chown.
export FAKEROOTDONTTRYCHOWN=1

# Scratch space goes in the action's working directory (the execroot, or the
# sandbox's copy of it) rather than /tmp: image actions unpack and write several
# GB there, and remote executors only have a 1 GB /tmp (#10797).
# The image tools record the modes of the files they create in the images, so
# those mustn't depend on the environment: a fixed umask, and the scratch
# directory doesn't pass on a setgid bit (the sandbox on the dind-large CI
# runners has one, which made root directories 2755) or a default ACL of the
# working directory.
umask 022
tmpdir=$(mktemp -d -p "$PWD" "icosbuildXXXX")
chmod g-s "$tmpdir"
python3 -c '
import os, sys
for name in os.listxattr(sys.argv[1]):
    if name == "system.posix_acl_default":
        os.removexattr(sys.argv[1], name)
' "$tmpdir"
# Under fakeroot, tar applies archive modes exactly, so the tree can contain
# directories without u+w that a plain `rm -rf` can't empty. Restore write
# permissions first, and never let a failed cleanup fail a successful command.
_cleanup() {
    chmod -R u+rwX "$tmpdir" 2>/dev/null || true
    rm -rf "$tmpdir" || true
}
trap _cleanup EXIT
# Fail when interrupted, rather than exiting 0 once the cleanup has run.
trap 'exit 130' INT
trap 'exit 143' TERM
TMPDIR="$tmpdir" "$@"
