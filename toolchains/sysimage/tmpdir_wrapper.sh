#!/usr/bin/env bash

# Process wrapper for the ic-os build commands that don't run podman. They need
# no privileges, so they can run sandboxed and remotely.
# Usage:
# ./tmpdir_wrapper.sh COMMAND

set -euo pipefail

# fakeroot first tries the real chown and only ignores EPERM. In the user
# namespace of Bazel's linux-sandbox, chown to an unmapped uid fails with EINVAL
# instead, which fakeroot passes on. Ownership is recorded in fakeroot's state
# file either way, so skip the real chown.
export FAKEROOTDONTTRYCHOWN=1

# Scratch in the working directory: remote executors only have a 1 GB /tmp (#10797).
# The images record the modes of the files created here, so they mustn't depend
# on the environment: fix the umask, and don't let the scratch directory inherit
# a setgid bit (the sandbox on the dind-large CI runners has one, which made root
# directories 2755).
umask 022
tmpdir=$(mktemp -d -p "$PWD" "icosbuildXXXX")
chmod g-s "$tmpdir"
# Under fakeroot, tar can create directories without u+w, which `rm -rf` can't empty.
_cleanup() {
    chmod -R u+rwX "$tmpdir" 2>/dev/null || true
    rm -rf "$tmpdir" || true
}
trap _cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
TMPDIR="$tmpdir" "$@"
