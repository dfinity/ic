#!/usr/bin/env bash
# Align the in-container `kvm` group with the host's /dev/kvm device.
#
# Ubuntu's libvirt has a compiled-in default QEMU `group = "kvm"`, so the QEMU
# state driver fails to initialize ("Failed to parse group 'kvm'") unless a
# group named `kvm` exists. QEMU runs as `libvirt-qemu:kvm` and reaches
# /dev/kvm (typically mode 0660, owned by root:<kvm-gid>) through that group, so
# the group's GID must match the device's GID.
#
# That GID is assigned by the host kernel and passed through into this
# privileged container, so it is not known when the image is built; it can only
# be determined at container start. This script is therefore invoked from the
# container startup paths (ci/container/container-run.sh and
# .devcontainer/devcontainer.json) rather than baked into the image.
#
# Idempotent and safe to run when /dev/kvm is absent (no-op in that case).
set -euo pipefail

# Only relevant when KVM is available (used by the local system-test backend,
# see rs/tests/driver/src/driver/local_backend.rs).
[ -e /dev/kvm ] || exit 0

# Managing groups requires root; re-exec via sudo if needed.
if [ "$(id -u)" -ne 0 ]; then
    exec sudo -n "$0" "$@"
fi

gid="$(stat -c %g /dev/kvm)"

if getent group kvm >/dev/null; then
    cur="$(getent group kvm | cut -d: -f3)"
    if [ "$cur" != "$gid" ]; then
        # `-o` permits a non-unique GID in case the target GID is already used
        # by another group name inside the container.
        groupmod -o -g "$gid" kvm
    fi
else
    groupadd -o -g "$gid" kvm
fi
