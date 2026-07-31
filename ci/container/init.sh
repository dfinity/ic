#!/usr/bin/env bash
# Entrypoint shim for the dev container started by container-run.sh when using
# docker.

set -euo pipefail

# Docker exposes /dev/fuse as mode 600 root:root, which the unprivileged
# container user can't open. fuse-overlayfs (used by the inner rootless
# podman) needs read/write access to it, so we open up the perms here.
if [ -e /dev/fuse ] && [ ! -w /dev/fuse ]; then
    sudo chmod 0666 /dev/fuse
fi

# system-tests that use the "local" backend spawn qemu-system-x86_64
# processes which need write access to /dev/kvm.
if [ -e /dev/kvm ] && [ ! -w /dev/kvm ]; then
    sudo chmod 0666 /dev/kvm
fi

# system-tests that use the "local" backend create a per-VM TAP device via
# `ip tuntap add` (rs/tests/driver/src/driver/local_backend.rs), which opens
# /dev/net/tun. Docker exposes it as mode 600 root:root -- and the namespace.so
# docker daemon forces this regardless of the host's perms or how the device is
# passed in (--device / bind-mount), unlike /dev/null and /dev/kvm which inherit
# the host mode -- so the unprivileged container user can't open it. Note that
# CAP_NET_ADMIN (which the driver holds in the private user namespace it unshares
# for the tuntap ioctl) does not bypass this DAC check on the device node, whose
# owner is outside that namespace, so we open up the perms here.
if [ -e /dev/net/tun ] && [ ! -w /dev/net/tun ]; then
    sudo chmod 0666 /dev/net/tun
fi

# Bazel rules in .bazelrc.build bind-mount /tmp/zig-cache into sandboxed
# actions for the hermetic_cc toolchain. Ensure it exists and is writable.
if [ ! -d /tmp/zig-cache ]; then
    sudo mkdir -p /tmp/zig-cache
    sudo chown "$(id -u)":"$(id -g)" /tmp/zig-cache
fi

exec "$@"
