#!/usr/bin/env bash
# Runtime setup for the local (libvirt/QEMU) system-test backend
# (rs/tests/driver/src/driver/local_backend.rs).
#
# The local backend runs fully unprivileged: libvirtd runs as the current
# (non-root) user in session mode (qemu:///session) and QEMU opens pre-created,
# user-owned TAP devices directly. This script arranges the two prerequisites
# that depend on the host kernel / runtime and therefore cannot be baked into
# the image:
#
#  1. /dev/kvm access. The device is owned by root:<kvm-gid> (mode 0660) and the
#     GID is assigned by the host kernel and passed into this privileged
#     container, so it is unknown at image-build time. We align the in-container
#     `kvm` group GID to the device and add the unprivileged users to that
#     group. The processes that actually open /dev/kvm (the on-demand
#     libvirtd/QEMU spawned by the bazel server) gain access by inheriting the
#     kvm GID as a *supplementary group* from the container's init process.
#     Supplementary group membership is fixed when a process is created, so it
#     cannot be added later by this script (the VS Code / bazel server tree is
#     already running by the time this `postStartCommand` runs); instead the kvm
#     GID is added at *container creation* time via `--group-add` in both
#     ci/container/container-run.sh and .devcontainer/devcontainer.json. This is
#     purely a group/permission arrangement on the container side; it modifies
#     neither the host nor the /dev/kvm device node.
#
#  2. Allow Bazel's linux-sandbox to run. The backend's test actions must run
#     under `linux-sandbox` so they match CI (under the weaker
#     `processwrapper-sandbox` fallback `$HOME` stays writable, which masks
#     real, CI-only failures). Bazel runs as the unprivileged container user
#     with no effective capabilities, so linux-sandbox creates an
#     *unprivileged* user namespace to obtain the CAP_SYS_ADMIN it needs to set
#     up its mounts. Ubuntu 24.04 ships
#     `kernel.apparmor_restrict_unprivileged_userns=1`, which blocks that and
#     makes Bazel silently fall back to `processwrapper-sandbox`. We relax it
#     here. NOTE: this is a host kernel sysctl; because the container is
#     privileged and shares the host kernel, setting it takes effect host-wide.
#
# A third prerequisite -- the `ic-net-admin` capability launcher
# (/usr/local/bin/ic-net-admin, NET_ADMIN_LAUNCHER in local_backend.rs) -- is no
# longer provisioned here. It is a copy of `capsh` endowed with narrow file
# capabilities (CAP_NET_ADMIN / CAP_NET_RAW / CAP_NET_BIND_SERVICE) that the
# backend uses to create the per-group bridge and TAPs and to run its dnsmasq
# router-advertiser / DHCPv4 server (which binds the privileged UDP port 67).
# Being fully static it is baked into the image at build time instead
# (ci/container/Dockerfile), so it no longer depends on this hook -- which
# matters because in the devcontainer this script runs as a VS Code
# `postStartCommand`, and VS Code can skip lifecycle commands (e.g. when its
# in-container command runner crashes), which would leave the launcher
# unprovisioned.
#
# This script is invoked from the container startup paths
# (ci/container/container-run.sh and .devcontainer/devcontainer.json).
#
# Idempotent and safe to run when /dev/kvm is absent.
set -euo pipefail

# Aligning groups and setting the apparmor sysctl require root; re-exec via sudo
# if needed.
if [ "$(id -u)" -ne 0 ]; then
    exec sudo -n "$0" "$@"
fi

# --- 1. /dev/kvm group alignment and membership ---------------------------
#
# Only relevant when KVM is available.
if [ -e /dev/kvm ]; then
    gid="$(stat -c %g /dev/kvm)"

    if getent group kvm >/dev/null; then
        cur="$(getent group kvm | cut -d: -f3)"
        if [ "$cur" != "$gid" ]; then
            # `-o` permits a non-unique GID in case the target GID is already
            # used by another group name inside the container.
            groupmod -o -g "$gid" kvm
        fi
    else
        groupadd -o -g "$gid" kvm
    fi

    # Add the unprivileged users to the `kvm` group so that *newly created*
    # processes which (re)compute their supplementary groups -- a fresh login,
    # `sudo`, `su`, or a `podman exec` into the container -- can open /dev/kvm.
    #
    # NOTE: this does NOT help the already-running process tree (the VS Code
    # server, its terminals, and the bazel server they spawn). Those inherit
    # their supplementary groups from the container's init process and never
    # re-run initgroups, so they only obtain the kvm GID if it was added at
    # *container creation* time. That is done via `--group-add` in both
    # ci/container/container-run.sh (dynamically, `--group-add "$(stat -c %g
    # /dev/kvm)"`) and .devcontainer/devcontainer.json. Neither this script nor
    # those modify the host or the /dev/kvm device node itself.
    for user in ubuntu buildifier; do
        if getent passwd "$user" >/dev/null && ! id -nG "$user" | tr ' ' '\n' | grep -qx kvm; then
            usermod -aG kvm "$user"
        fi
    done
fi

# --- 2. Allow Bazel's linux-sandbox (unprivileged user namespaces) ---------
#
# Best-effort: the sysctl only exists on AppArmor-enabled kernels (Ubuntu
# 24.04+) and may be read-only in some environments, so never fail setup over
# it. Bazel probes linux-sandbox support once at server startup, so the bazel
# server must be (re)started after this runs to pick up the change.
sysctl_key=kernel.apparmor_restrict_unprivileged_userns
if [ -w "/proc/sys/${sysctl_key//.//}" ]; then
    sysctl -w "${sysctl_key}=0" >/dev/null 2>&1 || true
fi
