#!/usr/bin/env bash
# Runtime setup for the local (libvirt/QEMU) system-test backend
# (rs/tests/driver/src/driver/local_backend.rs).
#
# The local backend runs fully unprivileged: libvirtd runs as the current
# (non-root) user in session mode (qemu:///session) and QEMU opens pre-created,
# user-owned TAP devices directly. Two things must be arranged at container
# start, because they depend on the host kernel / runtime and cannot be baked
# into the image:
#
#  1. /dev/kvm access. The device is owned by root:<kvm-gid> (mode 0660) and the
#     GID is assigned by the host kernel and passed into this privileged
#     container, so it is unknown at image-build time. We align the in-container
#     `kvm` group GID to the device and add the unprivileged users to it so the
#     session-mode QEMU (which runs as that user) can open /dev/kvm.
#
#  2. The `ic-net-admin` capability launcher. The backend performs a handful of
#     networking operations that the kernel gates behind CAP_NET_ADMIN /
#     CAP_NET_RAW (creating the per-group bridge and TAPs, and running its own
#     dnsmasq router advertiser). Rather than `sudo`, it invokes a
#     file-capability-endowed copy of `capsh` that raises exactly those two
#     capabilities into the ambient set and then execs the requested command.
#     File capabilities (set via setcap, which needs CAP_SETFCAP) cannot be
#     applied from an unprivileged test process, so we provision the launcher
#     here.
#
#  3. Allow Bazel's linux-sandbox to run. The backend's test actions must run
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
# This script is invoked from the container startup paths
# (ci/container/container-run.sh and .devcontainer/devcontainer.json).
#
# Idempotent and safe to run when /dev/kvm is absent.
set -euo pipefail

# Path to the capability launcher referenced by the local backend
# (NET_ADMIN_LAUNCHER in local_backend.rs).
LAUNCHER=/usr/local/bin/ic-net-admin

# Managing groups and file capabilities requires root; re-exec via sudo if
# needed.
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

    # Session-mode QEMU runs as the unprivileged container user, so that user
    # must be a member of the `kvm` group to open /dev/kvm.
    #
    # NOTE: supplementary group membership is fixed when a process is created,
    # so this `usermod` only takes effect for processes started *afterwards*.
    # In particular the bazel server (which spawns the QEMU test actions) must
    # be started after this runs, otherwise it never picks up the `kvm` group
    # and libvirtd ends up caching the emulator as not supporting `virt type
    # 'kvm'`. Each CI workflow step and each devcontainer terminal is a fresh
    # exec that recomputes supplementary groups, so running this before the
    # first bazel invocation is sufficient there. The single-exec
    # container-run.sh path cannot rely on that and instead adds the kvm GID as
    # a supplementary group at container creation time (see container-run.sh).
    for user in ubuntu buildifier; do
        if getent passwd "$user" >/dev/null && ! id -nG "$user" | tr ' ' '\n' | grep -qx kvm; then
            usermod -aG kvm "$user"
        fi
    done
fi

# --- 2. Provision the ic-net-admin capability launcher --------------------
#
# `capsh` ships in libcap2-bin. Copy it to a stable path and grant the two
# narrow capabilities as effective+permitted file caps so it can raise them
# into the ambient set for the command it execs.
if command -v capsh >/dev/null 2>&1; then
    capsh_bin="$(command -v capsh)"
    install -m 0755 "$capsh_bin" "$LAUNCHER"
    setcap cap_net_admin,cap_net_raw+ep "$LAUNCHER"
fi

# --- 3. Allow Bazel's linux-sandbox (unprivileged user namespaces) ---------
#
# Best-effort: the sysctl only exists on AppArmor-enabled kernels (Ubuntu
# 24.04+) and may be read-only in some environments, so never fail setup over
# it. Bazel probes linux-sandbox support once at server startup, so the bazel
# server must be (re)started after this runs to pick up the change.
sysctl_key=kernel.apparmor_restrict_unprivileged_userns
if [ -w "/proc/sys/${sysctl_key//.//}" ]; then
    sysctl -w "${sysctl_key}=0" >/dev/null 2>&1 || true
fi
