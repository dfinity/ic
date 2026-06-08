#!/usr/bin/env bash
# Runtime setup for the local (libvirt/QEMU) system-test backend
# (rs/tests/driver/src/driver/local_backend.rs).
#
# The local backend runs fully unprivileged: libvirtd runs as the current
# (non-root) user in session mode (qemu:///session) and QEMU opens pre-created,
# user-owned TAP devices directly. This script performs the single piece of
# runtime setup that depends on the host kernel and cannot be baked into the
# image:
#
#   Allow Bazel's linux-sandbox to run. The backend's test actions must run
#   under `linux-sandbox` so they match CI (under the weaker
#   `processwrapper-sandbox` fallback `$HOME` stays writable, which masks real,
#   CI-only failures). Bazel runs as the unprivileged container user with no
#   effective capabilities, so linux-sandbox creates an *unprivileged* user
#   namespace to obtain the CAP_SYS_ADMIN it needs to set up its mounts. Ubuntu
#   24.04 ships `kernel.apparmor_restrict_unprivileged_userns=1`, which blocks
#   that and makes Bazel silently fall back to `processwrapper-sandbox`. We
#   relax it here. NOTE: this is a host kernel sysctl; because the container is
#   privileged and shares the host kernel, setting it takes effect host-wide.
#
# Two other prerequisites of the backend are handled outside this script:
#
#  * /dev/kvm access. The device is owned by root:<kvm-gid> (mode 0660). The
#    processes that open it (the on-demand libvirtd/QEMU spawned by the bazel
#    server) gain access by inheriting <kvm-gid> as a supplementary group from
#    the container's init process. Supplementary group membership is fixed when
#    a process is created, so the GID is granted at *container creation* time
#    via `--group-add`: dynamically in ci/container/container-run.sh
#    (`--group-add "$(stat -c %g /dev/kvm)"`) and as the static GID 993 in
#    .devcontainer/devcontainer.json and .github/workflows/ci-main.yml. This
#    modifies neither the host nor the /dev/kvm device node.
#
#  * The `ic-net-admin` capability launcher (/usr/local/bin/ic-net-admin,
#    NET_ADMIN_LAUNCHER in local_backend.rs): a copy of `capsh` endowed with
#    narrow file capabilities (CAP_NET_ADMIN / CAP_NET_RAW /
#    CAP_NET_BIND_SERVICE) used to create the per-group bridge and TAPs and to
#    run the backend's dnsmasq router-advertiser / DHCPv4 server (which binds
#    the privileged UDP port 67). Being fully static it is baked into the image
#    at build time (ci/container/Dockerfile).
#
# This script is invoked from the container startup paths
# (ci/container/container-run.sh and .devcontainer/devcontainer.json).
#
# Idempotent.
set -euo pipefail

# Setting the apparmor sysctl requires root; re-exec via sudo if needed.
if [ "$(id -u)" -ne 0 ]; then
    exec sudo -n "$0" "$@"
fi

# Allow Bazel's linux-sandbox (unprivileged user namespaces).
#
# Best-effort: the sysctl only exists on AppArmor-enabled kernels (Ubuntu
# 24.04+) and may be read-only in some environments, so never fail setup over
# it. Bazel probes linux-sandbox support once at server startup, so the bazel
# server must be (re)started after this runs to pick up the change.
sysctl_key=kernel.apparmor_restrict_unprivileged_userns
if [ -w "/proc/sys/${sysctl_key//.//}" ]; then
    sysctl -w "${sysctl_key}=0" >/dev/null 2>&1 || true
fi
