//! Local (QEMU) system-test backend.
//!
//! Counterpart to [`crate::driver::farm::Farm`] for tests run on a developer or
//! CI host instead of the Farm cluster. Selected via `SYSTEM_TEST_INFRA=local`.
//!
//! Boots each VM as a per-VM daemonized `qemu-system-x86_64` process, controlled
//! afterwards through its pid-file (destroy) and a per-VM QMP unix socket
//! (reboot). Networking (per-group Linux bridge + per-VM TAPs, `dnsmasq`
//! RA/DHCPv4) and disk images (qcow2 overlays over a shared base) are managed
//! directly by this backend.
//!
//! Many Farm features have no local equivalent (managed playnet DNS, TLS
//! issuance, HTTP file upload, multi-tenant scheduling); those operations warn
//! and return dummy values or `bail!`.
//!
//! In the QEMU command line built by [`LocalBackend::start_vm`], each virtio/PCIe
//! device sits behind its own `pcie-root-port` so the guest's predictable
//! interface names stay deterministic (primary NIC -> `enp1s0`, IPv4 NIC ->
//! `enp2s0`).

use crate::driver::farm::{VMCreateResponse, VmSpec};
use crate::driver::resource::DiskImage;
use crate::driver::test_env::{TestEnv, TestEnvAttribute};
use crate::driver::test_env_api::get_dependency_path_from_env;
use anyhow::{Context, Result, anyhow, bail};
use deterministic_ips::MacAddr6Ext;
use macaddr::MacAddr6;
use serde::{Deserialize, Serialize};
use slog::{Logger, info, warn};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::Ipv6Addr;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// UEFI firmware (OVMF) split-image paths, provided by the container's `ovmf`
/// package. The code image is read-only and shared; each VM gets a writable copy
/// of the variable store (its per-VM UEFI NVRAM).
const OVMF_CODE: &str = "/usr/share/OVMF/OVMF_CODE_4M.fd";
const OVMF_VARS_TEMPLATE: &str = "/usr/share/OVMF/OVMF_VARS_4M.fd";

/// Persistent record (in the root TestEnv) of the backend's working dir, so
/// forked task subprocesses resolve the same paths (VM disks, per-VM metadata,
/// pid-files and QMP sockets) the setup task created.
#[derive(Serialize, Deserialize, Clone)]
struct ActiveLocalBackend {
    /// Working dir where VM disks and per-VM metadata (`meta.json`), pid-files
    /// and QMP sockets live. Resolves to the same `<group_dir>/local_backend`
    /// path in every process, so a subprocess reads back the metadata the setup
    /// process persisted and can control VMs the setup process started.
    working_dir: PathBuf,
}

impl TestEnvAttribute for ActiveLocalBackend {
    fn attribute_name() -> String {
        "active_local_backend".to_string()
    }
}

/// Process-wide cache of the single `LocalBackend`. One backend per `bazel test`
/// invocation, so a single slot suffices: every `from_test_env` call in a
/// process resolves to the same backend.
static REGISTRY: Mutex<Option<Arc<LocalBackend>>> = Mutex::new(None);

/// Per-test handle to the local backend.
///
/// There is no daemon: each VM is a self-contained daemonized `qemu-system`
/// process (see [`start_vm`](Self::start_vm)) that outlives the process which
/// launched it, controlled afterwards via its pid-file (destroy) and QMP socket
/// (reboot) — both under `working_dir`, so any process (setup task or a forked
/// task subprocess) can control a VM regardless of which one started it. QEMU is
/// reparented to an init-like ancestor (PID 1 of the test action's execution
/// environment, e.g. bazel's sandbox or the RBE container) when its launcher
/// exits and is stopped explicitly in [`delete_group`](Self::delete_group);
/// anything that outlives the driver is killed when that environment is torn
/// down.
pub struct LocalBackend {
    /// Working dir; see [`from_test_env`](Self::from_test_env).
    active_local_backend: ActiveLocalBackend,
    logger: Logger,
    /// Per-VM allocated IPv6, keyed by `vm_name`.
    vm_ipv6: Mutex<HashMap<String, Ipv6Addr>>,
}

/// Per-VM configuration persisted to disk (as `meta.json` under the VM's working
/// dir) by [`LocalBackend::create_vm`] and amended by
/// [`LocalBackend::attach_disk_images`].
///
/// It cannot live solely in the in-memory `LocalBackend`: `create_vm` runs in
/// the setup process, whereas [`LocalBackend::start_vm`] may run in a forked
/// task subprocess (e.g. a test calling `vm.start()`) whose `connect_only`
/// handle has no in-memory record of the VM. Persisting under `working_dir` lets
/// `start_vm` recover it regardless of which process calls it.
#[derive(Serialize, Deserialize, Clone)]
struct PersistedVm {
    /// Primary boot image. Must be a [`DiskImage::Local`] (see
    /// [`LocalBackend::start_vm`]).
    primary_image: DiskImage,
    /// vCPU / memory spec used to render the domain XML.
    spec: VmSpec,
    /// Optional minimum boot-image size in GiB; the primary disk is grown to at
    /// least this size before boot.
    min_boot_image_size_gib: Option<u64>,
    /// Whether the VM requested a second (IPv4) NIC.
    has_ipv4: bool,
    /// Absolute paths of extra disk images attached via
    /// [`LocalBackend::attach_disk_images`]; empty until that call runs.
    extra_disks: Vec<PathBuf>,
}

impl LocalBackend {
    /// Return the LocalBackend associated with `env`.
    ///
    /// - If `env` already has an `ActiveLocalBackend` attribute (setup has run
    ///   and persisted the working dir), build a handle from it. This is what
    ///   forked task subprocesses get.
    /// - Otherwise resolve the working dir, persist it as a `TestEnvAttribute`,
    ///   and return the handle. This is what the setup task gets on first call.
    ///
    /// The returned `Arc` is cached in a process-wide slot, so repeated calls in
    /// the same process share state.
    pub fn from_test_env(env: &TestEnv) -> Result<Arc<LocalBackend>> {
        let mut reg = REGISTRY.lock().unwrap();
        if let Some(b) = reg.as_ref() {
            return Ok(b.clone());
        }

        if let Ok(existing) = ActiveLocalBackend::try_read_attribute(env) {
            // Setup has run: build a handle from the persisted working dir.
            let backend = Arc::new(LocalBackend::new(existing, env.logger()));
            *reg = Some(backend.clone());
            return Ok(backend);
        }

        // The working dir holds per-VM pid-files/QMP sockets and the
        // (potentially multi-gibibyte) VM disk images, so it must live OUTSIDE
        // the env directory: each `TestEnv` is recursively `cp -R`'d when setup
        // artifacts are forked into the per-test directories. Copying a live
        // unix socket hangs `cp` (blocks in `D` state) and copying the disks
        // would duplicate gigabytes per test. We therefore place it as a sibling
        // of the env directory (directly under the group dir), which is never
        // copied.
        let env_path = env.get_path("");
        let group_dir = env_path
            .parent()
            .with_context(|| format!("env dir {} has no parent", env_path.display()))?;
        std::fs::create_dir_all(group_dir).with_context(|| {
            format!(
                "creating group dir {} for local backend",
                group_dir.display()
            )
        })?;
        // Canonicalize so the working dir persisted for forked subprocesses is
        // absolute (qcow2 overlays record their backing file by absolute path).
        let group_dir = group_dir
            .canonicalize()
            .with_context(|| format!("canonicalizing group dir {}", group_dir.display()))?;
        let working_dir = group_dir.join("local_backend");
        std::fs::create_dir_all(&working_dir).with_context(|| {
            format!(
                "creating local backend working dir {}",
                working_dir.display()
            )
        })?;
        let backend = Arc::new(LocalBackend::new(
            ActiveLocalBackend { working_dir },
            env.logger(),
        ));
        // Persist the working dir so forked subprocesses resolve the same paths.
        backend.active_local_backend.write_attribute(env);
        *reg = Some(backend.clone());
        Ok(backend)
    }

    /// Build a [`Command`] that runs a short shell `script` with `CAP_NET_ADMIN`
    /// (and `CAP_NET_RAW`/`CAP_NET_BIND_SERVICE`) available to the program(s) it
    /// `exec`s.
    ///
    /// These are the *only* privileged operations the backend needs: creating the
    /// per-group bridge and TAP devices, and letting the group's `dnsmasq` bind
    /// UDP port 67 for DHCPv4.
    ///
    /// - Unprivileged (the normal dev-container case): the caps come from the
    ///   [`NET_ADMIN_LAUNCHER`] binary, a file-capability-endowed `capsh`
    ///   provisioned in the container image (see `ci/container/Dockerfile`).
    ///   `capsh` raises the caps into its inheritable+ambient sets and `exec`s
    ///   `/bin/sh -c <script>`; ambient caps survive the `exec`, so the script's
    ///   commands run with them even though the shell is not capability-endowed.
    /// - Root (e.g. the `bazel-test-rbe` RBE cluster): `capsh` is both unnecessary
    ///   and harmful. A root process already holds these caps — in the nested
    ///   user namespace the RBE executor runs the action in, root owns the
    ///   namespace and thus its full capability set — and its children inherit
    ///   them. Meanwhile `capsh`'s *file* capabilities are not honored across that
    ///   namespace boundary, so its inheritable-set step fails with `EPERM`
    ///   (`Unable to set inheritable capabilities`). So run `/bin/sh -c <script>`
    ///   directly; `ip`/`dnsmasq` inherit root's caps.
    ///
    ///   Root's caps only count over a *network namespace owned by its user
    ///   namespace*, which is not a given (the RBE executor leaves the action in
    ///   a netns owned by an ancestor userns);
    ///   [`ensure_administrable_netns`](Self::ensure_administrable_netns) runs
    ///   at driver startup to guarantee it by the time any `net_admin` script
    ///   runs.
    ///
    /// `script` must only interpolate sanitized, shell-safe tokens (interface
    /// names and IPv6 prefixes are restricted to `[0-9a-f:.-]`).
    fn net_admin(script: &str) -> Command {
        if running_as_root() {
            let mut cmd = Command::new("/bin/sh");
            cmd.arg("-c").arg(script);
            return cmd;
        }
        let net_admin_launcher = get_dependency_path_from_env("NET_ADMIN_LAUNCHER_PATH");
        let mut cmd = Command::new(net_admin_launcher);
        cmd.arg("--inh=cap_net_admin,cap_net_raw,cap_net_bind_service")
            .arg("--addamb=cap_net_admin")
            .arg("--addamb=cap_net_raw")
            .arg("--addamb=cap_net_bind_service")
            .arg("--")
            .arg("-c")
            .arg(script);
        cmd
    }

    /// Run a [`net_admin`] `script` to completion, returning an error if the
    /// launcher is missing or the script exits non-zero. `what` describes the
    /// operation for error context.
    fn run_net_admin(script: &str, what: &str) -> Result<()> {
        let output = Self::net_admin(script)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .with_context(|| format!("running net-admin launcher for {what}"))?;
        if !output.status.success() {
            bail!(
                "net-admin operation '{what}' failed with status {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(())
    }

    /// Ensure the driver can administer its network namespace, moving the
    /// process into a freshly unshared, self-owned one when it cannot.
    ///
    /// Under bazel's `linux-sandbox` (the dev-container / internal-CI case)
    /// this is a no-op: the sandbox already runs the test in a network
    /// namespace owned by its user namespace, which the [`net_admin`] launcher
    /// can administer. On an RBE cluster (e.g. `bazel-test-rbe`) there is no
    /// bazel sandbox: the executor runs the action as root inside a nested
    /// user namespace but leaves it in a network namespace owned by an
    /// *ancestor* user namespace (the action container's). Capabilities are
    /// relative to the user namespace that owns a resource, so root's
    /// `CAP_NET_ADMIN` does not apply to that netns and every RTNETLINK
    /// operation fails with `Operation not permitted` — even when the action
    /// container itself is privileged. In that case `unshare(CLONE_NEWNET)`
    /// (permitted: root holds `CAP_SYS_ADMIN` in its own userns) moves the
    /// process into a fresh netns owned by that userns, over which it holds
    /// full `CAP_NET_ADMIN` — recreating exactly what `linux-sandbox` gives
    /// the unprivileged case. The backend needs no external connectivity (the
    /// bridge, TAPs and the driver's `lo` addresses are namespace-internal;
    /// that is also why the `_local` targets do not carry `requires-network`,
    /// see `rs/tests/system_tests.bzl`), so an isolated netns loses nothing.
    ///
    /// Must run in the root (parent) driver process before the tokio runtime
    /// and the task subprocesses are spawned: `unshare` moves only the calling
    /// thread, while threads and processes created *afterwards* inherit its
    /// namespace. Calling this early therefore puts the entire process tree —
    /// task subprocesses, QEMU, `dnsmasq` — into the same netns.
    pub fn ensure_administrable_netns(logger: &Logger) -> Result<()> {
        // Unprivileged: the linux-sandbox netns is administrable via the
        // capability launcher, and without CAP_SYS_ADMIN over the current
        // userns an unshare would not be permitted anyway.
        if !running_as_root() {
            return Ok(());
        }
        // Root with effective CAP_NET_ADMIN over the current netns (e.g. a
        // plain root shell, or a second call in an already-unshared process):
        // keep the namespace, preserving the previous behavior.
        if Self::probe_netlink().is_ok() {
            return Ok(());
        }
        info!(
            logger,
            "Running as root but without CAP_NET_ADMIN over the current network \
             namespace (RTNETLINK operations are denied); unsharing a self-owned one"
        );
        // SAFETY: `unshare(CLONE_NEWNET)` only moves the calling thread into a
        // new network namespace; it touches no user-space state.
        if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
            return Err(anyhow!(std::io::Error::last_os_error())).context(
                "unshare(CLONE_NEWNET) failed; the local backend needs either \
                 CAP_NET_ADMIN over its network namespace or the ability to \
                 unshare a new one",
            );
        }
        // A fresh netns starts with `lo` down; the driver's per-group
        // management/logs/files addresses (and any `127.0.0.1`/`::1` traffic)
        // live on `lo`, so bring it up.
        Self::run_net_admin("ip link set dev lo up", "bring up lo in unshared netns")?;
        // Fail fast, with a clear message, if even the fresh netns cannot be
        // administered (e.g. a seccomp filter denying netlink altogether).
        Self::probe_netlink()
            .context("cannot administer even a freshly unshared network namespace")?;
        Ok(())
    }

    /// Probe whether the process can administer its current network namespace
    /// by creating (and immediately deleting) a short-lived bridge. A bridge —
    /// the very link type [`create_group`](Self::create_group) needs — makes
    /// the probe's verdict match the real operations. The name is derived from
    /// the pid, so concurrent groups (distinct driver processes) cannot
    /// collide, and stays within `IFNAMSIZ - 1` = 15 chars.
    fn probe_netlink() -> Result<()> {
        let probe = format!("prb-{}", std::process::id());
        Self::run_net_admin(
            &format!("ip link add name {probe} type bridge && ip link del dev {probe}"),
            "probe netlink administrability",
        )
    }

    /// Build a handle over `active_local_backend.working_dir`. There is no daemon
    /// to start or connect to: VMs are launched directly in
    /// [`start_vm`](Self::start_vm) and controlled via files under the working
    /// dir. Used for both the setup task and forked task subprocesses.
    fn new(active_local_backend: ActiveLocalBackend, logger: Logger) -> Self {
        LocalBackend {
            active_local_backend,
            logger,
            vm_ipv6: Mutex::new(HashMap::new()),
        }
    }

    /// Returns the VM identifier (used as the QEMU `-name` and to derive per-VM
    /// paths) for `(group_name, vm_name)`.
    fn domain_name(group_name: &str, vm_name: &str) -> String {
        sanitize_name(&format!("ictest-{group_name}-{vm_name}"))
    }

    /// Returns the per-group IPv6 prefix (a deterministic /64 in the
    /// ULA range `fd00::/8`).
    fn group_ipv6_prefix(group_name: &str) -> String {
        use ic_crypto_sha2::Sha256;
        let hash = Sha256::hash(group_name.as_bytes());
        format!(
            "fd00:{:02x}{:02x}:{:02x}{:02x}::",
            hash[0], hash[1], hash[2], hash[3]
        )
    }

    /// Returns the per-group IPv6 gateway address (`<prefix>1`). Assigned to the
    /// group's bridge in [`create_group`](Self::create_group).
    pub fn group_gateway_ipv6(group_name: &str) -> String {
        format!("{}1", Self::group_ipv6_prefix(group_name))
    }

    /// Returns the per-group IPv6 *management* address (`<prefix>:1::1`), the
    /// source the test driver originates its host→node traffic from.
    ///
    /// It shares the group hash with
    /// [`group_ipv6_prefix`](Self::group_ipv6_prefix) but uses subnet-id `1`
    /// (vs the nodes' `0`), so it lies *outside* every node `/64` — meaning the
    /// GuestOS firewall's hard-coded accept for a node's own prefix does not
    /// match the driver, letting registry-derived deny rules actually be
    /// exercised — while staying in the ULA range `fd00::/8` the backend
    /// whitelists at bootstrap.
    ///
    /// It is reserved for the driver's *own* host→node traffic; journald
    /// streaming ([`group_logs_ipv6`](Self::group_logs_ipv6)) and the file
    /// server ([`group_files_ipv6`](Self::group_files_ipv6)) use dedicated
    /// sibling addresses, so nothing else competes for this address' per-source
    /// firewall connection budget (which matters for the firewall
    /// `connection_count_test` that saturates it).
    ///
    /// Assigned to `lo` (not the bridge) so `dnsmasq` does not advertise it for
    /// SLAAC; [`create_group`](Self::create_group) overrides the node `/64`'s
    /// connected-route source to it.
    pub fn group_mgmt_ipv6(group_name: &str) -> String {
        use ic_crypto_sha2::Sha256;
        let hash = Sha256::hash(group_name.as_bytes());
        format!(
            "fd00:{:02x}{:02x}:{:02x}{:02x}:1::1",
            hash[0], hash[1], hash[2], hash[3]
        )
    }

    /// Returns the per-group IPv6 address the driver streams the nodes' journald
    /// logs from (see [`logs_stream_task`](crate::driver::logs_stream_task)).
    ///
    /// Constructed like [`group_mgmt_ipv6`](Self::group_mgmt_ipv6) but with
    /// subnet-id `2` (`<prefix>:2::1`), so it shares all that address' properties
    /// while being distinct. The GuestOS firewall caps simultaneous connections
    /// *per source address*, so streaming the long-lived journald connection from
    /// a dedicated address keeps it from consuming a slot in the management
    /// address' budget — otherwise the firewall `connection_count_test` (which
    /// saturates that budget) would race the stream for the last slot and flake.
    /// Like the management address it is assigned to `lo` in
    /// [`create_group`](Self::create_group).
    pub fn group_logs_ipv6(group_name: &str) -> String {
        use ic_crypto_sha2::Sha256;
        let hash = Sha256::hash(group_name.as_bytes());
        format!(
            "fd00:{:02x}{:02x}:{:02x}{:02x}:2::1",
            hash[0], hash[1], hash[2], hash[3]
        )
    }

    /// Returns the per-group IPv6 address the file server
    /// ([`serve_files_task`](crate::driver::serve_files_task)) listens on, and
    /// that node image-download URLs point at (see
    /// [`ic_images`](crate::driver::ic_images)).
    ///
    /// Constructed like [`group_mgmt_ipv6`](Self::group_mgmt_ipv6) but with
    /// subnet-id `3` (`<prefix>:3::1`). Serving images from an off-`/64` address
    /// mirrors production (the image web server is not on the nodes' `/64`);
    /// nodes still reach it because the host is their default router (their
    /// static gateway; see [`create_group`](Self::create_group)) and their
    /// replies match the firewall's stateful `established,related` rule. Using a
    /// dedicated address keeps the management address reserved for the driver's
    /// own traffic. Like it, this is assigned to `lo` in
    /// [`create_group`](Self::create_group).
    pub fn group_files_ipv6(group_name: &str) -> String {
        use ic_crypto_sha2::Sha256;
        let hash = Sha256::hash(group_name.as_bytes());
        format!(
            "fd00:{:02x}{:02x}:{:02x}{:02x}:3::1",
            hash[0], hash[1], hash[2], hash[3]
        )
    }

    /// Returns the per-group private IPv4 `/24` (a deterministic subnet in
    /// `10.0.0.0/8`). Hashed from the group name so concurrent groups get
    /// distinct subnets, with the `.0` network and `.1` gateway reserved.
    ///
    /// Only used to hand the guest an IPv4 address on its second NIC (`enp2s0`)
    /// via DHCP; the driver reaches VMs over IPv6, so this subnet needs no
    /// routing or NAT.
    fn group_ipv4_prefix(group_name: &str) -> String {
        use ic_crypto_sha2::Sha256;
        let hash = Sha256::hash(format!("ipv4/{group_name}").as_bytes());
        format!("10.{}.{}", hash[0], hash[1])
    }

    /// Returns the Linux bridge interface name for `group_name`.
    ///
    /// Interface names are limited to `IFNAMSIZ - 1` = 15 chars, so we hash the
    /// group name into a short digest (`vbr-` + 10 hex chars = 14) that stays
    /// unique per group within the limit.
    ///
    /// Tests run under bazel's linux-sandbox (a network namespace), so hashing is
    /// not strictly needed to avoid host collisions, but it adds safety and keeps
    /// accidental `bazel run //rs/tests/<test>_local` from clobbering the host.
    fn bridge_name(group_name: &str) -> String {
        use ic_crypto_sha2::Sha256;
        let hash = Sha256::hash(group_name.as_bytes());
        format!("vbr-{}", hex::encode(&hash[0..5]))
    }

    /// Returns the TAP interface name for `(group_name, vm_name)`.
    ///
    /// Like [`bridge_name`], bounded by `IFNAMSIZ - 1` = 15 chars, so a short
    /// digest of the group and VM name (`tap-` + 10 hex chars = 14) keeps it
    /// unique per VM and stable across re-runs.
    fn tap_name(group_name: &str, vm_name: &str) -> String {
        use ic_crypto_sha2::Sha256;
        let hash = Sha256::hash(format!("{group_name}/{vm_name}").as_bytes());
        format!("tap-{}", hex::encode(&hash[0..5]))
    }

    /// Returns the TAP interface name for the VM's *second* (IPv4) NIC.
    ///
    /// Same constraints as [`tap_name`](Self::tap_name); a distinct digest seed
    /// (`ipv4/...`) avoids colliding with the primary TAP (`ta4-` + 10 hex
    /// chars = 14).
    fn tap_name_ipv4(group_name: &str, vm_name: &str) -> String {
        use ic_crypto_sha2::Sha256;
        let hash = Sha256::hash(format!("ipv4/{group_name}/{vm_name}").as_bytes());
        format!("ta4-{}", hex::encode(&hash[0..5]))
    }

    /// Create the per-group Linux bridge that hosts the group's `/64`.
    ///
    /// We manage the network ourselves via the narrow [`net_admin`] launcher
    /// (rather than a privileged system-wide bridge): a bridge holds the group's
    /// `/64` and per-VM TAPs are attached to it in [`start_vm`].
    ///
    /// IC GuestOS nodes statically configure their global IPv6: the test driver
    /// hands each node a fixed address plus the `<prefix>::1` gateway (which
    /// lives on the bridge), so they need neither RA nor SLAAC. We still run a
    /// minimal `dnsmasq` as an RA daemon on the bridge for non-IC-node VMs (e.g.
    /// universal VMs), which bring up only a link-local address and derive their
    /// global one via SLAAC from the RA; the RA's non-zero router lifetime also
    /// installs the bridge (the host) as their default router.
    ///
    /// Either way the host is each guest's default router, which lets a guest
    /// reply to the driver's off-`/64` management address
    /// ([`group_mgmt_ipv6`](Self::group_mgmt_ipv6)). No IP forwarding is
    /// involved — the management address is on `lo`, so traffic to it terminates
    /// on the host.
    pub fn create_group(&self, group_name: &str) -> Result<()> {
        let bridge = Self::bridge_name(group_name);
        let prefix = Self::group_ipv6_prefix(group_name);
        // The gateway address (`<prefix>1`) lives on the bridge.
        let gateway = Self::group_gateway_ipv6(group_name);
        // Driver addresses, all assigned to `lo`: the management source for
        // host→node traffic, the dedicated journald-streaming source, and the
        // file server's listen address. See the respective `group_*_ipv6`.
        let mgmt = Self::group_mgmt_ipv6(group_name);
        let logs = Self::group_logs_ipv6(group_name);
        let files = Self::group_files_ipv6(group_name);
        // The IPv4 gateway (`<ipv4_prefix>.1`) also lives on the bridge so
        // `dnsmasq` can serve DHCPv4 to VMs that requested a second NIC.
        let ipv4_prefix = Self::group_ipv4_prefix(group_name);
        let ipv4_gateway = format!("{ipv4_prefix}.1");
        info!(
            self.logger,
            "Creating local bridge {bridge} for group {group_name} ({prefix}/64, {ipv4_prefix}.0/24)"
        );

        // (Re)create the bridge, assign the gateway, and bring it up. Deleting
        // first makes this idempotent across an interrupted run that leaked the
        // bridge. The IPv4 `/24` gateway is always assigned (harmless if no VM
        // requests IPv4) so `dnsmasq` can answer DHCPv4.
        //
        // Then assign `mgmt`/`logs`/`files` to `lo` (idempotent `replace`, since
        // `lo` is shared across groups and survives the bridge delete) and
        // override the node `/64`'s connected-route source to `mgmt`, so
        // host→node traffic uses the off-`/64` management address rather than the
        // on-bridge gateway. (`logs` and `files` are bound explicitly by their
        // consumers.) The override must target the *kernel* connected route that
        // `ip -6 addr add {gateway}/64` auto-creates (`proto kernel metric 256`):
        // replacing it in place sets its source. A separate route would land at
        // metric 1024 and lose to the metric-256 kernel route.
        let create_script = format!(
            "ip link del {bridge} 2>/dev/null; \
             ip link add name {bridge} type bridge && \
             ip link set dev {bridge} up && \
             ip -6 addr add {gateway}/64 dev {bridge} nodad && \
             ip addr add {ipv4_gateway}/24 dev {bridge} && \
             ip -6 addr replace {mgmt}/128 dev lo && \
             ip -6 addr replace {logs}/128 dev lo && \
             ip -6 addr replace {files}/128 dev lo && \
             ip -6 route replace {prefix}/64 dev {bridge} proto kernel metric 256 src {mgmt}"
        );
        Self::run_net_admin(&create_script, "create group bridge")?;

        // Start the RA daemon. Non-IC-node VMs (e.g. universal VMs) SLAAC their
        // global address from it; IC GuestOS nodes use a static config instead.
        // The same `dnsmasq` also serves DHCPv4 on the group's IPv4 `/24` for
        // VMs that requested a second NIC.
        self.start_ra_daemon(group_name, &bridge, &prefix, &ipv4_prefix)?;

        Ok(())
    }

    /// Path of the pid-file for the group's `dnsmasq` RA daemon.
    fn dnsmasq_pid_path(&self, bridge: &str) -> PathBuf {
        self.active_local_backend
            .working_dir
            .join("dnsmasq")
            .join(format!("{bridge}.pid"))
    }

    /// Spawn a minimal `dnsmasq` as an IPv6 Router Advertisement daemon on
    /// `bridge`, advertising the group's `/64` for SLAAC with a non-zero router
    /// lifetime (installing the host as the default router for VMs that use the
    /// RA; IC GuestOS nodes use a static config instead). The same daemon serves
    /// DHCPv4 on the group's IPv4 `/24` for VMs with a second NIC. See
    /// [`create_group`](Self::create_group) for the rationale.
    fn start_ra_daemon(
        &self,
        group_name: &str,
        bridge: &str,
        prefix: &str,
        ipv4_prefix: &str,
    ) -> Result<()> {
        let dnsmasq_dir = self.active_local_backend.working_dir.join("dnsmasq");
        std::fs::create_dir_all(&dnsmasq_dir).with_context(|| {
            format!("creating dnsmasq working dir at {}", dnsmasq_dir.display())
        })?;
        let pid_path = self.dnsmasq_pid_path(bridge);
        let lease_path = dnsmasq_dir.join(format!("{bridge}.leases"));
        let log_path = dnsmasq_dir.join(format!("{bridge}.log"));
        // Remove a stale pid-file from a previous interrupted run.
        let _ = std::fs::remove_file(&pid_path);

        info!(
            self.logger,
            "Starting RA daemon (dnsmasq) for group {group_name} on bridge {bridge}"
        );

        // `dnsmasq` needs `CAP_NET_RAW`/`CAP_NET_ADMIN` to open the ICMPv6 raw
        // socket and send RAs, so it runs through the capability launcher.
        // `--ra-param=<bridge>,10,1800` sends an RA every 10s with a 1800s router
        // lifetime; `--dhcp-range=<prefix>,ra-only` advertises the autonomous
        // prefix for SLAAC without stateful leases. The second `--dhcp-range`
        // enables stateful DHCPv4 on the IPv4 `/24` for the guest's second NIC
        // (`enp2s0`). `--port=0` disables DNS. `dnsmasq` daemonizes (writing its
        // pid-file) and is signalled via it in teardown.
        let user = current_username();
        let dnsmasq_path = get_dependency_path_from_env("ENV_DEPS__DNSMASQ_PATH");
        let dnsmasq_script = format!(
            "exec {dnsmasq_path:?} \
                 --conf-file=/dev/null \
                 --pid-file={pid} \
                 --dhcp-leasefile={lease} \
                 --log-facility={log} \
                 --user={user} \
                 --port=0 \
                 --bind-interfaces \
                 --interface={bridge} \
                 --except-interface=lo \
                 --enable-ra \
                 --dhcp-range={prefix},ra-only \
                 --dhcp-range={ipv4_prefix}.2,{ipv4_prefix}.254,255.255.255.0,1h \
                 --ra-param={bridge},10,1800",
            pid = pid_path.display(),
            lease = lease_path.display(),
            log = log_path.display(),
        );
        Self::run_net_admin(&dnsmasq_script, "start dnsmasq RA daemon")?;

        Ok(())
    }

    /// Stop the group's `dnsmasq` RA daemon, if running. It runs as the current
    /// user, so it is signalled directly via its pid-file. Best-effort and
    /// idempotent.
    fn stop_ra_daemon(&self, bridge: &str) {
        let pid_path = self.dnsmasq_pid_path(bridge);
        if let Ok(contents) = std::fs::read_to_string(&pid_path)
            && let Ok(pid) = contents.trim().parse::<i32>()
        {
            // SIGTERM lets dnsmasq remove its pid-file on exit.
            let _ = Command::new("kill").arg(pid.to_string()).status();
        }
        let _ = std::fs::remove_file(&pid_path);
    }

    /// Path of a VM's QEMU pid-file (written via `-pidfile` in [`start_vm`]).
    fn qemu_pid_path(vm_dir: &Path) -> PathBuf {
        vm_dir.join("qemu.pid")
    }

    /// Path of a VM's QMP control socket (bound by QEMU in [`start_vm`]), used by
    /// [`reboot_vm`](Self::reboot_vm).
    ///
    /// Placed in a short `/tmp` path keyed by a hash of `vm_dir`, NOT under
    /// `vm_dir`: the working dir resolves to a deep Bazel path that would push a
    /// unix socket past the kernel's ~108-byte `sun_path` limit. The hash is
    /// stable across processes and re-runs (so a forked subprocess derives the
    /// same path) yet distinct per VM and per concurrent group.
    fn qmp_socket_path(vm_dir: &Path) -> PathBuf {
        use ic_crypto_sha2::Sha256;
        let hash = Sha256::hash(vm_dir.to_string_lossy().as_bytes());
        PathBuf::from(format!("/tmp/ictest-qmp-{}.sock", hex::encode(&hash[0..8])))
    }

    /// Stop the QEMU process recorded in `pid_path`, if running. Best-effort and
    /// idempotent.
    ///
    /// Sends SIGTERM (QEMU powers the guest off and exits), waits briefly for a
    /// graceful exit, then escalates to SIGKILL. Signalling via the pid-file
    /// (rather than a `Child` handle) lets any process tear a VM down: QEMU is
    /// daemonized and reparented to an init-like ancestor (PID 1 of the test
    /// action's execution environment), so no process holds a handle on it. The
    /// teardown of that environment (bazel sandbox or RBE container) remains
    /// the final safety net.
    fn stop_qemu(&self, pid_path: &Path) {
        let Ok(contents) = std::fs::read_to_string(pid_path) else {
            return;
        };
        let Ok(pid) = contents.trim().parse::<i32>() else {
            let _ = std::fs::remove_file(pid_path);
            return;
        };
        info!(self.logger, "Stopping QEMU (pid {pid}) via SIGTERM");
        let _ = Command::new("kill").arg(pid.to_string()).status();

        // Wait briefly for it to exit so teardown is deterministic. QEMU was
        // reparented to an init-like ancestor, which reaps it once it exits so
        // `/proc/<pid>` disappears; poll for that. If it overruns the grace
        // period, escalate to SIGKILL.
        let deadline = Instant::now() + Duration::from_secs(5);
        while Path::new(&format!("/proc/{pid}")).exists() {
            if Instant::now() >= deadline {
                // Guard against PID reuse before force-killing: the pid-file may
                // be old, so confirm the process still looks like QEMU (exec
                // basename truncated to `qemu-system-x86` in `comm`, hence a
                // prefix match). Failing closed just defers to the teardown of
                // the test action's execution environment.
                let still_qemu = std::fs::read_to_string(format!("/proc/{pid}/comm"))
                    .map(|c| c.trim_end().starts_with("qemu-"))
                    .unwrap_or(false);
                if still_qemu {
                    warn!(
                        self.logger,
                        "QEMU (pid {pid}) survived the SIGTERM grace period; sending SIGKILL"
                    );
                    let _ = Command::new("kill")
                        .arg("-KILL")
                        .arg(pid.to_string())
                        .status();
                }
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = std::fs::remove_file(pid_path);
    }

    /// Tear down all VMs in `group_name`, remove the bridge and any TAPs
    /// attached to it, and remove the per-group addresses (management,
    /// journald-streaming and file-server) from `lo`.
    pub fn delete_group(&self, group_name: &str) -> Result<()> {
        let bridge = Self::bridge_name(group_name);
        let mgmt = Self::group_mgmt_ipv6(group_name);
        let logs = Self::group_logs_ipv6(group_name);
        let files = Self::group_files_ipv6(group_name);
        info!(
            self.logger,
            "Deleting local group {group_name} (bridge {bridge})"
        );

        // Stop the RA daemon before removing the bridge it listens on.
        self.stop_ra_daemon(&bridge);

        // Best effort: stop every VM QEMU process started for this group. Each
        // VM records its pid under `working_dir/vms/<vm>/qemu.pid`; killing it
        // closes QEMU, which releases the TAP device it had open. A backend
        // hosts a single group per `bazel test` invocation, so every VM dir
        // belongs to this group.
        let vms_dir = self.active_local_backend.working_dir.join("vms");
        if let Ok(entries) = std::fs::read_dir(&vms_dir) {
            for entry in entries.flatten() {
                let pid_path = Self::qemu_pid_path(&entry.path());
                if pid_path.exists() {
                    self.stop_qemu(&pid_path);
                }
            }
        }

        // Delete every TAP enslaved to the bridge, then the bridge itself. TAPs
        // are persistent (created so in `start_vm`), so enumerate the bridge's
        // slaves via sysfs and delete each before removing the bridge.
        let delete_script = format!(
            "for tap in $(ls /sys/class/net/{bridge}/brif 2>/dev/null); do \
                 ip link del \"$tap\" 2>/dev/null; \
             done; \
             ip link del {bridge} 2>/dev/null; \
             ip -6 addr del {mgmt}/128 dev lo 2>/dev/null; \
             ip -6 addr del {logs}/128 dev lo 2>/dev/null; \
             ip -6 addr del {files}/128 dev lo 2>/dev/null; \
             true"
        );
        let _ = Self::run_net_admin(&delete_script, "delete group bridge");

        Ok(())
    }

    /// Allocate metadata for a VM (deterministic MAC + IPv6). The actual QEMU
    /// process is only launched in [`start_vm`].
    pub fn create_vm(
        &self,
        group_name: &str,
        vm_name: &str,
        vcpus: u64,
        memory_kib: u64,
        primary_image: DiskImage,
        boot_image_minimal_size_gibibytes: Option<u64>,
        has_ipv4: bool,
    ) -> Result<VMCreateResponse> {
        let mac = vm_mac(group_name, vm_name);
        let prefix = Self::group_ipv6_prefix(group_name);
        let ipv6 = mac
            .calculate_slaac(prefix.trim_end_matches("::"))
            .with_context(|| format!("calculating slaac for {mac} in {prefix}"))?;

        let hostname = Self::domain_name(group_name, vm_name);
        let spec = VmSpec {
            v_cpus: vcpus,
            memory_ki_b: memory_kib,
        };
        // Cache the IPv6 in-process (currently write-only) and persist
        // everything `start_vm` needs to disk, so a forked task subprocess
        // (whose `connect_only` handle has empty in-memory state) can still start
        // the VM.
        self.vm_ipv6
            .lock()
            .unwrap()
            .insert(vm_name.to_string(), ipv6);
        self.write_vm_meta(
            vm_name,
            &PersistedVm {
                primary_image,
                spec: spec.clone(),
                min_boot_image_size_gib: boot_image_minimal_size_gibibytes,
                has_ipv4,
                extra_disks: Vec::new(),
            },
        )?;

        Ok(VMCreateResponse {
            ipv6,
            ipv4: None,
            mac6: mac.to_string(),
            hostname,
            spec,
        })
    }

    /// Attach extra disk images to `vm_name`. Each image is extracted (if it's
    /// `*.tar.zst` or `*.img.zst`) into the VM's working dir, chmod'd 0600, and
    /// remembered so it can be attached to the VM as a virtio disk at start time.
    pub fn attach_disk_images(&self, vm_name: &str, images: &[PathBuf]) -> Result<()> {
        let vm_dir = self.vm_dir(vm_name);
        std::fs::create_dir_all(&vm_dir)
            .with_context(|| format!("creating VM dir {}", vm_dir.display()))?;

        let mut paths = Vec::with_capacity(images.len());
        for (i, src) in images.iter().enumerate() {
            let dst_name = format!("extra-{i}.img");
            let dst = vm_dir.join(&dst_name);
            extract_image(src, &dst, &self.logger)?;
            pad_to_request_alignment(&dst)?;
            std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o600))?;
            paths.push(dst);
        }
        // Record the extra disks in the metadata persisted by `create_vm` so
        // `start_vm` attaches them, even from a forked task subprocess.
        let mut meta = self.read_vm_meta(vm_name)?;
        meta.extra_disks = paths;
        self.write_vm_meta(vm_name, &meta)?;
        Ok(())
    }

    /// Extract `src` into a shared, content-addressed base image exactly once
    /// and return its path (`image_cache/<key>.img` under `working_dir`).
    ///
    /// [`start_vm`](Self::start_vm) boots every IC node in a testnet from the
    /// *same* primary GuestOS image. Decompressing a multi-gibibyte
    /// `*.tar.zst` / `*.img.zst` once per node is wasteful, so the first caller
    /// for a given `src` extracts it here while concurrent callers (other setup
    /// threads, or a forked task subprocess running `vm.start()`) block on a
    /// per-key file lock and then observe the finished base. Each VM gets a thin
    /// qcow2 overlay backed by this base (see [`start_vm`]), so the base is kept
    /// read-only and never written to.
    ///
    /// The cache lives under `working_dir` (same filesystem as the per-VM disks,
    /// torn down with the group). The base is keyed by a hash of the `src`
    /// *path*: within a single bazel invocation a given image always resolves to
    /// the same immutable runfiles path, so the path identifies the content
    /// without reading the (large) file to hash it.
    ///
    /// The returned path is absolute (`working_dir` is canonicalized during
    /// backend setup) and each VM's qcow2 overlay records it as its backing
    /// file, so the base must not be relocated while overlays reference it. It
    /// isn't: it stays under `working_dir` and is torn down together with the
    /// overlays at the end of the group.
    fn ensure_base_image(&self, src: &Path) -> Result<PathBuf> {
        use ic_crypto_sha2::Sha256;
        use std::os::unix::io::AsRawFd;

        let cache_dir = self.active_local_backend.working_dir.join("image_cache");
        std::fs::create_dir_all(&cache_dir)
            .with_context(|| format!("creating image cache dir {}", cache_dir.display()))?;

        let key = hex::encode(&Sha256::hash(src.to_string_lossy().as_bytes())[0..16]);
        let base = cache_dir.join(format!("{key}.img"));

        // Serialize extraction of a given `src` across threads *and* processes
        // with a blocking, exclusive advisory lock on a per-key lock file. Only
        // the first holder extracts; others wake to find `base` already present.
        let lock_path = cache_dir.join(format!("{key}.lock"));
        // `append` (rather than `write`) gives the open a defined, non-truncating
        // behavior; the file is only a lock holder, never written to.
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&lock_path)
            .with_context(|| format!("opening image cache lock {}", lock_path.display()))?;
        nix::fcntl::flock(lock.as_raw_fd(), nix::fcntl::FlockArg::LockExclusive)
            .with_context(|| format!("locking image cache lock {}", lock_path.display()))?;
        // The lock is released when `lock` is dropped at the end of this function
        // (its `File` closes the fd, which drops the advisory lock). Rust opens
        // files `O_CLOEXEC`, so a forked task subprocess that `exec`s does not
        // inherit this fd and therefore cannot keep the lock held after we
        // return.

        if !base.exists() {
            // Extract to a temp file on the same filesystem, then atomically
            // rename it into place, so a crash never leaves a partial base that a
            // later caller would mistake for a complete one.
            let tmp = cache_dir.join(format!("{key}.tmp.{}", std::process::id()));
            extract_image(src, &tmp, &self.logger)?;
            // The base is shared and read-only; each VM writes to its own overlay.
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o444))
                .with_context(|| format!("chmod base image {}", tmp.display()))?;
            std::fs::rename(&tmp, &base).with_context(|| {
                format!(
                    "publishing base image {} -> {}",
                    tmp.display(),
                    base.display()
                )
            })?;
        }
        Ok(base)
    }

    /// Build the QEMU command line for `vm_name` and launch it (daemonized).
    pub fn start_vm(&self, group_name: &str, vm_name: &str) -> Result<()> {
        // Recover the per-VM state persisted by `create_vm` /
        // `attach_disk_images`. Reading from disk (not an in-memory cache) lets
        // `start_vm` run from a forked task subprocess whose `connect_only`
        // handle has no in-memory record of the VM.
        let PersistedVm {
            primary_image,
            spec,
            min_boot_image_size_gib: min_gib,
            has_ipv4,
            extra_disks: extra,
        } = self.read_vm_meta(vm_name)?;

        let vm_dir = self.vm_dir(vm_name);
        std::fs::create_dir_all(&vm_dir)?;
        let primary_disk = vm_dir.join("primary.qcow2");
        // Only materialize the primary disk on first boot. On a later `start_vm`
        // (e.g. a test that did `vm().kill()` then `vm().start()`) the qcow2
        // overlay already exists and holds the node's persisted writes; reusing
        // it mirrors a real VM reboot. Re-creating it would discard that state.
        if !primary_disk.exists() {
            let local_src = match &primary_image {
                DiskImage::Local { path, .. } => path.clone(),
                DiskImage::Url { .. } => {
                    panic!(
                        "LocalBackend cannot fetch URL-based primary image for {vm_name}; \
                         a `DiskImage::Local` was expected. \
                         Did the bazel `system_test` macro set `local = True`?"
                    );
                }
            };
            // Extract the shared pristine image once into the content-addressed
            // base cache, then give this VM a thin copy-on-write qcow2 overlay
            // backed by it. Creating the overlay is near-instant and filesystem
            // independent (unlike `cp --reflink`, which needs a CoW filesystem);
            // the VM's writes stay in its own overlay while the base is shared
            // read-only across all nodes.
            let base = self.ensure_base_image(&local_src)?;
            info!(
                self.logger,
                "Creating qcow2 overlay {} backed by {}",
                primary_disk.display(),
                base.display()
            );
            let mut cmd = Command::new(get_dependency_path_from_env("ENV_DEPS__QEMU_IMG_PATH"));
            cmd.arg("create")
                .arg("-q")
                .arg("-f")
                .arg("qcow2")
                .arg("-F")
                .arg("raw")
                .arg("-b")
                .arg(&base)
                .arg(&primary_disk);
            // Grow the overlay's virtual size to `min_gib`, but only when it
            // exceeds the base image's size (the base is raw, so its byte length
            // is its virtual size). This is grow-only: a request smaller than the
            // base leaves the overlay at the base size.
            if let Some(min_gib) = min_gib {
                let base_virtual = std::fs::metadata(&base)
                    .with_context(|| format!("stat base image {}", base.display()))?
                    .len();
                if min_gib.saturating_mul(1024 * 1024 * 1024) > base_virtual {
                    cmd.arg(format!("{min_gib}G"));
                }
            }
            let output = cmd.output().with_context(|| {
                format!("running qemu-img create for {}", primary_disk.display())
            })?;
            if !output.status.success() {
                bail!(
                    "creating qcow2 overlay {} failed with status {}: {}",
                    primary_disk.display(),
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
            std::fs::set_permissions(&primary_disk, std::fs::Permissions::from_mode(0o600))?;
        }

        let mac = vm_mac(group_name, vm_name);
        let domain_name = Self::domain_name(group_name, vm_name);
        let console_log = vm_dir.join("console.log");
        let uuid = vm_uuid(group_name, vm_name);

        // Create the per-VM TAP, attach it to the group bridge, and bring it up
        // via the [`net_admin`] launcher. `user <current>` tags the TAP as ours,
        // letting the unprivileged QEMU (which runs as the same user) open it via
        // `-netdev tap,ifname=...,script=no,downscript=no` without needing root
        // to create a device. Recreating it fresh (delete first) keeps this
        // idempotent across a re-used VM (e.g. `vm().kill()` + `vm().start()`).
        let tap = Self::tap_name(group_name, vm_name);
        let bridge = Self::bridge_name(group_name);
        let user = current_username();
        let tap_script = format!(
            "ip link del {tap} 2>/dev/null; \
             ip tuntap add dev {tap} mode tap user {user} && \
             ip link set dev {tap} master {bridge} && \
             ip link set dev {tap} up"
        );
        Self::run_net_admin(&tap_script, "create VM tap")?;

        // If the VM requested IPv4, create a second TAP on the same bridge for
        // the guest's `enp2s0`, which obtains an address via DHCPv4 from the
        // group's `dnsmasq`.
        let mac_ipv4 = vm_mac_ipv4(group_name, vm_name);
        let tap_ipv4 = Self::tap_name_ipv4(group_name, vm_name);
        if has_ipv4 {
            let tap_ipv4_script = format!(
                "ip link del {tap_ipv4} 2>/dev/null; \
                 ip tuntap add dev {tap_ipv4} mode tap user {user} && \
                 ip link set dev {tap_ipv4} master {bridge} && \
                 ip link set dev {tap_ipv4} up"
            );
            Self::run_net_admin(&tap_ipv4_script, "create VM ipv4 tap")?;
        }

        // Give the VM a writable copy of the OVMF variable store on first boot
        // (like the primary disk above): OVMF needs a writable varstore as its
        // second pflash. Persisting it across restarts mirrors a real VM's NVRAM.
        let ovmf_vars = vm_dir.join("OVMF_VARS.fd");
        if !ovmf_vars.exists() {
            std::fs::copy(OVMF_VARS_TEMPLATE, &ovmf_vars).with_context(|| {
                format!(
                    "copying OVMF vars template {} -> {}",
                    OVMF_VARS_TEMPLATE,
                    ovmf_vars.display()
                )
            })?;
            std::fs::set_permissions(&ovmf_vars, std::fs::Permissions::from_mode(0o600))?;
        }

        let pid_path = Self::qemu_pid_path(&vm_dir);
        let qmp_path = Self::qmp_socket_path(&vm_dir);
        // Clear a stale pid-file/socket from a previous VM incarnation so a
        // failed start is not mistaken for a live VM and QMP can bind cleanly.
        let _ = std::fs::remove_file(&pid_path);
        let _ = std::fs::remove_file(&qmp_path);

        // Assemble the QEMU command line. `arg!` appends space-separated tokens;
        // every virtio/PCIe device is placed behind its own `pcie-root-port` on
        // `pcie.0` (allocated by `root_port!`, one slot each in ascending order).
        // The guest assigns PCI bus numbers to the root ports in slot order, so
        // putting the NIC(s) on the FIRST root port(s) makes the guest name them
        // deterministically -- `enp1s0` (primary) and `enp2s0` (IPv4) -- no
        // matter how many disks are attached.
        let mut args: Vec<String> = Vec::new();
        macro_rules! arg {
            ($($a:expr),+ $(,)?) => {{ $(args.push($a.to_string());)+ }};
        }
        // Allocate PCIe root-port slots 0x1, 0x2, ... on `pcie.0` in call order.
        // Increment-then-read so every write is read in the same expansion (no
        // dead final assignment).
        let mut next_slot: u32 = 0;
        macro_rules! root_port {
            () => {{
                next_slot += 1;
                let slot = next_slot;
                let id = format!("rp{slot}");
                arg!(
                    "-device",
                    format!("pcie-root-port,id={id},bus=pcie.0,chassis={slot},addr=0x{slot:x}")
                );
                id
            }};
        }

        // Specify the path for qemu data (e.g. the virtio-net PXE ROM), otherwise qemu tries to
        // find it at /usr/share/qemu.
        arg!(
            "-L",
            get_dependency_path_from_env("ENV_DEPS__QEMU_SYSTEM_DATA_PATH").display()
        );
        arg!("-name", format!("guest={domain_name}"));
        arg!("-machine", "q35,accel=kvm");
        arg!("-cpu", "host");
        arg!("-m", format!("size={}k", spec.memory_ki_b));
        arg!("-smp", spec.v_cpus.to_string());
        arg!("-uuid", uuid);
        arg!("-rtc", "base=utc");
        arg!("-nodefaults");
        arg!("-no-user-config");
        arg!("-display", "none");
        // Split OVMF firmware: read-only code + writable per-VM varstore.
        arg!(
            "-drive",
            format!("if=pflash,format=raw,unit=0,readonly=on,file={OVMF_CODE}")
        );
        arg!(
            "-drive",
            format!("if=pflash,format=raw,unit=1,file={}", ovmf_vars.display())
        );

        // Primary NIC on the first root port -> guest `enp1s0`.
        let rp = root_port!();
        arg!(
            "-netdev",
            format!("tap,id=net0,ifname={tap},script=no,downscript=no")
        );
        arg!(
            "-device",
            format!("virtio-net-pci,netdev=net0,mac={mac},bus={rp},addr=0x0")
        );
        // Optional IPv4 NIC on the second root port -> guest `enp2s0`.
        if has_ipv4 {
            let rp = root_port!();
            arg!(
                "-netdev",
                format!("tap,id=net1,ifname={tap_ipv4},script=no,downscript=no")
            );
            arg!(
                "-device",
                format!("virtio-net-pci,netdev=net1,mac={mac_ipv4},bus={rp},addr=0x0")
            );
        }

        // Primary boot disk (qcow2 overlay), then any extra (raw) disks. Disks go
        // on later root ports so they never take the NICs' bus numbers.
        let rp = root_port!();
        arg!(
            "-drive",
            format!(
                "if=none,id=disk0,file={},format=qcow2,cache=none,discard=unmap",
                primary_disk.display()
            )
        );
        arg!(
            "-device",
            format!("virtio-blk-pci,drive=disk0,bus={rp},addr=0x0,bootindex=1")
        );
        for (i, p) in extra.iter().enumerate() {
            let rp = root_port!();
            arg!(
                "-drive",
                format!(
                    "if=none,id=disk{n},file={file},format=raw,cache=none,discard=unmap",
                    n = i + 1,
                    file = p.display()
                )
            );
            arg!(
                "-device",
                format!("virtio-blk-pci,drive=disk{n},bus={rp},addr=0x0", n = i + 1)
            );
        }

        // virtio-balloon and virtio-rng, each on its own root port.
        let rp = root_port!();
        arg!("-device", format!("virtio-balloon-pci,bus={rp},addr=0x0"));
        let rp = root_port!();
        arg!("-object", "rng-random,id=rng0,filename=/dev/urandom");
        arg!(
            "-device",
            format!("virtio-rng-pci,rng=rng0,bus={rp},addr=0x0")
        );

        // Serial console -> `console.log` with `append=on`, so the log survives
        // VM restarts (guest reboots and `vm().kill()` + `vm().start()`) and
        // `log_consoles_task` can simply tail it.
        arg!(
            "-chardev",
            format!("file,id=serial0,path={},append=on", console_log.display())
        );
        arg!("-device", "isa-serial,chardev=serial0");

        // QMP control socket (used by `reboot_vm`), pid-file, and daemonize so
        // the VM outlives the launching process (a forked task subprocess may
        // start it, yet it must keep running afterwards). No
        // `-no-reboot`/`-no-shutdown`, so a guest reboot resets the VM and a
        // guest poweroff exits QEMU.
        arg!(
            "-qmp",
            format!("unix:{},server=on,wait=off", qmp_path.display())
        );
        arg!("-pidfile", pid_path.display().to_string());
        arg!("-daemonize");

        info!(
            self.logger,
            "Launching QEMU for {domain_name}";
            "pidfile" => %pid_path.display(), "console" => %console_log.display()
        );
        // With `-daemonize` the foreground process exits once the guest is up (or
        // nonzero, having printed the error to stderr, if startup failed), while
        // the VM runs on as a reparented process.
        let output = Command::new(get_dependency_path_from_env(
            "ENV_DEPS__QEMU_SYSTEM_X86_64_PATH",
        ))
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("launching qemu-system-x86_64 for {domain_name}"))?;
        if !output.status.success() {
            bail!(
                "qemu-system-x86_64 failed to start VM {domain_name} (status {}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(())
    }

    /// Destroy the QEMU process backing `vm_name`, if running.
    pub fn destroy_vm(&self, _group_name: &str, vm_name: &str) -> Result<()> {
        let vm_dir = self.vm_dir(vm_name);
        self.stop_qemu(&Self::qemu_pid_path(&vm_dir));
        Ok(())
    }

    /// Reboot the VM `vm_name` with *soft* (graceful) semantics: ask the guest to
    /// power down via an ACPI power-button press (QMP `system_powerdown`), wait
    /// for QEMU to exit as the guest completes its orderly shutdown, then boot a
    /// fresh QEMU from the (persisted) disk. The qcow2 overlay and OVMF varstore
    /// are reused by [`start_vm`], so the node's state survives the reboot.
    ///
    /// A *hard* reset is intentionally not offered here; a test that wants one can
    /// `vm().kill()` then `vm().start()` (which is what such tests already do).
    ///
    /// If the guest does not power down within the grace period (e.g. it ignores
    /// the ACPI event), force-stop it so the reboot still makes progress.
    pub fn reboot_vm(&self, group_name: &str, vm_name: &str) -> Result<()> {
        let vm_dir = self.vm_dir(vm_name);
        let pid_path = Self::qemu_pid_path(&vm_dir);
        let qmp_path = Self::qmp_socket_path(&vm_dir);

        // Ask the guest to shut down gracefully (ACPI power button).
        qmp_command(&qmp_path, "system_powerdown", &self.logger).with_context(|| {
            format!(
                "sending ACPI powerdown to VM {vm_name} via QMP {}",
                qmp_path.display()
            )
        })?;

        // Wait for the guest to finish shutting down: QEMU exits on guest
        // poweroff (we run it without `-no-shutdown`). If it overruns the grace
        // period, force-stop it so the reboot still proceeds.
        if !self.await_qemu_exit(&pid_path, Duration::from_secs(60)) {
            warn!(
                self.logger,
                "VM {vm_name} did not power down gracefully within 60s; force-stopping"
            );
            self.stop_qemu(&pid_path);
        }

        // Boot a fresh QEMU from the persisted disk.
        self.start_vm(group_name, vm_name)
    }

    /// Poll until the process recorded in `pid_path` disappears, up to `timeout`.
    /// Returns `true` if it exited in time (or there was nothing to wait for).
    /// Used by [`reboot_vm`](Self::reboot_vm) to await a graceful guest shutdown;
    /// the init-like ancestor QEMU was reparented to reaps it promptly, so
    /// `/proc/<pid>` disappears soon after exit.
    fn await_qemu_exit(&self, pid_path: &Path, timeout: Duration) -> bool {
        let Ok(contents) = std::fs::read_to_string(pid_path) else {
            return true;
        };
        let Ok(pid) = contents.trim().parse::<i32>() else {
            return true;
        };
        let deadline = Instant::now() + timeout;
        while Path::new(&format!("/proc/{pid}")).exists() {
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        true
    }

    fn vm_dir(&self, vm_name: &str) -> PathBuf {
        self.active_local_backend
            .working_dir
            .join("vms")
            .join(sanitize_name(vm_name))
    }

    /// Path of the per-VM metadata file ([`PersistedVm`]) under the VM's dir.
    fn vm_meta_path(&self, vm_name: &str) -> PathBuf {
        self.vm_dir(vm_name).join("meta.json")
    }

    /// Persist `meta` for `vm_name`, creating its working directory if needed.
    fn write_vm_meta(&self, vm_name: &str, meta: &PersistedVm) -> Result<()> {
        let vm_dir = self.vm_dir(vm_name);
        std::fs::create_dir_all(&vm_dir)
            .with_context(|| format!("creating VM dir {}", vm_dir.display()))?;
        let path = self.vm_meta_path(vm_name);
        let json = serde_json::to_vec_pretty(meta)
            .with_context(|| format!("serializing VM metadata for {vm_name}"))?;
        std::fs::write(&path, json)
            .with_context(|| format!("writing VM metadata {}", path.display()))?;
        Ok(())
    }

    /// Read back the [`PersistedVm`] for `vm_name` persisted by `create_vm`.
    fn read_vm_meta(&self, vm_name: &str) -> Result<PersistedVm> {
        let path = self.vm_meta_path(vm_name);
        let json = std::fs::read(&path).with_context(|| {
            format!(
                "reading VM metadata {} (was create_vm run for {vm_name} in this group?)",
                path.display()
            )
        })?;
        serde_json::from_slice(&json)
            .with_context(|| format!("deserializing VM metadata {}", path.display()))
    }
}

/// Deterministic MAC address for a `(group, vm)` pair.
fn vm_mac(group_name: &str, vm_name: &str) -> MacAddr6 {
    use ic_crypto_sha2::Sha256;
    let hash = Sha256::hash(format!("{group_name}/{vm_name}").as_bytes());
    // 0x6a: locally-administered, unicast prefix consistent with
    // `calculate_deterministic_mac`.
    [0x6a, 0x01, hash[0], hash[1], hash[2], hash[3]].into()
}

/// Deterministic MAC address for a `(group, vm)` pair's *second* (IPv4) NIC.
///
/// A distinct digest seed (`ipv4/...`) guarantees it differs from the primary
/// NIC's [`vm_mac`] so the two interfaces never share a MAC on the bridge.
fn vm_mac_ipv4(group_name: &str, vm_name: &str) -> MacAddr6 {
    use ic_crypto_sha2::Sha256;
    let hash = Sha256::hash(format!("ipv4/{group_name}/{vm_name}").as_bytes());
    // 0x6a: locally-administered, unicast prefix consistent with `vm_mac`.
    [0x6a, 0x01, hash[0], hash[1], hash[2], hash[3]].into()
}

/// Deterministic, RFC 9562 name-based UUIDv8 for a `(group, vm)` pair.
fn vm_uuid(group_name: &str, vm_name: &str) -> String {
    use ic_crypto_sha2::Sha256;
    let mut hash = Sha256::hash(format!("uuid/{group_name}/{vm_name}").as_bytes());
    // Overwrite the only bits RFC 9562 fixes for UUIDv8: the version in the high
    // nibble of octet 6 (-> 0x8) and the variant in the top two bits of octet 8
    // (-> 0b10). The remaining 122 bits stay as SHA-256 output.
    hash[6] = (hash[6] & 0x0f) | 0x80;
    hash[8] = (hash[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        hash[0],
        hash[1],
        hash[2],
        hash[3],
        hash[4],
        hash[5],
        hash[6],
        hash[7],
        hash[8],
        hash[9],
        hash[10],
        hash[11],
        hash[12],
        hash[13],
        hash[14],
        hash[15],
    )
}

/// Sanitize a name for use in filesystem paths and the QEMU `-name`
/// (alphanumeric, `-` and `_`; every other character maps to `-`).
fn sanitize_name(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

/// Whether the driver process is running as root (effective uid 0).
///
/// The `bazel-test-rbe` RBE cluster may run `_local` test actions as root.
///
/// When this returns true, the local backend adjusts its networking strategy:
/// it bypasses the file-capability `capsh` launcher in [`net_admin`] and may
/// `unshare(CLONE_NEWNET)` in [`ensure_administrable_netns`] so RTNETLINK
/// operations are permitted.
fn running_as_root() -> bool {
    nix::unistd::geteuid().as_raw() == 0
}

/// The current user's login name, used to tag TAP device ownership so an
/// unprivileged QEMU may open them. Falls back to the `USER` environment
/// variable and finally to `ubuntu` (the container's default user).
fn current_username() -> String {
    std::env::var("USER").unwrap_or_else(|_| "ubuntu".to_string())
}

/// Send a single no-argument QMP command to a VM's monitor socket and wait for
/// its reply.
///
/// The backend only needs one such command (`system_powerdown`, for
/// [`reboot_vm`](LocalBackend::reboot_vm)). QEMU ships no scriptable one-shot QMP
/// client in the base package (`qmp-shell` is an interactive Python tool and
/// isn't installed), so we speak the protocol directly: it is line-delimited
/// JSON needing only a capabilities handshake, after which we send the command
/// and read its reply, skipping any interleaved asynchronous events. Read/write
/// timeouts keep a wedged VM from blocking teardown.
fn qmp_command(socket_path: &Path, execute: &str, logger: &Logger) -> Result<()> {
    let stream = UnixStream::connect(socket_path)
        .with_context(|| format!("connecting to QMP socket {}", socket_path.display()))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);

    // Consume the greeting banner ({"QMP": {...}}), then enter command mode.
    read_qmp_reply(&mut reader)?;
    writeln!(writer, r#"{{"execute":"qmp_capabilities"}}"#)?;
    read_qmp_reply(&mut reader)?;
    // Issue the requested command and await its reply.
    writeln!(writer, r#"{{"execute":"{execute}"}}"#)?;
    read_qmp_reply(&mut reader)?;
    info!(logger, "QMP command '{execute}' acknowledged"; "socket" => %socket_path.display());
    Ok(())
}

/// Read newline-delimited QMP messages until one is the greeting or a command
/// reply (`return`/`error`), skipping asynchronous events.
fn read_qmp_reply(reader: &mut impl BufRead) -> Result<()> {
    for _ in 0..100 {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            bail!("QMP connection closed before a reply arrived");
        }
        if line.contains("\"return\"") || line.contains("\"error\"") || line.contains("\"QMP\"") {
            return Ok(());
        }
        // Otherwise an asynchronous event; keep reading.
    }
    bail!("no QMP reply after 100 messages")
}

/// Extract an image:
/// - `*.tar.zst` is extracted with `tar -xf` (tar auto-detects the zstd
///   compression from the archive's magic bytes) into the parent directory of
///   `dst`; the single contained file is then renamed to `dst`.
/// - `*.img.zst` is decompressed with `unzstd -o dst`.
/// - Any other file is hard-linked (or copied) to `dst`.
fn extract_image(src: &Path, dst: &Path, logger: &Logger) -> Result<()> {
    let parent = dst
        .parent()
        .ok_or_else(|| anyhow!("dst has no parent: {}", dst.display()))?;
    std::fs::create_dir_all(parent)?;

    let name = src
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();

    if dst.exists() {
        std::fs::remove_file(dst).ok();
    }

    if name.ends_with(".tar.zst") {
        info!(
            logger,
            "Extracting tar.zst {} -> {}",
            src.display(),
            dst.display()
        );
        // Extract into a fresh tempdir to find the disk-image entry. The dir
        // name is unique per process *and* per thread, and also includes the
        // destination file name, so concurrent extractions of *different* images
        // into the same parent directory — e.g. distinct base images under
        // `image_cache`, which are guarded by distinct per-key locks — cannot
        // collide on the scratch dir.
        let tmp = parent.join(format!(
            ".extract-{}-{:?}-{}",
            std::process::id(),
            std::thread::current().id(),
            dst.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&tmp)?;
        let status = Command::new("tar")
            .arg("-xf")
            .arg(src)
            .arg("-C")
            .arg(&tmp)
            .status()
            .context("running tar")?;
        if !status.success() {
            bail!("tar extraction of {} failed", src.display());
        }
        // The archive is expected to contain a single `disk.img` entry.
        let img = tmp.join("disk.img");
        if !img.exists() {
            bail!(
                "expected `disk.img` in archive {}, but it was not found",
                src.display()
            );
        }
        std::fs::rename(&img, dst)?;
        let _ = std::fs::remove_dir_all(&tmp);
    } else if name.ends_with(".img.zst") || name.ends_with(".zst") {
        info!(
            logger,
            "Decompressing {} -> {}",
            src.display(),
            dst.display()
        );
        let output = Command::new("unzstd")
            // `-f` forces decompression of symbolic links (runtime deps are
            // symlinks into the bazel cache, which unzstd otherwise ignores)
            // and overwrites any existing output file.
            .arg("-f")
            .arg("-o")
            .arg(dst)
            .arg(src)
            .output()
            .context("running unzstd")?;
        if !output.status.success() {
            bail!(
                "unzstd decompression of {} failed: {}",
                src.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
    } else {
        info!(logger, "Copying {} -> {}", src.display(), dst.display());
        std::fs::copy(src, dst)
            .with_context(|| format!("copying {} -> {}", src.display(), dst.display()))?;
    }
    Ok(())
}

/// Round the raw disk image at `path` up so its byte length is a multiple of
/// [`DISK_REQUEST_ALIGNMENT`], padding with trailing zeros.
///
/// The domain XML opens every disk with `cache='none'` (O_DIRECT), whose QEMU
/// request alignment is the host block size (512 or 4096 bytes). A *writable*
/// raw image whose size is not a multiple of that alignment cannot be opened
/// without the `resize` permission, so QEMU aborts the domain start with:
///
///   Cannot get 'write' permission without 'resize':
///   Image size is not a multiple of request alignment
///
/// The universal-VM config images are sized as `2*du + 1MiB`
/// (`rs/tests/driver/assets/create-universal-vm-config-image.sh`), and prebuilt
/// UVM config images need not be aligned either, so pad them here. They carry a
/// FAT filesystem that records its own length and ignores trailing bytes, so the
/// padding is inert. Only these extra (config) disks are padded; boot disks are
/// already block aligned and may use a GPT backup header at the last sector,
/// which padding would displace.
fn pad_to_request_alignment(path: &Path) -> Result<()> {
    /// Upper bound on the host block size (covers 512- and 4096-byte sectors).
    const DISK_REQUEST_ALIGNMENT: u64 = 4096;
    let len = std::fs::metadata(path)
        .with_context(|| format!("stat {} for alignment padding", path.display()))?
        .len();
    let aligned = len.next_multiple_of(DISK_REQUEST_ALIGNMENT);
    if aligned != len {
        std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .with_context(|| format!("opening {} to pad for alignment", path.display()))?
            .set_len(aligned)
            .with_context(|| {
                format!(
                    "padding {} from {len} to {aligned} bytes for request alignment",
                    path.display()
                )
            })?;
    }
    Ok(())
}
