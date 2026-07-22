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

/// Environment variables holding the runfiles paths of the split OVMF (UEFI)
/// firmware images, provided by the `@ovmf` Bazel repo (extracted from the
/// Ubuntu `ovmf-generic-hwe` package; see `bazel/ovmf.bzl`). The code image is
/// read-only and shared; each VM gets a writable copy of the variable store (its
/// per-VM UEFI NVRAM).
const OVMF_CODE_ENV: &str = "ENV_DEPS__OVMF_CODE_PATH";
const OVMF_VARS_TEMPLATE_ENV: &str = "ENV_DEPS__OVMF_VARS_PATH";

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
/// environment, i.e. bazel's `linux-sandbox`) when its launcher exits and is
/// stopped explicitly in [`delete_group`](Self::delete_group); anything that
/// outlives the driver is killed when that environment is torn down.
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

    /// Run a short shell `script` via `/bin/sh -c` to completion, returning an
    /// error if it cannot be spawned or exits non-zero (`what` describes the
    /// operation, for error context).
    fn run_shell(script: &str, what: &str) -> Result<()> {
        let output = Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .with_context(|| format!("running shell script for {what}"))?;
        if !output.status.success() {
            bail!(
                "shell operation '{what}' failed with status {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(())
    }

    /// Put the driver into a network namespace it fully owns and arrange for its
    /// `ip`/`dnsmasq` operations to run with `CAP_NET_ADMIN`/`CAP_NET_RAW`/
    /// `CAP_NET_BIND_SERVICE` over that namespace — without any *host* capability
    ///
    /// `unshare(CLONE_NEWUSER | CLONE_NEWNET)` creates a private user namespace,
    /// in which the caller holds a full capability set (it is the namespace's
    /// creator), plus a network namespace owned by it — so every RTNETLINK
    /// operation on the new netns succeeds.
    /// We keep the caller's uid/gid unchanged (an *identity* mapping) so
    /// files, `/dev/kvm` and `/dev/net/tun` are accessed exactly as before, then
    /// raise the three networking capabilities into the process's *ambient* set
    /// via [`raise_ambient_net_caps`](Self::raise_ambient_net_caps) so they
    /// survive `execve` into the unprivileged `ip`/`dnsmasq`/QEMU children.
    ///
    /// The backend needs no external connectivity (the bridge, TAPs and the
    /// driver's `lo` addresses are namespace-internal; that is also why the
    /// `_local` targets do not carry `requires-network`, see
    /// `rs/tests/system_tests.bzl`), so an isolated netns loses nothing.
    ///
    /// # IMPORTANT: Must run single-threaded, before the tokio runtime and task subprocesses
    ///
    /// `unshare(CLONE_NEWUSER)` requires a single-threaded process, so this must
    /// run before any thread is spawned — in particular before the group's
    /// async (threaded) logger is built. Running it before the tokio runtime and the task
    /// subprocesses also puts the whole process tree — task subprocesses, QEMU,
    /// `dnsmasq` — into the same namespaces and lets them inherit the ambient
    /// capabilities (`unshare`/`fork`/`exec` all preserve both).
    pub fn ensure_administrable_netns() -> Result<()> {
        let uid = nix::unistd::geteuid().as_raw();
        let gid = nix::unistd::getegid().as_raw();
        // SAFETY: `unshare` only affects the calling (single) thread/process; it
        // touches no user-space state.
        if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) } != 0 {
            return Err(anyhow!(std::io::Error::last_os_error())).context(
                "unshare(CLONE_NEWUSER | CLONE_NEWNET) failed; the local backend needs \
                 to create a private user+network namespace to administer its \
                 networking without host capabilities",
            );
        }
        // Map the caller's uid/gid into the new user namespace so it keeps its
        // usual identity (files, `/dev/kvm` and `/dev/net/tun` are opened exactly
        // as before) while being the namespace owner. The mapping is an identity
        // one, with a single exception: if the caller is (fake-)root we map it to
        // a *non-zero* inner uid/gid instead of `0`.
        //
        // The reason: the backend relies on `dnsmasq` staying unprivileged so it
        // skips its privilege-drop path (see `start_ra_daemon`). That path is
        // gated purely on `getuid() == 0`, and when taken it fails in this
        // namespace — `setgroups` is denied (below) and the default `dip` gid is
        // unmapped. This normally holds because the action runs as an ordinary
        // user, but under an RBE sandbox that runs actions as uid 0 in its own
        // user namespace (e.g. Namespace's `namespace_action_isolation=sandboxed`)
        // an identity map would make the driver root here too and trip that path.
        // Presenting a non-zero uid keeps `dnsmasq` (and any other root-sensitive
        // child) out of it regardless of the outer uid. On-disk ownership,
        // `/dev/kvm` and `/dev/net/tun` are still accessed as the mapping's
        // *outer* uid, so nothing else changes.
        //
        // `setgroups` must be denied before an unprivileged process may write
        // `gid_map`; that is fine here because nothing in the process tree needs
        // `setgroups` to succeed. A single-line self-map is always permitted, with
        // or without `CAP_SETUID`/`CAP_SETGID` in the parent user namespace.
        let inner_uid = if uid == 0 { 1 } else { uid };
        let inner_gid = if gid == 0 { 1 } else { gid };
        std::fs::write("/proc/self/setgroups", "deny")
            .context("denying setgroups for the private user namespace")?;
        std::fs::write("/proc/self/uid_map", format!("{inner_uid} {uid} 1"))
            .context("writing uid_map for the private user namespace")?;
        std::fs::write("/proc/self/gid_map", format!("{inner_gid} {gid} 1"))
            .context("writing gid_map for the private user namespace")?;
        // Raise the networking capabilities into the ambient set so the
        // unprivileged `ip`/`dnsmasq`/QEMU children inherit them across `exec`.
        Self::raise_ambient_net_caps()?;
        // A freshly unshared netns starts with `lo` down; the driver's per-group
        // management/logs/files addresses (and any `127.0.0.1`/`::1` traffic)
        // live on `lo`, so bring it up. This is also the first operation that
        // needs `CAP_NET_ADMIN`, so it fails fast (with the `ip` error) if the
        // ambient capabilities did not take effect.
        Self::run_shell("ip link set dev lo up", "bring up lo in the owned netns")?;
        Ok(())
    }

    /// Raise `CAP_NET_ADMIN`, `CAP_NET_RAW` and `CAP_NET_BIND_SERVICE` into the
    /// process's inheritable *and* ambient capability sets, so they survive
    /// `execve` and are granted to the unprivileged child programs (`ip`,
    /// `dnsmasq`, QEMU) the backend spawns. Called right after the process
    /// becomes the owner of a fresh user namespace (see
    /// [`ensure_administrable_netns`](Self::ensure_administrable_netns)), where it
    /// holds these capabilities in its permitted set. Mirrors what the `capsh`
    /// launcher used to do (`--inh=... --addamb=...`).
    fn raise_ambient_net_caps() -> Result<()> {
        // Capability bit numbers (see <linux/capability.h>); all are < 32 so they
        // live in the first of the two 32-bit capability words.
        const CAP_NET_BIND_SERVICE: u32 = 10;
        const CAP_NET_ADMIN: u32 = 12;
        const CAP_NET_RAW: u32 = 13;
        const CAPS: [u32; 3] = [CAP_NET_BIND_SERVICE, CAP_NET_ADMIN, CAP_NET_RAW];
        // _LINUX_CAPABILITY_VERSION_3 (64-bit caps, two data words).
        const CAP_VERSION_3: u32 = 0x2008_0522;

        // The libc crate does not expose the capability get/set structs, so
        // declare them here to match the kernel's stable `capget(2)`/`capset(2)`
        // ABI for `_LINUX_CAPABILITY_VERSION_3`: a header plus an array of two
        // 32-bit data words (covering capabilities 0..63).
        #[repr(C)]
        struct CapHeader {
            version: u32,
            pid: libc::c_int,
        }
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct CapData {
            effective: u32,
            permitted: u32,
            inheritable: u32,
        }

        // Add the caps to the inheritable set. They are already in the permitted
        // set (this process created the user namespace), which the ambient-raise
        // below requires. Read the current sets first so permitted/effective are
        // preserved.
        let mut header = CapHeader {
            version: CAP_VERSION_3,
            pid: 0,
        };
        let mut data = [CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        }; 2];
        // SAFETY: `capget` fills `data` (2 words) for the current process (pid 0);
        // the pointers are valid for the duration of the call.
        if unsafe {
            libc::syscall(
                libc::SYS_capget,
                &mut header as *mut CapHeader,
                data.as_mut_ptr(),
            )
        } != 0
        {
            return Err(anyhow!(std::io::Error::last_os_error())).context("capget");
        }
        for cap in CAPS {
            data[0].inheritable |= 1_u32 << cap;
        }
        // SAFETY: `capset` writes the 2-word `data` back for the current process.
        if unsafe {
            libc::syscall(
                libc::SYS_capset,
                &mut header as *mut CapHeader,
                data.as_ptr(),
            )
        } != 0
        {
            return Err(anyhow!(std::io::Error::last_os_error()))
                .context("capset (raising inheritable networking capabilities)");
        }
        for cap in CAPS {
            // SAFETY: `prctl(PR_CAP_AMBIENT, ...)` only mutates this process's
            // ambient capability set.
            let rc = unsafe {
                libc::prctl(
                    libc::PR_CAP_AMBIENT,
                    libc::PR_CAP_AMBIENT_RAISE as libc::c_ulong,
                    cap as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                )
            };
            if rc != 0 {
                return Err(anyhow!(std::io::Error::last_os_error()))
                    .context("prctl(PR_CAP_AMBIENT_RAISE) for a networking capability");
            }
        }
        Ok(())
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
        Self::run_shell(&create_script, "create group bridge")?;

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
        // socket and send RAs, and `CAP_NET_BIND_SERVICE` to bind UDP port 67 for
        // DHCPv4; it inherits them from the ambient capability set the driver set
        // up (see `ensure_administrable_netns`).
        // `--ra-param=<bridge>,10,1800` sends an RA every 10s with a 1800s router
        // lifetime; `--dhcp-range=<prefix>,ra-only` advertises the autonomous
        // prefix for SLAAC without stateful leases. The second `--dhcp-range`
        // enables stateful DHCPv4 on the IPv4 `/24` for the guest's second NIC
        // (`enp2s0`). `--port=0` disables DNS. `dnsmasq` daemonizes (writing its
        // pid-file) and is signalled via it in teardown.
        //
        // `dnsmasq` runs unprivileged: `ensure_administrable_netns` guarantees a
        // non-zero uid inside the driver's user namespace (identity-mapped, or
        // remapped away from `0` when the caller is fake-root), so `dnsmasq` skips
        // its privilege-drop path entirely, which is what we want. That path is
        // gated on `getuid() == 0` and would otherwise `setgroups(2)` — denied in
        // the driver's user namespace — and drop to a user/group id that is
        // unmapped there.
        let dnsmasq_path = get_dependency_path_from_env("ENV_DEPS__DNSMASQ_PATH");
        let dnsmasq_script = format!(
            "exec {dnsmasq_path:?} \
                 --conf-file=/dev/null \
                 --pid-file={pid} \
                 --dhcp-leasefile={lease} \
                 --log-facility={log} \
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
        Self::run_shell(&dnsmasq_script, "start dnsmasq RA daemon")?;

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
    /// teardown of that environment (bazel's `linux-sandbox`) remains the final
    /// safety net.
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
        let _ = Self::run_shell(&delete_script, "delete group bridge");

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

        // Create the per-VM TAP, attach it to the group bridge, and bring it up.
        // `user <uid>` tags the TAP as owned by the driver's effective uid,
        // letting QEMU — which runs as that same uid — open it via
        // `-netdev tap,ifname=...,script=no,downscript=no` by owner match, so
        // opening the device relies on no QEMU capability (even though QEMU does
        // inherit the ambient net caps — see `raise_ambient_net_caps`). Recreating
        // it fresh (delete first) keeps this idempotent across a re-used VM (e.g.
        // `vm().kill()` + `vm().start()`).
        //
        // We pass the numeric effective uid, not a username: the kernel resolves
        // the `TUNSETOWNER` uid through the driver's private user namespace, whose
        // only mapped uid is the driver's own (see `ensure_administrable_netns`,
        // which maps a single uid — the caller's, or `1` when the caller is
        // fake-root). Any other uid — e.g. the one a username like `ubuntu`
        // resolves to — is unmapped there, so `ioctl(TUNSETOWNER)` fails with
        // `EINVAL`. `geteuid()` here returns that inner uid, which is also the uid
        // QEMU runs as, so the owner match holds.
        let tap = Self::tap_name(group_name, vm_name);
        let bridge = Self::bridge_name(group_name);
        let uid = nix::unistd::geteuid().as_raw();
        let tap_script = format!(
            "ip link del {tap} 2>/dev/null; \
             ip tuntap add dev {tap} mode tap user {uid} && \
             ip link set dev {tap} master {bridge} && \
             ip link set dev {tap} up"
        );
        Self::run_shell(&tap_script, "create VM tap")?;

        // If the VM requested IPv4, create a second TAP on the same bridge for
        // the guest's `enp2s0`, which obtains an address via DHCPv4 from the
        // group's `dnsmasq`.
        let mac_ipv4 = vm_mac_ipv4(group_name, vm_name);
        let tap_ipv4 = Self::tap_name_ipv4(group_name, vm_name);
        if has_ipv4 {
            let tap_ipv4_script = format!(
                "ip link del {tap_ipv4} 2>/dev/null; \
                 ip tuntap add dev {tap_ipv4} mode tap user {uid} && \
                 ip link set dev {tap_ipv4} master {bridge} && \
                 ip link set dev {tap_ipv4} up"
            );
            Self::run_shell(&tap_ipv4_script, "create VM ipv4 tap")?;
        }

        // Give the VM a writable copy of the OVMF variable store on first boot
        // (like the primary disk above): OVMF needs a writable varstore as its
        // second pflash. Persisting it across restarts mirrors a real VM's NVRAM.
        let ovmf_vars = vm_dir.join("OVMF_VARS.fd");
        if !ovmf_vars.exists() {
            let ovmf_vars_template = get_dependency_path_from_env(OVMF_VARS_TEMPLATE_ENV);
            std::fs::copy(&ovmf_vars_template, &ovmf_vars).with_context(|| {
                format!(
                    "copying OVMF vars template {} -> {}",
                    ovmf_vars_template.display(),
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
        // Split OVMF firmware: read-only code + writable per-VM varstore. The
        // code image comes from runfiles (a relative path); canonicalize it to
        // an absolute path so the daemonized QEMU (which `chdir`s away) can still
        // open it. The varstore is already under the absolute `working_dir`.
        let ovmf_code = get_dependency_path_from_env(OVMF_CODE_ENV)
            .canonicalize()
            .context("resolving OVMF code firmware path")?;
        arg!(
            "-drive",
            format!(
                "if=pflash,format=raw,unit=0,readonly=on,file={}",
                ovmf_code.display()
            )
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
