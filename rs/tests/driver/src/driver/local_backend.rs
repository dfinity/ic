//! Local (libvirt + QEMU) system-test backend.
//!
//! Counterpart to [`crate::driver::farm::Farm`] for tests run on a developer or
//! CI host instead of the Farm cluster. Selected via `SYSTEM_TEST_INFRA=local`.
//!
//! Spawns a per-test libvirtd daemon on a unix socket, then drives it through
//! the `virt` crate to create networks (for groups), domains (for VMs) and to
//! extract disk images.
//!
//! Many Farm features have no local equivalent (managed playnet DNS, TLS
//! issuance, HTTP file upload, multi-tenant scheduling); those operations warn
//! and return dummy values or `bail!`.
//!
//! See `rs/tests/driver/templates/guestos_vm_template.xml` for the domain XML
//! template used to launch VMs.

use crate::driver::farm::{VMCreateResponse, VmSpec};
use crate::driver::resource::DiskImage;
use crate::driver::test_env::{TestEnv, TestEnvAttribute};
use crate::driver::test_env_api::get_dependency_path_from_env;
use anyhow::{Context, Result, anyhow, bail};
use askama::Template;
use deterministic_ips::MacAddr6Ext;
use macaddr::MacAddr6;
use serde::{Deserialize, Serialize};
use slog::{Logger, info};
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use virt::connect::Connect;
use virt::domain::Domain;

/// Persistent record (in the root TestEnv) of the libvirtd socket and working
/// dir, so forked task subprocesses can connect to the daemon spawned by the
/// setup task instead of spawning their own.
#[derive(Serialize, Deserialize, Clone)]
struct ActiveLocalBackend {
    /// Path of the libvirtd unix socket the spawning process bound. Forked
    /// subprocesses open a connect-only handle to it (see
    /// [`LocalBackend::connect_only`]).
    socket_path: PathBuf,
    /// Working dir where VM disks and per-VM metadata (`meta.json`) live.
    /// Resolves to the same `<group_dir>/local_backend` path in every process,
    /// so a `connect_only` handle reads back the metadata the setup process
    /// persisted.
    working_dir: PathBuf,
}

impl TestEnvAttribute for ActiveLocalBackend {
    fn attribute_name() -> String {
        "active_local_backend".to_string()
    }
}

/// Process-wide cache of the single `LocalBackend`. One libvirtd (hence one
/// socket) per `bazel test` invocation, so a single slot suffices: every
/// `from_test_env` call in a process resolves to the same backend.
static REGISTRY: Mutex<Option<Arc<LocalBackend>>> = Mutex::new(None);

/// Per-test handle that owns a libvirtd subprocess (in the setup process only)
/// and a `virt::Connect`.
pub struct LocalBackend {
    /// Socket path and working dir.
    /// [`from_test_env`](Self::from_test_env).
    active_local_backend: ActiveLocalBackend,
    /// `Some(child)` only in the process that spawned libvirtd; `None` in forked
    /// tasks that merely connect. `Drop` kills the child only if we own it.
    libvirtd: Option<Child>,
    /// Path to the libvirtd pid-file; `Some` only in the spawning process. Used
    /// as a teardown fallback from a connect-only handle in the finalize task.
    pid_path: Option<PathBuf>,
    /// libvirt connection.
    connect: Connect,
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
    /// Return the LocalBackend for the libvirtd associated with `env`.
    ///
    /// - If `env` already has an `ActiveLocalBackend` attribute (setup has run
    ///   and persisted the socket path), open a connect-only handle to it. This
    ///   is what forked task subprocesses get.
    /// - Otherwise spawn a new libvirtd, persist the socket path as a
    ///   `TestEnvAttribute`, and return the spawning handle. This is what the
    ///   setup task gets on first call.
    ///
    /// The returned `Arc` is cached in a process-wide slot, so repeated calls in
    /// the same process share state.
    pub fn from_test_env(env: &TestEnv) -> Result<Arc<LocalBackend>> {
        let mut reg = REGISTRY.lock().unwrap();
        if let Some(b) = reg.as_ref() {
            return Ok(b.clone());
        }

        if let Ok(existing) = ActiveLocalBackend::try_read_attribute(env) {
            // Setup has run: open a connect-only handle to the running daemon.
            let backend = Arc::new(LocalBackend::connect_only(existing, env.logger())?);
            *reg = Some(backend.clone());
            return Ok(backend);
        }

        // The working dir holds the live libvirtd socket/pid/log and the
        // (potentially multi-gibibyte) VM disk images, so it must live OUTSIDE
        // the env directory: each `TestEnv` is recursively `cp -R`'d when setup
        // artifacts are forked into the per-test directories. Copying the live
        // socket hangs `cp` (blocks in `D` state) and copying the disks would
        // duplicate gigabytes per test. We therefore place it as a sibling of
        // the env directory (directly under the group dir), which is never
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
        // Canonicalize so the socket path persisted for forked subprocesses is
        // absolute.
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
        let backend = Arc::new(LocalBackend::spawn(working_dir.clone(), env.logger())?);
        // Persist the socket path so forked subprocesses can find it.
        backend.active_local_backend.write_attribute(env);
        *reg = Some(backend.clone());
        Ok(backend)
    }

    /// Build a [`Command`] that runs a short shell `script` with `CAP_NET_ADMIN`
    /// (and `CAP_NET_RAW`/`CAP_NET_BIND_SERVICE`) raised into the ambient set,
    /// so the program(s) it `exec`s inherit them.
    ///
    /// This is the *only* privileged primitive the backend uses — narrow
    /// capabilities, never root — needed for the few operations the kernel gates
    /// behind them: creating the per-group bridge and TAP devices, and letting
    /// the group's `dnsmasq` bind UDP port 67 for DHCPv4.
    ///
    /// The capabilities come from the [`NET_ADMIN_LAUNCHER`] binary, a
    /// file-capability-endowed `capsh` provisioned in the container image (see
    /// `ci/container/Dockerfile`). `capsh` raises the caps into its
    /// inheritable+ambient sets and `exec`s `/bin/sh -c <script>`; ambient caps
    /// survive the `exec`, so the script's commands run with them even though the
    /// shell binary is not capability-endowed.
    ///
    /// `script` must only interpolate sanitized, shell-safe tokens (interface
    /// names and IPv6 prefixes are restricted to `[0-9a-f:.-]`).
    fn net_admin(script: &str) -> Command {
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

    /// Short, host-global directory for this backend's libvirtd unix socket.
    ///
    /// See [`spawn`] for why the socket cannot live under `working_dir`. Keyed by
    /// a hash of `working_dir` so it is stable across re-runs of the same group
    /// yet distinct between concurrent groups.
    fn socket_dir(working_dir: &Path) -> PathBuf {
        use ic_crypto_sha2::Sha256;
        let hash = Sha256::hash(working_dir.to_string_lossy().as_bytes());
        PathBuf::from(format!("/tmp/ictest-libvirt-{}", hex::encode(&hash[0..5])))
    }

    /// Spawn a fresh libvirtd subprocess in `working_dir/libvirt` and open a
    /// connection to it.
    fn spawn(working_dir: PathBuf, logger: Logger) -> Result<Self> {
        let libvirt_dir = working_dir.join("libvirt");
        std::fs::create_dir_all(&libvirt_dir).with_context(|| {
            format!("creating libvirt working dir at {}", libvirt_dir.display())
        })?;

        let conf_path = libvirt_dir.join("libvirtd.conf");
        let pid_path = libvirt_dir.join("libvirtd.pid");
        let log_path = libvirt_dir.join("libvirtd.log");

        // libvirtd runs as the current (non-root) user in *session* mode
        // (`qemu:///session`), which ignores `unix_sock_dir` and always places
        // its socket at `$XDG_RUNTIME_DIR/libvirt/libvirt-sock`. The default
        // `$XDG_RUNTIME_DIR` (`/run/user/<uid>`) may be absent in the container,
        // and we want a deterministic, short path anyway: the kernel caps unix
        // socket paths (`sun_path`) at ~108 bytes, and the working dir resolves
        // to a deep Bazel cache path already past that limit. So we point
        // `$XDG_RUNTIME_DIR` at a short `/tmp` dir keyed by a hash of the working
        // dir (distinct per concurrent group, stable across re-runs). The
        // pid/log/conf files stay in `libvirt_dir`.
        let xdg_runtime_dir = Self::socket_dir(&working_dir);
        std::fs::create_dir_all(&xdg_runtime_dir).with_context(|| {
            format!(
                "creating libvirt XDG_RUNTIME_DIR {}",
                xdg_runtime_dir.display()
            )
        })?;
        let socket_path = xdg_runtime_dir.join("libvirt").join("libvirt-sock");
        // Although not necessary in the bazel sandbox a `bazel run` might have left a socket behind at this fixed path; remove it
        // so libvirtd can bind cleanly.
        let _ = std::fs::remove_file(&socket_path);

        // Minimal libvirtd config: log to a file.
        std::fs::write(
            &conf_path,
            format!("log_outputs = \"1:file:{log}\"\n", log = log_path.display(),),
        )?;

        // Session-mode libvirtd initializes per-user state drivers on startup,
        // creating config/cache/data dirs derived from `$HOME`. If they cannot be
        // created the daemon aborts in `daemonRunStateInit` *before* binding its
        // socket, and the caller below times out. Under the Bazel `linux-sandbox`
        // the real `$HOME` is read-only, so we point `$HOME` and the XDG vars at
        // a writable directory we control.
        //
        // The state dir lives under `xdg_runtime_dir` (the short `/tmp` path),
        // NOT `libvirt_dir`: libvirtd's QEMU driver opens a QMP monitor socket
        // under `$XDG_CONFIG_HOME`, and rooting `$HOME` at the deep Bazel working
        // dir would push that path past the ~108-byte `sun_path` limit.
        let state_home = xdg_runtime_dir.join("home");
        for sub in [".config", ".cache", ".local/share"] {
            std::fs::create_dir_all(state_home.join(sub)).with_context(|| {
                format!(
                    "creating libvirt state dir {}",
                    state_home.join(sub).display()
                )
            })?;
        }

        // Pin the QEMU driver's core-dump limit. libvirt *unconditionally* sets
        // QEMU's `RLIMIT_CORE` to `max_core` (default "unlimited"). Under the
        // Bazel `linux-sandbox` QEMU runs in an unprivileged user namespace
        // lacking `CAP_SYS_RESOURCE`, so *raising* the hard limit to unlimited is
        // rejected with `EPERM` and the domain never starts. Setting
        // `max_core = 0` makes libvirt *lower* the limit instead (always
        // permitted); core dumps of the test QEMU are not needed.
        let qemu_conf_dir = state_home.join(".config").join("libvirt");
        std::fs::create_dir_all(&qemu_conf_dir).with_context(|| {
            format!(
                "creating libvirt qemu config dir {}",
                qemu_conf_dir.display()
            )
        })?;
        // Also route QEMU's stdout/stderr and file-backed chardevs (the VM's
        // serial console) straight to plain files instead of through `virtlogd`.
        // The QEMU driver defaults `stdio_handler` to `"logd"` (spawns
        // `virtlogd`, whose only value is size-limited log rolling we don't need
        // for bounded test runs). `stdio_handler = "file"` makes QEMU write the
        // console log straight to `console.log` with no `virtlogd`; the domain
        // XML's `append='on'` is honoured natively, so console output survives
        // domain restarts (guest reboots and `vm().kill()` + `vm().start()`).
        std::fs::write(
            qemu_conf_dir.join("qemu.conf"),
            "max_core = 0\nstdio_handler = \"file\"\n",
        )
        .with_context(|| format!("writing {}", qemu_conf_dir.join("qemu.conf").display()))?;

        // The backend is fully unprivileged: libvirtd runs as the current user
        // in session mode with a per-user QEMU driver. No `sudo`, no system-wide
        // bridge, no `virtlogd`. The few operations needing elevated networking
        // caps (bridge and TAPs) go through the narrow [`net_admin`] launcher.
        info!(logger, "Spawning libvirtd (session mode)"; "conf" => %conf_path.display(), "socket" => %socket_path.display());

        let libvirtd_path = get_dependency_path_from_env("ENV_DEPS__LIBVIRTD_PATH");
        let child = Command::new(&libvirtd_path)
            .arg("--config")
            .arg(&conf_path)
            .arg("--pid-file")
            .arg(&pid_path)
            .env("XDG_RUNTIME_DIR", &xdg_runtime_dir)
            .env("HOME", &state_home)
            .env("XDG_CONFIG_HOME", state_home.join(".config"))
            .env("XDG_CACHE_HOME", state_home.join(".cache"))
            .env("XDG_DATA_HOME", state_home.join(".local/share"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("spawning libvirtd")?;

        // Wait for the socket to appear.
        let deadline = Instant::now() + Duration::from_secs(30);
        while !socket_path.exists() {
            if Instant::now() > deadline {
                bail!(
                    "libvirtd socket {} did not appear within 30s",
                    socket_path.display()
                );
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        let connect = open_connect(&socket_path, &logger)?;

        Ok(LocalBackend {
            active_local_backend: ActiveLocalBackend {
                socket_path,
                working_dir,
            },
            libvirtd: Some(child),
            pid_path: Some(pid_path),
            connect,
            logger,
            vm_ipv6: Mutex::new(HashMap::new()),
        })
    }

    /// Open a connection-only handle to an already-running libvirtd. Used by
    /// forked task subprocesses.
    fn connect_only(active_local_backend: ActiveLocalBackend, logger: Logger) -> Result<Self> {
        let connect = open_connect(&active_local_backend.socket_path, &logger)?;
        Ok(LocalBackend {
            active_local_backend,
            libvirtd: None,
            pid_path: None,
            connect,
            logger,
            vm_ipv6: Mutex::new(HashMap::new()),
        })
    }

    /// Returns the libvirt domain name for `(group_name, vm_name)`.
    fn domain_name(group_name: &str, vm_name: &str) -> String {
        sanitize_libvirt_name(&format!("ictest-{group_name}-{vm_name}"))
    }

    /// Returns the common prefix shared by every domain name in `group_name`.
    /// Since [`sanitize_libvirt_name`] maps each character independently,
    /// `domain_name(group, vm)` always starts with this prefix.
    fn domain_name_prefix(group_name: &str) -> String {
        sanitize_libvirt_name(&format!("ictest-{group_name}-"))
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
    /// Instead of a libvirt-managed (system-mode) network — which needs
    /// `libvirtd` as root — we manage the network ourselves via the narrow
    /// [`net_admin`] launcher: a bridge holds the group's `/64` and per-VM TAPs
    /// are attached to it in [`start_vm`].
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

    /// Tear down all domains in `group_name`, remove the bridge and any TAPs
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

        // Best effort: shut down all domains whose names start with the group
        // prefix. Destroying a domain closes its QEMU process, which releases
        // the TAP device it had open.
        let prefix = Self::domain_name_prefix(group_name);
        if let Ok(domains) = self.connect.list_all_domains(0) {
            for d in domains {
                if let Ok(name) = d.get_name()
                    && name.starts_with(&prefix)
                {
                    let _ = d.destroy();
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

    /// Allocate metadata for a VM (deterministic MAC + IPv6). The actual
    /// libvirt domain is only created in [`start_vm`].
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
    /// remembered so it can be added to the libvirt domain XML at start time.
    pub fn attach_disk_images(&self, vm_name: &str, images: &[PathBuf]) -> Result<()> {
        let vm_dir = self.vm_dir(vm_name);
        std::fs::create_dir_all(&vm_dir)
            .with_context(|| format!("creating VM dir {}", vm_dir.display()))?;

        let mut paths = Vec::with_capacity(images.len());
        for (i, src) in images.iter().enumerate() {
            let dst_name = format!("extra-{i}.img");
            let dst = vm_dir.join(&dst_name);
            extract_image(src, &dst, &self.logger)?;
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

    /// Build the libvirt domain XML for `vm_name` and start it.
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
        let primary_disk = vm_dir.join("primary.img");
        // Only materialize the primary disk on first boot. On a later `start_vm`
        // (e.g. a test that did `vm().kill()` then `vm().start()`) the extracted
        // `primary.img` already exists and holds the node's persisted state.
        // Re-extracting the pristine image would wipe it,
        // so the node would come back as freshly provisioned and never rejoin.
        // Reuse the existing disk, mirroring a real VM reboot.
        if !primary_disk.exists() {
            let local_src = match &primary_image {
                DiskImage::Local { path, .. } => path.clone(),
                DiskImage::Url { .. } => {
                    bail!(
                        "LocalBackend cannot fetch URL-based primary image for {vm_name}; \
                         a `DiskImage::Local` was expected. \
                         Did the bazel `system_test` macro set `local = True`?"
                    );
                }
            };
            extract_image(&local_src, &primary_disk, &self.logger)?;
            std::fs::set_permissions(&primary_disk, std::fs::Permissions::from_mode(0o600))?;
            if let Some(min_gib) = min_gib {
                let _ = Command::new("truncate")
                    .arg(format!("--size=>{min_gib}G"))
                    .arg(&primary_disk)
                    .status()
                    .with_context(|| {
                        format!("truncating {} to {min_gib}G", primary_disk.display())
                    })?;
            }
        }

        let mac = vm_mac(group_name, vm_name);
        let domain_name = Self::domain_name(group_name, vm_name);
        let console_log = vm_dir.join("console.log");
        let uuid = vm_uuid(group_name, vm_name);

        // Create the per-VM TAP, attach it to the group bridge, and bring it up
        // via the [`net_admin`] launcher. `user <current>` tags the TAP as ours,
        // letting an unprivileged QEMU (session-mode libvirtd) open it; the
        // domain XML references it with `managed='no'` so libvirt uses the
        // existing device instead of creating one (which needs root). Recreating
        // it fresh (delete first) keeps this idempotent across a re-used domain.
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

        let mut disks = Vec::new();
        disks.push(DiskEntry {
            file: primary_disk.display().to_string(),
            target: "vda".to_string(),
            bus: "virtio".to_string(),
        });
        for (i, p) in extra.iter().enumerate() {
            let letter = (b'b' + i as u8) as char;
            disks.push(DiskEntry {
                file: p.display().to_string(),
                target: format!("vd{letter}"),
                bus: "virtio".to_string(),
            });
        }

        let tpl = GuestVmTemplate {
            domain_name: domain_name.clone(),
            domain_uuid: uuid,
            vm_memory_kib: spec.memory_ki_b,
            nr_of_vcpus: spec.v_cpus,
            mac_address: mac.to_string(),
            disks,
            console_log_path: console_log.display().to_string(),
            tap_name: tap,
            has_ipv4,
            mac_address_ipv4: mac_ipv4.to_string(),
            tap_name_ipv4: tap_ipv4,
        };
        let xml = tpl.render().context("rendering guest VM XML")?;

        Domain::create_xml(&self.connect, &xml, 0)
            .with_context(|| format!("creating libvirt domain {domain_name}"))?;
        Ok(())
    }

    /// Destroy the libvirt domain for `vm_name`.
    pub fn destroy_vm(&self, group_name: &str, vm_name: &str) -> Result<()> {
        let domain_name = Self::domain_name(group_name, vm_name);
        if let Ok(d) = Domain::lookup_by_name(&self.connect, &domain_name) {
            let _ = d.destroy();
        }
        Ok(())
    }

    /// Reboot the libvirt domain for `vm_name`.
    pub fn reboot_vm(&self, group_name: &str, vm_name: &str) -> Result<()> {
        let domain_name = Self::domain_name(group_name, vm_name);
        let d = Domain::lookup_by_name(&self.connect, &domain_name)
            .with_context(|| format!("looking up domain {domain_name}"))?;
        d.reboot(0)
            .with_context(|| format!("rebooting {domain_name}"))?;
        Ok(())
    }

    fn vm_dir(&self, vm_name: &str) -> PathBuf {
        self.active_local_backend
            .working_dir
            .join("vms")
            .join(sanitize_libvirt_name(vm_name))
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

impl Drop for LocalBackend {
    fn drop(&mut self) {
        // libvirtd runs as the current user in session mode (no `sudo`), so the
        // `Child` handle refers to the daemon itself and we can signal it.
        if let Some(mut child) = self.libvirtd.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = self.pid_path.take();
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

/// Sanitize a name so it is a valid libvirt resource name (alphanumeric,
/// `-` and `_`).
fn sanitize_libvirt_name(s: &str) -> String {
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

/// Open a libvirt connection over a unix socket on `socket_path`.
fn open_connect(socket_path: &Path, logger: &Logger) -> Result<Connect> {
    // `///session`: the daemon runs as the current (non-root) user, so it
    // exposes the per-user (session) QEMU driver rather than the system one.
    let uri = format!("qemu+unix:///session?socket={}", socket_path.display());
    let connect = Connect::open(Some(&uri))
        .with_context(|| format!("opening libvirt connection to {uri}"))?;
    info!(logger, "Connected to libvirtd"; "uri" => &uri);
    Ok(connect)
}

/// The current user's login name, used to tag TAP device ownership so an
/// unprivileged QEMU may open them. Falls back to the `USER` environment
/// variable and finally to `ubuntu` (the container's default user).
fn current_username() -> String {
    std::env::var("USER").unwrap_or_else(|_| "ubuntu".to_string())
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
        // Extract into a fresh tempdir to find the disk-image entry.
        let tmp = parent.join(format!(".extract-{}", std::process::id()));
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

#[derive(Clone)]
struct DiskEntry {
    file: String,
    target: String,
    bus: String,
}

#[derive(Template)]
#[template(path = "guestos_vm_template.xml", escape = "xml")]
struct GuestVmTemplate {
    domain_name: String,
    domain_uuid: String,
    vm_memory_kib: u64,
    nr_of_vcpus: u64,
    mac_address: String,
    disks: Vec<DiskEntry>,
    console_log_path: String,
    tap_name: String,
    /// When `true`, the domain gets a second virtio NIC (the guest's `enp2s0`)
    /// attached to `tap_name_ipv4` with `mac_address_ipv4`, used to obtain an
    /// IPv4 address via DHCP. When `false`, the other two fields are unused.
    has_ipv4: bool,
    mac_address_ipv4: String,
    tap_name_ipv4: String,
}

// `vm_ipv6` is currently a write-only cache; future operations (e.g. ARP
// pre-population) will read it.
