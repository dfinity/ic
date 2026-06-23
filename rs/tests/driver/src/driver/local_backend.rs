//! Local (libvirt + QEMU) system-test backend.
//!
//! This module is the counterpart to [`crate::driver::farm::Farm`] for tests
//! that are run on a developer or CI host instead of being shipped to the Farm
//! cluster. It is selected by setting the environment variable:
//! `SYSTEM_TEST_INFRA=local`.
//!
//! The backend spawns a *per-test* libvirtd daemon on a unix socket under the
//! test's `working_dir`, then drives the daemon through the `virt` crate to
//! create libvirt networks (for groups), domains (for VMs) and to extract and
//! mount disk images.
//!
//! Many Farm features have no equivalent locally (managed playnet DNS, TLS
//! certificate issuance, HTTP file upload, multi-tenant scheduling). Those
//! operations log a warning and either return dummy values or are explicit
//! `bail!`s; the test author is expected to mark a test as `backend = "local"`
//! or `backend = None` (default)` only after auditing those code paths.
//!
//! See `rs/tests/driver/templates/guestos_vm_template.xml` for the libvirt
//! domain XML template used to launch VMs.

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

/// Persistent record (in the root TestEnv) of the libvirtd unix socket so that
/// forked task subprocesses can connect to the daemon spawned by the setup
/// task instead of trying to spawn their own.
#[derive(Serialize, Deserialize, Clone)]
struct ActiveLocalBackend {
    /// Path of the libvirtd unix socket the spawning process bound. Forked task
    /// subprocesses open a connect-only handle to it (see
    /// [`LocalBackend::connect_only`]).
    socket_path: PathBuf,
    /// Working directory under which VM disks and the per-VM metadata
    /// (`meta.json`) are materialized. It resolves to the same
    /// `<group_dir>/local_backend` path in every process, so a `connect_only`
    /// handle in a forked task subprocess (e.g. a test calling `vm.start()`)
    /// reads back the metadata that the setup process persisted in
    /// [`LocalBackend::create_vm`] / [`LocalBackend::attach_disk_images`].
    working_dir: PathBuf,
}

impl TestEnvAttribute for ActiveLocalBackend {
    fn attribute_name() -> String {
        "active_local_backend".to_string()
    }
}

/// Process-wide cache of the single `LocalBackend`. There is exactly one
/// libvirtd (and therefore one socket) per `bazel test` invocation, and the
/// registry is a process-local `static`, so a single slot suffices: every
/// `from_test_env` call in a process resolves to the same backend.
static REGISTRY: Mutex<Option<Arc<LocalBackend>>> = Mutex::new(None);

/// Per-test handle that owns a libvirtd subprocess (in the setup process only)
/// and a `virt::Connect`.
pub struct LocalBackend {
    /// The libvirtd socket path and backend working directory. Persisted (in
    /// the setup process) as a `TestEnvAttribute` so forked task subprocesses
    /// can reconstruct a connect-only handle from the same values; see
    /// [`from_test_env`](Self::from_test_env).
    active_local_backend: ActiveLocalBackend,
    /// `Some(child)` only in the process that spawned libvirtd; `None` in
    /// forked tasks that merely connect to an already-running daemon. `Drop`
    /// only kills the child if we own it.
    libvirtd: Option<Child>,
    /// Path to the libvirtd pid-file. `Some` only in the spawning process.
    /// libvirtd runs as the current (unprivileged) user in session mode, so it
    /// is a direct child we can signal; the pid-file is used as a fallback for
    /// teardown from a connect-only handle in the finalize task.
    pid_path: Option<PathBuf>,
    /// libvirt connection.
    connect: Connect,
    logger: Logger,
    /// Per-VM allocated IPv6, keyed by `vm_name`.
    vm_ipv6: Mutex<HashMap<String, Ipv6Addr>>,
}

/// Per-VM configuration persisted to disk (as `meta.json` under the VM's
/// working directory) by [`LocalBackend::create_vm`] and amended by
/// [`LocalBackend::attach_disk_images`].
///
/// The per-VM state cannot live solely in the in-memory `LocalBackend`:
/// `create_vm` / `attach_disk_images` run in the setup process, whereas
/// [`LocalBackend::start_vm`] may run in a *forked task subprocess* (e.g. a
/// test driving `vm.start()`), which holds a `connect_only` handle with no
/// in-memory record of the VM. Persisting under `working_dir` — which resolves
/// to the same `<group_dir>/local_backend` path in every process — lets
/// `start_vm` recover everything it needs regardless of which process calls it.
#[derive(Serialize, Deserialize, Clone)]
struct PersistedVm {
    /// Primary boot image. Must be a [`DiskImage::Local`] under the Local
    /// backend (see [`LocalBackend::start_vm`]).
    primary_image: DiskImage,
    /// vCPU / memory spec used to render the domain XML.
    spec: VmSpec,
    /// Optional minimum boot-image size in gibibytes; the primary disk is grown
    /// to at least this size before boot.
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
    /// Behavior:
    /// - If `env` already has an `ActiveLocalBackend` attribute (i.e. setup has
    ///   run and persisted the socket path), open a connect-only handle to
    ///   that socket. This is what forked task subprocesses get.
    /// - Otherwise, spawn a new libvirtd in `env`'s working directory, persist
    ///   the absolute socket path as a `TestEnvAttribute`, and return the
    ///   spawning handle. This is what the setup task gets on first call from
    ///   `create_group_setup`.
    ///
    /// In both cases the returned `Arc` is cached in a single process-wide
    /// slot, so repeated calls within the same process share state.
    pub fn from_test_env(env: &TestEnv) -> Result<Arc<LocalBackend>> {
        let mut reg = REGISTRY.lock().unwrap();
        if let Some(b) = reg.as_ref() {
            return Ok(b.clone());
        }

        if let Ok(existing) = ActiveLocalBackend::try_read_attribute(env) {
            // Setup has run and persisted the socket path: open a connect-only
            // handle to the already-running daemon.
            let backend = Arc::new(LocalBackend::connect_only(existing, env.logger())?);
            *reg = Some(backend.clone());
            return Ok(backend);
        }

        // First call in this group: spawn libvirtd.
        //
        // The working dir holds the live libvirtd socket/pid/log and the
        // (potentially multi-gibibyte) VM disk images. It must live OUTSIDE the
        // env directory: each `TestEnv` (`root_env`, `setup`, `tests/<name>`)
        // is recursively `cp -R`'d when the setup artifacts are forked into the
        // per-test directories. Copying the live unix socket hangs `cp` (it
        // blocks in `D` state), and copying the disk images would duplicate
        // gigabytes into every test directory. We therefore place the working
        // dir as a sibling of the env directory (i.e. directly under the group
        // directory), which is never copied.
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
        // absolute; a failure here means the directory is missing/inaccessible
        // and there is no sensible way to continue.
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

    /// Build a [`Command`] that runs a short shell `script` with
    /// `CAP_NET_ADMIN` raised into the ambient set, so the program(s) it
    /// `exec`s inherit that capability.
    ///
    /// This is the *only* privileged primitive the backend uses, and it grants
    /// exactly one narrow capability — never root. It is needed for the few
    /// operations the kernel gates behind `CAP_NET_ADMIN`: creating the
    /// per-group bridge and TAP devices.
    ///
    /// The capability comes from the [`NET_ADMIN_LAUNCHER`] binary, a
    /// file-capability-endowed `capsh` provisioned once in the container image
    /// (`cap_net_admin,cap_net_raw,cap_net_bind_service+ep`; see
    /// `ci/container/Dockerfile`). `capsh` raises the requested
    /// caps into its inheritable+ambient sets and then `exec`s `/bin/sh -c
    /// <script>`; ambient capabilities survive the `exec`, so the commands in
    /// `script` (e.g. `ip link add ...`) run with the caps even though the
    /// shell binary itself is not capability-endowed.
    ///
    /// `CAP_NET_BIND_SERVICE` is additionally needed by the group's `dnsmasq`
    /// to bind the privileged UDP port 67 of its DHCPv4 server (see
    /// [`start_ra_daemon`](Self::start_ra_daemon)).
    ///
    /// `script` must only ever interpolate sanitized, shell-safe tokens
    /// (bridge/TAP interface names and IPv6 prefixes are restricted to
    /// `[0-9a-f:.-]`).
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
    /// See the call site in [`spawn`] for why the socket cannot live under
    /// `working_dir`. Keyed by a hash of `working_dir` so it is stable across
    /// re-runs of the same group yet distinct between concurrent groups.
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
        // (`qemu:///session`). A session-mode daemon ignores `unix_sock_dir`
        // and always places its socket at `$XDG_RUNTIME_DIR/libvirt/libvirt-sock`.
        // The default `$XDG_RUNTIME_DIR` (`/run/user/<uid>`) may be absent in
        // the container, and in any case we want a deterministic, short path
        // (the kernel caps unix socket paths, `sockaddr_un.sun_path`, at ~108
        // bytes, and the working dir resolves to a deep Bazel cache path that
        // already exceeds that limit). We therefore point `$XDG_RUNTIME_DIR` at
        // a short `/tmp` directory keyed by a hash of the working dir, so
        // concurrent test targets on the same host do not collide while a given
        // group stays stable across re-runs. The pid/log/conf files stay in
        // `libvirt_dir`.
        let xdg_runtime_dir = Self::socket_dir(&working_dir);
        std::fs::create_dir_all(&xdg_runtime_dir).with_context(|| {
            format!(
                "creating libvirt XDG_RUNTIME_DIR {}",
                xdg_runtime_dir.display()
            )
        })?;
        let socket_path = xdg_runtime_dir.join("libvirt").join("libvirt-sock");
        // A previous run with the same working dir leaves the socket behind at
        // this fixed path; remove it so libvirtd can bind cleanly.
        let _ = std::fs::remove_file(&socket_path);

        // Minimal libvirtd configuration: log to a file. Session-mode libvirtd
        // needs no auth/TLS settings and derives its socket path from
        // `$XDG_RUNTIME_DIR` (see above), so no `unix_sock_dir` is configured.
        std::fs::write(
            &conf_path,
            format!("log_outputs = \"1:file:{log}\"\n", log = log_path.display(),),
        )?;

        // Session-mode libvirtd initializes per-user *state drivers* on
        // startup, which create config/cache/data directories derived from
        // `$HOME` (`~/.config/libvirt`, `~/.cache/libvirt`,
        // `~/.local/share/libvirt`). If those directories cannot be created the
        // daemon aborts in `daemonRunStateInit` *before* binding its socket,
        // and the caller below times out waiting for the socket.
        //
        // Under the Bazel `linux-sandbox` the real `$HOME` is bind-mounted
        // read-only (only the exec root, `$TEST_TMPDIR`, the hermetic `/tmp`
        // and any `--sandbox_writable_path`s are writable), so libvirtd's
        // attempt to create `~/.config/libvirt/...` fails with `Permission
        // denied` and no socket ever appears. (Run unsandboxed the same code
        // works because `$HOME` is then writable.) To make the backend
        // sandbox-friendly we point `$HOME` and the XDG base-directory vars at
        // a writable directory we control.
        //
        // The state dir lives under `xdg_runtime_dir` (the short `/tmp` path
        // above), NOT under `libvirt_dir`: libvirtd's QEMU driver opens a QMP
        // monitor unix socket at
        // `$XDG_CONFIG_HOME/libvirt/qemu/lib/qmp-XXXXXX/qmp.monitor`, and
        // rooting `$HOME` at the deep Bazel working dir pushes that path past
        // the ~108-byte `sun_path` limit (`QEMU ... UNIX socket path ... is too
        // long`). The short `/tmp` base keeps every derived socket path within
        // the limit, for the same reason `$XDG_RUNTIME_DIR` is placed there.
        let state_home = xdg_runtime_dir.join("home");
        for sub in [".config", ".cache", ".local/share"] {
            std::fs::create_dir_all(state_home.join(sub)).with_context(|| {
                format!(
                    "creating libvirt state dir {}",
                    state_home.join(sub).display()
                )
            })?;
        }

        // Pin the QEMU driver's core-dump limit. In session mode the QEMU
        // driver reads its config from `$XDG_CONFIG_HOME/libvirt/qemu.conf`,
        // and libvirt *unconditionally* sets the QEMU process's `RLIMIT_CORE`
        // to `max_core` (whose built-in default is "unlimited", i.e.
        // `RLIM_INFINITY` == `18446744073709551615`). Under the Bazel
        // `linux-sandbox` QEMU runs in an unprivileged user namespace and thus
        // lacks `CAP_SYS_RESOURCE` in the *initial* user namespace, so *raising*
        // the hard `RLIMIT_CORE` to unlimited is rejected by the kernel with
        // `EPERM` and the domain never starts (libvirt reports "cannot limit
        // core file size of process ... to 18446744073709551615: Operation not
        // permitted"). Setting `max_core = 0` makes libvirt *lower* the limit
        // to 0 instead (disabling core dumps), which is always permitted
        // regardless of capabilities or the inherited hard limit. Core dumps of
        // the test QEMU are not needed.
        let qemu_conf_dir = state_home.join(".config").join("libvirt");
        std::fs::create_dir_all(&qemu_conf_dir).with_context(|| {
            format!(
                "creating libvirt qemu config dir {}",
                qemu_conf_dir.display()
            )
        })?;
        // Also route QEMU's stdout/stderr (and file-backed character devices
        // such as the VM's serial console) directly to plain files instead of
        // through the `virtlogd` daemon. libvirt's QEMU driver defaults
        // `stdio_handler` to `"logd"`, which makes libvirtd spawn `virtlogd`,
        // whose sole added value is rolling the log files over at a size limit
        // to bound a runaway guest's on-disk log growth. Bounded test runs do
        // not need that, and the extra double-forked daemon would just be one
        // more process the teardown reaper has to track. Setting
        // `stdio_handler = "file"` (libvirt's historical backend) makes QEMU
        // write the console log straight to `console.log`, so no `virtlogd` is
        // started. The domain XML's `append='on'` is honoured natively by
        // QEMU's file chardev, so console output is still preserved across
        // domain restarts (guest reboots and `vm().kill()` + `vm().start()`).
        std::fs::write(
            qemu_conf_dir.join("qemu.conf"),
            "max_core = 0\nstdio_handler = \"file\"\n",
        )
        .with_context(|| format!("writing {}", qemu_conf_dir.join("qemu.conf").display()))?;

        // The backend is fully unprivileged: libvirtd runs as the current user
        // in session mode and connects to a per-user QEMU driver. There is no
        // `sudo`, no system-wide bridge, and no `virtlogd` (the `qemu.conf`
        // `stdio_handler = "file"` set above makes QEMU write the domain serial
        // and console output directly to files instead). The few operations
        // that need elevated networking capabilities (creating the bridge and
        // TAPs) go through the narrow [`net_admin`] capability launcher instead.
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
    ///
    /// The [`ActiveLocalBackend`] (socket path + working dir) is passed in
    /// (persisted as a `TestEnvAttribute` by the spawning process) rather than
    /// derived from the socket path, because the socket lives at a short
    /// `/tmp` path (see `spawn`) and no longer sits under `working_dir`. The
    /// working dir resolves to the SAME `<group_dir>/local_backend` directory
    /// the spawning process used, regardless of which env (`root_env`, `setup`,
    /// `tests/<name>`) this handle was constructed from. This keeps VM disks
    /// out of the env tree that gets recursively `cp -R`'d into every per-test
    /// directory.
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

    /// Returns the per-group IPv6 gateway address (`<prefix>1`). The Local
    /// backend assigns this address to the group's bridge in
    /// [`create_group`](Self::create_group), which both puts the node `/64`
    /// on-link there and creates the bridge's connected route for it (whose
    /// preferred source `create_group` then overrides to the management
    /// address, [`group_mgmt_ipv6`](Self::group_mgmt_ipv6)).
    pub fn group_gateway_ipv6(group_name: &str) -> String {
        format!("{}1", Self::group_ipv6_prefix(group_name))
    }

    /// Returns the per-group IPv6 *management* address: the source the test
    /// driver originates its host→node traffic from.
    ///
    /// It is `<prefix>:1::1`, sharing the group hash with
    /// [`group_ipv6_prefix`](Self::group_ipv6_prefix): the node `/64`
    /// `fd00:AABB:CCDD::/64` yields the management address `fd00:AABB:CCDD:1::1`
    /// (subnet-id `1` instead of the nodes' subnet-id `0`). It therefore lies
    /// *outside* every node `/64` — so the GuestOS firewall's hard-coded accept
    /// for a node's own prefix does not match the driver, letting
    /// registry-derived deny rules actually be exercised on the Local backend —
    /// while staying within the ULA range `fd00::/8` that the Local backend
    /// whitelists at bootstrap. Reusing the group hash keeps it per-group
    /// unique, introducing no new collision class beyond the node `/64`'s
    /// existing per-group uniqueness.
    ///
    /// It is reserved for the test driver's *own* host→node traffic: the
    /// driver's other long-lived connections each use their own dedicated
    /// sibling address ([`group_logs_ipv6`](Self::group_logs_ipv6) for journald
    /// streaming), and the per-group file server listens on yet another
    /// ([`group_files_ipv6`](Self::group_files_ipv6)), so nothing else competes
    /// with the management address' per-source firewall connection budget —
    /// which matters for tests that deliberately saturate it (the firewall
    /// `connection_count_test`).
    ///
    /// The address is assigned to `lo` (not the bridge) so `dnsmasq` does not
    /// advertise it for SLAAC; [`create_group`](Self::create_group) overrides
    /// the node `/64`'s connected-route source to it.
    pub fn group_mgmt_ipv6(group_name: &str) -> String {
        use ic_crypto_sha2::Sha256;
        let hash = Sha256::hash(group_name.as_bytes());
        format!(
            "fd00:{:02x}{:02x}:{:02x}{:02x}:1::1",
            hash[0], hash[1], hash[2], hash[3]
        )
    }

    /// Returns the per-group IPv6 address the test driver streams the IC nodes'
    /// journald logs from (see
    /// [`logs_stream_task`](crate::driver::logs_stream_task)).
    ///
    /// It is constructed exactly like [`group_mgmt_ipv6`](Self::group_mgmt_ipv6)
    /// but with subnet-id `2` (`<prefix>:2::1`), so it shares all of that
    /// address' properties — per-group unique, inside the whitelisted ULA range
    /// `fd00::/8`, and *outside* every node `/64` so nodes reach it via their
    /// default route — while being a *distinct* source address.
    ///
    /// The driver sources all other host→node traffic from
    /// [`group_mgmt_ipv6`](Self::group_mgmt_ipv6). The GuestOS firewall caps the
    /// number of simultaneous connections *per source address*
    /// (`max_simultaneous_connections_per_ip_address`); streaming the long-lived
    /// journald connection from this dedicated address keeps it from consuming a
    /// slot in the management address' budget. Otherwise a test that
    /// deliberately saturates that budget (the firewall `connection_count_test`)
    /// would race the journald stream for the last slot and flake. Like
    /// [`group_mgmt_ipv6`](Self::group_mgmt_ipv6) it is assigned to `lo` in
    /// [`create_group`](Self::create_group).
    pub fn group_logs_ipv6(group_name: &str) -> String {
        use ic_crypto_sha2::Sha256;
        let hash = Sha256::hash(group_name.as_bytes());
        format!(
            "fd00:{:02x}{:02x}:{:02x}{:02x}:2::1",
            hash[0], hash[1], hash[2], hash[3]
        )
    }

    /// Returns the per-group IPv6 address the Local backend's per-group file
    /// server ([`serve_files_task`](crate::driver::serve_files_task)) listens
    /// on, and that node image-download URLs point at (see
    /// [`ic_images`](crate::driver::ic_images)).
    ///
    /// It is constructed exactly like [`group_mgmt_ipv6`](Self::group_mgmt_ipv6)
    /// but with subnet-id `3` (`<prefix>:3::1`), so it shares all of that
    /// address' properties — per-group unique, inside the whitelisted ULA range
    /// `fd00::/8`, and *outside* every node `/64` — while being a *distinct*
    /// address. Serving images from an off-`/64` address mirrors production,
    /// where the web server hosting GuestOS/HostOS images is not on the IC
    /// nodes' `/64`; nodes still reach it because the RA installs the host as
    /// their default router (see [`create_group`](Self::create_group)) and their
    /// download replies are accepted by the GuestOS firewall's stateful
    /// `established,related` rule.
    ///
    /// Listening here rather than on [`group_mgmt_ipv6`](Self::group_mgmt_ipv6)
    /// keeps the management address reserved for the test driver's own host→node
    /// traffic, so the per-source firewall connection budget stays easy to
    /// reason about. Like [`group_mgmt_ipv6`](Self::group_mgmt_ipv6) it is
    /// assigned to `lo` in [`create_group`](Self::create_group).
    pub fn group_files_ipv6(group_name: &str) -> String {
        use ic_crypto_sha2::Sha256;
        let hash = Sha256::hash(group_name.as_bytes());
        format!(
            "fd00:{:02x}{:02x}:{:02x}{:02x}:3::1",
            hash[0], hash[1], hash[2], hash[3]
        )
    }

    /// Returns the per-group private IPv4 `/24` (a deterministic subnet in the
    /// RFC 1918 `10.0.0.0/8` range). Derived from a hash of the group name —
    /// like [`group_ipv6_prefix`](Self::group_ipv6_prefix) — so concurrently
    /// running groups get distinct subnets (and therefore distinct host
    /// connected routes), with the `.0` network and `.1` gateway reserved.
    ///
    /// This network is only used to hand the guest an IPv4 address on its
    /// second NIC (the guest's `enp2s0`) via DHCP; the driver reaches VMs over
    /// IPv6, so the IPv4 subnet needs no routing or NAT.
    fn group_ipv4_prefix(group_name: &str) -> String {
        use ic_crypto_sha2::Sha256;
        let hash = Sha256::hash(format!("ipv4/{group_name}").as_bytes());
        format!("10.{}.{}", hash[0], hash[1])
    }

    /// Returns the Linux bridge interface name for `group_name`.
    ///
    /// Bridge (interface) names are limited to `IFNAMSIZ - 1` = 15 characters
    /// by the kernel, so we cannot embed the full (timestamped, therefore
    /// unique) network name. Instead we hash the group name and use a short
    /// hex digest, which keeps the name both unique per group and within the
    /// length limit (`vbr-` + 10 hex chars = 14 chars).
    ///
    /// Note that tests are executed under bazel's linux-sandbox which introduces a networking namespace,
    /// so the hashing is not strictly necessary to avoid collisions with other groups on the host.
    /// However, it's done for extra safety and to make accidental `bazel run //rs/tests/<test>_local` invocations
    /// not catastrophic for the host.
    fn bridge_name(group_name: &str) -> String {
        use ic_crypto_sha2::Sha256;
        let hash = Sha256::hash(group_name.as_bytes());
        format!("vbr-{}", hex::encode(&hash[0..5]))
    }

    /// Returns the TAP interface name for `(group_name, vm_name)`.
    ///
    /// Like [`bridge_name`], TAP names are bounded by `IFNAMSIZ - 1` = 15
    /// characters, so we use a short hash digest (`tap-` + 10 hex chars = 14
    /// chars). The digest covers both the group and VM name so TAPs are unique
    /// per VM and stable across re-runs.
    fn tap_name(group_name: &str, vm_name: &str) -> String {
        use ic_crypto_sha2::Sha256;
        let hash = Sha256::hash(format!("{group_name}/{vm_name}").as_bytes());
        format!("tap-{}", hex::encode(&hash[0..5]))
    }

    /// Returns the TAP interface name for the VM's *second* (IPv4) NIC.
    ///
    /// Same length constraints as [`tap_name`](Self::tap_name); a distinct
    /// digest seed (`ipv4/...`) keeps it from colliding with the primary TAP
    /// while remaining unique per VM and stable across re-runs (`ta4-` + 10 hex
    /// chars = 14 chars).
    fn tap_name_ipv4(group_name: &str, vm_name: &str) -> String {
        use ic_crypto_sha2::Sha256;
        let hash = Sha256::hash(format!("ipv4/{group_name}/{vm_name}").as_bytes());
        format!("ta4-{}", hex::encode(&hash[0..5]))
    }

    /// Create the per-group Linux bridge that hosts the group's `/64`.
    ///
    /// Instead of a libvirt-managed (system-mode) network — which would require
    /// `libvirtd` to run as root — we manage the network ourselves with the
    /// narrow [`net_admin`] capability launcher: a Linux bridge holds the
    /// group's `/64` and per-VM TAPs are attached to it in [`start_vm`].
    ///
    /// The IC GuestOS does not statically configure its global IPv6 address; it
    /// only brings up a link-local address and then derives its deterministic
    /// global address via SLAAC from a Router Advertisement (the global address
    /// is the group `/64` prefix plus the EUI-64 of the deterministic MAC). We
    /// therefore run a minimal `dnsmasq` purely as an RA daemon on the bridge.
    /// The RA advertises the on-link, autonomous prefix (so guests perform
    /// SLAAC) *and* a non-zero router lifetime (`--ra-param=<bridge>,10,1800`),
    /// which installs the bridge — i.e. the host — as the guests' default
    /// router.
    ///
    /// The default route is what lets a guest reply to the driver's per-group
    /// *management* address ([`group_mgmt_ipv6`](Self::group_mgmt_ipv6)), which
    /// lives in a second `/64` *outside* the node `/64`. The driver uses that
    /// off-`/64` source so the GuestOS firewall's built-in accept for the
    /// node's own prefix does not shadow the registry rules under test. No IP
    /// forwarding is involved — the management address is assigned to `lo`, so
    /// traffic to it terminates on the host and is delivered locally rather
    /// than forwarded.
    pub fn create_group(&self, group_name: &str) -> Result<()> {
        let bridge = Self::bridge_name(group_name);
        let prefix = Self::group_ipv6_prefix(group_name);
        // The gateway address (`<prefix>1`) lives on the bridge.
        let gateway = Self::group_gateway_ipv6(group_name);
        // The driver's per-group management address (`<mgmt-prefix>:1::1`, a
        // second `/64` outside the node `/64`) is assigned to `lo` and used as
        // the source for host→node traffic; see `group_mgmt_ipv6`.
        let mgmt = Self::group_mgmt_ipv6(group_name);
        // The driver's per-group journald-streaming source address
        // (`<prefix>:2::1`, also assigned to `lo`). The IC node journald stream
        // is sourced from this dedicated address rather than `mgmt` so the
        // long-lived stream does not occupy one of the node firewall's
        // per-source-address connection slots that tests saturating that budget
        // rely on; see `group_logs_ipv6`.
        let logs = Self::group_logs_ipv6(group_name);
        // The per-group file server's listen address (`<prefix>:3::1`, also
        // assigned to `lo`). Serving images from a dedicated address rather than
        // `mgmt` keeps the management address reserved for the test driver's own
        // host→node traffic; see `group_files_ipv6`.
        let files = Self::group_files_ipv6(group_name);
        // The IPv4 gateway (`<ipv4_prefix>.1`) also lives on the bridge so
        // `dnsmasq` can serve DHCPv4 to VMs that requested a second NIC.
        let ipv4_prefix = Self::group_ipv4_prefix(group_name);
        let ipv4_gateway = format!("{ipv4_prefix}.1");
        info!(
            self.logger,
            "Creating local bridge {bridge} for group {group_name} ({prefix}/64, {ipv4_prefix}.0/24)"
        );

        // (Re)create the bridge, assign the gateway address, and bring it up.
        // Deleting first makes this idempotent across an interrupted previous
        // run that leaked the bridge.
        //
        // The IPv4 `/24` gateway is always assigned (harmless when no VM in the
        // group requests IPv4); it is what lets `dnsmasq` answer DHCPv4
        // requests from the guests' second NIC.
        //
        // Finally, assign the per-group management address to `lo` (idempotent
        // via `replace`, since `lo` is shared across groups and survives the
        // bridge delete above), assign the dedicated journald-streaming source
        // address (`logs`) and file-server address (`files`) to `lo` the same
        // way, and override the preferred source of the node `/64`'s connected
        // route to the management address, so host→node traffic is sourced from
        // the off-`/64` management address rather than the on-bridge gateway.
        // (The journald stream binds to `logs` and the file server to `files`
        // explicitly; everything else uses the route's preferred source.)
        // The override must target the *kernel* connected route that
        // `ip -6 addr add {gateway}/64` auto-creates (`proto kernel metric
        // 256`): replacing it in place sets its preferred source. Adding a
        // separate route instead would land at a higher metric (1024) and lose
        // to the still-present metric-256 kernel route, leaving source
        // selection on the on-`/64` gateway.
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

        // Start the RA daemon so guests can SLAAC their global address. The
        // same `dnsmasq` also serves DHCPv4 on the group's IPv4 `/24` for VMs
        // that requested a second NIC.
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
    /// lifetime (so the bridge — i.e. the host — is installed as the guests'
    /// default router, letting them reply to the driver's off-`/64` management
    /// address). The same daemon also serves DHCPv4 on the group's IPv4 `/24`
    /// (`ipv4_prefix`) so VMs that requested a second NIC obtain an IPv4
    /// address. See [`create_group`](Self::create_group) for the rationale.
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
        // socket and send Router Advertisements, so it runs through the
        // capability launcher. `--ra-param=<bridge>,10,1800` sends an RA every
        // 10s with a router lifetime of 1800s, installing the bridge (the host)
        // as the guests' default router; `--dhcp-range=<prefix>,ra-only`
        // advertises the on-link, autonomous prefix for SLAAC without handing
        // out stateful leases.
        // A second `--dhcp-range=<ipv4_prefix>.2,<ipv4_prefix>.254,...` enables
        // stateful DHCPv4 on the group's IPv4 `/24` (the `.1` gateway lives on
        // the bridge), which is what gives a VM's second NIC (the guest's
        // `enp2s0`) an IPv4 address. `--port=0` disables the DNS service
        // entirely. `dnsmasq` daemonizes (writing its pid-file) and is later
        // signalled via that pid-file in teardown.
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

    /// Stop the group's `dnsmasq` RA daemon, if running. The daemon runs as the
    /// current (unprivileged) user, so it can be signalled directly via the pid
    /// recorded in its pid-file. Best-effort and idempotent.
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

        // Delete every TAP enslaved to the bridge, then the bridge itself. The
        // TAPs persist (they were created persistent in `start_vm`) until
        // explicitly removed, so enumerate the bridge's slave interfaces via
        // sysfs and delete each one before removing the bridge.
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
        // everything `start_vm` needs to disk, so a forked task subprocess —
        // which holds a `connect_only` handle with empty in-memory state — can
        // still start the VM (e.g. a test calling `vm.start()`).
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
            // chmod 0600
            std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o600))?;
            paths.push(dst);
        }
        // Record the extra disks in the metadata persisted by `create_vm` so
        // `start_vm` attaches them, including when it runs in a forked task
        // subprocess.
        let mut meta = self.read_vm_meta(vm_name)?;
        meta.extra_disks = paths;
        self.write_vm_meta(vm_name, &meta)?;
        Ok(())
    }

    /// Build the libvirt domain XML for `vm_name` and start it.
    pub fn start_vm(&self, group_name: &str, vm_name: &str) -> Result<()> {
        // Recover the per-VM state persisted by `create_vm` /
        // `attach_disk_images`. Reading it from disk (instead of an in-memory
        // cache) is what lets `start_vm` run from a forked task subprocess —
        // e.g. a test calling `vm.start()` — whose `connect_only` handle has no
        // in-memory record of the VM.
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
        // Only materialize the primary disk on first boot. On a subsequent
        // `start_vm` — e.g. a test that stopped the VM via `vm().kill()`
        // (`destroy_vm`) and restarted it via `vm().start()` — the extracted
        // `primary.img` already exists and holds the node's persisted disk
        // state: its data partition (crypto keys, registry local store,
        // replicated/consensus state) and, crucially for upgrade tests, any
        // GuestOS upgrade written to the previously-inactive root partition.
        // Re-extracting the pristine image here would wipe all of that, so the
        // node would come back as if freshly provisioned and never rejoin the
        // subnet or become healthy again. Reuse the existing disk instead,
        // mirroring how a real VM reboot preserves its disks.
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

        // Create the per-VM TAP, attach it to the group bridge, and bring it
        // up — all via the [`net_admin`] capability launcher. `user ubuntu`
        // (the current user) tags the TAP as owned by us, which is what lets
        // an unprivileged QEMU (driven by session-mode libvirtd) open it. The
        // domain XML references the TAP with `managed='no'`, so libvirt uses
        // the existing device instead of trying to create one (which would
        // require root). Creating it fresh each time (delete first) keeps this
        // idempotent across a re-used domain name.
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
        // libvirtd runs as the current user in session mode (no `sudo`
        // wrapper), so the `Child` handle refers to the daemon itself and we
        // can signal it directly.
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

/// Deterministic UUID for a `(group, vm)` pair.
fn vm_uuid(group_name: &str, vm_name: &str) -> String {
    use ic_crypto_sha2::Sha256;
    let hash = Sha256::hash(format!("uuid/{group_name}/{vm_name}").as_bytes());
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
