//! Local (libvirt + QEMU) system-test backend.
//!
//! This module is the counterpart to [`crate::driver::farm::Farm`] for tests
//! that are run on a developer or CI host instead of being shipped to the Farm
//! cluster. It is selected by setting `SYSTEM_TEST_INFRA=local` in the test
//! environment, which is done by the `system_test(local = True, ...)` Bazel
//! macro in `rs/tests/system_tests.bzl`.
//!
//! The backend spawns a *per-test* libvirtd daemon on a unix socket under the
//! test's `working_dir`, then drives the daemon through the `virt` crate to
//! create libvirt networks (for groups), domains (for VMs) and to extract and
//! mount disk images.
//!
//! Many Farm features have no equivalent locally (managed playnet DNS, TLS
//! certificate issuance, HTTP file upload, multi-tenant scheduling). Those
//! operations log a warning and either return dummy values or are explicit
//! `bail!`s; the test author is expected to mark a test as `local = True` only
//! after auditing those code paths.
//!
//! See `rs/tests/driver/templates/guestos_vm_template.xml` for the libvirt
//! domain XML template used to launch VMs.

use crate::driver::farm::{VMCreateResponse, VmSpec};
use crate::driver::resource::DiskImage;
use crate::driver::test_env::{TestEnv, TestEnvAttribute};
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
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use virt::connect::Connect;
use virt::domain::Domain;

/// Absolute path to the `libvirtd` binary.
///
/// `libvirtd` is installed in `/usr/sbin`, which is absent from `PATH` inside
/// the Bazel test sandbox, so we reference it by absolute path rather than
/// relying on a `PATH` lookup.
///
/// TODO: provide libvirt via a bazel dependency and replace this with an environment variable.
const LIBVIRTD_BIN: &str = "/usr/sbin/libvirtd";

/// Absolute path to the `dnsmasq` binary, used purely as an IPv6 Router
/// Advertisement daemon so the GuestOS can derive its global SLAAC address (see
/// [`LocalBackend::create_group`]). Like [`LIBVIRTD_BIN`], it lives in
/// `/usr/sbin`, which is not on `PATH` in the Bazel test sandbox, so we
/// reference it by absolute path.
///
/// TODO: provide dnsmasq via a bazel dependency and replace this with an environment variable.
const DNSMASQ_BIN: &str = "/usr/sbin/dnsmasq";

/// Absolute path to the capability launcher used for the few networking
/// operations that require `CAP_NET_ADMIN` (creating the per-group bridge and
/// attaching TAP devices). See [`LocalBackend::net_admin`] for the rationale
/// and `ci/container/setup-local-system-test-backend.sh` for how the launcher is
/// provisioned.
///
/// The backend is otherwise fully unprivileged: `libvirtd` runs as the
/// current (non-root) user in session mode (`qemu:///session`), and QEMU opens
/// the pre-created, user-owned TAPs directly. No `sudo` is used anywhere.
///
/// TODO: provide the launcher via a bazel dependency and replace this with an
/// environment variable.
const NET_ADMIN_LAUNCHER: &str = "/usr/local/bin/ic-net-admin";

/// TCP port on which the per-group file server listens (on the group's IPv6
/// gateway address). Under the Local backend there is no external network, so
/// `icos_images` that IC nodes must fetch over HTTP (e.g. GuestOS/HostOS update
/// images used by upgrade tests) are served by a small web server spawned from
/// the test driver (see `serve_files_task`). The port is fixed because every
/// group runs in its own network namespace, so there is no cross-group
/// contention on the gateway address.
pub const FILE_SERVER_PORT: u16 = 8080;

/// Persistent record (in the root TestEnv) of the libvirtd unix socket so that
/// forked task subprocesses can connect to the daemon spawned by the setup
/// task instead of trying to spawn their own.
#[derive(Serialize, Deserialize, Clone)]
struct LocalBackendSocket {
    /// Absolute path on the host's filesystem; survives `cp -R` of the
    /// surrounding TestEnv directory because it is just a JSON string.
    socket_path: PathBuf,
    /// Backend working directory (where VM disks and the libvirt pid/log
    /// files live). Persisted alongside the socket because the socket no
    /// longer lives under `working_dir` (it is placed at a short `/tmp` path,
    /// see `spawn`), so it can no longer be derived from `socket_path`.
    working_dir: PathBuf,
}

impl TestEnvAttribute for LocalBackendSocket {
    fn attribute_name() -> String {
        "local_backend_socket".to_string()
    }
}

/// Process-wide cache of the single `LocalBackend`. There is exactly one
/// libvirtd (and therefore one socket) per `bazel test` invocation, and the
/// registry is a process-local `static`, so a single slot suffices: every
/// `from_test_env` call in a process resolves to the same backend.
fn registry() -> &'static Mutex<Option<Arc<LocalBackend>>> {
    static REG: OnceLock<Mutex<Option<Arc<LocalBackend>>>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(None))
}

/// Per-test handle that owns a libvirtd subprocess (in the setup process only)
/// and a `virt::Connect`.
pub struct LocalBackend {
    socket_path: PathBuf,
    /// `Some(child)` only in the process that spawned libvirtd; `None` in
    /// forked tasks that merely connect to an already-running daemon. `Drop`
    /// only kills the child if we own it.
    libvirtd: Option<Child>,
    /// Path to the libvirtd pid-file. `Some` only in the spawning process.
    /// libvirtd runs as the current (unprivileged) user in session mode, so it
    /// is a direct child we can signal; the pid-file is used as a fallback for
    /// teardown from a connect-only handle in the finalize task.
    pid_path: Option<PathBuf>,
    /// libvirt connection. `virt::Connect` is `Send + Sync` and all its
    /// methods take `&self` (the underlying libvirt C API is thread-safe), so
    /// no interior mutex is needed.
    connect: Connect,
    logger: Logger,
    /// Per-VM extra disk paths, keyed by `vm_name`.
    extra_disks: Mutex<HashMap<String, Vec<PathBuf>>>,
    /// Per-VM primary disk path, keyed by `vm_name`.
    primary_disks: Mutex<HashMap<String, DiskImage>>,
    /// Per-VM allocated IPv6, keyed by `vm_name`.
    vm_ipv6: Mutex<HashMap<String, Ipv6Addr>>,
    /// Per-VM resource spec, keyed by `vm_name`.
    vm_specs: Mutex<HashMap<String, VmSpec>>,
    /// Per-VM minimum boot-image size in gibibytes, keyed by `vm_name`.
    vm_min_boot_image_size_gib: Mutex<HashMap<String, u64>>,
    /// Per-VM flag recording whether the VM requested a second (IPv4) NIC,
    /// keyed by `vm_name`. When set, [`start_vm`](Self::start_vm) attaches an
    /// additional TAP/interface (the guest's `enp2s0`) that obtains an IPv4
    /// address via DHCP from the group bridge's `dnsmasq`.
    vm_has_ipv4: Mutex<HashMap<String, bool>>,
    /// Working directory under which to materialize VM disks. Only meaningful
    /// in the setup process; forked tasks never call `create_vm` /
    /// `attach_disk_images` / `start_vm`.
    working_dir: PathBuf,
}

impl LocalBackend {
    /// Return the LocalBackend for the libvirtd associated with `env`.
    ///
    /// Behavior:
    /// - If `env` already has a `LocalBackendSocket` attribute (i.e. setup has
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
        let mut reg = registry().lock().unwrap();
        if let Some(b) = reg.as_ref() {
            return Ok(b.clone());
        }

        if let Ok(existing) = LocalBackendSocket::try_read_attribute(env) {
            // Setup has run and persisted the socket path: open a connect-only
            // handle to the already-running daemon.
            let backend = Arc::new(LocalBackend::connect_only(
                existing.socket_path,
                existing.working_dir,
                env.logger(),
            )?);
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
        LocalBackendSocket {
            socket_path: backend.socket_path.clone(),
            working_dir: backend.working_dir.clone(),
        }
        .write_attribute(env);
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
    /// `ci/container/setup-local-system-test-backend.sh`). `capsh` raises the requested
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
        let mut cmd = Command::new(NET_ADMIN_LAUNCHER);
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

        // Run libvirtd from a private copy rather than directly from
        // `LIBVIRTD_BIN`.
        //
        // The host's `libvirtd` AppArmor profile attaches *by executable path*
        // (it is defined for `/usr/sbin/libvirtd`) and, in enforce mode, only
        // permits peers in the same profile to signal the daemon. Our teardown
        // (`kill_all_descendants`) runs unconfined, so signalling the confined
        // daemon is denied by the kernel and surfaces as `EACCES`; the daemon
        // then survives teardown until its PID namespace is torn down, stalling
        // the reaper and spamming the log.
        //
        // AppArmor matches the profile against the exec'd path, so a copy at any
        // other path does not match and runs *unconfined* — exactly like the
        // QEMU and dnsmasq processes we already spawn (in session mode libvirt's
        // AppArmor security driver does not confine QEMU, so dropping the
        // daemon's own confinement changes nothing for the guests). The copy is
        // therefore signalable and reaped normally at teardown.
        //
        // TODO: this is no longer necessary when we provide libvirtd as a bazel dependency.
        let libvirtd_bin = libvirt_dir.join("libvirtd");
        std::fs::copy(LIBVIRTD_BIN, &libvirtd_bin).with_context(|| {
            format!(
                "copying {LIBVIRTD_BIN} to {} to escape its path-attached AppArmor profile",
                libvirtd_bin.display()
            )
        })?;
        std::fs::set_permissions(&libvirtd_bin, std::fs::Permissions::from_mode(0o755))
            .with_context(|| format!("making {} executable", libvirtd_bin.display()))?;

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
        std::fs::write(qemu_conf_dir.join("qemu.conf"), "max_core = 0\n")
            .with_context(|| format!("writing {}", qemu_conf_dir.join("qemu.conf").display()))?;

        // The backend is fully unprivileged: libvirtd runs as the current user
        // in session mode and connects to a per-user QEMU driver. There is no
        // `sudo`, no system-wide bridge, and no `virtlogd` (domain serial and
        // console output is written directly to files). The few operations that
        // need elevated networking capabilities (creating the bridge and TAPs)
        // go through the narrow [`net_admin`] capability launcher instead.
        info!(logger, "Spawning libvirtd (session mode)"; "bin" => %libvirtd_bin.display(), "conf" => %conf_path.display(), "socket" => %socket_path.display());

        let child = Command::new(&libvirtd_bin)
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
            socket_path,
            libvirtd: Some(child),
            pid_path: Some(pid_path),
            connect,
            logger,
            extra_disks: Mutex::new(HashMap::new()),
            primary_disks: Mutex::new(HashMap::new()),
            vm_ipv6: Mutex::new(HashMap::new()),
            vm_specs: Mutex::new(HashMap::new()),
            vm_min_boot_image_size_gib: Mutex::new(HashMap::new()),
            vm_has_ipv4: Mutex::new(HashMap::new()),
            working_dir,
        })
    }

    /// Open a connection-only handle to an already-running libvirtd. Used by
    /// forked task subprocesses.
    ///
    /// The working dir (where VM disks live) is passed in (persisted in the
    /// `LocalBackendSocket` attribute by the spawning process) rather than
    /// derived from the socket path, because the socket lives at a short
    /// `/tmp` path (see `spawn`) and no longer sits under `working_dir`. It
    /// resolves to the SAME `<group_dir>/local_backend` directory the spawning
    /// process used, regardless of which env (`root_env`, `setup`,
    /// `tests/<name>`) this handle was constructed from. This keeps VM disks
    /// out of the env tree that gets recursively `cp -R`'d into every per-test
    /// directory.
    fn connect_only(socket_path: PathBuf, working_dir: PathBuf, logger: Logger) -> Result<Self> {
        let connect = open_connect(&socket_path, &logger)?;
        Ok(LocalBackend {
            socket_path,
            libvirtd: None,
            pid_path: None,
            connect,
            logger,
            extra_disks: Mutex::new(HashMap::new()),
            primary_disks: Mutex::new(HashMap::new()),
            vm_ipv6: Mutex::new(HashMap::new()),
            vm_specs: Mutex::new(HashMap::new()),
            vm_min_boot_image_size_gib: Mutex::new(HashMap::new()),
            vm_has_ipv4: Mutex::new(HashMap::new()),
            working_dir,
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
    /// [`create_group`](Self::create_group); it is the address on which the
    /// per-group file server listens and that node-download URLs point at.
    pub fn group_gateway_ipv6(group_name: &str) -> String {
        format!("{}1", Self::group_ipv6_prefix(group_name))
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
    /// Crucially the RA is sent with a **router lifetime of 0**
    /// (`--ra-param=<bridge>,10,0`): this advertises the on-link, autonomous
    /// prefix so guests perform SLAAC, but does **not** install `dnsmasq` as a
    /// default router. A default route is neither needed (the driver lives on
    /// the same `/64`, on-link) nor wanted (this `dnsmasq` does not forward, so
    /// a default route through it would black-hole all off-link traffic and the
    /// replica would never become reachable).
    pub fn create_group(&self, group_name: &str) -> Result<()> {
        let bridge = Self::bridge_name(group_name);
        let prefix = Self::group_ipv6_prefix(group_name);
        // The gateway address (`<prefix>1`) lives on the bridge.
        let gateway = format!("{prefix}1");
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
        let create_script = format!(
            "ip link del {bridge} 2>/dev/null; \
             ip link add name {bridge} type bridge && \
             ip link set dev {bridge} up && \
             ip -6 addr add {gateway}/64 dev {bridge} nodad && \
             ip addr add {ipv4_gateway}/24 dev {bridge}"
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
        self.working_dir
            .join("dnsmasq")
            .join(format!("{bridge}.pid"))
    }

    /// Spawn a minimal `dnsmasq` as an IPv6 Router Advertisement daemon on
    /// `bridge`, advertising the group's `/64` for SLAAC with a router lifetime
    /// of 0 (so it is not selected as a default router). The same daemon also
    /// serves DHCPv4 on the group's IPv4 `/24` (`ipv4_prefix`) so VMs that
    /// requested a second NIC obtain an IPv4 address. See
    /// [`create_group`](Self::create_group) for the rationale.
    fn start_ra_daemon(
        &self,
        group_name: &str,
        bridge: &str,
        prefix: &str,
        ipv4_prefix: &str,
    ) -> Result<()> {
        let dnsmasq_dir = self.working_dir.join("dnsmasq");
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
        // capability launcher. `--ra-param=<bridge>,,0` sets the router lifetime
        // to 0; `--dhcp-range=<prefix>,ra-only` advertises the on-link,
        // autonomous prefix for SLAAC without handing out stateful leases.
        // A second `--dhcp-range=<ipv4_prefix>.2,<ipv4_prefix>.254,...` enables
        // stateful DHCPv4 on the group's IPv4 `/24` (the `.1` gateway lives on
        // the bridge), which is what gives a VM's second NIC (the guest's
        // `enp2s0`) an IPv4 address. `--port=0` disables the DNS service
        // entirely. `dnsmasq` daemonizes (writing its pid-file) and is later
        // signalled via that pid-file in teardown.
        let user = current_username();
        let dnsmasq_script = format!(
            "exec {DNSMASQ_BIN} \
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
                 --ra-param={bridge},10,0",
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

    /// Tear down all domains in `group_name` and remove the bridge and any
    /// TAPs attached to it.
    pub fn delete_group(&self, group_name: &str) -> Result<()> {
        let bridge = Self::bridge_name(group_name);
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
        let key = vm_name.to_string();
        self.primary_disks
            .lock()
            .unwrap()
            .insert(key.clone(), primary_image);
        self.vm_ipv6.lock().unwrap().insert(key.clone(), ipv6);
        let spec = VmSpec {
            v_cpus: vcpus,
            memory_ki_b: memory_kib,
        };
        self.vm_specs
            .lock()
            .unwrap()
            .insert(key.clone(), spec.clone());
        self.vm_has_ipv4
            .lock()
            .unwrap()
            .insert(key.clone(), has_ipv4);
        if let Some(min_gib) = boot_image_minimal_size_gibibytes {
            self.vm_min_boot_image_size_gib
                .lock()
                .unwrap()
                .insert(key, min_gib);
        }

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
        self.extra_disks
            .lock()
            .unwrap()
            .insert(vm_name.to_string(), paths);
        Ok(())
    }

    /// Build the libvirt domain XML for `vm_name` and start it.
    pub fn start_vm(&self, group_name: &str, vm_name: &str) -> Result<()> {
        let key = vm_name.to_string();
        let primary_image = self
            .primary_disks
            .lock()
            .unwrap()
            .get(&key)
            .cloned()
            .ok_or_else(|| anyhow!("start_vm: no primary image registered for {vm_name}"))?;
        let spec = self
            .vm_specs
            .lock()
            .unwrap()
            .get(&key)
            .cloned()
            .ok_or_else(|| anyhow!("start_vm: no spec registered for {vm_name}"))?;
        let min_gib = self
            .vm_min_boot_image_size_gib
            .lock()
            .unwrap()
            .get(&key)
            .copied();

        let vm_dir = self.vm_dir(vm_name);
        std::fs::create_dir_all(&vm_dir)?;
        let primary_disk = vm_dir.join("primary.img");
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
                .with_context(|| format!("truncating {} to {min_gib}G", primary_disk.display()))?;
        }

        let extra = self
            .extra_disks
            .lock()
            .unwrap()
            .get(&key)
            .cloned()
            .unwrap_or_default();

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
        let has_ipv4 = self
            .vm_has_ipv4
            .lock()
            .unwrap()
            .get(&key)
            .copied()
            .unwrap_or(false);
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
        self.working_dir
            .join("vms")
            .join(sanitize_libvirt_name(vm_name))
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
