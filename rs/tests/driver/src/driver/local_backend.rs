//! Local (QEMU) system-test backend.
//!
//! Counterpart to [`crate::driver::farm::Farm`] for tests run on a developer or
//! CI host instead of the Farm cluster. Selected via `SYSTEM_TEST_INFRA=local`.
//!
//! Boots each VM as a per-VM daemonized `qemu-system-x86_64` process, controlled
//! afterwards through its pid-file (destroy) and a per-VM QMP unix socket
//! (reboot). Networking (per-group Linux bridge + per-VM TAPs, `dnsmasq`
//! RA/DHCPv4/DNS) and disk images (qcow2 overlays over a shared base) are
//! managed directly by this backend.
//!
//! Many Farm features have no local equivalent (managed playnet DNS, TLS
//! issuance, HTTP file upload, multi-tenant scheduling); those operations warn
//! and return dummy values or `bail!`.
//!
//! The driver also gives itself a private view of two `/etc` files, in the mount
//! namespace [`LocalBackend::ensure_administrable_netns`] creates: a
//! `resolv.conf` naming the group's own `dnsmasq`, and a CA bundle that also
//! trusts the dev root CA. Together they are what let a driver-side client reach
//! the group's IC gateway by name over verified HTTPS, exactly as it would on
//! Farm, with no per-client configuration.
//!
//! In the QEMU command line built by [`LocalBackend::start_vm`], each virtio/PCIe
//! device sits behind its own `pcie-root-port` so the guest's predictable
//! interface names stay deterministic (primary NIC -> `enp1s0`, IPv4 NIC ->
//! `enp2s0`).

use crate::driver::dev_root_ca::dev_root_ca_cert_pem;
use crate::driver::farm::{VMCreateResponse, VmSpec};
use crate::driver::resource::DiskImage;
use crate::driver::test_env::{TestEnv, TestEnvAttribute};
use crate::driver::test_env_api::get_dependency_path_from_env;
use anyhow::{Context, Result, anyhow, bail};
use deterministic_ips::MacAddr6Ext;
use macaddr::MacAddr6;
use network::systemd::IPV6_NAME_SERVERS;
use serde::{Deserialize, Serialize};
use slog::{Logger, info, warn};
use std::collections::HashMap;
use std::ffi::{CString, OsString};
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv6Addr};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The domain under which the group's `dnsmasq` synthesises a DNS name for every
/// address in the group's `/64`, by writing the address with `:` replaced by `-`
/// (e.g. `2a00-fb01-400-2c--3.ipv6.nip.io`).
///
/// This mirrors the public `nip.io` wildcard DNS service, which is what system
/// tests use when they need to reach a VM by a *name* rather than by an address
/// literal — see `rs/tests/networking/canister_http_socks_test.rs`. Answering
/// for it locally is what makes those tests work without external DNS; on the
/// Farm backend the real service resolves the same names to the same addresses.
const NIP_IO_DOMAIN: &str = "ipv6.nip.io";

/// The domain suffix under which the group's `dnsmasq` answers for names the
/// driver registers explicitly with [`LocalBackend::add_dns_record`] or
/// [`LocalBackend::add_wildcard_dns_record`], as opposed to the addresses it
/// synthesises under [`NIP_IO_DOMAIN`].
///
/// Resolvable from inside a test group, and from the driver, which shares the
/// group's resolver (see [`LocalBackend::install_group_resolv_conf`]). Used for
/// the API boundary nodes (`apibn-{idx}.ic.net`, see
/// `InternetComputer::setup_api_bn_local_playnet`) and for the IC gateway
/// (`<vm name>.ic.net`, see `IcGatewayVm::load_or_create_local_playnet`). On Farm
/// those names are handed out without DNS records, or replaced by a playnet
/// FQDN.
///
/// It must not be a `.local` name: both GuestOS and HostOS resolve through
/// `systemd-resolved`, which routes `*.local` to mDNS and never to the unicast
/// `DNS=` servers the group's `dnsmasq` answers on.
pub const IN_GROUP_DOMAIN_SUFFIX: &str = "ic.net";

/// How long [`LocalBackend::stop_dnsmasq`] waits for `dnsmasq` to exit, applied
/// once after `SIGTERM` and again after the `SIGKILL` that follows if the first
/// wait runs out. It normally exits within milliseconds; this only bounds the
/// wait if it wedges. Outlasting the second wait means `SIGKILL` did not take
/// effect, which no further signal is going to fix.
const DNSMASQ_STOP_TIMEOUT: Duration = Duration::from_secs(5);

/// How often [`LocalBackend::await_dnsmasq_exit`] re-checks whether `dnsmasq` is
/// gone. Short enough that a restart is not noticeably delayed by the poll.
const DNSMASQ_STOP_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Where the driver's own TLS clients read their root certificates from when the
/// environment does not say otherwise; see
/// [`system_ca_bundle`](LocalBackend::system_ca_bundle).
///
/// This exact path is load-bearing, through a chain worth spelling out because
/// nothing type-checks it: `reqwest::ClientBuilder::build` constructs a
/// `rustls_platform_verifier::Verifier`, whose Unix implementation calls
/// `rustls_native_certs::load_native_certs`, which — with neither `SSL_CERT_FILE`
/// nor `SSL_CERT_DIR` set — defers to `openssl_probe::probe()`, and this is the
/// first candidate in its Linux list. `rs/tests/BUILD.bazel` builds a bundle at the
/// same path for the colocated driver image, for the same reason.
///
/// Being *first* in that list is what makes hard-coding it safe rather than merely
/// convenient: if this file exists, it is the one `probe()` returns, so the mount
/// cannot end up on a bundle the verifier ignores. The remaining exposure is a
/// platform that does not have it at all (RHEL keeps its bundle under
/// `/etc/pki/...`), where this fails loudly on the read rather than silently — and
/// `SSL_CERT_FILE` is the supported way out, since
/// [`system_ca_bundle`](LocalBackend::system_ca_bundle) honours it.
const DEFAULT_SYSTEM_CA_BUNDLE: &str = "/etc/ssl/certs/ca-certificates.crt";

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
    ///
    /// Only for scripts whose every word is a literal or backend-derived
    /// (interface and bridge names, addresses of the group's own prefixes). Any
    /// command taking a value a *test* supplies — a VM name, a domain — belongs
    /// in [`run_command`](Self::run_command) instead, which never lets a shell
    /// see it.
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

    /// Run `command` to completion, returning an error if it cannot be spawned or
    /// exits non-zero (`what` describes the operation, for error context).
    ///
    /// The argv-passing counterpart of [`run_shell`](Self::run_shell), and the one
    /// to prefer: the arguments reach the kernel as a vector, so no word-splitting,
    /// globbing or metacharacter interpretation stands between what the caller
    /// wrote and what the program receives, and paths need no quoting.
    fn run_command(command: &mut Command, what: &str) -> Result<()> {
        let output = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .with_context(|| format!("spawning the command for {what}"))?;
        if !output.status.success() {
            bail!(
                "operation '{what}' failed with status {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(())
    }

    /// The single argument `<option><path>`, e.g. `--pid-file=/run/x.pid`.
    ///
    /// Built as an [`OsString`] rather than through `Path::display`, which is
    /// lossy: a path that is not valid UTF-8 reaches the program unchanged instead
    /// of with U+FFFD substituted into it.
    fn path_arg(option: &str, path: &Path) -> OsString {
        let mut arg = OsString::from(option);
        arg.push(path);
        arg
    }

    /// Put the driver into a network namespace it fully owns and arrange for its
    /// `ip`/`dnsmasq` operations to run with `CAP_NET_ADMIN`/`CAP_NET_RAW`/
    /// `CAP_NET_BIND_SERVICE` over that namespace — without any *host* capability
    ///
    /// It also installs the per-group `/etc` overrides that make that namespace
    /// usable from the driver's own code — a resolver
    /// ([`install_group_resolv_conf`](Self::install_group_resolv_conf)) and a trust
    /// store ([`install_dev_root_ca`](Self::install_dev_root_ca)) — so the name is
    /// narrower than what the function does.
    ///
    /// `unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWNET)` creates a private
    /// user namespace, in which the caller holds a full capability set (it is the
    /// namespace's creator), plus a mount and a network namespace owned by it — so
    /// every RTNETLINK operation on the new netns succeeds, and the driver can
    /// give itself a resolver for that netns (see
    /// [`install_group_resolv_conf`](Self::install_group_resolv_conf)) without
    /// touching anything outside its own process tree.
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
    /// `dnsmasq` — into the same namespaces (so they resolve names through the
    /// group's `dnsmasq` as well) and lets them inherit the ambient capabilities
    /// (`unshare`/`fork`/`exec` all preserve both).
    pub fn ensure_administrable_netns() -> Result<()> {
        let uid = nix::unistd::geteuid().as_raw();
        let gid = nix::unistd::getegid().as_raw();
        // SAFETY: `unshare` only affects the calling (single) thread/process; it
        // touches no user-space state. The kernel creates the user namespace
        // first, so the mount and network namespaces are both owned by it and the
        // caller holds `CAP_SYS_ADMIN`/`CAP_NET_ADMIN` over them.
        if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS | libc::CLONE_NEWNET) }
            != 0
        {
            return Err(anyhow!(std::io::Error::last_os_error())).context(
                "unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWNET) failed; the local \
                 backend needs to create a private user+mount+network namespace to \
                 administer its networking without host capabilities",
            );
        }
        // Map the caller's uid/gid into the new user namespace so it keeps its
        // usual identity (files, `/dev/kvm` and `/dev/net/tun` are opened exactly
        // as before) while being the namespace owner. The mapping is an identity
        // one, with a single exception: if the caller is (fake-)root we map it to
        // a *non-zero* inner uid/gid instead of `0`.
        //
        // The reason: the backend relies on `dnsmasq` staying unprivileged so it
        // skips its privilege-drop path (see `start_dnsmasq`). That path is
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
        // Detach the mount namespace's propagation before mounting anything into
        // it, so neither install below can escape. A host that leaves `/` shared —
        // the systemd default — would otherwise have the real files replaced for as
        // long as the mount lived. Done here rather than inside either installer so
        // that neither depends on the other having run first.
        Self::mount(
            None,
            Path::new("/"),
            libc::MS_REC | libc::MS_PRIVATE,
            "making / private in the owned mount namespace",
        )?;
        // Finally the two per-group `/etc` overrides, which are what make the
        // driver resolve and trust the group's own services.
        Self::install_group_resolv_conf()?;
        Self::install_dev_root_ca()?;
        Ok(())
    }

    /// Path of the generated `resolv.conf`
    /// [`install_group_resolv_conf`](Self::install_group_resolv_conf) bind-mounts
    /// over `/etc/resolv.conf`.
    ///
    /// It lives in the process's temp dir — under Bazel that is the test's own
    /// scratch dir, which the runner cleans up — because it is written before the
    /// group dir exists; see
    /// [`ensure_administrable_netns`](Self::ensure_administrable_netns) for why
    /// that has to run so early. The pid keeps concurrent drivers from sharing a
    /// file, even though each one mounts it only in its own namespace.
    fn generated_resolv_conf_path() -> PathBuf {
        std::env::temp_dir().join(format!("system-test-resolv.conf.{}", std::process::id()))
    }

    /// Point the driver's own name resolution at the group's `dnsmasq`, by
    /// bind-mounting a generated `resolv.conf` naming [`IPV6_NAME_SERVERS`] over
    /// `/etc/resolv.conf` in the private mount namespace
    /// [`ensure_administrable_netns`](Self::ensure_administrable_netns) just
    /// created.
    ///
    /// Without this the driver has no resolver at all: it sits in the group's
    /// network namespace but reads the *host's* `/etc/resolv.conf`, whose
    /// nameserver is unreachable from there, so every lookup fails. The group's
    /// `dnsmasq` binds those very [`IPV6_NAME_SERVERS`] on the group bridge inside
    /// this netns (see [`create_group`](Self::create_group)), so pointing at them
    /// makes the driver resolve the in-group names ([`IN_GROUP_DOMAIN_SUFFIX`],
    /// [`NIP_IO_DOMAIN`]) exactly like the VMs do — which is what lets a
    /// driver-side client reach the IC gateway by name rather than having to
    /// resolve the host for itself.
    ///
    /// Four details worth knowing:
    ///
    /// * `mount(2)` needs `CAP_SYS_ADMIN` over the mount namespace's *user*
    ///   namespace, which the caller holds as that namespace's creator. Mounting
    ///   here, in-process, is what keeps `CAP_SYS_ADMIN` out of the ambient set
    ///   the unprivileged children inherit — they have no business mounting
    ///   anything.
    /// * glibc reads at most `MAXNS` (3) nameservers, so the fourth line is
    ///   ignored. Harmless, since all four addresses are the same `dnsmasq`;
    ///   writing all four keeps the file identical to what the guests are
    ///   configured with.
    /// * `/etc/nsswitch.conf` resolves `hosts` through `files` before `dns`, so
    ///   `/etc/hosts` — and with it `localhost` — keeps working.
    /// * Until [`create_group`](Self::create_group) has run, no bridge holds these
    ///   addresses, so a lookup before that fails fast instead of hanging.
    ///   Nothing resolves a name that early.
    fn install_group_resolv_conf() -> Result<()> {
        let contents: String = IPV6_NAME_SERVERS
            .iter()
            .map(|name_server| format!("nameserver {name_server}\n"))
            .collect();
        let path = Self::generated_resolv_conf_path();
        std::fs::write(&path, contents)
            .with_context(|| format!("writing the generated resolv.conf {}", path.display()))?;

        Self::mount(
            Some(&path),
            Path::new("/etc/resolv.conf"),
            libc::MS_BIND,
            "bind-mounting the generated resolv.conf over /etc/resolv.conf",
        )
    }

    /// Path of the generated CA bundle
    /// [`install_dev_root_ca`](Self::install_dev_root_ca) bind-mounts over the
    /// system one ([`system_ca_bundle`](Self::system_ca_bundle)). Same placement,
    /// and for the same reasons, as
    /// [`generated_resolv_conf_path`](Self::generated_resolv_conf_path).
    fn generated_ca_bundle_path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "system-test-ca-certificates.crt.{}",
            std::process::id()
        ))
    }

    /// The CA bundle `rustls-native-certs` will actually read, which is the file
    /// [`install_dev_root_ca`](Self::install_dev_root_ca) has to append to.
    ///
    /// Mirrors `rustls_native_certs::load_native_certs`: `SSL_CERT_FILE` names the
    /// bundle whenever it is set, and `openssl_probe`'s first Linux candidate
    /// ([`DEFAULT_SYSTEM_CA_BUNDLE`]) is used otherwise.
    ///
    /// Honouring that variable is not politeness. CI runners set it — Namespace points
    /// it at its own worker bundle — and an earlier version of this code *refused to
    /// run* when it was set, which passed locally and failed every `_local` target
    /// there. Appending to whichever bundle the environment designates works in both
    /// places, and keeps whatever roots that bundle carries.
    ///
    /// `SSL_CERT_DIR` set *without* `SSL_CERT_FILE` is the one shape this cannot
    /// serve: `rustls-native-certs` then reads only those directories and no bundle at
    /// all, so there is no file to append to — and a new file cannot be added to a
    /// directory the driver does not own, for the reasons in
    /// [`install_dev_root_ca`](Self::install_dev_root_ca). Nothing sets it that way
    /// today; if something starts to, this fails loudly rather than quietly leaving
    /// the CA out.
    fn system_ca_bundle() -> Result<PathBuf> {
        if let Some(file) = std::env::var_os("SSL_CERT_FILE") {
            return Ok(PathBuf::from(file));
        }
        if let Some(dirs) = std::env::var_os("SSL_CERT_DIR") {
            bail!(
                "SSL_CERT_DIR is set ({dirs:?}) without SSL_CERT_FILE, so the driver's \
                 TLS clients would read only those directories and never a CA bundle, \
                 leaving nowhere to install the dev root CA"
            );
        }
        Ok(PathBuf::from(DEFAULT_SYSTEM_CA_BUNDLE))
    }

    /// Put the dev root CA in the driver's own trust store, by bind-mounting a copy
    /// of the system CA bundle ([`system_ca_bundle`](Self::system_ca_bundle)) with
    /// that CA appended over the original.
    ///
    /// This is what lets a driver-side client verify the local IC gateway's
    /// certificate without any code of its own: the CA is simply one of the roots
    /// every TLS client in the process tree already loads. The guests arrive at the
    /// same place by a different route — `update-ca-certificates` in the `output_dev`
    /// stage of the IC-OS Dockerfiles, see [`dev_root_ca_cert_pem`] — so the driver
    /// and the nodes end up trusting the gateway on the same terms.
    ///
    /// A bind mount over an *existing* entry is the only option, which is worth
    /// spelling out because two simpler-looking routes are dead ends. Adding a new
    /// file beside the bundle fails on `mount(2)`, which will not create a directory
    /// entry: the target has to exist already, and the driver cannot create one —
    /// `/etc/ssl/certs` belongs to root, root is not mapped into the driver's user
    /// namespace, and so the `CAP_DAC_OVERRIDE` it holds there does not apply to it.
    /// Writing the file for real, the way `update-ca-certificates` does, escapes the
    /// namespace altogether: it isolates the mount *table*, not file contents.
    ///
    /// Shadowing the bundle rather than the whole directory is then the better of
    /// what is left: the bundle is what `rustls-native-certs` reads for the driver's
    /// own clients, and what OpenSSL and `curl` read by default on Debian, whose
    /// default `CAfile` is this same path. It also avoids reproducing the
    /// directory's ~240 entries.
    ///
    /// The limitation that leaves, since it is easy to assume otherwise: a consumer
    /// using `CApath` *alone* resolves `<subject hash>.0` symlinks and never scans
    /// the bundle, so it does not see this CA. Nothing in the driver's process tree
    /// works that way today — and a plainly named file in the directory would not
    /// have helped it either, since only a hash-named symlink would, which is what
    /// `update-ca-certificates` generates and what this cannot create.
    ///
    /// Appending, never replacing: the original bytes are copied verbatim first, so
    /// this can only widen the driver's trust, never narrow it. That matters,
    /// because the driver has clients that need the public roots
    /// ([`Farm::new`](crate::driver::farm::Farm::new) and the log-upload client in
    /// `group.rs`), and because `dfx` and every other child inherits this mount too.
    ///
    /// What is being trusted deserves saying plainly: a CA whose private key is
    /// checked into a public repository, valid until 2122, becomes trusted by every
    /// TLS client in the driver's process tree. That is acceptable only because the
    /// tree lives in a network namespace with no route off the host (see
    /// [`ensure_administrable_netns`](Self::ensure_administrable_netns)), so the only
    /// servers it can reach are the group's own VMs. Giving the local backend
    /// outbound connectivity would invalidate that reasoning, not just this comment.
    ///
    /// This covers the gateway only. Clients that dial an API boundary node directly
    /// still need `danger_accept_invalid_certs`, for an unrelated reason:
    /// `IcNodeSnapshot::get_public_url` hands them an IP-literal URL, which no name
    /// in the node's certificate can match. (Whether that certificate has a CA at
    /// all depends on the test — under `with_api_boundary_nodes_playnet` it is issued
    /// by `LocalApiBoundaryNodesPlaynet`'s ephemeral CA, and otherwise the node
    /// self-signs it via `generate_ic_boundary_tls_cert`.)
    fn install_dev_root_ca() -> Result<()> {
        let bundle_path = Self::system_ca_bundle()?;
        let bundle_path_display = bundle_path.display();
        let mut bundle = std::fs::read_to_string(&bundle_path).with_context(|| {
            format!(
                "reading the system CA bundle {bundle_path_display} (a platform that keeps \
                 its bundle elsewhere can point SSL_CERT_FILE at it)"
            )
        })?;
        let dev_root_ca_pem = dev_root_ca_cert_pem()?;
        // Guard the separator rather than trusting the bundle to end in a newline:
        // `-----END CERTIFICATE----------BEGIN CERTIFICATE-----` parses as neither,
        // and a PEM that fails to parse is reported by `rustls-platform-verifier`
        // through `log::warn!` — for which the driver installs no implementation, so
        // it would go nowhere.
        if !bundle.ends_with('\n') {
            bundle.push('\n');
        }
        bundle.push_str(&dev_root_ca_pem);

        let path = Self::generated_ca_bundle_path();
        std::fs::write(&path, &bundle)
            .with_context(|| format!("writing the generated CA bundle {}", path.display()))?;
        // `write` honours the umask, and this shadows a world-readable file that
        // every child in the tree reads.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .with_context(|| format!("making {} world-readable", path.display()))?;

        Self::mount(
            Some(&path),
            &bundle_path,
            libc::MS_BIND,
            "bind-mounting the generated CA bundle over the system one",
        )?;

        // Read it back. Every step above can succeed while leaving the CA
        // unreachable — a mount that did not take, a short write, a stale target —
        // and none of that surfaces until a TLS handshake fails, six minutes into a
        // test, in a retry loop. One extra read turns that into an error here.
        let installed = std::fs::read_to_string(&bundle_path)
            .with_context(|| format!("reading back {bundle_path_display}"))?;
        if !installed.contains(&dev_root_ca_pem) {
            bail!(
                "the dev root CA is missing from {bundle_path_display} after mounting {} \
                 over it",
                path.display()
            );
        }
        Ok(())
    }

    /// `mount(2)`, which the `nix` crate cannot offer here because the workspace
    /// builds it without its `mount` feature.
    ///
    /// `source` is `None` for a propagation change, which takes none; the
    /// filesystem type and the mount data are always `NULL`, because every call
    /// site is either a bind mount or a propagation change and neither uses them.
    fn mount(source: Option<&Path>, target: &Path, flags: libc::c_ulong, what: &str) -> Result<()> {
        let source = source
            .map(|source| CString::new(source.as_os_str().as_bytes()))
            .transpose()
            .with_context(|| format!("{what}: the source path contains a NUL byte"))?;
        let target =
            CString::new(target.as_os_str().as_bytes()).expect("mount target contains a NUL byte");
        // SAFETY: both strings are NUL-terminated and outlive the call. A NULL
        // source is what `mount(2)` expects for a propagation change (the kernel
        // never looks at it), and a NULL filesystem type and data are what it
        // expects for a bind mount.
        let rc = unsafe {
            libc::mount(
                source.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
                target.as_ptr(),
                std::ptr::null(),
                flags,
                std::ptr::null(),
            )
        };
        if rc != 0 {
            return Err(anyhow!(std::io::Error::last_os_error())).context(format!(
                "{what} failed (mount(2) follows the target symlink, so a target that \
                 dangles is reported as a missing file rather than as a bad source)"
            ));
        }
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

    /// Returns the `/64` the group's *nodes* are addressed out of, i.e. subnet-id
    /// 0 of [`group_subnet_prefix`](Self::group_subnet_prefix).
    fn group_ipv6_prefix(group_name: &str) -> String {
        Self::group_subnet_prefix(group_name, 0)
    }

    /// Returns `2a00:fb01:400:<group><subnet>::`, the group's `/64` for
    /// `subnet_id` (0 for the nodes, 1..=3 for the driver's own addresses).
    ///
    /// The range is deliberately an ordinary global unicast prefix rather than a
    /// reserved one. It must not be a ULA or link-local address, because the
    /// orchestrator reads those as a sign that it is running in a cloud and
    /// blocks on cloud metadata discovery before it can register itself
    /// (`assemble_add_node_message` in `rs/orchestrator/src/registration.rs`),
    /// which never completes here. But reserved ranges are no good either: they
    /// are exactly the ones software special-cases. `2001:db8::/32` (RFC 3849)
    /// looks appealing for a fake network and breaks `bitcoind`, whose
    /// `CNetAddr::IsValid()` rejects documentation addresses outright, so every
    /// RPC from the driver is refused with "Client network is not allowed RPC
    /// access" even under `-rpcallowip='::/0'`. A boring routable-looking prefix
    /// has no such classifier to trip over. Nothing leaves the group's network
    /// namespace, so real-world routability is irrelevant — only how software
    /// *classifies* the bits.
    ///
    /// [`GROUP_PREFIX`](Self::GROUP_PREFIX) is a `/56`, which leaves one byte
    /// before the `/64` boundary: 6 bits of group digest and 2 bits of
    /// subnet-id. The digest is therefore much shorter than the bridge's and
    /// TAP's (see [`bridge_name`](Self::bridge_name)), but a collision between
    /// two groups is unobservable: each test owns a private network namespace
    /// (see [`ensure_administrable_netns`](Self::ensure_administrable_netns)).
    fn group_subnet_prefix(group_name: &str, subnet_id: u8) -> String {
        use ic_crypto_sha2::Sha256;
        debug_assert!(subnet_id < 4, "subnet-id must fit in 2 bits");
        let hash = Sha256::hash(group_name.as_bytes());
        format!("2a00:fb01:400:{:02x}::", (hash[0] & 0xfc) | subnet_id)
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
    /// exercised. `init_ic` whitelists it (see
    /// [`group_driver_ipv6_prefixes`](Self::group_driver_ipv6_prefixes)) so the
    /// driver can still reach the nodes once the firewall is active.
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
        format!("{}1", Self::group_subnet_prefix(group_name, 1))
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
        format!("{}1", Self::group_subnet_prefix(group_name, 2))
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
        format!("{}1", Self::group_subnet_prefix(group_name, 3))
    }

    /// The IPv6 range every address the local backend hands out lives in: the
    /// nodes' `/64`, the driver's own addresses and any other VM in the group.
    /// Offered to tests that have to whitelist the *whole* group on the nodes'
    /// firewall; see
    /// [`InternetComputer::with_group_wide_firewall_whitelist`](crate::driver::ic::InternetComputer::with_group_wide_firewall_whitelist).
    ///
    /// `2a00:fb01:400::/56` is DFINITY's Zurich DC prefix. The addresses never
    /// leave the group's network namespace, so nothing is actually routed there;
    /// it is used because an ordinary global unicast prefix is the one thing no
    /// classifier special-cases — see
    /// [`group_subnet_prefix`](Self::group_subnet_prefix).
    pub const GROUP_PREFIX: &'static str = "2a00:fb01:400::/56";

    /// The three addresses the test driver reaches the group's VMs from: the
    /// management source ([`group_mgmt_ipv6`](Self::group_mgmt_ipv6)), the
    /// journald-streaming source ([`group_logs_ipv6`](Self::group_logs_ipv6))
    /// and the file server's listen address
    /// ([`group_files_ipv6`](Self::group_files_ipv6)).
    ///
    /// Kept as one list so that the places which have to know the full set —
    /// assigning them to `lo` in [`create_group`](Self::create_group), removing
    /// them again in [`delete_group`](Self::delete_group), and whitelisting them
    /// on the nodes' firewall via
    /// [`group_driver_ipv6_prefixes`](Self::group_driver_ipv6_prefixes) — cannot
    /// drift apart when a fourth one is added.
    fn group_driver_ipv6s(group_name: &str) -> [String; 3] {
        [
            Self::group_mgmt_ipv6(group_name),
            Self::group_logs_ipv6(group_name),
            Self::group_files_ipv6(group_name),
        ]
    }

    /// [`group_driver_ipv6s`](Self::group_driver_ipv6s) as `/128` prefixes, for
    /// the firewall whitelist `init_ic` seeds into the initial registry (see
    /// `rs/tests/driver/src/driver/bootstrap.rs`).
    pub fn group_driver_ipv6_prefixes(group_name: &str) -> Vec<String> {
        Self::group_driver_ipv6s(group_name)
            .into_iter()
            .map(|addr| format!("{addr}/128"))
            .collect()
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
    /// lives on the bridge), so they need neither RA nor SLAAC. The group's
    /// `dnsmasq` still advertises the prefix on the bridge for non-IC-node VMs
    /// (e.g. universal VMs), which bring up only a link-local address and derive
    /// their global one via SLAAC from the RA; the RA's non-zero router lifetime
    /// also installs the bridge (the host) as their default router.
    ///
    /// Either way the host is each guest's default router, which lets a guest
    /// reply to the driver's off-`/64` management address
    /// ([`group_mgmt_ipv6`](Self::group_mgmt_ipv6)). No IP forwarding is
    /// involved — the management address is on `lo`, so traffic to it terminates
    /// on the host.
    ///
    /// The bridge additionally carries the name-server addresses GuestOS is
    /// hard-coded to query ([`IPV6_NAME_SERVERS`]), so that the group's
    /// `dnsmasq` can answer DNS on them; see
    /// [`start_dnsmasq`](Self::start_dnsmasq).
    pub fn create_group(&self, group_name: &str) -> Result<()> {
        let bridge = Self::bridge_name(group_name);
        let prefix = Self::group_ipv6_prefix(group_name);
        // The gateway address (`<prefix>1`) lives on the bridge.
        let gateway = Self::group_gateway_ipv6(group_name);
        // Driver addresses, all assigned to `lo`: the management source for
        // host→node traffic, the dedicated journald-streaming source, and the
        // file server's listen address. See `group_driver_ipv6s`.
        let [mgmt, logs, files] = Self::group_driver_ipv6s(group_name);
        // The IPv4 gateway (`<ipv4_prefix>.1`) also lives on the bridge so
        // `dnsmasq` can serve DHCPv4 to VMs that requested a second NIC.
        let ipv4_prefix = Self::group_ipv4_prefix(group_name);
        let ipv4_gateway = format!("{ipv4_prefix}.1");
        info!(
            self.logger,
            "Creating local bridge {bridge} for group {group_name} ({prefix}/64, {ipv4_prefix}.0/24)"
        );

        // The name-server addresses GuestOS sends its DNS queries to. They are
        // globally routable addresses owned by Cloudflare and Google, but the
        // backend runs in its own network namespace with no external
        // connectivity (see `ensure_administrable_netns`), so nothing else can
        // claim them and no query can escape. Assigning them here — rather than
        // reconfiguring the guests, which have no name-server knob and boot with
        // `IPv6AcceptRA=no` — is what gives every node a working resolver
        // without touching IC-OS.
        let name_server_addrs: String = IPV6_NAME_SERVERS
            .iter()
            .map(|name_server| format!("ip -6 addr add {name_server}/128 dev {bridge} nodad && "))
            .collect();

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
             {name_server_addrs}\
             ip -6 addr replace {mgmt}/128 dev lo && \
             ip -6 addr replace {logs}/128 dev lo && \
             ip -6 addr replace {files}/128 dev lo && \
             ip -6 route replace {prefix}/64 dev {bridge} proto kernel metric 256 src {mgmt}"
        );
        Self::run_shell(&create_script, "create group bridge")?;

        // Truncate the two files the group's DNS records live in, both to drop
        // records an interrupted run left behind and so they exist before
        // `dnsmasq` starts. They deliberately survive a `dnsmasq` *restart* (see
        // `add_wildcard_dns_record`), which is why this happens here rather than
        // in `start_dnsmasq`.
        self.reset_dns_records(&bridge)?;

        // Start `dnsmasq`. Non-IC-node VMs (e.g. universal VMs) SLAAC their
        // global address from its RA; IC GuestOS nodes use a static config instead.
        // The same `dnsmasq` also serves DHCPv4 on the group's IPv4 `/24` for
        // VMs that requested a second NIC, and DNS on the name-server addresses
        // assigned above.
        self.start_dnsmasq(group_name, &bridge, &prefix, &ipv4_prefix)?;

        Ok(())
    }

    /// Path of the pid-file for the group's `dnsmasq`.
    fn dnsmasq_pid_path(&self, bridge: &str) -> PathBuf {
        self.active_local_backend
            .working_dir
            .join("dnsmasq")
            .join(format!("{bridge}.pid"))
    }

    /// Path of the extra hosts-file the group's `dnsmasq` serves DNS records
    /// from (`--addn-hosts`), written by
    /// [`add_dns_record`](Self::add_dns_record).
    fn dnsmasq_hosts_path(&self, bridge: &str) -> PathBuf {
        self.active_local_backend
            .working_dir
            .join("dnsmasq")
            .join(format!("{bridge}.hosts"))
    }

    /// Path of the file the group's *wildcard* DNS records are accumulated in by
    /// [`add_wildcard_dns_record`](Self::add_wildcard_dns_record), and turned into
    /// `--address` options by
    /// [`dnsmasq_wildcard_args`](Self::dnsmasq_wildcard_args).
    ///
    /// Deliberately shaped like the `--addn-hosts` file next to it — one
    /// `<address> <name>` pair per line — even though `dnsmasq` never reads it
    /// itself.
    fn dnsmasq_wildcards_path(&self, bridge: &str) -> PathBuf {
        self.active_local_backend
            .working_dir
            .join("dnsmasq")
            .join(format!("{bridge}.wildcards"))
    }

    /// Create the group's `dnsmasq` working dir and truncate both DNS record
    /// files, so they exist and are empty before `dnsmasq` first starts. Called
    /// from [`create_group`](Self::create_group); see the comment there for why
    /// not from [`start_dnsmasq`](Self::start_dnsmasq).
    fn reset_dns_records(&self, bridge: &str) -> Result<()> {
        let dnsmasq_dir = self.active_local_backend.working_dir.join("dnsmasq");
        std::fs::create_dir_all(&dnsmasq_dir).with_context(|| {
            format!("creating dnsmasq working dir at {}", dnsmasq_dir.display())
        })?;
        for path in [
            self.dnsmasq_hosts_path(bridge),
            self.dnsmasq_wildcards_path(bridge),
        ] {
            std::fs::write(&path, "").with_context(|| format!("truncating {}", path.display()))?;
        }
        Ok(())
    }

    /// The `--address=/<name>/<addr>` options for the wildcard records registered
    /// for `bridge` so far, read back from
    /// [`dnsmasq_wildcards_path`](Self::dnsmasq_wildcards_path).
    fn dnsmasq_wildcard_args(&self, bridge: &str) -> Result<Vec<String>> {
        let path = self.dnsmasq_wildcards_path(bridge);
        let contents = match std::fs::read_to_string(&path) {
            Ok(contents) => contents,
            // A group that never got as far as `reset_dns_records` has no
            // wildcards to serve.
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(err) => return Err(err).with_context(|| format!("reading {}", path.display())),
        };
        contents
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                let (addr, name) =
                    line.trim().split_once(char::is_whitespace).ok_or_else(|| {
                        anyhow!("malformed wildcard record {line:?} in {}", path.display())
                    })?;
                Ok(format!("--address=/{}/{addr}", name.trim()))
            })
            .collect()
    }

    /// Spawn a minimal `dnsmasq` on `bridge` serving three roles:
    ///
    /// * an IPv6 Router Advertisement daemon advertising the group's `/64` for
    ///   SLAAC with a non-zero router lifetime (installing the host as the
    ///   default router for VMs that use the RA; IC GuestOS nodes use a static
    ///   config instead),
    /// * a DHCPv4 server on the group's IPv4 `/24` for VMs with a second NIC,
    /// * the group's DNS server, answering on the name-server addresses
    ///   [`create_group`](Self::create_group) put on the bridge.
    ///
    /// See [`create_group`](Self::create_group) for the rationale.
    fn start_dnsmasq(
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
        let hosts_path = self.dnsmasq_hosts_path(bridge);
        let lease_path = dnsmasq_dir.join(format!("{bridge}.leases"));
        let log_path = dnsmasq_dir.join(format!("{bridge}.log"));
        // Remove a stale pid-file from a previous interrupted run.
        let _ = std::fs::remove_file(&pid_path);
        // The wildcard records registered so far. Unlike the `--addn-hosts` file,
        // these are *command-line* options, which is why registering one has to
        // restart `dnsmasq`; see `add_wildcard_dns_record`. Empty on the first
        // start, since `create_group` truncates the file it reads.
        let wildcard_args = self.dnsmasq_wildcard_args(bridge)?;

        info!(
            self.logger,
            "Starting dnsmasq for group {group_name} on bridge {bridge}"
        );

        // `dnsmasq` needs `CAP_NET_RAW`/`CAP_NET_ADMIN` to open the ICMPv6 raw
        // socket and send RAs, and `CAP_NET_BIND_SERVICE` to bind UDP port 67 for
        // DHCPv4 and port 53 for DNS; it inherits them from the ambient
        // capability set the driver set up (see `ensure_administrable_netns`).
        // `--ra-param=<bridge>,10,1800` sends an RA every 10s with a 1800s router
        // lifetime; `--dhcp-range=<prefix>,ra-only` advertises the autonomous
        // prefix for SLAAC without stateful leases. The second `--dhcp-range`
        // enables stateful DHCPv4 on the IPv4 `/24` for the guest's second NIC
        // (`enp2s0`). `dnsmasq` daemonizes (writing its pid-file) and is
        // signalled via it in teardown.
        //
        // DNS: `--no-resolv --no-hosts` keeps the resolver hermetic — it reads
        // neither `/etc/resolv.conf` nor `/etc/hosts`. Both matter: with no
        // upstream server left to forward to, anything it cannot answer is REFUSED
        // rather than leaked — and `/etc/resolv.conf` in this mount namespace is
        // the generated file naming *these very addresses*
        // (`install_group_resolv_conf`), so reading it would make `dnsmasq` forward
        // to itself. It answers from three sources:
        //
        // * `--addn-hosts` — records tests register through
        //   [`add_dns_record`](Self::add_dns_record).
        // * `--address` — the wildcard records tests register through
        //   [`add_wildcard_dns_record`](Self::add_wildcard_dns_record), each
        //   answering for a name *and every subdomain of it*.
        // * `--synth-domain` — synthesises `<address>.ipv6.nip.io` for the
        //   group's `/64`, with `:` written as `-`, mirroring the public
        //   `nip.io` wildcard service that tests use to name a VM by its
        //   address. `dnsmasq` parses the label with `inet_pton`, so it accepts
        //   exactly the form Rust's `Ipv6Addr` Display produces.
        //
        // `--bind-interfaces` binds the bridge's addresses as they are at
        // startup, which is why `create_group` assigns the name-server addresses
        // before calling this.
        //
        // `dnsmasq` runs unprivileged: `ensure_administrable_netns` guarantees a
        // non-zero uid inside the driver's user namespace (identity-mapped, or
        // remapped away from `0` when the caller is fake-root), so `dnsmasq` skips
        // its privilege-drop path entirely, which is what we want. That path is
        // gated on `getuid() == 0` and would otherwise `setgroups(2)` — denied in
        // the driver's user namespace — and drop to a user/group id that is
        // unmapped there.
        //
        // `dnsmasq` is spawned directly rather than through a shell, so every
        // argument reaches it as one argv entry. That matters for the `--address`
        // options above all: their names originate in a test-supplied VM name
        // (`IcGatewayVm::new`), and a shell would word-split and metacharacter-expand
        // them on the way. It also drops the quoting question for the paths, which
        // the working directory could otherwise raise by containing a space.
        let dnsmasq_path = get_dependency_path_from_env("ENV_DEPS__DNSMASQ_PATH");
        let mut dnsmasq = Command::new(&dnsmasq_path);
        dnsmasq
            .arg("--conf-file=/dev/null")
            .arg(Self::path_arg("--pid-file=", &pid_path))
            .arg(Self::path_arg("--dhcp-leasefile=", &lease_path))
            .arg(Self::path_arg("--log-facility=", &log_path))
            .arg("--bind-interfaces")
            .arg(format!("--interface={bridge}"))
            .arg("--except-interface=lo")
            .arg("--enable-ra")
            .arg(format!("--dhcp-range={prefix},ra-only"))
            .arg(format!(
                "--dhcp-range={ipv4_prefix}.2,{ipv4_prefix}.254,255.255.255.0,1h"
            ))
            .arg(format!("--ra-param={bridge},10,1800"))
            .arg("--no-resolv")
            .arg("--no-hosts")
            .arg(Self::path_arg("--addn-hosts=", &hosts_path))
            .arg(format!("--synth-domain={NIP_IO_DOMAIN},{prefix}/64"))
            .args(&wildcard_args);
        Self::run_command(&mut dnsmasq, "start dnsmasq")?;

        Ok(())
    }

    /// Reject a `name` that cannot be stored as a DNS record, before
    /// [`add_dns_record`](Self::add_dns_record) or
    /// [`add_wildcard_dns_record`](Self::add_wildcard_dns_record) persists it.
    ///
    /// Both record files are line-based — one `<address> <name>` pair per line —
    /// and [`dnsmasq_wildcard_args`](Self::dnsmasq_wildcard_args) splits a line
    /// back apart on whitespace. So a name containing a space would not fail to
    /// register, it would register a *different* record, and one containing a
    /// newline would register a second record nobody asked for. Names reach here
    /// from test-supplied VM names (`IcGatewayVm::new`) and API BN domains, which
    /// nothing upstream validates; failing here is the difference between a clear
    /// error at registration and an unresolvable name six minutes into a test.
    ///
    /// Accepted is a plain ASCII hostname: dot-separated non-empty labels of
    /// letters, digits, `-` and `_`, no label starting or ending with `-`, no
    /// label over 63 bytes and no name over 253 (RFC 1035 §2.3.4's limits, with
    /// the leading-digit relaxation of RFC 1123 §2.1 and the `_` that service
    /// labels use in practice).
    fn validate_dns_name(name: &str) -> Result<()> {
        let is_valid_label = |label: &str| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        };
        if name.is_empty() || name.len() > 253 || !name.split('.').all(is_valid_label) {
            bail!(
                "refusing to register {name:?} as a DNS record: expected dot-separated \
                 ASCII labels of letters, digits, '-' and '_' (none starting or ending \
                 with '-'), each at most 63 bytes and at most 253 bytes in total"
            );
        }
        Ok(())
    }

    /// Register a DNS record with the group's `dnsmasq`, so that `name` resolves
    /// to `addr` on every VM in the group.
    ///
    /// Appends to the `--addn-hosts` file and signals `dnsmasq` with `SIGHUP`,
    /// which makes it flush its cache and re-read that file. Records therefore
    /// accumulate across calls.
    ///
    /// This is how the local backend replaces Farm's playnet DNS: see
    /// `InternetComputer::setup_api_bn_local_playnet`. Use
    /// [`add_wildcard_dns_record`](Self::add_wildcard_dns_record) when the
    /// subdomains of `name` have to resolve as well; a hosts file has no
    /// wildcards.
    ///
    /// `name` must be a plain ASCII hostname, per
    /// [`validate_dns_name`](Self::validate_dns_name).
    pub fn add_dns_record(&self, group_name: &str, name: &str, addr: IpAddr) -> Result<()> {
        Self::validate_dns_name(name)?;
        let bridge = Self::bridge_name(group_name);
        let hosts_path = self.dnsmasq_hosts_path(&bridge);

        info!(
            self.logger,
            "Registering DNS record {name} -> {addr} with the dnsmasq of group {group_name}"
        );

        let mut hosts_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&hosts_path)
            .with_context(|| format!("opening {}", hosts_path.display()))?;
        writeln!(hosts_file, "{addr} {name}")
            .with_context(|| format!("appending to {}", hosts_path.display()))?;
        drop(hosts_file);

        // `dnsmasq` runs as the current user, so it can be signalled directly via
        // its pid-file.
        let pid_path = self.dnsmasq_pid_path(&bridge);
        let pid = std::fs::read_to_string(&pid_path)
            .with_context(|| format!("reading {}", pid_path.display()))?
            .trim()
            .parse::<i32>()
            .with_context(|| format!("parsing the pid in {}", pid_path.display()))?;
        let status = Command::new("kill")
            .args(["-HUP", &pid.to_string()])
            .status()
            .context("signalling dnsmasq with SIGHUP")?;
        if !status.success() {
            bail!("failed to SIGHUP dnsmasq (pid {pid}): {status}");
        }

        Ok(())
    }

    /// Register a *wildcard* DNS record with the group's `dnsmasq`, so that
    /// `name` **and every subdomain of it, at any depth** resolve to `addrs` — on
    /// every VM in the group, and in the driver, which shares their resolver (see
    /// [`install_group_resolv_conf`](Self::install_group_resolv_conf)).
    ///
    /// This is the local replacement for the apex record plus the `*` and `*.raw`
    /// `CNAME`s Farm's playnet DNS serves for the IC gateway, whose per-canister
    /// subdomains (`<canister id>.<domain>`, `<canister id>.raw.<domain>`) clients
    /// are expected to reach; see `IcGatewayVm::configure_dns_records`. Mixing
    /// address families in `addrs` is fine — `dnsmasq` answers each query type
    /// from the matching `--address` option — and takes the whole set at once
    /// because a single record is what costs a restart, not a single address.
    ///
    /// It does cost a `dnsmasq` restart, unlike
    /// [`add_dns_record`](Self::add_dns_record), because a wildcard needs
    /// `--address`, and nothing re-reads a *command-line* option: `SIGHUP` re-reads
    /// the hosts-shaped files and `--servers-file`, and a servers-file admits
    /// nothing but `server` and `rev-server`. Prefer `add_dns_record` when an exact
    /// name is enough.
    ///
    /// `name` must be a plain ASCII hostname, per
    /// [`validate_dns_name`](Self::validate_dns_name); it is what ends up in an
    /// `--address` option on `dnsmasq`'s command line.
    pub fn add_wildcard_dns_record(
        &self,
        group_name: &str,
        name: &str,
        addrs: &[IpAddr],
    ) -> Result<()> {
        Self::validate_dns_name(name)?;
        if addrs.is_empty() {
            return Ok(());
        }
        let bridge = Self::bridge_name(group_name);
        let wildcards_path = self.dnsmasq_wildcards_path(&bridge);

        info!(
            self.logger,
            "Registering wildcard DNS record {name} (and its subdomains) -> {addrs:?} \
             with the dnsmasq of group {group_name}"
        );

        let mut wildcards_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&wildcards_path)
            .with_context(|| format!("opening {}", wildcards_path.display()))?;
        for addr in addrs {
            writeln!(wildcards_file, "{addr} {name}")
                .with_context(|| format!("appending to {}", wildcards_path.display()))?;
        }
        drop(wildcards_file);

        self.restart_dnsmasq(group_name)
    }

    /// Stop and restart the group's `dnsmasq` so it picks up command-line options
    /// derived from state that changed since it started — currently only the
    /// wildcard records of
    /// [`add_wildcard_dns_record`](Self::add_wildcard_dns_record).
    ///
    /// The record files are left alone (they are truncated once, by
    /// [`create_group`](Self::create_group)), so records registered before the
    /// restart survive it.
    ///
    /// Restarting is safe for VMs that are already up: IC GuestOS nodes are
    /// statically configured and never consult the RA; a VM that SLAAC'd its
    /// address holds it for the `--dhcp-range ... ra-only` lifetime, which far
    /// outlives the gap; DHCPv4 leases live in the lease-file `dnsmasq` re-reads at
    /// startup; and the only real loss is its DNS cache. A guest that happens to
    /// query during the gap retries.
    fn restart_dnsmasq(&self, group_name: &str) -> Result<()> {
        let bridge = Self::bridge_name(group_name);
        let prefix = Self::group_ipv6_prefix(group_name);
        let ipv4_prefix = Self::group_ipv4_prefix(group_name);
        // Propagate a stop that could not be confirmed rather than starting a
        // second `dnsmasq`: the one still holding port 53 would make the new one
        // fail to bind, and `start_dnsmasq`'s error would then point at the wrong
        // thing.
        self.stop_dnsmasq(&bridge)?;
        self.start_dnsmasq(group_name, &bridge, &prefix, &ipv4_prefix)
    }

    /// Stop the group's `dnsmasq`, if running, and wait for it to exit. It runs as
    /// the current user, so it is signalled directly via its pid-file. Idempotent,
    /// and reports whether the exit could be *confirmed*.
    ///
    /// The wait is what makes [`restart_dnsmasq`](Self::restart_dnsmasq) sound:
    /// returning while the old instance still holds UDP port 53 on the name-server
    /// addresses would make the new one fail to bind. Signals are delivered
    /// asynchronously, `SIGKILL` included, so each one is followed by its own wait
    /// and an unconfirmed exit is an error rather than something to start a second
    /// `dnsmasq` on top of.
    ///
    /// The pid-file is removed either way: it names a process we have given up on,
    /// so keeping it would only mislead the next caller.
    fn stop_dnsmasq(&self, bridge: &str) -> Result<()> {
        let pid_path = self.dnsmasq_pid_path(bridge);
        let stopped = if let Ok(contents) = std::fs::read_to_string(&pid_path)
            && let Ok(pid) = contents.trim().parse::<i32>()
            && Self::dnsmasq_is_alive(pid, &pid_path)
        {
            // SIGTERM lets dnsmasq remove its pid-file on exit.
            let _ = Command::new("kill").arg(pid.to_string()).status();
            let terminated = Self::await_dnsmasq_exit(pid, &pid_path);
            if terminated.is_err() {
                warn!(
                    self.logger,
                    "dnsmasq (pid {pid}) did not exit within {DNSMASQ_STOP_TIMEOUT:?} of \
                     SIGTERM; sending SIGKILL"
                );
                let _ = Command::new("kill")
                    .args(["-KILL", &pid.to_string()])
                    .status();
                Self::await_dnsmasq_exit(pid, &pid_path).context("dnsmasq survived SIGKILL")
            } else {
                terminated
            }
        } else {
            // No pid-file, or it names something that is not a `dnsmasq` of ours
            // any more; either way there is nothing holding the port.
            Ok(())
        };
        let _ = std::fs::remove_file(&pid_path);
        stopped.with_context(|| format!("stopping the dnsmasq of {bridge}"))
    }

    /// Wait up to [`DNSMASQ_STOP_TIMEOUT`] for `pid` to stop being a `dnsmasq` of
    /// ours, per [`dnsmasq_is_alive`](Self::dnsmasq_is_alive).
    ///
    /// That observes the process's `argv` going away, which the kernel does while
    /// tearing the process down — a hair *before* it closes its files. So in
    /// principle a sample could land in between and read an exiting `dnsmasq` as
    /// gone while its sockets are still open. Two reasons not to chase that: the
    /// window is microseconds of non-blocking kernel work against a poll every
    /// [`DNSMASQ_STOP_POLL_INTERVAL`], and the backstop is loud rather than silent —
    /// `dnsmasq` refuses to start at all when it cannot bind, so `start_dnsmasq`
    /// surfaces that error instead of leaving a half-working resolver behind.
    ///
    /// Waiting for the pid to disappear outright would be worse, not better:
    /// `dnsmasq` daemonizes, so it lingers as a zombie until whatever it was
    /// reparented to reaps it, which under a sandbox is not guaranteed to be prompt.
    fn await_dnsmasq_exit(pid: i32, pid_path: &Path) -> Result<()> {
        let deadline = Instant::now() + DNSMASQ_STOP_TIMEOUT;
        while Self::dnsmasq_is_alive(pid, pid_path) {
            if Instant::now() >= deadline {
                bail!("dnsmasq (pid {pid}) was still running {DNSMASQ_STOP_TIMEOUT:?} later");
            }
            std::thread::sleep(DNSMASQ_STOP_POLL_INTERVAL);
        }
        Ok(())
    }

    /// Whether `pid` is a live `dnsmasq` that this backend started with
    /// `pid_path`, decided by looking for the `--pid-file=<pid_path>` argument
    /// [`start_dnsmasq`](Self::start_dnsmasq) passed it in
    /// `/proc/<pid>/cmdline`.
    ///
    /// That one check settles both of the questions
    /// [`stop_dnsmasq`](Self::stop_dnsmasq) has to answer before it signals:
    ///
    /// * **Is it still ours?** The pid comes from a pid-file that a `dnsmasq` which
    ///   died on its own never got to remove, so it can name a pid the kernel has
    ///   since handed to something else — and `stop_dnsmasq` escalates to
    ///   `SIGKILL`, which is not a signal to send to a stranger. The pid-file path
    ///   is unique per group, so nothing else carries it in its `argv`.
    /// * **Is it still running?** A zombie's `cmdline` reads back empty, so this
    ///   answers `false` for one — which is what we want, since a zombie holds no
    ///   sockets. `dnsmasq` does become one briefly: it daemonizes, so it is not a
    ///   child of this process and lingers until whoever it was reparented to reaps
    ///   it.
    ///
    /// The process *name* is no help here, which is worth knowing before reaching
    /// for it: Bazel links the `dnsmasq` runfiles entry under a hashed basename, so
    /// `/proc/<pid>/comm` holds a 15-character truncation of that hash rather than
    /// anything resembling `dnsmasq`.
    fn dnsmasq_is_alive(pid: i32, pid_path: &Path) -> bool {
        let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
            return false;
        };
        // `cmdline` is NUL-separated, so split it and compare *whole* arguments.
        // A substring search over the raw bytes would be weaker in a way that
        // matters here, since a false positive gets something signalled: it would
        // also accept our argument embedded in a longer one, or our path as the
        // prefix of a longer path.
        let mut expected = b"--pid-file=".to_vec();
        expected.extend_from_slice(pid_path.as_os_str().as_bytes());
        cmdline
            .split(|byte| *byte == 0)
            .any(|arg| arg == expected.as_slice())
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
        let [mgmt, logs, files] = Self::group_driver_ipv6s(group_name);
        info!(
            self.logger,
            "Deleting local group {group_name} (bridge {bridge})"
        );
        // Best-effort here, unlike in `restart_dnsmasq`: the bridge and its
        // addresses are deleted just below, so a `dnsmasq` that outlives its
        // SIGKILL has nothing left to serve and nothing left to hold.

        // Stop `dnsmasq` before removing the bridge it listens on.
        let _ = self.stop_dnsmasq(&bridge);

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
        use nix::fcntl::{Flock, FlockArg};

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
        // Hold an exclusive advisory lock through a `Flock` guard. The lock is
        // released when the guard is dropped at the end of this function (which
        // also closes the underlying `File`). Rust opens files `O_CLOEXEC`, so a
        // forked task subprocess that `exec`s does not inherit this fd and
        // therefore cannot keep the lock held after we return.
        let _image_cache_lock = Flock::lock(lock, FlockArg::LockExclusive)
            .map_err(|(_, errno)| errno)
            .with_context(|| format!("locking image cache lock {}", lock_path.display()))?;

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
                // Pin the qcow2 version instead of inheriting `qemu-img`'s
                // default, because `detect-zeroes=unmap` on the `-drive` below
                // depends on it: only v3 (`compat=1.1`) can record a *zero
                // cluster*, which is what makes a zeroed range read back as
                // zeros rather than falling through to the backing file. On v2
                // qcow2 would have to write the zeros out instead, silently
                // giving up the space saving.
                .arg("-o")
                .arg("compat=1.1")
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
        //
        // `detect-zeroes=unmap` keeps upgrade tests from filling the host's disk.
        // A GuestOS upgrade `dd`s the whole update image onto the inactive slot
        // (see `manageboot.sh`), and that image is mostly holes: ~11 GiB of
        // `boot.img` + `root.img` for ~1.2 GiB of content. Without zero
        // detection every one of those zero blocks allocates a qcow2 cluster, so
        // a single 4-node upgrade/downgrade test — which writes both slots on
        // every node — grows its overlays by ~87 GiB. Paired with the
        // `discard=unmap` on the same drive, zero writes instead become unmaps,
        // bringing that down to ~11 GiB. That is safe over a backing
        // file because the overlay is created with `compat=1.1` above: qcow2 v3
        // records a *zero cluster* rather than deallocating, so reads keep
        // returning zeros instead of falling through to the base image.
        let rp = root_port!();
        arg!(
            "-drive",
            format!(
                "if=none,id=disk0,file={},format=qcow2,cache=none,discard=unmap,detect-zeroes=unmap",
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
/// padding is inert.
///
/// Unaligned GPT-partitioned images cannot be padded and return an error instead.
fn pad_to_request_alignment(path: &Path) -> Result<()> {
    /// Upper bound on the host block size (covers 512- and 4096-byte sectors).
    const DISK_REQUEST_ALIGNMENT: u64 = 4096;
    let len = std::fs::metadata(path)
        .with_context(|| format!("stat {} for alignment padding", path.display()))?
        .len();
    let aligned = len.next_multiple_of(DISK_REQUEST_ALIGNMENT);
    if aligned == len {
        return Ok(());
    }
    if has_gpt_header(path)? {
        bail!(
            "{} is GPT-partitioned and its length ({len} bytes) is not a multiple of the \
             {DISK_REQUEST_ALIGNMENT}-byte request alignment: it can neither be padded (that \
             would displace the GPT backup header in the last sector) nor opened writable with \
             `cache=none`",
            path.display()
        );
    }
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
    Ok(())
}

/// Whether the disk image at `path` carries a GPT: its primary header sits in
/// LBA 1 and starts with the `EFI PART` signature (UEFI spec 5.3.2).
fn has_gpt_header(path: &Path) -> Result<bool> {
    use std::os::unix::fs::FileExt;

    /// LBA size assumed by the GPT signature's location. Every image the backend
    /// attaches uses 512-byte logical sectors.
    const LBA_SIZE: u64 = 512;
    const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";

    let file = std::fs::File::open(path)
        .with_context(|| format!("opening {} to look for a GPT", path.display()))?;
    let mut signature = [0_u8; GPT_SIGNATURE.len()];
    match file.read_exact_at(&mut signature, LBA_SIZE) {
        Ok(()) => Ok(&signature == GPT_SIGNATURE),
        // An image shorter than two sectors cannot hold a GPT.
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(err) => {
            Err(err).with_context(|| format!("reading the GPT signature of {}", path.display()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::LocalBackend;

    #[test]
    fn accepts_the_names_the_backend_registers() {
        for name in [
            // `IcGatewayVm::load_or_create_local_playnet`.
            "ic-gateway.ic.net",
            "ic-gateway-3.ic.net",
            // `InternetComputer::setup_api_bn_local_playnet`.
            "apibn-0.ic.net",
            // Leading digits and `_` labels are legal in practice.
            "0.example.com",
            "_acme-challenge.example.com",
            &format!("{}.example.com", "a".repeat(63)),
        ] {
            assert!(
                LocalBackend::validate_dns_name(name).is_ok(),
                "expected {name:?} to be accepted"
            );
        }
    }

    #[test]
    fn rejects_names_that_would_corrupt_a_record_file_or_a_command_line() {
        for name in [
            // Splits the `<address> <name>` line the wrong way when read back.
            "ic gateway.ic.net",
            "ic\tgateway.ic.net",
            // Appends a record nobody asked for.
            "ic-gateway.ic.net\n2001:db8::1 evil.ic.net",
            // Shell metacharacters. No shell sees these any more, now that
            // `start_dnsmasq` passes argv directly — but they are not DNS names
            // either, so they have no business in a record file.
            "ic-gateway.ic.net; touch /tmp/pwned",
            "$(id).ic.net",
            "`id`.ic.net",
            // Malformed as a name.
            "",
            ".",
            "ic-gateway..ic.net",
            "-gateway.ic.net",
            "gateway-.ic.net",
            &format!("{}.example.com", "a".repeat(64)),
            &format!("{}.example.com", vec!["a"; 127].join(".")),
        ] {
            assert!(
                LocalBackend::validate_dns_name(name).is_err(),
                "expected {name:?} to be rejected"
            );
        }
    }
}
