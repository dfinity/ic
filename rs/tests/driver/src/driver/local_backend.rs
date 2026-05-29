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
use slog::{Logger, info, warn};
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use virt::connect::Connect;
use virt::domain::Domain;
use virt::network::Network;

/// Persistent record (in the root TestEnv) of the libvirtd unix socket so that
/// forked task subprocesses can connect to the daemon spawned by the setup
/// task instead of trying to spawn their own.
#[derive(Serialize, Deserialize, Clone)]
struct LocalBackendSocket {
    /// Absolute path on the host's filesystem; survives `cp -R` of the
    /// surrounding TestEnv directory because it is just a JSON string.
    socket_path: PathBuf,
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
                env.get_path(""),
                env.logger(),
            )?);
            *reg = Some(backend.clone());
            return Ok(backend);
        }

        // First call in this group: spawn libvirtd in this env's working_dir.
        // Canonicalize so the socket path persisted for forked subprocesses is
        // absolute; a failure here means the directory is missing/inaccessible
        // and there is no sensible way to continue.
        let working_dir = env.get_path("");
        let working_dir = working_dir
            .canonicalize()
            .with_context(|| format!("canonicalizing working dir {}", working_dir.display()))?;
        let backend = Arc::new(LocalBackend::spawn(working_dir.clone(), env.logger())?);
        // Persist the socket path so forked subprocesses can find it.
        LocalBackendSocket {
            socket_path: backend.socket_path.clone(),
        }
        .write_attribute(env);
        *reg = Some(backend.clone());
        Ok(backend)
    }

    /// Spawn a fresh libvirtd subprocess in `working_dir/libvirt` and open a
    /// connection to it.
    fn spawn(working_dir: PathBuf, logger: Logger) -> Result<Self> {
        let libvirt_dir = working_dir.join("libvirt");
        std::fs::create_dir_all(&libvirt_dir).with_context(|| {
            format!("creating libvirt working dir at {}", libvirt_dir.display())
        })?;

        let socket_path = libvirt_dir.join("libvirt-sock");
        let conf_path = libvirt_dir.join("libvirtd.conf");
        let pid_path = libvirt_dir.join("libvirtd.pid");
        let log_path = libvirt_dir.join("libvirtd.log");

        // Minimal libvirtd configuration: unix socket only, no auth, no TLS.
        std::fs::write(
            &conf_path,
            format!(
                r#"unix_sock_dir = "{dir}"
unix_sock_group = "libvirt"
unix_sock_ro_perms = "0777"
unix_sock_rw_perms = "0777"
auth_unix_ro = "none"
auth_unix_rw = "none"
log_outputs = "1:file:{log}"
"#,
                dir = libvirt_dir.display(),
                log = log_path.display(),
            ),
        )?;
        info!(logger, "Spawning libvirtd"; "conf" => %conf_path.display(), "socket" => %socket_path.display());

        let child = Command::new("libvirtd")
            .arg("--config")
            .arg(&conf_path)
            .arg("--pid-file")
            .arg(&pid_path)
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
            connect,
            logger,
            extra_disks: Mutex::new(HashMap::new()),
            primary_disks: Mutex::new(HashMap::new()),
            vm_ipv6: Mutex::new(HashMap::new()),
            vm_specs: Mutex::new(HashMap::new()),
            vm_min_boot_image_size_gib: Mutex::new(HashMap::new()),
            working_dir,
        })
    }

    /// Open a connection-only handle to an already-running libvirtd. Used by
    /// forked task subprocesses.
    fn connect_only(socket_path: PathBuf, working_dir: PathBuf, logger: Logger) -> Result<Self> {
        let connect = open_connect(&socket_path, &logger)?;
        Ok(LocalBackend {
            socket_path,
            libvirtd: None,
            connect,
            logger,
            extra_disks: Mutex::new(HashMap::new()),
            primary_disks: Mutex::new(HashMap::new()),
            vm_ipv6: Mutex::new(HashMap::new()),
            vm_specs: Mutex::new(HashMap::new()),
            vm_min_boot_image_size_gib: Mutex::new(HashMap::new()),
            working_dir,
        })
    }

    /// Returns the libvirt network name for `group_name`.
    fn network_name(group_name: &str) -> String {
        sanitize_libvirt_name(&format!("ictest-{group_name}"))
    }

    /// Returns the libvirt domain name for `(group_name, vm_name)`.
    fn domain_name(group_name: &str, vm_name: &str) -> String {
        sanitize_libvirt_name(&format!("ictest-{group_name}-{vm_name}"))
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

    /// Create a libvirt isolated network for `group_name`.
    pub fn create_group(&self, group_name: &str) -> Result<()> {
        let name = Self::network_name(group_name);
        info!(self.logger, "Creating libvirt network {name}");
        let prefix = Self::group_ipv6_prefix(group_name);
        let bridge_name = format!("vbr-{:.10}", &name);
        let xml = format!(
            r#"<network>
  <name>{name}</name>
  <bridge name='{bridge}' stp='off' delay='0'/>
  <ip family='ipv6' address='{prefix}1' prefix='64'>
  </ip>
</network>
"#,
            name = name,
            bridge = bridge_name,
            prefix = prefix,
        );
        match Network::create_xml(&self.connect, &xml) {
            Ok(_) => Ok(()),
            Err(e) => {
                // If the network already exists, ignore.
                let msg = format!("{e}");
                if msg.contains("already") || msg.contains("exists") {
                    warn!(self.logger, "Network {name} already exists; reusing");
                    Ok(())
                } else {
                    Err(anyhow!("create_group({group_name}): {e}"))
                }
            }
        }
    }

    /// Tear down all domains in `group_name` and remove the network.
    pub fn delete_group(&self, group_name: &str) -> Result<()> {
        let net_name = Self::network_name(group_name);
        info!(self.logger, "Deleting libvirt group {net_name}");

        // Best effort: shut down all domains whose names start with the group prefix.
        let prefix = format!("ictest-{}-", sanitize_libvirt_name(group_name));
        if let Ok(domains) = self.connect.list_all_domains(0) {
            for d in domains {
                if let Ok(name) = d.get_name()
                    && name.starts_with(&prefix)
                {
                    let _ = d.destroy();
                }
            }
        }

        if let Ok(net) = Network::lookup_by_name(&self.connect, &net_name) {
            let _ = net.destroy();
        }

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
        let net_name = Self::network_name(group_name);
        let uuid = vm_uuid(group_name, vm_name);

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
            network_name: net_name,
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
        if let Some(mut child) = self.libvirtd.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
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
    let uri = format!("qemu+unix:///session?socket={}", socket_path.display());
    let connect = Connect::open(Some(&uri))
        .with_context(|| format!("opening libvirt connection to {uri}"))?;
    info!(logger, "Connected to libvirtd"; "uri" => &uri);
    Ok(connect)
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
        let status = Command::new("unzstd")
            .arg("-o")
            .arg(dst)
            .arg(src)
            .status()
            .context("running unzstd")?;
        if !status.success() {
            bail!("unzstd decompression of {} failed", src.display());
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
    network_name: String,
}

// `vm_ipv6` is currently a write-only cache; future operations (e.g. ARP
// pre-population, dnsmasq integration) will read it.
