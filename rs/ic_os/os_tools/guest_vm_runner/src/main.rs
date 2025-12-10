use crate::guest_direct_boot::{DirectBoot, prepare_direct_boot};
use crate::guest_vm_config::{
    assemble_config_media, generate_vm_config, serial_log_path, vm_domain_name,
};
use crate::systemd_notifier::SystemdNotifier;
use crate::upgrade_device_mapper::create_mapped_device_for_upgrade;
use anyhow::{Context, Error, Result, bail};
use clap::{Parser, ValueEnum};
use config_types::{HostOSConfig, Ipv6Config};
use deterministic_ips::node_type::NodeType;
use deterministic_ips::{IpVariant, MacAddr6Ext, calculate_deterministic_mac};
use ic_device::device_mapping::MappedDevice;
use ic_device::mount::{GptPartitionProvider, PartitionProvider};
use ic_metrics_tool::{Metric, MetricsWriter};
use ic_sev::host::HostSevCertificateProvider;
use nix::unistd::getuid;
use std::fmt::{Debug, Formatter};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::signal::unix::{SignalKind, signal};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use virt::connect::Connect;
use virt::domain::Domain;
use virt::sys::{
    VIR_DOMAIN_CRASHED, VIR_DOMAIN_DESTROY_GRACEFUL, VIR_DOMAIN_NONE, VIR_DOMAIN_RUNNING,
};

mod boot_args;
mod guest_direct_boot;
mod guest_vm_config;
mod systemd_notifier;
mod upgrade_device_mapper;

const DEFAULT_METRICS_FILE_PATH: &str =
    "/run/node_exporter/collector_textfile/hostos_guestos_service.prom";
const UPGRADE_METRICS_FILE_PATH: &str =
    "/run/node_exporter/collector_textfile/hostos_guestos_upgrade_service.prom";

const DEFAULT_GUESTOS_SERVICE_NAME: &str = "guestos.service";
const UPGRADE_GUESTOS_SERVICE_NAME: &str = "upgrade-guestos.service";

const CONSOLE_TTY1_PATH: &str = "/dev/tty1";
const CONSOLE_TTY_SERIAL_PATH: &str = "/dev/ttyS0";
const GUESTOS_DEVICE: &str = "/dev/hostlvm/guestos";

const SEV_CERTIFICATE_CACHE_DIR: &str = "/var/ic/sev/certificates";

/// If we cannot decide from the logs within this timeout whether the GuestOS boot succeeded or
/// failed, we dump GuestOS logs on the console.
/// We have an alert that triggers if the subnet is not available after 5 minutes, we use the same
/// timeout here.
const GUESTOS_BOOT_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// The GuestOS will log one of these marker texts on the serial output.
const GUESTOS_BOOT_SUCCESS_MARKER: &str = "GUESTOS BOOT SUCCESS";
const GUESTOS_BOOT_FAILURE_MARKER: &str = "GUESTOS BOOT FAILURE";

#[derive(Copy, Clone, Eq, PartialEq, Debug, ValueEnum)]
pub enum GuestVMType {
    Default,
    Upgrade,
}

impl GuestVMType {
    pub fn to_config_type(self) -> config_types::GuestVMType {
        match self {
            GuestVMType::Default => config_types::GuestVMType::Default,
            GuestVMType::Upgrade => config_types::GuestVMType::Upgrade,
        }
    }
}

#[derive(Parser)]
struct Args {
    #[arg(long = "type", default_value = "default", value_enum)]
    vm_type: GuestVMType,
}

#[tokio::main]
pub async fn main() -> Result<()> {
    // TODO: We could replace this with Linux capabilities but this works well for now.
    if !getuid().is_root() {
        bail!("This program requires root privileges.");
    }

    let args = Args::parse();

    match args.vm_type {
        GuestVMType::Default => println!("Starting GuestOS service"),
        GuestVMType::Upgrade => println!("Starting Upgrade GuestOS service"),
    }

    let termination_token = CancellationToken::new();
    setup_signal_handler(termination_token.clone()).context("Failed to setup signal handler")?;

    loop {
        match GuestVmService::create_and_run(args.vm_type, termination_token.clone()).await {
            // If the VM started and stopped regularly, we exit with success.
            Ok(()) => return Ok(()),
            // If the VM started but stopped, we restart it. Note that we recreate the entire
            // service in order to start the VM with fresh config.
            Err(GuestVmServiceError::VirtualMachineStopped) => match args.vm_type {
                GuestVMType::Default => {
                    println!("Guest VM stopped, restarting");
                    continue;
                }
                GuestVMType::Upgrade => {
                    println!("Upgrade VM stopped, exiting");
                    break Ok(());
                }
            },
            // If we encounter an unexpected error, we exit with the error and let systemd restart
            // the service.
            Err(GuestVmServiceError::Other(err)) => return Err(err),
        }
    }
}

fn setup_signal_handler(termination_token: CancellationToken) -> Result<()> {
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    tokio::spawn(async move {
        tokio::select! {
            _ = sigterm.recv() => termination_token.cancel(),
            _ = sigint.recv() => termination_token.cancel(),
        }
    });
    Ok(())
}

/// Manages a libvirt-based virtual machine
pub struct VirtualMachine {
    domain_id: u32,
    domain_name: String,
    libvirt_connect: Connect,
    // These fields hold resources (files) that are used by the virtual machine and must be kept
    // alive until the virtual machine is destroyed.
    _config_media: NamedTempFile,
    _direct_boot: Option<DirectBoot>,
}

impl VirtualMachine {
    /// Creates a new virtual machine from the provided XML configuration
    /// The `config_media` is moved into the struct and deleted when the struct goes out of scope.
    pub fn new(
        libvirt_connect: &Connect,
        xml_config: &str,
        config_media: NamedTempFile,
        direct_boot: Option<DirectBoot>,
        vm_domain_name: &str,
    ) -> Result<Self> {
        // Check if a domain with the same name already exists and, if so, try to destroy it
        Self::try_destroy_existing_vm(libvirt_connect, vm_domain_name);

        let mut retries = 3;
        let domain = loop {
            let domain_result = Domain::create_xml(libvirt_connect, xml_config, VIR_DOMAIN_NONE);
            match domain_result {
                Ok(domain) => {
                    eprintln!("Domain successfully created: {vm_domain_name}");
                    break domain;
                }
                Err(e) if retries > 0 => {
                    eprintln!("Domain creation failed, retrying: {e}");
                    // TODO: Monitor if this code path is ever triggered - remove if unused
                    if Domain::lookup_by_name(libvirt_connect, vm_domain_name).is_ok() {
                        eprintln!(
                            "VM domain '{}' exists even though create_xml failed, attempting to destroy it before retry",
                            vm_domain_name
                        );
                        Self::try_destroy_existing_vm(libvirt_connect, vm_domain_name);
                    }
                    retries -= 1;
                    continue;
                }
                err => err.context("Failed to create domain after retries")?,
            };
        };
        Ok(Self {
            domain_id: domain.get_id().context("Domain does not have id")?,
            libvirt_connect: libvirt_connect.clone(),
            domain_name: vm_domain_name.to_string(),
            _config_media: config_media,
            _direct_boot: direct_boot,
        })
    }

    fn try_destroy_existing_vm(libvirt_connect: &Connect, vm_domain_name: &str) {
        if let Ok(existing_domain) = Domain::lookup_by_name(libvirt_connect, vm_domain_name) {
            eprintln!("Attempting to destroy existing '{vm_domain_name}' domain");
            if let Err(err) = existing_domain.destroy_flags(VIR_DOMAIN_DESTROY_GRACEFUL) {
                eprintln!("destroy_flags failed: {err}");
            }
            if let Err(err) = existing_domain.undefine() {
                eprintln!("undefine failed: {err}");
            }
        } else {
            eprintln!("No existing domain found to destroy");
        }
    }

    fn get_domain(&self) -> Result<Domain> {
        Domain::lookup_by_id(&self.libvirt_connect, self.domain_id)
            .context("Domain no longer exists")
    }

    /// Returns once the VM is no longer running.
    async fn wait_for_shutdown(&self) {
        loop {
            let domain = match self.get_domain() {
                Ok(domain) => domain,
                Err(e) => {
                    eprintln!("Failed to get domain: {e}");
                    break;
                }
            };
            match domain.get_state() {
                Ok((VIR_DOMAIN_RUNNING, _reason)) => {
                    // all good, VM is running
                }
                Ok((VIR_DOMAIN_CRASHED, reason)) => {
                    eprintln!("VM crashed, reason: {reason}");
                    break;
                }
                Ok((state, reason)) => {
                    eprintln!("VM is in state {state}, reason: {reason}");
                }
                Err(e) => {
                    eprintln!("Failed to get domain state: {e}");
                    break;
                }
            }

            // Poll every 1s in production and 50ms in tests to speed up tests (in prod, we can
            // wait 1s between polls and we save some CPU cycles).
            #[cfg(not(test))]
            sleep(Duration::from_secs(1)).await;
            #[cfg(test)]
            sleep(Duration::from_millis(50)).await;
        }
    }
}

impl Drop for VirtualMachine {
    /// Ensures the VM is properly shut down when the object is dropped
    fn drop(&mut self) {
        if let Ok(domain) = self.get_domain() {
            println!("Shutting down {} domain gracefully", self.domain_name);
            if let Err(e) = domain.destroy_flags(VIR_DOMAIN_DESTROY_GRACEFUL) {
                eprintln!("Failed to gracefully destroy domain: {e}");
            }
        }
    }
}

#[derive(thiserror::Error)]
pub enum GuestVmServiceError {
    /// This can happen because QEMU stopped/crashed or because the GuestOS requested reboot.
    #[error("Virtual machine stopped")]
    VirtualMachineStopped,
    #[error("{0}")]
    Other(#[from] Error),
}

impl From<std::io::Error> for GuestVmServiceError {
    fn from(e: std::io::Error) -> Self {
        Self::Other(e.into())
    }
}

impl Debug for GuestVmServiceError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VirtualMachineStopped => write!(f, "VirtualMachineStopped"),
            Self::Other(e) => e.fmt(f),
        }
    }
}

/// Service responsible for managing the GuestOS virtual machine lifecycle
pub struct GuestVmService {
    metrics_writer: MetricsWriter,
    libvirt_connection: Connect,
    hostos_config: HostOSConfig,
    systemd_notifier: Arc<dyn SystemdNotifier>,
    console_ttys: Vec<Mutex<Box<dyn Write + Send + Sync>>>,
    guest_vm_type: GuestVMType,
    sev_certificate_provider: HostSevCertificateProvider,
    disk_device: PathBuf,
    partition_provider: Box<dyn PartitionProvider>,
    // Partition provider uses the mapped device, so it must be declared after it.
    _upgrade_mapped_device: Option<MappedDevice>,
    guestos_boot_timeout: Duration,
    vm_serial_log_path: PathBuf,
}

impl GuestVmService {
    #[cfg(not(target_os = "linux"))]
    pub fn new(guest_vm_type: GuestVMType) -> Result<Self> {
        anyhow::bail!("GuestVM service is only supported on Linux");
    }

    #[cfg(target_os = "linux")]
    pub fn new(guest_vm_type: GuestVMType) -> Result<Self> {
        let metrics_writer =
            MetricsWriter::new(std::path::PathBuf::from(Self::metrics_path(guest_vm_type)));
        let libvirt_connection = Connect::open(None).context("Failed to connect to libvirt")?;
        let hostos_config: HostOSConfig =
            config::deserialize_config(config::DEFAULT_HOSTOS_CONFIG_OBJECT_PATH)
                .context("Failed to read HostOS config file")?;
        let console_tty1 = std::fs::File::options()
            .write(true)
            .open(CONSOLE_TTY1_PATH)
            .context("Failed to open console tty1")?;

        let console_tty_serial = std::fs::File::options()
            .write(true)
            .open(CONSOLE_TTY_SERIAL_PATH)
            .context("Failed to open console ttyS0")?;

        let sev_certificate_provider = HostSevCertificateProvider::new(
            PathBuf::from(SEV_CERTIFICATE_CACHE_DIR),
            hostos_config
                .icos_settings
                .enable_trusted_execution_environment,
        )
        .context("Could not initialize SEV certificate provider")?;

        // If this is an Upgrade VM, create a mapped device which protects the data partition of the
        // Guest device.
        let upgrade_mapped_device = (guest_vm_type == GuestVMType::Upgrade)
            .then(|| {
                create_mapped_device_for_upgrade(Path::new(GUESTOS_DEVICE))
                    .context("Cannot create mapped device")
            })
            .transpose()?;

        let disk_device = upgrade_mapped_device
            .as_ref()
            .map(|x| x.path())
            .unwrap_or(Path::new(GUESTOS_DEVICE));

        Ok(Self {
            metrics_writer,
            libvirt_connection,
            hostos_config,
            guest_vm_type,
            systemd_notifier: Arc::new(systemd_notifier::DefaultSystemdNotifier),
            console_ttys: vec![
                Mutex::new(Box::new(console_tty1)),
                Mutex::new(Box::new(console_tty_serial)),
            ],
            sev_certificate_provider,
            partition_provider: Box::new(
                GptPartitionProvider::new(disk_device.to_path_buf())
                    .context("Failed to create partition provider")?,
            ),
            disk_device: disk_device.to_path_buf(),
            _upgrade_mapped_device: upgrade_mapped_device,
            guestos_boot_timeout: GUESTOS_BOOT_TIMEOUT,
            vm_serial_log_path: serial_log_path(guest_vm_type).to_path_buf(),
        })
    }

    #[cfg(target_os = "linux")]
    pub async fn create_and_run(
        guest_vm_type: GuestVMType,
        termination_token: CancellationToken,
    ) -> Result<(), GuestVmServiceError> {
        let mut guest_vm_service = Self::new(guest_vm_type)?;
        guest_vm_service.run(termination_token).await
    }

    /// Runs the GuestOS service
    pub async fn run(
        &mut self,
        termination_token: CancellationToken,
    ) -> Result<(), GuestVmServiceError> {
        let virtual_machine = match self.start_virtual_machine().await {
            Ok(virtual_machine) => {
                self.metrics_writer
                    .write_metrics(&[Metric::with_annotation(
                        "hostos_guestos_service_start",
                        1.0,
                        "GuestOS virtual machine define state",
                    )])?;
                virtual_machine
            }
            Err(err) => {
                self.handle_startup_error(&err).await;
                self.metrics_writer
                    .write_metrics(&[Metric::with_annotation(
                        "hostos_guestos_service_start",
                        0.0,
                        "GuestOS virtual machine define state",
                    )])?;
                return Err(err.into());
            }
        };

        // Monitor the VM and the GuestOS boot. If the VM shuts down before the boot monitoring
        // returns, stop the boot monitoring.
        let mut monitor_vm =
            pin!(self.monitor_virtual_machine(&virtual_machine, termination_token));
        tokio::select! {
            // Wait for VM to shut down or for stop signal
            monitor_vm_result = &mut monitor_vm => monitor_vm_result,
            // Monitor GuestOS boot process in the background
            _ = self.monitor_guestos_boot() => monitor_vm.await,
        }
    }

    async fn start_virtual_machine(&mut self) -> Result<VirtualMachine> {
        let config_media = NamedTempFile::with_prefix("config_media")
            .context("Failed to create config media file")?;

        println!("Extracting direct boot dependencies");
        let direct_boot = prepare_direct_boot(self.guest_vm_type, self.partition_provider.as_ref())
            .await
            .context("Failed to prepare direct boot")?;

        if direct_boot.is_none() {
            println!(
                "Direct boot dependencies not found (old GuestOS version?). Falling back to \
                 legacy boot."
            );
        }

        let enable_tee = self
            .hostos_config
            .icos_settings
            .enable_trusted_execution_environment;
        if enable_tee && direct_boot.is_none() {
            bail!(
                "enable_trusted_execution_environment is true but direct boot could not be \
                 configured."
            )
        }

        let sev_certificate_chain_pem = self
            .sev_certificate_provider
            .load_certificate_chain_pem()
            .await
            .context("Failed to load SEV certificate chain")?;

        assemble_config_media(
            &self.hostos_config,
            self.guest_vm_type,
            sev_certificate_chain_pem,
            config_media.path(),
        )
        .context("Failed to assemble config media")?;

        let vm_config = generate_vm_config(
            &self.hostos_config,
            config_media.path(),
            direct_boot.as_ref().map(DirectBoot::to_config),
            &self.disk_device,
            &self.vm_serial_log_path,
            self.guest_vm_type,
        )
        .context("Failed to generate GuestOS VM config")?;

        println!("Creating GuestOS virtual machine");

        let virtual_machine = VirtualMachine::new(
            &self.libvirt_connection,
            &vm_config,
            config_media,
            direct_boot,
            vm_domain_name(self.guest_vm_type),
        )
        .context("Failed to define GuestOS virtual machine")?;

        // Notify systemd that we're ready
        self.systemd_notifier.notify_ready()?;

        println!("Started GuestOS virtual machine");

        // Wait before printing messages to console
        // (but not in unit tests otherwise tests take too long to finish).
        #[cfg(not(test))]
        sleep(Duration::from_secs(10)).await;

        self.display_startup_messages()?;

        Ok(virtual_machine)
    }

    fn display_startup_messages(&mut self) -> Result<()> {
        self.write_to_console_and_stdout("");
        self.write_to_console_and_stdout("#################################################");
        self.write_to_console_and_stdout("GuestOS virtual machine launched");
        self.write_to_console_and_stdout("IF ONBOARDING, please wait for up to 10 MINUTES for a 'Join request successful!' message");
        self.write_to_console_and_stdout(&format!(
            "Host IPv6 address: {}",
            self.get_host_ipv6_address()
        ));
        self.write_to_console_and_stdout("#################################################");

        Ok(())
    }

    /// Gets the IPv6 address of the host for debugging purposes
    fn get_host_ipv6_address(&self) -> String {
        let generated_mac = calculate_deterministic_mac(
            &self.hostos_config.icos_settings.mgmt_mac,
            self.hostos_config.icos_settings.deployment_environment,
            IpVariant::V6,
            NodeType::HostOS,
        );

        let Ipv6Config::Deterministic(ipv6_config) =
            &self.hostos_config.network_settings.ipv6_config
        else {
            return "Error: Ipv6Config is not of type Deterministic. Cannot get IPv6 address."
                .to_string();
        };

        match generated_mac.calculate_slaac(&ipv6_config.prefix) {
            Ok(ipv6_addr) => ipv6_addr.to_string(),
            Err(e) => format!("Error: Failed to get IPv6 address: {e}"),
        }
    }

    /// Handles errors that occur during VM startup
    async fn handle_startup_error(&self, e: &Error) {
        // Give QEMU time to clear the console before printing error messages
        // (but not in unit tests otherwise tests take too long to finish).
        #[cfg(not(test))]
        sleep(Duration::from_secs(10)).await;

        self.write_to_console_and_stdout("ERROR: Failed to start GuestOS virtual machine.");
        // Write debug repr because it includes the cause.
        self.write_to_console(&format!("{e:?}"));
        self.write_to_console("#################################################");
        self.write_to_console(&format!(
            "###      LOGGING {} LOGS...      ###",
            self.systemd_service_name().to_uppercase()
        ));
        self.write_to_console("#################################################");

        let _ignore = self.display_systemd_logs().await;

        self.write_to_console("#################################################");
        self.write_to_console("###          TROUBLESHOOTING INFO...          ###");
        self.write_to_console("#################################################");
        self.write_to_console(&format!(
            "Host IPv6 address: {}",
            self.get_host_ipv6_address()
        ));

        // Check for and display serial logs if they exist
        self.display_serial_logs().await;

        self.write_to_console_and_stdout(&format!(
            "Exiting so that systemd can restart {}",
            self.systemd_service_name()
        ));
    }

    /// Captures and displays journalctl logs for the guestos service
    async fn display_systemd_logs(&self) -> Result<()> {
        let journalctl_output = Command::new("journalctl")
            .args(["-u", self.systemd_service_name()])
            .output()
            .await
            .context("Failed to run journalctl")?;

        let logs = String::from_utf8_lossy(&journalctl_output.stdout);
        for line in logs.lines() {
            self.write_to_console(line);
        }

        Ok(())
    }

    fn systemd_service_name(&self) -> &str {
        match self.guest_vm_type {
            GuestVMType::Default => DEFAULT_GUESTOS_SERVICE_NAME,
            GuestVMType::Upgrade => UPGRADE_GUESTOS_SERVICE_NAME,
        }
    }

    fn metrics_path(guest_vm_type: GuestVMType) -> &'static Path {
        match guest_vm_type {
            GuestVMType::Default => Path::new(DEFAULT_METRICS_FILE_PATH),
            GuestVMType::Upgrade => Path::new(UPGRADE_METRICS_FILE_PATH),
        }
    }

    /// Monitors the GuestOS boot
    async fn monitor_guestos_boot(&self) {
        match tokio::time::timeout(self.guestos_boot_timeout, self.guestos_boot_success()).await {
            Ok(Ok(true)) => {
                self.write_to_console_and_stdout("GuestOS boot succeeded");
            }
            Ok(Ok(false)) => {
                self.write_to_console_and_stdout("GuestOS boot failed");
                self.display_serial_logs().await;
            }
            Ok(Err(err)) => {
                self.write_to_console_and_stdout(&format!(
                    "Failed to monitor GuestOS boot state. Caused by: {err:?}"
                ));
            }
            Err(_) => {
                self.write_to_console_and_stdout("GuestOS boot timed out");
                self.display_serial_logs().await;
            }
        }
    }

    /// Returns whether the GuestOS boot succeeded. The function does not return until
    /// we have evidence that the GuestOS boot succeeded or failed. It can happen that the
    /// function never returns, therefore, it should be used with a timeout (see
    /// monitor_guestos_boot above).
    ///
    /// Returns Ok(true) if GuestOS boot was successful, Ok(false) if GuestOS boot failed and
    /// Err(...) if there was an error during monitoring the GuestOS boot.
    async fn guestos_boot_success(&self) -> Result<bool> {
        while !self.vm_serial_log_path.exists() {
            sleep(Duration::from_secs(1)).await;
        }

        let file = tokio::fs::File::open(&self.vm_serial_log_path).await?;
        let reader = BufReader::new(file);
        // Note: we're not using lines() because the log can contain non-UTF8 characters, so we
        // cannot use the String type.
        let mut lines = reader.split(b'\n');

        let success = memchr::memmem::Finder::new(GUESTOS_BOOT_SUCCESS_MARKER);
        let fail = memchr::memmem::Finder::new(GUESTOS_BOOT_FAILURE_MARKER);

        loop {
            let Some(line) = lines.next_segment().await? else {
                sleep(Duration::from_secs(1)).await;
                continue;
            };
            if success.find(&line).is_some() {
                return Ok(true);
            }
            if fail.find(&line).is_some() {
                return Ok(false);
            }
        }
    }

    /// Displays serial logs from the console log file if it exists
    async fn display_serial_logs(&self) {
        let serial_log_path = &self.vm_serial_log_path;
        if serial_log_path.exists() {
            self.write_to_console_and_stdout("#################################################");
            self.write_to_console_and_stdout("###  LOGGING GUESTOS CONSOLE LOGS, IF ANY...  ###");
            self.write_to_console_and_stdout("#################################################");

            let tail_output = Command::new("tail")
                .args(["-n", "100", serial_log_path.to_str().unwrap()])
                .output()
                .await;

            match tail_output {
                Ok(tail_output) => {
                    for line in String::from_utf8_lossy(&tail_output.stdout).lines() {
                        self.write_to_console_and_stdout(&format!("[GUESTOS] {line}"));
                    }
                }
                Err(err) => {
                    self.write_to_console_and_stdout(&format!(
                        "Failed to tail Guest serial log. {err}"
                    ));
                }
            }
        } else {
            self.write_to_console_and_stdout("No console log file found.");
        }
    }

    /// Monitors the virtual machine for shutdown or stop signals
    async fn monitor_virtual_machine(
        &self,
        vm: &VirtualMachine,
        termination_token: CancellationToken,
    ) -> Result<(), GuestVmServiceError> {
        tokio::select! {
            biased;
            // Wait for either VM shutdown event or stop signal
            _ = termination_token.cancelled() => {
                println!("Received stop signal, shutting down VM");
                Ok(())
            },
            _ = vm.wait_for_shutdown() => {
                Err(GuestVmServiceError::VirtualMachineStopped)
            }
        }
    }

    // We have two different ways to log:
    // 1. Log to stdout. These logs will end up in the systemd journal. Upon error,
    //    display_systemd_logs() writes the journal logs to the console.
    // 2. Log to the console. These logs will show up in the terminal but not in the journal.
    fn write_to_console_and_stdout(&self, message: &str) {
        self.write_to_console(message);
        println!("{message}");
    }

    fn write_to_console(&self, message: &str) {
        for console_tty in &self.console_ttys {
            if let Ok(mut console_tty) = console_tty.lock() {
                let _ignore = writeln!(console_tty, "{message}");
                let _ignore = console_tty.flush();
            }
        }
    }
}

impl Drop for GuestVmService {
    fn drop(&mut self) {
        let _ignored = self.libvirt_connection.close();
    }
}

#[cfg(all(test, feature = "integration_tests"))]
mod tests {
    use super::*;
    use crate::systemd_notifier::testing::MockSystemdNotifier;
    use config_types::{
        DeploymentEnvironment, DeterministicIpv6Config, HostOSDevSettings, HostOSSettings,
        ICOSSettings, NetworkSettings,
    };
    use ic_device::mount::GptPartitionProvider;
    use ic_device::mount::testing::ExtractingFilesystemMounter;
    use ic_sev::host::testing::mock_host_sev_certificate_provider;
    use nix::sys::signal::SIGTERM;
    use regex::Regex;
    use std::fs::File;
    use std::path::PathBuf;
    use std::sync::LazyLock;
    use tempfile::TempDir;
    use tokio::task::JoinHandle;
    use virt::sys::VIR_DOMAIN_RUNNING_BOOTED;

    static GUESTOS_IMAGE: LazyLock<NamedTempFile> = LazyLock::new(|| {
        let icos_image_path =
            std::env::var("ICOS_IMAGE").expect("Could not find ICOS_IMAGE environment variable");
        let tempdir = TempDir::new().expect("Failed to create temp dir");

        assert!(
            std::process::Command::new("tar")
                .args([
                    "-xa",
                    "-f",
                    &icos_image_path,
                    "-C",
                    tempdir.path().to_str().unwrap(),
                    "disk.img"
                ])
                .status()
                .expect("Could not run tar command")
                .success(),
            "Tar returned error"
        );

        let guestos_device = NamedTempFile::with_prefix("guestos_device").unwrap();
        std::fs::rename(tempdir.path().join("disk.img"), guestos_device.path()).unwrap();

        guestos_device
    });

    /// A running service and methods to interact with it from the test code.
    struct TestServiceInstance {
        task: JoinHandle<Result<(), GuestVmServiceError>>,
        vm_domain_name: String,
        libvirt_connection: Connect,
        console_file: NamedTempFile,
        metrics_file: NamedTempFile,
        systemd_notifier: Arc<MockSystemdNotifier>,
        termination_token: CancellationToken,
        _sev_certificate_cache_dir: TempDir,
    }

    impl TestServiceInstance {
        async fn wait_for_systemd_ready(&mut self) {
            tokio::select! {
                biased;
                    _ = self.systemd_notifier.await_ready() => {/*success*/},
                result = &mut self.task => {
                    panic!("{} stopped before becoming ready. Status: {result:?}", self.vm_domain_name);
                }
            }
        }

        async fn wait_for_vm_shutdown(&mut self) {
            loop {
                if Domain::lookup_by_name(&self.libvirt_connection, &self.vm_domain_name).is_err() {
                    return;
                }
                sleep(Duration::from_millis(100)).await;
            }
        }

        fn get_domain(&self) -> Domain {
            Domain::lookup_by_name(&self.libvirt_connection, &self.vm_domain_name)
                .expect("Failed to find VM domain")
        }

        fn assert_vm_running(&self) {
            let domain = self.get_domain();
            assert_eq!(
                domain.get_state(),
                Ok((VIR_DOMAIN_RUNNING, VIR_DOMAIN_RUNNING_BOOTED as _))
            );
        }

        fn assert_vm_not_exists(&self) {
            Domain::lookup_by_name(&self.libvirt_connection, &self.vm_domain_name)
                .expect_err("Expected VM domain to not exist");
        }

        fn read_console(&self) -> String {
            let console_content =
                std::fs::read(&self.console_file).expect("Failed to read console log");
            String::from_utf8(console_content).expect("Console log is not valid UTF-8")
        }

        fn assert_metrics_contains(&self, expected: &str) {
            let metrics = std::fs::read_to_string(&self.metrics_file).unwrap();
            assert!(
                metrics.contains(expected),
                "Metrics file does not contain expected content '{expected}'\n\
                Metrics content:\n{metrics}",
            );
        }

        async fn wait_for_console_contains(&self, expected_parts: &[&str]) {
            const MAX_ATTEMPTS: u64 = 20;
            'retry: for attempt in 1..=MAX_ATTEMPTS {
                let console_content = self.read_console();
                for part in expected_parts {
                    if !console_content.contains(part) {
                        if attempt == MAX_ATTEMPTS {
                            panic!(
                                "Console content does not contain '{part}'\nConsole content:\n{console_content}"
                            );
                        }
                        sleep(Duration::from_millis(attempt * 50)).await;
                        continue 'retry;
                    };
                }
            }
        }

        fn assert_console_contains(&self, expected_parts: &[&str]) {
            let console_content = self.read_console();
            for part in expected_parts {
                assert!(
                    console_content.contains(part),
                    "Console content does not contain '{part}'\nConsole content:\n{console_content}"
                );
            }
        }

        fn get_config_media_path(&self) -> PathBuf {
            let domain = self.get_domain();
            let vm_config = domain.get_xml_desc(0).unwrap();
            PathBuf::from(
                &Regex::new("<source file='([^']+)'")
                    .unwrap()
                    .captures(&vm_config)
                    .expect("Config media path not found in VM config")[1],
            )
        }

        fn get_kernel_path(&self) -> PathBuf {
            let domain = self.get_domain();
            let vm_config = domain.get_xml_desc(0).unwrap();
            PathBuf::from(
                &Regex::new("<kernel>([^']+)</kernel>")
                    .unwrap()
                    .captures(&vm_config)
                    .expect("Kernel path not found in VM config")[1],
            )
        }

        fn get_kernel_cmdline(&self) -> String {
            let domain = self.get_domain();
            let vm_config = domain.get_xml_desc(0).unwrap();
            Regex::new("<cmdline>([^']+)</cmdline>")
                .unwrap()
                .captures(&vm_config)
                .expect("Kernel cmdline not found in VM config")[1]
                .to_string()
        }

        #[allow(dead_code)] // Remove once used
        fn terminate(&self) {
            self.termination_token.cancel();
        }
    }

    /// Test fixture for setting up the test environment
    struct TestFixture {
        libvirt_connection: Connect,
        hostos_config: HostOSConfig,
        guestos_device: PathBuf,
        mock_mounter: ExtractingFilesystemMounter,
        /// Fake libvirt host definition that backs `libvirt_connection`.
        _libvirt_definition: NamedTempFile,
        guestos_boot_timeout: Duration,
        guest_serial_log: NamedTempFile,
    }

    impl TestFixture {
        fn new(hostos_config: HostOSConfig) -> TestFixture {
            let libvirt_definition =
                NamedTempFile::new().expect("Failed to create libvirt connection");
            std::fs::write(&libvirt_definition, "<node/>").unwrap();

            let libvirt_connection = Connect::open(Some(&format!(
                "test://{}",
                libvirt_definition.path().display()
            )))
            .unwrap();

            TestFixture {
                libvirt_connection,
                hostos_config,
                guestos_device: GUESTOS_IMAGE.path().to_path_buf(),
                mock_mounter: ExtractingFilesystemMounter::default(),
                _libvirt_definition: libvirt_definition,
                guestos_boot_timeout: GUESTOS_BOOT_TIMEOUT,
                guest_serial_log: NamedTempFile::new().unwrap(),
            }
        }

        /// Starts a VM service in the background.
        /// This roughly corresponds to invoking `run_guest_vm()` in prod code.
        /// The returned instance can be used to interact with the newly started service.
        fn start_service(&self, guest_vm_type: GuestVMType) -> TestServiceInstance {
            let console_file = NamedTempFile::new().expect("Failed to create console log file");
            let metrics_file = NamedTempFile::new().expect("Failed to create metrics file");
            let systemd_notifier = Arc::new(MockSystemdNotifier::new());
            let termination_token = CancellationToken::new();
            let (sev_certificate_provider, sev_certificate_cache_dir) =
                mock_host_sev_certificate_provider()
                    .expect("Failed to create mock SEV cert provider");
            let mut service = GuestVmService {
                metrics_writer: MetricsWriter::new(metrics_file.path().to_path_buf()),
                libvirt_connection: self.libvirt_connection.clone(),
                hostos_config: self.hostos_config.clone(),
                systemd_notifier: systemd_notifier.clone(),
                console_ttys: vec![Mutex::new(Box::new(
                    File::create(console_file.path()).unwrap(),
                ))],
                partition_provider: Box::new(
                    GptPartitionProvider::with_mounter(
                        self.guestos_device.clone(),
                        Box::new(self.mock_mounter.clone()),
                    )
                    .unwrap(),
                ),
                guest_vm_type,
                sev_certificate_provider,
                disk_device: GUESTOS_DEVICE.into(),
                _upgrade_mapped_device: None,
                guestos_boot_timeout: self.guestos_boot_timeout,
                vm_serial_log_path: self.guest_serial_log.path().to_path_buf(),
            };

            // Start the service in the background
            let termination_token_clone = termination_token.clone();
            let task = tokio::spawn(async move { service.run(termination_token_clone).await });

            TestServiceInstance {
                task,
                console_file,
                metrics_file,
                systemd_notifier,
                termination_token,
                libvirt_connection: self.libvirt_connection.clone(),
                vm_domain_name: vm_domain_name(guest_vm_type).to_string(),
                _sev_certificate_cache_dir: sev_certificate_cache_dir,
            }
        }
    }

    fn valid_hostos_config() -> HostOSConfig {
        HostOSConfig {
            config_version: "".to_string(),
            network_settings: NetworkSettings {
                ipv6_config: Ipv6Config::Deterministic(DeterministicIpv6Config {
                    prefix: "2001:db8::".to_string(),
                    prefix_length: 64,
                    gateway: "2001:db8::1".parse().unwrap(),
                }),
                ipv4_config: None,
                domain_name: None,
            },
            icos_settings: ICOSSettings {
                node_reward_type: None,
                mgmt_mac: Default::default(),
                deployment_environment: DeploymentEnvironment::Mainnet,
                nns_urls: vec![],
                use_node_operator_private_key: false,
                enable_trusted_execution_environment: false,
                use_ssh_authorized_keys: false,
                icos_dev_settings: Default::default(),
            },
            hostos_settings: HostOSSettings {
                verbose: false,
                hostos_dev_settings: HostOSDevSettings {
                    vm_memory: 16,
                    vm_cpu: "qemu".to_string(),
                    vm_nr_of_vcpus: 56,
                },
            },
            guestos_settings: Default::default(),
        }
    }

    fn invalid_hostos_config() -> HostOSConfig {
        let mut hostos_config = valid_hostos_config();
        hostos_config
            .hostos_settings
            .hostos_dev_settings
            .vm_nr_of_vcpus = 0;
        hostos_config
    }

    #[tokio::test]
    async fn test_run_guest_vm() {
        let fixture = TestFixture::new(valid_hostos_config());
        let mut service = fixture.start_service(GuestVMType::Default);
        // The signal handlers work on the process level. All unit tests in this file are run in the
        // same process. We must only test the signal handler in one test otherwise a signal sent in
        // one unit test may be caught by a service running in another unit test which leads to
        // unexpected test results.
        // An alternative is `service.terminate()` which fakes termination and does not interfere
        // with other tests.
        setup_signal_handler(service.termination_token.clone()).unwrap();

        // Wait for the service to start the VM and notify systemd
        service.wait_for_systemd_ready().await;

        service.assert_metrics_contains("hostos_guestos_service_start 1");
        service.assert_vm_running();
        service.assert_console_contains(&[
            "GuestOS virtual machine launched",
            "2001:db8::6800:d8ff:fecb:f597",
        ]);

        // Ensure that the config media and kernel exist
        let config_media_path = service.get_config_media_path();
        assert!(config_media_path.exists());
        let kernel_path = service.get_kernel_path();
        assert!(kernel_path.exists());

        nix::sys::signal::raise(SIGTERM).expect("Failed to send SIGTERM");

        tokio::time::timeout(Duration::from_secs(2), service.wait_for_vm_shutdown())
            .await
            .expect("VM did not shut down within 2 seconds");
        service
            .task
            .await
            .expect("Could not join task")
            .expect("Task did not return Ok(())");
    }

    #[tokio::test]
    async fn test_vm_killed() {
        let fixture = TestFixture::new(valid_hostos_config());
        let mut service = fixture.start_service(GuestVMType::Default);
        // Wait for the service to start the VM and notify systemd
        service.wait_for_systemd_ready().await;

        // Kill the VM
        service.get_domain().destroy().unwrap();

        assert!(matches!(
            service.task.await.unwrap().unwrap_err(),
            GuestVmServiceError::VirtualMachineStopped
        ));
    }

    #[tokio::test]
    async fn test_vm_cannot_be_started() {
        let fixture = TestFixture::new(invalid_hostos_config());
        let mut service = fixture.start_service(GuestVMType::Default);

        // Wait until the service fails
        let error = (&mut service.task)
            .await
            .expect("Service should have failed but did not")
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Failed to define GuestOS virtual machine"),
            "Got unexpected error: \"{error:?}\""
        );

        service.assert_metrics_contains("hostos_guestos_service_start 0");
        service.assert_vm_not_exists();
        service
            .assert_console_contains(&["Failed to create domain", "2001:db8::6800:d8ff:fecb:f597"]);
    }

    #[tokio::test]
    async fn test_stops_already_running_vm() {
        let fixture = TestFixture::new(valid_hostos_config());

        let mut service1 = fixture.start_service(GuestVMType::Default);
        service1.wait_for_systemd_ready().await;

        let mut service2 = fixture.start_service(GuestVMType::Default);

        service2.wait_for_systemd_ready().await;

        // Assert that the first service was stopped
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), service1.task)
                .await
                .unwrap()
                .unwrap()
                .expect_err("Stopped VM service did not return error"),
            GuestVmServiceError::VirtualMachineStopped
        ));
    }

    #[tokio::test]
    async fn test_run_default_and_upgrade_vm_at_once() {
        let fixture = TestFixture::new(valid_hostos_config());

        let mut service1 = fixture.start_service(GuestVMType::Default);
        service1.wait_for_systemd_ready().await;

        let mut service2 = fixture.start_service(GuestVMType::Upgrade);
        service2.wait_for_systemd_ready().await;

        // Assert that both VMs are running
        service1.assert_vm_running();
        service2.assert_vm_running();

        assert!(service1.get_kernel_cmdline().contains("root=/dev/vda5"));
        assert!(service2.get_kernel_cmdline().contains("root=/dev/vda8"));
    }

    #[tokio::test]
    async fn test_guestos_boot_success() {
        let mut fixture = TestFixture::new(valid_hostos_config());
        let mut service = fixture.start_service(GuestVMType::Default);
        service.wait_for_systemd_ready().await;
        writeln!(
            fixture.guest_serial_log,
            "foo bar\n{GUESTOS_BOOT_SUCCESS_MARKER}"
        )
        .unwrap();
        service
            .wait_for_console_contains(&["GuestOS boot succeeded"])
            .await;
        assert!(!service.read_console().contains("foo bar"));
    }

    #[tokio::test]
    async fn test_guestos_boot_failure() {
        let mut fixture = TestFixture::new(valid_hostos_config());
        let mut service = fixture.start_service(GuestVMType::Default);
        service.wait_for_systemd_ready().await;
        writeln!(
            fixture.guest_serial_log,
            "foo bar\n{GUESTOS_BOOT_FAILURE_MARKER}"
        )
        .unwrap();
        service
            .wait_for_console_contains(&["GuestOS boot failed", "foo bar"])
            .await;
    }

    #[tokio::test]
    async fn test_guestos_boot_timeout() {
        let mut fixture = TestFixture::new(valid_hostos_config());
        fixture.guestos_boot_timeout = Duration::from_millis(50);
        let mut service = fixture.start_service(GuestVMType::Default);
        service.wait_for_systemd_ready().await;
        writeln!(fixture.guest_serial_log, "foo bar").unwrap();
        sleep(Duration::from_millis(500)).await;
        service
            .wait_for_console_contains(&["GuestOS boot timed out", "foo bar"])
            .await;
    }
}
