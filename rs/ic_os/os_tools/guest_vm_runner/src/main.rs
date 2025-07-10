use crate::guest_direct_boot::{prepare_direct_boot, DirectBoot};
use crate::guest_vm_config::{
    assemble_config_media, generate_vm_config, serial_log_path, vm_domain_name,
};
use crate::mount::PartitionProvider;
use crate::systemd_notifier::SystemdNotifier;
use anyhow::{anyhow, bail, Context, Error, Result};
use clap::{Parser, ValueEnum};
use config_types::{HostOSConfig, Ipv6Config};
use deterministic_ips::node_type::NodeType;
use deterministic_ips::{calculate_deterministic_mac, IpVariant, MacAddr6Ext};
use ic_metrics_tool::{Metric, MetricsWriter};
use std::fmt::{Debug, Formatter};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::process::Command;
use tokio::signal::unix::{signal, SignalKind};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use virt::connect::Connect;
use virt::domain::Domain;
use virt::error::{ErrorDomain, ErrorNumber};
use virt::sys::{VIR_DOMAIN_DESTROY_GRACEFUL, VIR_DOMAIN_NONE, VIR_DOMAIN_RUNNING};

mod boot_args;
mod guest_direct_boot;
mod guest_vm_config;
mod mount;
mod systemd_notifier;

const DEFAULT_METRICS_FILE_PATH: &str =
    "/run/node_exporter/collector_textfile/hostos_guestos_service.prom";
const UPGRADE_METRICS_FILE_PATH: &str =
    "/run/node_exporter/collector_textfile/hostos_guestos_upgrade_service.prom";

const DEFAULT_GUESTOS_SERVICE_NAME: &str = "guestos.service";
const UPGRADE_GUESTOS_SERVICE_NAME: &str = "upgrade-guestos.service";

const CONSOLE_TTY_PATH: &str = "/dev/tty1";
const GUESTOS_DEVICE: &str = "/dev/hostlvm/guestos";

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
            Err(GuestVmServiceError::VirtualMachineStopped) => {
                println!("Guest VM stopped, restarting");
                continue;
            }
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
        let mut retries = 3;
        let domain = loop {
            let domain_result = Domain::create_xml(libvirt_connect, xml_config, VIR_DOMAIN_NONE);
            match domain_result {
                Ok(domain) => break domain,
                Err(e)
                    if retries > 0
                        && e.code() == ErrorNumber::OperationInvalid
                        && e.domain() == ErrorDomain::Domain =>
                {
                    Self::try_destroy_existing_vm(libvirt_connect, vm_domain_name);
                    retries -= 1;
                    continue;
                }
                err => err.context("Failed to create domain")?,
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
        println!("Attempting to destroy existing '{vm_domain_name}' domain");
        if let Err(e) = Domain::lookup_by_name(libvirt_connect, vm_domain_name)
            .and_then(|existing| existing.destroy_flags(VIR_DOMAIN_DESTROY_GRACEFUL))
        {
            eprintln!("Failed to destroy existing domain: {e}");
        }
    }

    /// Checks if the virtual machine is currently running
    fn is_running(&self) -> bool {
        let Ok(domain) = self.get_domain() else {
            eprintln!("Failed to get domain");
            return false;
        };

        match domain.get_state() {
            Ok((state, _reason)) => state == VIR_DOMAIN_RUNNING,
            Err(err) => {
                eprintln!("Failed to get domain state: {err}");
                false
            }
        }
    }

    fn get_domain(&self) -> Result<Domain> {
        Domain::lookup_by_id(&self.libvirt_connect, self.domain_id)
            .context("Domain no longer exists")
    }

    /// Returns once the VM is no longer running.
    async fn wait_for_shutdown(&self) {
        while self.is_running() {
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
        if self.is_running() {
            println!("Shutting down {} domain gracefully", self.domain_name);
            if let Err(e) = self.get_domain().and_then(|domain| {
                domain
                    .destroy_flags(VIR_DOMAIN_DESTROY_GRACEFUL)
                    .context("Failed to gracefully destroy domain")
            }) {
                eprintln!("{e}");
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
    console_tty: Box<dyn Write + Send + Sync>,
    partition_provider: Box<dyn PartitionProvider>,
    guest_vm_type: GuestVMType,
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
        let console_tty = std::fs::File::options()
            .write(true)
            .open(CONSOLE_TTY_PATH)
            .context("Failed to open console")?;

        Ok(Self {
            metrics_writer,
            libvirt_connection,
            hostos_config,
            guest_vm_type,
            systemd_notifier: Arc::new(systemd_notifier::DefaultSystemdNotifier),
            console_tty: Box::new(console_tty),
            partition_provider: Box::new(mount::GptPartitionProvider::new(GUESTOS_DEVICE.into())?),
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
                self.handle_startup_error(&err).await?;
                self.metrics_writer
                    .write_metrics(&[Metric::with_annotation(
                        "hostos_guestos_service_start",
                        0.0,
                        "GuestOS virtual machine define state",
                    )])?;
                return Err(err.into());
            }
        };

        // Wait for VM to shut down or for stop signal
        self.monitor_virtual_machine(&virtual_machine, termination_token)
            .await
    }

    async fn start_virtual_machine(&mut self) -> Result<VirtualMachine> {
        let config_media = NamedTempFile::new().context("Failed to create config media file")?;

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

        assemble_config_media(&self.hostos_config, self.guest_vm_type, config_media.path())
            .context("Failed to assemble config media")?;

        let vm_config = generate_vm_config(
            &self.hostos_config,
            config_media.path(),
            direct_boot.as_ref().map(DirectBoot::to_config),
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
    async fn handle_startup_error(&mut self, e: &Error) -> Result<()> {
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

        self.display_systemd_logs().await?;

        self.write_to_console("#################################################");
        self.write_to_console("###          TROUBLESHOOTING INFO...          ###");
        self.write_to_console("#################################################");
        self.write_to_console(&format!(
            "Host IPv6 address: {}",
            self.get_host_ipv6_address()
        ));

        // Check for and display serial logs if they exist
        self.display_serial_logs().await?;

        self.write_to_console_and_stdout(&format!(
            "Exiting so that systemd can restart {}",
            self.systemd_service_name()
        ));

        Ok(())
    }

    /// Captures and displays journalctl logs for the guestos service
    async fn display_systemd_logs(&mut self) -> Result<()> {
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

    /// Displays serial logs from the console log file if it exists
    async fn display_serial_logs(&mut self) -> Result<()> {
        let serial_log_path = serial_log_path(self.guest_vm_type);
        if serial_log_path.exists() {
            self.write_to_console_and_stdout("#################################################");
            self.write_to_console_and_stdout("###  LOGGING GUESTOS CONSOLE LOGS, IF ANY...  ###");
            self.write_to_console_and_stdout("#################################################");

            let tail_output = Command::new("tail")
                .args(["-n", "30", serial_log_path.to_str().unwrap()])
                .output()
                .await
                .context("Failed to tail serial log")?;

            let logs = String::from_utf8_lossy(&tail_output.stdout);
            for line in logs.lines() {
                self.write_to_console_and_stdout(line);
            }
        } else {
            self.write_to_console_and_stdout("No console log file found.");
        }

        Ok(())
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
    fn write_to_console_and_stdout(&mut self, message: &str) {
        self.write_to_console(message);
        println!("{message}");
    }

    fn write_to_console(&mut self, message: &str) {
        let _ignore = writeln!(self.console_tty, "{message}");
        let _ignore = self.console_tty.flush();
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
    use crate::mount::testing::ExtractingFilesystemMounter;
    use crate::mount::GptPartitionProvider;
    use crate::systemd_notifier::testing::MockSystemdNotifier;
    use config_types::{
        DeploymentEnvironment, DeterministicIpv6Config, HostOSSettings, ICOSSettings,
        NetworkSettings,
    };
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

        let guestos_device = NamedTempFile::new().unwrap();
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
    }

    impl TestServiceInstance {
        async fn wait_for_systemd_ready(&mut self) {
            tokio::select! {
                biased;
                    _ = self.systemd_notifier.await_ready() => {/*success*/},
                result = &mut self.task => {
                    panic!("{} stopped before becoming ready. Status: {result:?}", self.vm_domain_name);
                }
            };
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
            let config_media_path = PathBuf::from(
                &Regex::new("<source file='([^']+)'")
                    .unwrap()
                    .captures(&vm_config)
                    .expect("Config media path not found in VM config")[1],
            );
            config_media_path
        }

        fn get_kernel_path(&self) -> PathBuf {
            let domain = self.get_domain();
            let vm_config = domain.get_xml_desc(0).unwrap();
            let kernel_path = PathBuf::from(
                &Regex::new("<kernel>([^']+)</kernel>")
                    .unwrap()
                    .captures(&vm_config)
                    .expect("Kernel path not found in VM config")[1],
            );
            kernel_path
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
                mock_mounter: ExtractingFilesystemMounter::new(),
                _libvirt_definition: libvirt_definition,
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
            let mut service = GuestVmService {
                metrics_writer: MetricsWriter::new(metrics_file.path().to_path_buf()),
                libvirt_connection: self.libvirt_connection.clone(),
                hostos_config: self.hostos_config.clone(),
                systemd_notifier: systemd_notifier.clone(),
                console_tty: Box::new(File::create(console_file.path()).unwrap()),
                partition_provider: Box::new(
                    GptPartitionProvider::with_mounter(
                        self.guestos_device.clone(),
                        Box::new(self.mock_mounter.clone()),
                    )
                    .unwrap(),
                ),
                guest_vm_type,
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
                logging: Default::default(),
                use_nns_public_key: false,
                nns_urls: vec![],
                use_node_operator_private_key: false,
                enable_trusted_execution_environment: false,
                use_ssh_authorized_keys: false,
                icos_dev_settings: Default::default(),
            },
            hostos_settings: HostOSSettings {
                vm_memory: 490,
                vm_cpu: "qemu".to_string(),
                vm_nr_of_vcpus: 56,
                verbose: false,
            },
            guestos_settings: Default::default(),
        }
    }

    fn invalid_hostos_config() -> HostOSConfig {
        let mut hostos_config = valid_hostos_config();
        hostos_config.hostos_settings.vm_memory = 0;
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
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("Failed to define GuestOS virtual machine"),
            "Got unexpected error: \"{error}\""
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
}
