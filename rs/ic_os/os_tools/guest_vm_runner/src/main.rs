use crate::guest_direct_boot::{prepare_direct_boot, DirectBoot};
use crate::guest_vm_config::{assemble_config_media, generate_vm_config};
use crate::mount::PartitionProvider;
use crate::systemd_notifier::SystemdNotifier;
use anyhow::{anyhow, bail, Context, Error, Result};
use config_types::{HostOSConfig, Ipv6Config};
use deterministic_ips::node_type::NodeType;
use deterministic_ips::{calculate_deterministic_mac, IpVariant, MacAddr6Ext};
use ic_metrics_tool::{Metric, MetricsWriter};
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
use virt::sys::{VIR_DOMAIN_DESTROY_GRACEFUL, VIR_DOMAIN_RUNNING};

mod boot_args;
mod guest_direct_boot;
mod guest_vm_config;
mod mount;
mod systemd_notifier;

const GUESTOS_DOMAIN_NAME: &str = "guestos";
const CONSOLE_LOG_PATH: &str = "/var/log/libvirt/qemu/guestos-serial.log";
const METRICS_FILE_PATH: &str = "/run/node_exporter/collector_textfile/hostos_guestos_service.prom";
const CONSOLE_TTY_PATH: &str = "/dev/tty1";
const GUESTOS_SERVICE_NAME: &str = "guestos.service";
const DEFAULT_GUESTOS_DEVICE: &str = "/dev/hostlvm/guestos";

#[tokio::main]
pub async fn main() -> Result<()> {
    println!("Starting GuestOS service");

    let termination_token = CancellationToken::new();
    setup_signal_handler(termination_token.clone()).context("Failed to setup signal handler")?;
    let mut service = GuestVmService::new()?;
    service.run(termination_token).await
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
    ) -> Result<Self> {
        let mut retries = 3;
        let domain = loop {
            let domain_result =
                Domain::create_xml(libvirt_connect, xml_config, virt::sys::VIR_DOMAIN_NONE);
            match domain_result {
                Ok(domain) => break domain,
                Err(e)
                    if retries > 0
                        && e.code() == ErrorNumber::OperationInvalid
                        && e.domain() == ErrorDomain::Domain =>
                {
                    Self::try_destroy_existing_vm(libvirt_connect);
                    retries -= 1;
                    continue;
                }
                err => err.context("Failed to create domain")?,
            };
        };
        Ok(Self {
            domain_id: domain.get_id().context("Domain does not have id")?,
            libvirt_connect: libvirt_connect.clone(),
            _config_media: config_media,
            _direct_boot: direct_boot,
        })
    }

    fn try_destroy_existing_vm(libvirt_connect: &Connect) {
        println!("Attempting to destroy existing {GUESTOS_DOMAIN_NAME} domain");
        if let Err(e) = Domain::lookup_by_name(libvirt_connect, GUESTOS_DOMAIN_NAME)
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
            println!("Shutting down {GUESTOS_DOMAIN_NAME} domain gracefully");
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

/// Service responsible for managing the GuestOS virtual machine lifecycle
pub struct GuestVmService {
    metrics_writer: MetricsWriter,
    libvirt_connection: Connect,
    hostos_config: HostOSConfig,
    systemd_notifier: Arc<dyn SystemdNotifier>,
    console_tty: Box<dyn Write + Send + Sync>,
    partition_provider: Box<dyn PartitionProvider>,
}

impl GuestVmService {
    #[cfg(not(target_os = "linux"))]
    pub fn new() -> Result<Self> {
        anyhow::bail!("GuestVM service is only supported on Linux");
    }

    #[cfg(target_os = "linux")]
    pub fn new() -> Result<Self> {
        let metrics_writer = MetricsWriter::new(std::path::PathBuf::from(METRICS_FILE_PATH));
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
            systemd_notifier: Arc::new(crate::systemd_notifier::DefaultSystemdNotifier),
            console_tty: Box::new(console_tty),
            partition_provider: Box::new(crate::mount::GptPartitionProvider::new(
                DEFAULT_GUESTOS_DEVICE.into(),
            )?),
        })
    }

    /// Runs the GuestOS service
    pub async fn run(&mut self, termination_token: CancellationToken) -> Result<()> {
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
                return Err(err);
            }
        };

        // Wait for VM to shut down or for stop signal
        self.monitor_virtual_machine(&virtual_machine, termination_token)
            .await
    }

    async fn start_virtual_machine(&mut self) -> Result<VirtualMachine> {
        let config_media = NamedTempFile::new().context("Failed to create config media file")?;

        let direct_boot = prepare_direct_boot(
            // TODO: We should not refresh in Upgrade VMs once we add them
            /*should_refresh_grubenv=*/
            true,
            self.partition_provider.as_ref(),
        )
        .await
        .context("Failed to prepare direct boot")?;

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

        assemble_config_media(&self.hostos_config, config_media.path())
            .context("Failed to assemble config media")?;

        let vm_config = generate_vm_config(
            &self.hostos_config,
            config_media.path(),
            direct_boot.as_ref().map(DirectBoot::to_config),
        )
        .context("Failed to generate GuestOS VM config")?;

        println!("Creating GuestOS virtual machine");

        let virtual_machine = VirtualMachine::new(
            &self.libvirt_connection,
            &vm_config,
            config_media,
            direct_boot,
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
        self.write_to_console("###      LOGGING GUESTOS.SERVICE LOGS...      ###");
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
            "Exiting guestos so that systemd can restart {GUESTOS_SERVICE_NAME}"
        ));

        Ok(())
    }

    /// Captures and displays journalctl logs for the guestos service
    async fn display_systemd_logs(&mut self) -> Result<()> {
        let journalctl_output = Command::new("journalctl")
            .args(["-u", GUESTOS_SERVICE_NAME])
            .output()
            .await
            .context("Failed to run journalctl")?;

        let logs = String::from_utf8_lossy(&journalctl_output.stdout);
        for line in logs.lines() {
            self.write_to_console(line);
        }

        Ok(())
    }

    /// Displays serial logs from the console log file if it exists
    async fn display_serial_logs(&mut self) -> Result<()> {
        let serial_log_path = Path::new(CONSOLE_LOG_PATH);
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
    ) -> Result<()> {
        tokio::select! {
            biased;
            // Wait for either VM shutdown event or stop signal
            _ = termination_token.cancelled() => {
                println!("Received stop signal, shutting down VM");
                Ok(())
            },
            _ = vm.wait_for_shutdown() => {
                self.metrics_writer.write_metrics(&[Metric::with_annotation(
                    "hostos_guestos_service_unexpected_shutdown",
                    1.0,
                    "GuestOS virtual machine unexpected shutdown"
                )])?;

                // Notify systemd we're stopping
                self.systemd_notifier.notify_stopping("GuestOS VM stopped unexpectedly.")?;

                Err(anyhow!("GuestOS VM stopped unexpectedly"))
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
    use tokio::io::AsyncWriteExt;
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

        let mut guestos_device = NamedTempFile::new().unwrap();
        std::fs::rename(tempdir.path().join("disk.img"), guestos_device.path()).unwrap();

        guestos_device
    });

    /// A running service and methods to interact with it from the test code.
    struct TestServiceInstance {
        task: JoinHandle<Result<()>>,
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
                    panic!("Service stopped before becoming ready. Status: {result:?}");
                }
            };
        }

        async fn wait_for_systemd_stopping(&mut self) {
            tokio::select! {
                biased;
                _ = self.systemd_notifier.await_stopping() => {/*success*/},
                result = &mut self.task => {
                    panic!("Service stopped before notifying about stopping. Status: {result:?}");
                }
            };
        }

        fn get_domain(&self) -> Domain {
            Domain::lookup_by_name(&self.libvirt_connection, GUESTOS_DOMAIN_NAME)
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
            assert!(Domain::lookup_by_name(&self.libvirt_connection, GUESTOS_DOMAIN_NAME).is_err());
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

        async fn assert_no_systemd_stopping_notification(&mut self) {
            tokio::select! {
                _ = self.systemd_notifier.await_stopping() => {
                    panic!("Expected service to stop without systemd stopping notification");
                }
                result = &mut self.task => {
                    result.expect("Service panicked").expect("Service failed with error")
                }
            }
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
        fn start_service(&self) -> TestServiceInstance {
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
        let mut service = fixture.start_service();
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

        // The service should not notify systemd when stopping after receiving SIGTERM
        service.assert_no_systemd_stopping_notification().await;

        // The domain should be destroyed
        service.assert_vm_not_exists();
    }

    #[tokio::test]
    async fn test_vm_killed() {
        let fixture = TestFixture::new(valid_hostos_config());
        let mut service = fixture.start_service();
        // Wait for the service to start the VM and notify systemd
        service.wait_for_systemd_ready().await;

        // Kill the VM
        service.get_domain().destroy().unwrap();

        // The service should notify systemd about stopping
        service.wait_for_systemd_stopping().await;

        service.assert_metrics_contains("hostos_guestos_service_unexpected_shutdown 1");

        assert!(service
            .task
            .await
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("GuestOS VM stopped unexpectedly"));
    }

    #[tokio::test]
    async fn test_vm_cannot_be_started() {
        let fixture = TestFixture::new(invalid_hostos_config());
        let mut service = fixture.start_service();

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

        let mut service1 = fixture.start_service();
        service1.wait_for_systemd_ready().await;

        let mut service2 = fixture.start_service();

        service2.wait_for_systemd_ready().await;

        // Assert that the first service was stopped
        assert!(tokio::time::timeout(Duration::from_secs(1), service1.task)
            .await
            .unwrap()
            .unwrap()
            .expect_err("Stopped VM service did not return error")
            .to_string()
            .contains("GuestOS VM stopped unexpectedly"));
    }
}
