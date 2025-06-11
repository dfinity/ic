use crate::systemd::SystemdNotifier;
use anyhow::{anyhow, bail, Context, Error, Result};
use config::guest_vm_config::{assemble_config_media, generate_vm_config};
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
use virt::connect::Connect;
use virt::domain::Domain;
use virt::error::{ErrorDomain, ErrorNumber};
use virt::sys::{VIR_DOMAIN_DESTROY_GRACEFUL, VIR_DOMAIN_RUNNING};

const GUESTOS_DOMAIN_NAME: &str = "guestos";
const CONSOLE_LOG_PATH: &str = "/var/log/libvirt/qemu/guestos-serial.log";
const METRICS_FILE_PATH: &str = "/run/node_exporter/collector_textfile/hostos_guestos_service.prom";
const CONSOLE_TTY_PATH: &str = "/dev/tty1";
const GUESTOS_SERVICE_NAME: &str = "guestos.service";

/// Manages a libvirt-based virtual machine
pub struct VirtualMachine {
    domain_id: u32,
    libvirt_connect: Connect,
    // The config media is used by the virtual machine and must be kept alive until the virtual
    // machine is destroyed.
    _config_media: NamedTempFile,
}

impl VirtualMachine {
    /// Creates a new virtual machine from the provided XML configuration
    /// The `config_media` is moved into the struct and deleted when the struct goes out of scope.
    pub fn new(
        libvirt_connect: &Connect,
        xml_config: &str,
        config_media: NamedTempFile,
    ) -> Result<Self> {
        let mut retries = 3;
        let domain = loop {
            let domain_result = Domain::create_xml(libvirt_connect, xml_config, 0);
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
}

impl GuestVmService {
    #[cfg(not(target_os = "linux"))]
    pub fn new() -> Result<Self> {
        bail!("GuestVM service is only supported on Linux");
    }

    #[cfg(target_os = "linux")]
    pub fn new() -> Result<Self> {
        let metrics_writer = MetricsWriter::new(std::path::PathBuf::from(METRICS_FILE_PATH));
        let libvirt_connection = Connect::open(None).context("Failed to connect to libvirt")?;
        let hostos_config: HostOSConfig =
            crate::deserialize_config(config::DEFAULT_HOSTOS_CONFIG_OBJECT_PATH)
                .context("Failed to read HostOS config file")?;
        let console_tty = std::fs::File::options()
            .write(true)
            .open(CONSOLE_TTY_PATH)
            .context("Failed to open console")?;

        Ok(Self {
            metrics_writer,
            libvirt_connection,
            hostos_config,
            systemd_notifier: Arc::new(crate::systemd::DefaultSystemdNotifier),
            console_tty: Box::new(console_tty),
        })
    }

    /// Runs the GuestOS service
    pub async fn run(&mut self) -> Result<()> {
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
        self.monitor_virtual_machine(&virtual_machine).await
    }

    async fn start_virtual_machine(&mut self) -> Result<VirtualMachine> {
        let config_media = NamedTempFile::new()?;
        assemble_config_media(&self.hostos_config, config_media.path())?;

        let vm_config = generate_vm_config(&self.hostos_config, config_media.path())
            .context("Failed to generate GuestOS VM config")?;

        println!("Creating GuestOS virtual machine");

        let virtual_machine =
            match VirtualMachine::new(&self.libvirt_connection, &vm_config, config_media) {
                Ok(virtual_machine) => virtual_machine,
                Err(e) => {
                    self.handle_startup_error(&e, &vm_config).await?;
                    bail!("Failed to define GuestOS virtual machine: {e}");
                }
            };

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
        self.write_to_console("")?;
        self.write_to_console("#################################################")?;
        self.write_to_console("GuestOS virtual machine launched")?;
        self.write_to_console("IF ONBOARDING, please wait for up to 10 MINUTES for a 'Join request successful!' message")?;
        self.write_to_console(&format!(
            "Host IPv6 address: {}",
            self.get_host_ipv6_address()
        ))?;
        self.write_to_console("#################################################")?;

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
    async fn handle_startup_error(&mut self, e: &Error, vm_config: &str) -> Result<()> {
        // Give QEMU time to clear the console before printing error messages
        // (but not in unit tests otherwise tests take too long to finish).
        #[cfg(not(test))]
        sleep(Duration::from_secs(10)).await;

        self.write_to_console("ERROR: Failed to start GuestOS virtual machine.")?;
        self.write_to_console(&e.to_string())?;
        self.write_to_console("#################################################")?;
        self.write_to_console("###      LOGGING GUESTOS.SERVICE LOGS...      ###")?;
        self.write_to_console("#################################################")?;

        self.display_systemd_logs().await?;

        self.write_to_console("#################################################")?;
        self.write_to_console("###          TROUBLESHOOTING INFO...          ###")?;
        self.write_to_console("#################################################")?;
        self.write_to_console(&format!(
            "Host IPv6 address: {}",
            self.get_host_ipv6_address()
        ))?;

        println!("GuestVM config:");
        println!("{vm_config}");

        // Check for and display serial logs if they exist
        self.display_serial_logs().await?;

        self.write_to_console(&format!(
            "Exiting guestos so that systemd can restart {GUESTOS_SERVICE_NAME}"
        ))?;

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
            self.write_to_console(line)?;
        }

        Ok(())
    }

    /// Displays serial logs from the console log file if it exists
    async fn display_serial_logs(&mut self) -> Result<()> {
        let serial_log_path = Path::new(CONSOLE_LOG_PATH);
        if serial_log_path.exists() {
            self.write_to_console("#################################################")?;
            self.write_to_console("###  LOGGING GUESTOS CONSOLE LOGS, IF ANY...  ###")?;
            self.write_to_console("#################################################")?;

            let tail_output = Command::new("tail")
                .args(["-n", "30", serial_log_path.to_str().unwrap()])
                .output()
                .await
                .context("Failed to tail serial log")?;

            let logs = String::from_utf8_lossy(&tail_output.stdout);
            for line in logs.lines() {
                self.write_to_console(line)?;
            }
        } else {
            self.write_to_console("No console log file found.")?;
        }

        Ok(())
    }

    /// Monitors the virtual machine for shutdown or stop signals
    async fn monitor_virtual_machine(&self, vm: &VirtualMachine) -> Result<()> {
        let mut sigterm = signal(SignalKind::terminate())?;
        let mut sigint = signal(SignalKind::interrupt())?;

        let on_interrupt = || {
            println!("Received stop signal, shutting down VM");
            Ok(())
        };

        tokio::select! {
            biased;
            // Wait for either VM shutdown event or stop signal
            _ = sigterm.recv() => on_interrupt(),
            _ = sigint.recv() => on_interrupt(),
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

    /// Writes a message to the console and stdout
    fn write_to_console(&mut self, message: &str) -> Result<()> {
        writeln!(self.console_tty, "{message}")?;
        self.console_tty.flush()?;

        // Also log to stdout
        println!("{message}");

        Ok(())
    }
}

impl Drop for GuestVmService {
    fn drop(&mut self) {
        let _ignored = self.libvirt_connection.close();
    }
}

/// The main async function that runs the GuestOS service
pub async fn run_guest_vm() -> Result<()> {
    println!("Starting GuestOS service");

    let mut service = GuestVmService::new()?;
    service.run().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::systemd::testing::MockSystemdNotifier;
    use config_types::{
        DeploymentEnvironment, DeterministicIpv6Config, HostOSSettings, ICOSSettings,
        NetworkSettings,
    };
    use nix::sys::signal::SIGTERM;
    use regex::Regex;
    use std::fs::File;
    use std::path::PathBuf;
    #[allow(clippy::disallowed_types)] // OK for testing
    use tokio::sync::{Mutex, MutexGuard};
    use virt::sys::VIR_DOMAIN_RUNNING_BOOTED;

    /// We must run each test case sequentially because they all work with the same libvirt mock
    /// instance. Each test case must hold this mutex while using a libvirt connection.
    #[allow(clippy::disallowed_types)]
    static LIBVIRT_CONN_MUTEX: Mutex<()> = Mutex::const_new(());

    /// Test fixture for setting up the test environment
    struct TestFixture<'a> {
        pub libvirt_connection: Connect,
        pub systemd_notifier: Arc<MockSystemdNotifier>,
        pub console_file: NamedTempFile,
        pub metrics_file: NamedTempFile,
        _libvirt_lock: &'a MutexGuard<'a, ()>,
    }

    impl TestFixture<'_> {
        fn new<'a>(libvirt_lock: &'a MutexGuard<()>) -> TestFixture<'a> {
            TestFixture {
                libvirt_connection: Connect::open(Some("test:///default")).unwrap(),
                systemd_notifier: Arc::new(MockSystemdNotifier::new()),
                console_file: NamedTempFile::new().unwrap(),
                metrics_file: NamedTempFile::new().unwrap(),
                _libvirt_lock: libvirt_lock,
            }
        }

        fn create_service(&self, config: HostOSConfig) -> GuestVmService {
            let console_tty = Box::new(
                File::options()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(self.console_file.path())
                    .unwrap(),
            );

            GuestVmService {
                metrics_writer: MetricsWriter::new(self.metrics_file.path().to_path_buf()),
                libvirt_connection: self.libvirt_connection.clone(),
                hostos_config: config,
                systemd_notifier: self.systemd_notifier.clone(),
                console_tty,
            }
        }

        async fn wait_for_systemd_ready(&self) {
            tokio::time::timeout(Duration::from_secs(5), self.systemd_notifier.await_ready())
                .await
                .expect("Guest VM creation timed out");
        }

        async fn wait_for_systemd_stopping(&self) {
            tokio::time::timeout(
                Duration::from_secs(5),
                self.systemd_notifier.await_stopping(),
            )
            .await
            .expect("Systemd was not notified about stopping");
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

        async fn assert_no_systemd_stopping_notification(&self) {
            assert!(tokio::time::timeout(
                Duration::from_secs(1),
                self.systemd_notifier.await_stopping()
            )
            .await
            .is_err());
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
        let libvirt_lock = LIBVIRT_CONN_MUTEX.lock().await;
        let fixture = TestFixture::new(&libvirt_lock);
        let mut service = fixture.create_service(valid_hostos_config());

        // Run the VM in the background
        tokio::spawn(async move { service.run().await });

        // Wait for the service to start the VM and notify systemd
        fixture.wait_for_systemd_ready().await;

        fixture.assert_metrics_contains("hostos_guestos_service_start 1");
        fixture.assert_vm_running();
        fixture.assert_console_contains(&[
            "GuestOS virtual machine launched",
            "2001:db8::6800:d8ff:fecb:f597",
        ]);

        // Ensure that the config media exists
        let config_media_path = fixture.get_config_media_path();
        assert!(config_media_path.exists());

        nix::sys::signal::raise(SIGTERM).expect("Failed to send SIGTERM");

        // The service should not notify systemd when stopping after receiving SIGTERM
        fixture.assert_no_systemd_stopping_notification().await;

        // The domain should be destroyed
        fixture.assert_vm_not_exists();
    }

    #[tokio::test]
    async fn test_vm_killed() {
        let libvirt_lock = LIBVIRT_CONN_MUTEX.lock().await;
        let fixture = TestFixture::new(&libvirt_lock);
        let mut service = fixture.create_service(valid_hostos_config());

        // Run the VM in the background
        let vm_service_task = tokio::spawn(async move { service.run().await });

        // Wait for the service to start the VM and notify systemd
        fixture.wait_for_systemd_ready().await;

        let domain = fixture.get_domain();

        // Kill the VM
        domain.destroy().unwrap();

        // The service should notify systemd about stopping
        fixture.wait_for_systemd_stopping().await;

        fixture.assert_metrics_contains("hostos_guestos_service_unexpected_shutdown 1");

        assert!(vm_service_task
            .await
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("GuestOS VM stopped unexpectedly"));
    }

    #[tokio::test]
    async fn test_vm_cannot_be_started() {
        let libvirt_lock = LIBVIRT_CONN_MUTEX.lock().await;
        let fixture = TestFixture::new(&libvirt_lock);
        let mut service = fixture.create_service(invalid_hostos_config());

        // Run the VM and wait until it fails
        assert!(tokio::time::timeout(Duration::from_secs(5), service.run())
            .await
            .expect("Service should have failed but did not")
            .unwrap_err()
            .to_string()
            .contains("Failed to create domain"));

        fixture.assert_metrics_contains("hostos_guestos_service_start 0");
        fixture.assert_vm_not_exists();
        fixture
            .assert_console_contains(&["Failed to create domain", "2001:db8::6800:d8ff:fecb:f597"]);
    }

    #[tokio::test]
    async fn test_stops_already_running_vm() {
        let libvirt_lock = LIBVIRT_CONN_MUTEX.lock().await;
        let fixture1 = TestFixture::new(&libvirt_lock);
        let mut service1 = fixture1.create_service(valid_hostos_config());

        // Run the first VM in the background
        let task1 = tokio::spawn(async move { service1.run().await });

        fixture1.wait_for_systemd_ready().await;

        let fixture2 = TestFixture::new(&libvirt_lock);
        let mut service2 = fixture2.create_service(valid_hostos_config());

        // Start the second VM in the background
        tokio::spawn(async move { service2.run().await });

        // Check that the first VM got stopped
        assert!(tokio::time::timeout(Duration::from_secs(5), task1)
            .await
            .expect("Task1 was not interrupted in time")
            .unwrap()
            .expect_err("Stopped VM service did not return error")
            .to_string()
            .contains("GuestOS VM stopped unexpectedly"));

        // Check that the second VM started
        fixture2.wait_for_systemd_ready().await;
    }
}
