use anyhow::{anyhow, bail, Context, Result};
use config::deserialize_config;
use config::guest_vm_config::{assemble_config_media, generate_vm_config};
use config_types::{HostOSConfig, Ipv6Config};
use deterministic_ips::node_type::NodeType;
use deterministic_ips::{calculate_deterministic_mac, IpVariant, MacAddr6Ext};
use ic_metrics_tool::{Metric, MetricsWriter};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::process::Command;
use tokio::signal::unix::{signal, SignalKind};
use tokio::time::sleep;
use virt::connect::Connect;
use virt::domain::Domain;
use virt::error::{Error, ErrorDomain, ErrorNumber};
use virt::sys::{VIR_DOMAIN_DESTROY_GRACEFUL, VIR_DOMAIN_RUNNING};

const GUESTOS_DOMAIN_NAME: &str = "guestos";
const CONSOLE_LOG_PATH: &str = "/var/log/libvirt/qemu/guestos-serial.log";
const METRICS_FILE_PATH: &str = "/run/node_exporter/collector_textfile/hostos_guestos_service.prom";
const CONSOLE_TTY_PATH: &str = "/dev/tty1";

/// Writes a message to the tty1 console and logs it
fn write_to_console(message: &str) -> Result<()> {
    let mut file = File::options()
        .write(true)
        .open(CONSOLE_TTY_PATH)
        .context("Failed to open console")?;

    writeln!(file, "{message}")?;

    // Also log to syslog
    println!("{message}");

    Ok(())
}

/// Manages a libvirt-based virtual machine
pub struct VirtualMachine {
    domain: Domain,
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
            domain,
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
    pub fn is_running(&self) -> bool {
        match self.domain.get_state() {
            Ok((state, _reason)) => state == VIR_DOMAIN_RUNNING,
            Err(err) => {
                eprintln!("Failed to get domain state: {}", err);
                false
            }
        }
    }

    /// Returns once the VM is no longer running.
    pub async fn wait_for_shutdown(&self) {
        while self.is_running() {
            sleep(Duration::from_secs(1)).await;
        }
    }
}

impl Drop for VirtualMachine {
    /// Ensures the VM is properly shut down when the object is dropped
    fn drop(&mut self) {
        if self.is_running() {
            println!("Shutting down {GUESTOS_DOMAIN_NAME} domain gracefully");
            if let Err(e) = self.domain.destroy_flags(VIR_DOMAIN_DESTROY_GRACEFUL) {
                eprintln!("Failed to gracefully destroy domain: {}", e);
            }
        }
    }
}

/// Service responsible for managing the GuestOS virtual machine lifecycle
pub struct GuestVmService {
    metrics_writer: MetricsWriter,
    libvirt_connection: Connect,
    hostos_config: HostOSConfig,
}

impl GuestVmService {
    pub fn new() -> Result<Self> {
        let metrics_writer = MetricsWriter::new(PathBuf::from(METRICS_FILE_PATH));
        let libvirt_connection = Connect::open(None).context("Failed to connect to libvirt")?;
        let hostos_config: HostOSConfig =
            deserialize_config(config::DEFAULT_HOSTOS_CONFIG_OBJECT_PATH)
                .context("Failed to read HostOS config file")?;

        Ok(Self {
            metrics_writer,
            libvirt_connection,
            hostos_config,
        })
    }

    /// Runs the GuestOS service
    pub async fn run(&self) -> Result<()> {
        let virtual_machine = self.start_virtual_machine().await?;

        self.metrics_writer
            .write_metrics(&[Metric::with_annotation(
                "hostos_guestos_service_start",
                1.0,
                "GuestOS virtual machine define state",
            )])?;

        // Wait for VM to shut down or for stop signal
        self.monitor_virtual_machine(&virtual_machine).await
    }

    async fn start_virtual_machine(&self) -> Result<VirtualMachine> {
        let config_media = NamedTempFile::new()?;
        assemble_config_media(&self.hostos_config, config_media.path())?;

        let vm_config = generate_vm_config(&self.hostos_config, config_media.path())
            .context("Failed to generate GuestOS VM config")?;

        println!("Creating GuestOS virtual machine");

        let virtual_machine =
            match VirtualMachine::new(&self.libvirt_connection, &vm_config, config_media) {
                Ok(virtual_machine) => virtual_machine,
                Err(e) => {
                    self.handle_startup_error().await?;
                    bail!("Failed to define GuestOS virtual machine: {e}");
                }
            };

        // Notify systemd that we're ready
        #[cfg(target_os = "linux")]
        systemd::daemon::notify(false, [(systemd::daemon::STATE_READY, "1")].iter())?;

        println!("Started GuestOS virtual machine");

        // Wait before printing messages to console
        sleep(Duration::from_secs(10)).await;

        self.display_startup_messages()?;

        self.metrics_writer
            .write_metrics(&[Metric::with_annotation(
                "hostos_guestos_service_start",
                1.0,
                "GuestOS virtual machine start state",
            )])?;

        Ok(virtual_machine)
    }

    fn display_startup_messages(&self) -> Result<()> {
        write_to_console("")?;
        write_to_console("#################################################")?;
        write_to_console("GuestOS virtual machine launched")?;
        write_to_console("IF ONBOARDING, please wait for up to 10 MINUTES for a 'Join request successful!' message")?;
        write_to_console(&format!(
            "Host IPv6 address: {}",
            self.get_host_ipv6_address()
        ))?;
        write_to_console("#################################################")?;

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
            Err(e) => format!("Error: Failed to get IPv6 address: {}", e),
        }
    }

    /// Handles errors that occur during VM startup
    async fn handle_startup_error(&self) -> Result<()> {
        // Give QEMU time to clear the console before printing error messages
        sleep(Duration::from_secs(10)).await;

        write_to_console("ERROR: Failed to start GuestOS virtual machine.")?;
        write_to_console("#################################################")?;
        write_to_console("###      LOGGING GUESTOS.SERVICE LOGS...      ###")?;
        write_to_console("#################################################")?;

        self.display_service_logs().await?;

        write_to_console("#################################################")?;
        write_to_console("###          TROUBLESHOOTING INFO...          ###")?;
        write_to_console("#################################################")?;
        write_to_console(&format!(
            "Host IPv6 address: {}",
            self.get_host_ipv6_address()
        ))?;

        // Check for and display serial logs if they exist
        self.display_serial_logs().await?;

        write_to_console("Exiting guestos so that systemd can restart guestos.service.")?;

        Ok(())
    }

    /// Captures and displays journalctl logs for the guestos service
    async fn display_service_logs(&self) -> Result<()> {
        let journalctl_output = Command::new("journalctl")
            .args(["-u", "guestos.service"])
            .output()
            .await
            .context("Failed to run journalctl")?;

        let logs = String::from_utf8_lossy(&journalctl_output.stdout);
        for line in logs.lines() {
            write_to_console(line)?;
        }

        Ok(())
    }

    /// Displays serial logs from the console log file if it exists
    async fn display_serial_logs(&self) -> Result<()> {
        let serial_log_path = Path::new(CONSOLE_LOG_PATH);
        if serial_log_path.exists() {
            write_to_console("#################################################")?;
            write_to_console("###  LOGGING GUESTOS CONSOLE LOGS, IF ANY...  ###")?;
            write_to_console("#################################################")?;

            let tail_output = Command::new("tail")
                .args(["-n", "30", serial_log_path.to_str().unwrap()])
                .output()
                .await
                .context("Failed to tail serial log")?;

            let logs = String::from_utf8_lossy(&tail_output.stdout);
            for line in logs.lines() {
                write_to_console(line)?;
            }
        } else {
            write_to_console("No console log file found.")?;
        }

        Ok(())
    }

    /// Monitors the virtual machine for shutdown or stop signals
    async fn monitor_virtual_machine(&self, vm: &VirtualMachine) -> Result<()> {
        let mut sigterm = signal(SignalKind::terminate())?;
        let mut sigint = signal(SignalKind::interrupt())?;

        let on_interrupt = || {
            println!("Received stop signal, shutting down VM");
            self.metrics_writer
                .write_metrics(&[Metric::with_annotation(
                    "hostos_guestos_service_graceful_shutdown",
                    1.0,
                    "GuestOS virtual machine graceful shutdown",
                )])?;
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

                // // Notify systemd we're stopping
                #[cfg(target_os = "linux")]
                systemd::daemon::notify(false, [
                    (systemd::daemon::STATE_STOPPING, "1"),
                    (systemd::daemon::STATE_STATUS, "GuestOS VM shut down unexpectedly.")
                ].iter())?;

                Err(anyhow!("GuestOS VM shut down unexpectedly"))
            }
        }
    }
}

/// The main async function that runs the GuestOS service
pub async fn run_guest_vm() -> Result<()> {
    println!("Starting GuestOS service");

    let service = GuestVmService::new()?;
    service.run().await
}
