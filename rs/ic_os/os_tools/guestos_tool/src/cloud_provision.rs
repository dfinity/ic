use std::{
    process::{Child, Command, Stdio},
    time::Duration,
};

use anyhow::{Context, Error, Result, bail};
use config_tool::guestos::{cloud::CloudType, network::get_best_interface_name};
use config_types::GuestOSConfig;
use nix::{sys::signal::Signal::SIGTERM, unistd::Pid};
use tracing::info;

/// Assigns IPv4 DHCP address to the interface and unassigns it when dropped
#[derive(Debug)]
struct DHCPConfig {
    process: Child,
}

impl DHCPConfig {
    /// Starts dhcpcd to obtain a DHCP lease
    fn new(interface: String) -> Result<Self, Error> {
        // Fire up DHCP client.
        // Avoid reading default config since it might contain unneeded options and they take precedence.
        info!("Starting dhcpcd");
        let process = Command::new("/usr/sbin/dhcpcd")
            .args([
                "--nobackground",
                "--ipv4only",
                "--noipv4ll",
                "--config",
                "/dev/null",
                &interface,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("unable to execute /usr/sbin/dhcpcd")?;

        Ok(Self { process })
    }
}

impl Drop for DHCPConfig {
    fn drop(&mut self) {
        // Tell dhcpcd to shutdown & wait for it to happen
        info!("Sending SIGTERM to dhcpcd");
        let _ = nix::sys::signal::kill(Pid::from_raw(self.process.id() as i32), SIGTERM);
        let _ = self.process.wait();
        info!("dhcpcd successfully stopped");
    }
}

/// Tries to obtain the GuestOS config from the cloud's metadata service
pub fn obtain_guestos_config() -> Result<GuestOSConfig, Error> {
    info!("Figuring out the network interface to use...");

    // Find the network interface to work on, it might not be initialized yet so give it a few tries
    let mut retries = 30;
    let intf = loop {
        match get_best_interface_name() {
            Ok(v) => break v,
            Err(e) => {
                info!("Unable to choose interface: {e:#}");

                retries -= 1;
                if retries == 0 {
                    bail!("unable to choose interface: retries exhausted");
                }

                std::thread::sleep(Duration::from_secs(1));
            }
        }
    };
    info!("Interface found: {intf}");

    // Configure it with a DHCP
    let _dhcp = DHCPConfig::new(intf.clone()).context("unable to configure IPv4 DHCP")?;
    info!("DHCP on the interface {intf} configured");

    // Discover the cloud we're running in.
    let cloud_type = CloudType::discover().context("unable to discover cloud type")?;
    info!("Cloud type detected: {cloud_type:?}");

    // Get the config from the MDS
    let mut retries = 120;
    let config = loop {
        match cloud_type.obtain_config() {
            Ok(v) => break v,
            Err(e) => {
                retries -= 1;
                if retries == 0 {
                    bail!("unable to obtain config: retries exhausted");
                }

                info!("Unable to obtain GuestOS config (retries left: {retries}): {e:#}");
                std::thread::sleep(Duration::from_secs(1));
            }
        };
    };

    Ok(config)
}
