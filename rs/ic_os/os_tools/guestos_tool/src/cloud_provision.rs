use std::{
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::Duration,
};

use anyhow::{Context, Error, Result, bail};
use config_tool::guestos::{cloud::CloudType, network::get_best_interface_name};
use config_types::GuestOSConfig;
use nix::{sys::signal::Signal::SIGTERM, unistd::Pid};

/// Assigns IPv4 DHCP address to the interface and unassigns it when dropped
#[derive(Debug)]
struct DHCPConfig {
    config_path: PathBuf,
    process: Child,
}

impl DHCPConfig {
    /// Installs a temporary systemd-networkd config to obtain a DHCP lease
    fn new(interface: String, systemd_network_dir: PathBuf) -> Result<Self, Error> {
        std::fs::create_dir_all(&systemd_network_dir)
            .context("unable to create the systemd-networkd dir")?;

        let intf_config = indoc::formatdoc!(
            r#"
                [Match]
                Name={interface}
                Virtualization=!container

                [Network]
                DHCP=ipv4
            "#,
        );

        // Write the config
        let config_path = systemd_network_dir.join(format!("10-{interface}.network"));
        std::fs::write(&config_path, intf_config)
            .context("unable to write systemd network config")?;

        // Fire up systemd-networkd
        let process = Command::new("/usr/lib/systemd/systemd-networkd")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("unable to execute systemd-networkd")?;

        Ok(Self {
            config_path,
            process,
        })
    }
}

impl Drop for DHCPConfig {
    fn drop(&mut self) {
        // Tell systemd-networkd to shutdown & wait for it to happen
        let _ = nix::sys::signal::kill(Pid::from_raw(self.process.id() as i32), SIGTERM);
        let _ = self.process.wait();

        // Remove the config
        let _ = std::fs::remove_file(&self.config_path);
    }
}

/// Tries to obtain the GuestOS config from the cloud's metadata service
pub fn obtain_guestos_config(systemd_network_dir: PathBuf) -> Result<GuestOSConfig, Error> {
    // Find the network interface to work on, it might not be initialized yet so give it a few tries
    let mut retries = 10;
    let intf = loop {
        match get_best_interface_name() {
            Ok(v) => break v,
            Err(e) => {
                println!("unable to choose interface: {e:#}");
                retries -= 1;
                if retries == 0 {
                    bail!("unable to choose interface: retries exhausted");
                }

                std::thread::sleep(Duration::from_secs(1));
            }
        }
    };

    // Configure it with a DHCP
    let _dhcp = DHCPConfig::new(intf.clone(), systemd_network_dir)
        .context("unable to configure IPv4 DHCP")?;
    println!("DHCP on the interface {intf} configured");

    // Discover the cloud we're running in.
    let cloud_type = CloudType::discover().context("unable to discover cloud type")?;
    println!("Cloud type detected: {cloud_type:?}");

    // Get the config from the MDS
    let config = cloud_type
        .obtain_config()
        .context("unable to obtain GuestOS config")?;

    Ok(config)
}
