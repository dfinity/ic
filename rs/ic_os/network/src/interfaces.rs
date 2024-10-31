use std::fs;
use std::net::{IpAddr, Ipv6Addr};
use std::path::PathBuf;
use std::thread::sleep;
use std::time::Duration;
use std::vec::Vec;

use anyhow::{Context, Result};
use ping::dgramsock;
use rayon::prelude::*;

use utils::{get_command_stdout, retry, retry_pred};

static SYSFS_NETWORK_DIR: &str = "/sys/class/net";

#[derive(Clone, PartialEq, Debug)]
pub struct Interface {
    pub name: String,
    pub speed_mbps: Option<u64>,
}

pub fn has_ipv6_connectivity(
    interface: &Interface,
    generated_ipv6: &Ipv6Addr,
    ipv6_prefix_length: u8,
    ping_target: &str,
) -> Result<bool> {
    // Format with the prefix length
    let ip = format!("{}/{}", generated_ipv6, ipv6_prefix_length);
    let interface_down_func = || {
        eprintln!("Removing ip address and bringing interface down");
        get_command_stdout("ip", ["addr", "del", &ip, "dev", &interface.name])?;
        deactivate_link(&interface.name)
    };

    eprintln!(
        "Bringing {} up with ip address {}",
        &interface.name,
        &ip.to_string()
    );
    get_command_stdout("ip", ["addr", "add", &ip, "dev", &interface.name])?;
    activate_link(&interface.name)?;

    let wait_time = Duration::from_secs(2);
    let ping_target = ping_target.parse::<IpAddr>()?;
    let ping_timeout = Duration::from_secs(3);
    let result = retry(
        40,
        || {
            eprintln!(
                "Attempting to ping {}, after {} seconds",
                ping_target,
                wait_time.as_secs()
            );
            dgramsock::ping(ping_target, Some(ping_timeout), None, None, None, None)
                .context("Ping failed.")
        },
        wait_time,
    );

    if result.is_err() {
        eprintln!("Failed to ping from configured interface.");
        interface_down_func()?;
        Ok(false)
    } else {
        eprintln!("Successful ipv6 connectivity");
        interface_down_func()?;
        Ok(true)
    }
}

pub fn get_interface_name(interface_path: &PathBuf) -> Result<String> {
    interface_path
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .context(format!(
            "Error getting filename from path: {:?}",
            interface_path
        ))
}

fn qualify_and_generate_interface(interface_name: &str) -> Result<Option<Interface>> {
    let ethtool_output = get_command_stdout("ethtool", [interface_name])?;
    let link_is_up = is_link_up_from_ethool_output(&ethtool_output)?;

    if !link_is_up {
        return Ok(None);
    }

    let speed = get_speed_from_ethtool_output(&ethtool_output);

    Ok(Some(Interface {
        name: interface_name.to_string(),
        speed_mbps: speed,
    }))
}

fn is_some_or_err<T>(r: &Result<Option<T>>) -> bool {
    matches!(r, Ok(Some(_)) | Err(_))
}

fn qualify_and_generate_interfaces(interface_names: &[&str]) -> Result<Vec<Interface>> {
    // On some hardware ethtool needs time before link status settles.
    // Takes 2.3 seconds for recent NP.
    // Wait a maximum of 20 seconds for link status to settle.
    let mut result_vec: Vec<Interface> = Vec::new();
    let wait_time = Duration::from_secs(2);
    let interface_results: Vec<Result<Option<Interface>>> = interface_names
        .par_iter()
        .map(|i| {
            retry_pred(
                10,
                || qualify_and_generate_interface(i),
                is_some_or_err,
                |_| sleep(wait_time),
            )
        })
        .collect();

    for (name, result) in std::iter::zip(interface_names, interface_results) {
        eprintln!("Interface name: {name}");
        match result {
            Ok(Some(interface)) => {
                eprintln!(
                    "Cable is ATTACHED. Speed (mbps) detected: {}",
                    match &interface.speed_mbps {
                        Some(s) => s.to_string(),
                        None => "None".to_string(),
                    }
                );
                result_vec.push(interface);
            }
            Ok(None) => eprintln!("Cable is NOT ATTACHED"),
            Err(e) => eprintln!("ERROR: {:#?}", e),
        }
    }
    Ok(result_vec)
}

/// Return vec of Interface's which:
///   Have physical links attached
///   Do not contain the string 'virtual'
pub fn get_interfaces() -> Result<Vec<Interface>> {
    let interfaces = get_interface_paths();
    eprintln!("Found raw network interfaces: {:?}", interfaces);

    // Valid == (not virtual) && first-3-letters in {enp, eno, ens}
    let valid_interfaces: Vec<&PathBuf> = interfaces
        .iter()
        .filter(is_valid_network_interface)
        .collect();
    eprintln!("Found valid network interfaces: {:?}", valid_interfaces);

    let interface_names = valid_interfaces
        .into_iter()
        .map(get_interface_name)
        .collect::<Result<Vec<_>, _>>()?;

    eprintln!("Activating each interface");
    for name in interface_names.iter() {
        // Activate the link to see physical cable connectivity.
        // Deactivate in the next step.
        // If result is error, return. That's an unrecoverable bigger problem.
        activate_link(name).context("Error activating interface link!")?;
    }

    let result = qualify_and_generate_interfaces(
        &interface_names
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<&str>>(),
    )?;
    eprintln!("Proceeding with interfaces: {:?}", result);

    for name in interface_names.iter() {
        deactivate_link(name).context("Error deactivating interface links!")?;
    }

    Ok(result)
}

/// Parse a number out of a given `line` after removing given `prefix` and `suffix`
fn parse_single_embedded_number(line: &str, prefix: &str, suffix: &str) -> Option<u64> {
    line.trim()
        .strip_prefix(prefix)
        .and_then(|s| s.strip_suffix(suffix))
        .map(|s| s.trim())
        .and_then(|s| s.parse::<u64>().ok())
}

/// Return the speed as u64 from the given ethtool `output`
/// Example line: '        Speed: 10000Mb/s'
/// Example line: '        Speed: 1000Mb/s'
/// Example line: '        Speed: Unknown!'
fn parse_speed_mbps_from_ethtool_output(output: &str) -> Option<u64> {
    let prefix = "Speed: ";
    let suffix = "Mb/s";
    output
        .lines()
        .find_map(|s| parse_single_embedded_number(s, prefix, suffix))
        .or_else(|| {
            eprintln!("Could not parse speed line from ethtool output.");
            None
        })
}

/// Returns speed of the fastest link mode detected from the given ethtool `output`
/// Most similar to the previous bash scrpit version - which just grepped for 1000/10000
fn parse_fastest_link_mode_from_ethtool_output(output: &str) -> Option<u64> {
    let lines = output.lines();
    if lines.clone().any(|s| s.contains("10000")) {
        return Some(10000);
    }
    if lines.clone().any(|s| s.contains("1000")) {
        return Some(1000);
    }
    eprintln!("Could not parse speed from valid link mode lines in output");
    None
}

/// Parse the given `output` and return speed in Mb/s.
/// Prefer the "Speed: " line. Fall back on the link mode lines.
fn get_speed_from_ethtool_output(output: &str) -> Option<u64> {
    let speed = parse_speed_mbps_from_ethtool_output(output)
        .or_else(|| parse_fastest_link_mode_from_ethtool_output(output));
    if speed.is_none() {
        eprintln!("Error parsing speed from ethtool output: {output}")
    }
    speed
}

fn is_link_up_from_ethool_output(output: &str) -> Result<bool> {
    output
        .lines()
        .map(|s| s.trim())
        .find(|s| s.starts_with("Link detected: "))
        .map(|s| s.contains("yes"))
        .context(format!(
            "Could not parse link line from ethtool output: {}",
            output
        ))
}

fn activate_link(interface_name: &str) -> Result<()> {
    let _ = get_command_stdout("ip", ["link", "set", interface_name, "up"])
        .context("Error bringing interface online")?;
    Ok(())
}

fn deactivate_link(interface_name: &str) -> Result<()> {
    let _ = get_command_stdout("ip", ["link", "set", interface_name, "down"])
        .context("Error bringing interface offline")?;
    Ok(())
}

/// Get paths of all available network interfaces. E.g. /sys/class/net/enp0s31f6
pub fn get_interface_paths() -> Vec<PathBuf> {
    let interfaces = match fs::read_dir(SYSFS_NETWORK_DIR) {
        Ok(itr) => itr,
        Err(e) => {
            eprintln!("Failed to read directory {SYSFS_NETWORK_DIR}: {e}");
            return Vec::new();
        }
    };

    // Keep only the items that are symlinks
    interfaces
        .filter_map(Result::ok)
        .map(|dir_entry| dir_entry.path())
        .filter(|path_buf| path_buf.is_symlink())
        .collect()
}

fn is_valid_network_interface(path: &&PathBuf) -> bool {
    let Some(filename) = path.file_name() else {
        eprintln!("ERROR: Invalid network interface path: {:#?}", path);
        return false;
    };
    let filename = filename.to_string_lossy();

    let first3_chars = filename.chars().take(3).collect::<String>().to_lowercase();
    /*
    Only target ethernet devices (not infiniband or wireless).
    Ignore enx - these are known to be used for bmc connectivity

        Ethernet Devices:
            en: General prefix for Ethernet devices.
                eno: Onboard Ethernet devices.
                ens: Ethernet devices connected through hot-plug slots (e.g., PCIe, USB).
                enp: Ethernet devices connected to the system's mainboard via PCI Express (PCIe) or PCI.
                enx: Ethernet devices with a fixed hardware address (common for USB Ethernet adapters).

        Wireless Devices:
            wl: General prefix for Wireless LAN (WLAN) devices.
                wlp: Wireless LAN devices connected through hot-plug slots (e.g., PCIe, USB).

        WWAN Devices:
            ww: General prefix for Wireless WAN devices.
                wwp: Wireless WAN devices connected through hot-plug slots (e.g., mobile broadband modems).

        InfiniBand Devices:
            ib: General prefix for InfiniBand devices.
                ibp: InfiniBand devices connected through hot-plug slots.
    */
    matches!(first3_chars.as_str(), "eno" | "enp" | "ens")
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_parse_speed_line() {
        assert_eq!(
            parse_single_embedded_number("   Speed: 10000Mb/s", "Speed:", "Mb/s").unwrap(),
            10000
        );
        assert_eq!(
            parse_single_embedded_number("   Speed: 1000Mb/s", "Speed:", "Mb/s").unwrap(),
            1000
        );
        assert_eq!(
            parse_single_embedded_number("Speed: 25Mb/s    ", "Speed:", "Mb/s").unwrap(),
            25
        );
        assert!(parse_single_embedded_number("   Speed: Unknown!   ", "Speed:", "Mb/s").is_none());
        assert!(parse_single_embedded_number("   Speed: 100Kb/s", "Speed:", "Mb/s").is_none());
        assert!(parse_single_embedded_number("Mb/s: 100Speed", "Speed:", "Mb/s").is_none());
    }

    static ETHTOOL_OUTPUT: &str = "Settings for enp68s0f0:
        Supported ports: [ TP ]
        Supported link modes:   100baseT/Full
                                1000baseT/Full
                                10000baseT/Full
                                2500baseT/Full
                                5000baseT/Full
        Supported pause frame use: Symmetric Receive-only
        Supports auto-negotiation: Yes
        Supported FEC modes: Not reported
        Advertised link modes:  100baseT/Full
                                1000baseT/Full
                                10000baseT/Full
                                2500baseT/Full
                                5000baseT/Full
        Advertised pause frame use: No
        Advertised auto-negotiation: Yes
        Advertised FEC modes: Not reported
        Speed: 10000Mb/s
        Duplex: Full
        Port: Twisted Pair
        PHYAD: 0
        Transceiver: internal
        Auto-negotiation: on
        MDI-X: Unknown
Cannot get wake-on-lan settings: Operation not permitted
        Current message level: 0x00000007 (7)
                               drv probe link
        Link detected: yes";

    #[test]
    fn test_is_link_up_from_ethtool_output() {
        assert!(is_link_up_from_ethool_output(ETHTOOL_OUTPUT).unwrap());

        let negative_output = "
Cannot get wake-on-lan settings: Operation not permitted
Current message level: 0x00000007 (7)
drv probe link
Link detected: no";
        assert!(!is_link_up_from_ethool_output(negative_output).unwrap());

        let invalid_output = "
Cannot get wake-on-lan settings: Operation not permitted
Current message level: 0x00000007 (7)
drv probe link
Blink 182 detected";
        assert!(is_link_up_from_ethool_output(invalid_output).is_err());
    }

    #[test]
    fn test_get_speed_from_ethtool_output() {
        assert_eq!(
            get_speed_from_ethtool_output(ETHTOOL_OUTPUT).unwrap(),
            10000
        );

        assert_eq!(
            get_speed_from_ethtool_output("        Speed: 10Mb/s").unwrap(),
            10
        );
        assert_eq!(
            get_speed_from_ethtool_output("        1000baseT/Full").unwrap(),
            1000
        );
        assert_eq!(
            get_speed_from_ethtool_output("        Speed: 300Mb/s").unwrap(),
            300
        );
    }
}
