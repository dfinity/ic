use std::fs::write;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Result, bail};

use config_types::Ipv6Config;
use network::interfaces::{get_interface_name as get_valid_interface_name, get_interface_paths};
use utils::get_command_stdout;

use network::systemd::IPV6_NAME_SERVER_NETWORKD_CONTENTS;

const IPV4_NAME_SERVER_NETWORKD_CONTENTS: &str =
    "DNS=1.1.1.1\nDNS=1.0.0.1\nDNS=8.8.8.8\nDNS=8.8.4.4\n";

#[derive(Debug)]
struct NetworkInfo {
    ipv6_info: Option<IpAddressInfo>,
    ipv4_info: Option<IpAddressInfo>,
}

#[derive(Debug)]
pub struct IpAddressInfo {
    address_with_prefix: String,
    gateway: String,
}

impl IpAddressInfo {
    pub fn new_ipv4_address(
        address: &str,
        prefix_length: &str,
        gateway: &str,
    ) -> Result<IpAddressInfo> {
        if Self::verify_ipv4_address(address, prefix_length, gateway) {
            eprintln!(
                "Valid IPv4 address configuration provided:\nAddress: {address}\nPrefix length: {prefix_length}\nGateway: {gateway}"
            );
            let address_with_prefix = format!("{address}/{prefix_length}");

            Ok(IpAddressInfo {
                address_with_prefix,
                gateway: gateway.to_string(),
            })
        } else {
            bail!(
                "ERROR: invalid Ipv4 configuration:\nAddress: {address}\nPrefix length: {prefix_length}\nGateway: {gateway}"
            )
        }
    }
    pub fn new_ipv6_address(address_with_prefix: &str, gateway: &str) -> Result<IpAddressInfo> {
        if Self::verify_ipv6_address(address_with_prefix, gateway)? {
            eprintln!(
                "Valid IPv6 address configuration provided:\nAddress: {address_with_prefix}\nGateway: {gateway}"
            );
            Ok(IpAddressInfo {
                address_with_prefix: address_with_prefix.to_string(),
                gateway: gateway.to_string(),
            })
        } else {
            bail!(
                "ERROR: invalid Ipv6 configuration:\nAddress: {address_with_prefix}\nGateway: {gateway}"
            )
        }
    }

    fn verify_ipv4_address(
        ipv4_address: &str,
        ipv4_prefix_length: &str,
        ipv4_gateway: &str,
    ) -> bool {
        let address_is_valid = Ipv4Addr::from_str(ipv4_address).is_ok();
        let gateway_is_valid = Ipv4Addr::from_str(ipv4_gateway).is_ok();

        let Ok(ipv4_prefix_length) = ipv4_prefix_length.parse::<u8>() else {
            return false;
        };

        address_is_valid && gateway_is_valid && (ipv4_prefix_length <= 32)
    }

    fn verify_ipv6_address(address_with_prefix: &str, gateway: &str) -> Result<bool> {
        let address = address_with_prefix
            .strip_suffix("/64")
            .context("ERROR: IPv6 address does not have the expected '/64' suffix")?;

        Ok(Ipv6Addr::from_str(address).is_ok() && Ipv6Addr::from_str(gateway).is_ok())
    }
}

/// Generate network configuration for systemd networkd based on the provided network configuration.
pub fn generate_networkd_config(
    ipv6_config: Ipv6Config,
    systemd_network_dir: &Path,
    ipv4_info: Option<IpAddressInfo>,
) -> Result<()> {
    eprintln!("IPv6 config info: {ipv6_config:?}");
    eprintln!("IPv4 address info: {ipv4_info:?}");
    eprintln!(
        "Systemd network directory: {}",
        systemd_network_dir.display()
    );

    std::fs::create_dir_all(systemd_network_dir)?;

    let network_info: NetworkInfo = create_network_info(ipv6_config, ipv4_info)?;
    eprintln!("{network_info:#?}");

    let network_interface_name = get_interface_name()?;

    let disable_dad = is_k8s_testnet()?;

    let networkd_config_file_contents =
        generate_networkd_config_contents(network_info, &network_interface_name, disable_dad);
    eprintln!("Networkd config contents: {networkd_config_file_contents:#?}");

    let networkd_config_file_path =
        systemd_network_dir.join(format!("10-{network_interface_name}.network"));

    eprintln!(
        "Writing systemd networkd config to {}",
        networkd_config_file_path.display()
    );
    write(networkd_config_file_path, networkd_config_file_contents)?;

    Ok(())
}

/// Constructs `IpAddressInfo` if all parameters are provided, warns and returns `None` if none are provided, or errors on incomplete input.
pub fn validate_and_construct_ipv4_address_info(
    ipv4_address: Option<&str>,
    ipv4_prefix_length: Option<&str>,
    ipv4_gateway: Option<&str>,
) -> Result<Option<IpAddressInfo>> {
    match (ipv4_address, ipv4_prefix_length, ipv4_gateway) {
        (Some(ipv4_address), Some(ipv4_prefix_length), Some(ipv4_gateway)) => Ok(Some(
            IpAddressInfo::new_ipv4_address(ipv4_address, ipv4_prefix_length, ipv4_gateway)?,
        )),
        (None, None, None) => {
            eprintln!(
                "No IPv4 address configuration provided. Configuring networkd without IPv4 address."
            );
            Ok(None)
        }
        _ => {
            bail!(
                "ERROR: Incomplete configuration - an IPv4 address, prefix length, and gateway are required. Please specify all."
            );
        }
    }
}

fn create_network_info(
    ipv6_config: Ipv6Config,
    ipv4_info: Option<IpAddressInfo>,
) -> Result<NetworkInfo> {
    let ipv6_info = match ipv6_config {
        Ipv6Config::Fixed(ipv6_config) => Some(IpAddressInfo::new_ipv6_address(
            &ipv6_config.address,
            &ipv6_config.gateway.to_string(),
        )?),
        Ipv6Config::RouterAdvertisement => None,
        Ipv6Config::Deterministic(_) => {
            bail!("GuestOSConfig Ipv6Config should not be of type Deterministic.");
        }
        Ipv6Config::Unknown => {
            bail!("Unknown Ipv6Config variant");
        }
    };

    Ok(NetworkInfo {
        ipv6_info,
        ipv4_info,
    })
}

fn generate_networkd_config_contents(
    network_info: NetworkInfo,
    interface_name: &str,
    disable_dad: bool,
) -> String {
    let match_contents = generate_network_config_match_contents(interface_name);
    let ipv6_contents = generate_network_config_ipv6_contents(network_info.ipv6_info, disable_dad);
    let ipv4_contents = generate_network_config_ipv4_contents(network_info.ipv4_info);

    format!("{match_contents}{ipv6_contents}{ipv4_contents}")
}

fn generate_network_config_match_contents(interface_name: &str) -> String {
    indoc::formatdoc!(
        r#"
            [Match]
            Name={interface_name}
            Virtualization=!container
        "#
    )
}

fn generate_network_config_ipv6_contents(
    ipv6_info: Option<IpAddressInfo>,
    disable_dad: bool,
) -> String {
    match ipv6_info {
        Some(ipv6_info) => {
            let (ipv6_address, ipv6_gateway) = (ipv6_info.address_with_prefix, ipv6_info.gateway);
            let ipv6_contents = indoc::formatdoc!(
                r#"
                    [Network]
                    Address={ipv6_address}
                    Gateway={ipv6_gateway}
                    IPv6AcceptRA=false
                    {IPV6_NAME_SERVER_NETWORKD_CONTENTS}
                "#,
            );
            if disable_dad {
                // Explicitly turn off router advertisements. Otherwise, we may
                // end up with two (distinct) addresses on the same interface
                let dad_contents = "IPv6DuplicateAddressDetection=0";
                format!("{ipv6_contents}{dad_contents}\n")
            } else {
                ipv6_contents
            }
        }
        // Default configuration when no IPv6 address is provided
        None => "[Network]\nIPv6AcceptRA=true\n".to_string(),
    }
}

fn generate_network_config_ipv4_contents(ipv4_info: Option<IpAddressInfo>) -> String {
    ipv4_info
        .map(|ipv4_info| {
            indoc::formatdoc!(
                r#"
                Address={}
                Gateway={}
                {}
            "#,
                ipv4_info.address_with_prefix,
                ipv4_info.gateway,
                IPV4_NAME_SERVER_NETWORKD_CONTENTS
            )
        })
        .unwrap_or_default()
}

fn get_interface_name() -> Result<String> {
    let interfaces: Vec<PathBuf> = get_interface_paths();
    eprintln!("Found raw network interfaces: {interfaces:?}");

    let valid_interfaces: Vec<_> = interfaces
        .iter()
        .filter(is_valid_network_interface)
        .collect();
    eprintln!("Found valid network interfaces: {valid_interfaces:?}");

    let first_valid_interface = valid_interfaces
        .first()
        .context("ERROR: No valid network interfaces found.")?;

    let interface_name = get_valid_interface_name(first_valid_interface)?;
    eprintln!("Chosen interface name: {interface_name:?}");
    Ok(interface_name)
}

fn is_valid_network_interface(path: &&PathBuf) -> bool {
    let Some(filename) = path.file_name() else {
        eprintln!("ERROR: Invalid network interface path: {path:#?}");
        return false;
    };
    let filename = filename.to_string_lossy();

    let first3_chars = filename.chars().take(3).collect::<String>().to_lowercase();
    matches!(first3_chars.as_str(), "enp")
}

// Turn off duplicate address detection for testnets running on k8s
fn is_k8s_testnet() -> Result<bool> {
    let output = get_command_stdout("lsblk", &["--nodeps", "-o", "name,serial"])?;
    if output.contains("config") {
        eprintln!("K8S testnet detected. Turning off DAD for tnet on k8s.");
        Ok(true)
    } else {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use config_types::*;

    #[test]
    fn test_create_network_info_with_valid_ipv6_and_ipv4() {
        let ipv4_info =
            Some(IpAddressInfo::new_ipv4_address("192.168.1.100", "30", "192.168.1.1").unwrap());
        let ipv6_config = Ipv6Config::Fixed(FixedIpv6Config {
            address: "2001:db8::1/64".to_string(),
            gateway: "2001:db8::1".parse().unwrap(),
        });

        let result = create_network_info(ipv6_config, ipv4_info).unwrap();
        assert!(result.ipv6_info.is_some());

        let ipv6_info = result.ipv6_info.as_ref().unwrap();
        assert_eq!(ipv6_info.address_with_prefix, "2001:db8::1/64");
        assert_eq!(ipv6_info.gateway, "2001:db8::1");

        let ipv4_info = result.ipv4_info.as_ref().unwrap();
        assert_eq!(ipv4_info.address_with_prefix, "192.168.1.100/30");
        assert_eq!(ipv4_info.gateway, "192.168.1.1");
    }

    #[test]
    fn test_create_network_info_with_valid_ipv6_and_no_ipv4() {
        let ipv6_config = Ipv6Config::Fixed(FixedIpv6Config {
            address: "2001:db8::1/64".to_string(),
            gateway: "2001:db8::1".parse().unwrap(),
        });
        let ipv4_info = None;

        let result = create_network_info(ipv6_config, ipv4_info).unwrap();
        assert!(result.ipv6_info.is_some());

        let ipv6_info = result.ipv6_info.as_ref().unwrap();
        assert_eq!(ipv6_info.address_with_prefix, "2001:db8::1/64");
        assert_eq!(ipv6_info.gateway, "2001:db8::1");
    }

    #[test]
    fn test_validate_ipv4_network_info_no_input() {
        assert!(
            validate_and_construct_ipv4_address_info(None, None, None)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn test_validate_ipv4_network_info_incomplete_configuration() {
        assert!(
            validate_and_construct_ipv4_address_info(None, Some("30"), Some("192.168.1.254"))
                .is_err()
        );
        assert!(
            validate_and_construct_ipv4_address_info(
                Some("192.168.1.1"),
                None,
                Some("192.168.1.254")
            )
            .is_err()
        );
        assert!(
            validate_and_construct_ipv4_address_info(Some("192.168.1.1"), Some("30"), None)
                .is_err()
        );
    }

    #[test]
    fn test_validate_ipv4_network_info_invalid_configuration() {
        assert!(
            validate_and_construct_ipv4_address_info(
                Some("invalid_ip"),
                Some("30"),
                Some("192.168.1.254")
            )
            .is_err()
        );
        assert!(
            validate_and_construct_ipv4_address_info(
                Some("192.168.1.1"),
                Some("30"),
                Some("invalid_gateway")
            )
            .is_err()
        );
        assert!(
            validate_and_construct_ipv4_address_info(
                Some("192.168.1.1"),
                Some("33"),
                Some("192.168.1.254")
            )
            .is_err()
        );
    }

    #[test]
    fn test_validate_ipv4_network_info_valid_configuration() {
        let result = validate_and_construct_ipv4_address_info(
            Some("192.168.1.1"),
            Some("30"),
            Some("192.168.1.254"),
        )
        .unwrap()
        .unwrap();
        assert_eq!(result.address_with_prefix, "192.168.1.1/30");
        assert_eq!(result.gateway, "192.168.1.254");
    }

    #[test]
    fn test_generate_networkd_config_contents_with_full_networking_info() {
        let network_info = NetworkInfo {
            ipv6_info: Some(
                IpAddressInfo::new_ipv6_address("2001:db8::1/64", "2001:db8::1").unwrap(),
            ),
            ipv4_info: Some(
                IpAddressInfo::new_ipv4_address("192.168.1.100", "30", "192.168.1.1").unwrap(),
            ),
        };
        let interface_name = "enp65s0f1";

        let result = generate_networkd_config_contents(network_info, interface_name, false);

        let expected_output = "[Match]\nName=enp65s0f1\nVirtualization=!container\n[Network]\nAddress=2001:db8::1/64\nGateway=2001:db8::1\nIPv6AcceptRA=false\n\nDNS=2606:4700:4700::1111\nDNS=2606:4700:4700::1001\nDNS=2001:4860:4860::8888\nDNS=2001:4860:4860::8844\n\nAddress=192.168.1.100/30\nGateway=192.168.1.1\nDNS=1.1.1.1\nDNS=1.0.0.1\nDNS=8.8.8.8\nDNS=8.8.4.4\n\n";
        assert_eq!(result, expected_output);
    }

    #[test]
    fn test_generate_networkd_config_contents_with_just_ipv6_networking_info() {
        let network_info = NetworkInfo {
            ipv6_info: Some(
                IpAddressInfo::new_ipv6_address("2001:db8::1/64", "2001:db8::1").unwrap(),
            ),
            ipv4_info: None,
        };
        let interface_name = "enp65s0f1";

        let result = generate_networkd_config_contents(network_info, interface_name, false);

        let expected_output = "[Match]\nName=enp65s0f1\nVirtualization=!container\n[Network]\nAddress=2001:db8::1/64\nGateway=2001:db8::1\nIPv6AcceptRA=false\n\nDNS=2606:4700:4700::1111\nDNS=2606:4700:4700::1001\nDNS=2001:4860:4860::8888\nDNS=2001:4860:4860::8844\n\n";
        assert_eq!(result, expected_output);
    }

    #[test]
    fn test_generate_networkd_config_contents_with_full_info_disable_dad() {
        let network_info = NetworkInfo {
            ipv6_info: Some(
                IpAddressInfo::new_ipv6_address("2001:db8::1/64", "2001:db8::1").unwrap(),
            ),
            ipv4_info: Some(
                IpAddressInfo::new_ipv4_address("192.168.1.100", "30", "192.168.1.1").unwrap(),
            ),
        };
        let interface_name = "enp65s0f1";

        let result = generate_networkd_config_contents(network_info, interface_name, true);

        let expected_output = "[Match]\nName=enp65s0f1\nVirtualization=!container\n[Network]\nAddress=2001:db8::1/64\nGateway=2001:db8::1\nIPv6AcceptRA=false\n\nDNS=2606:4700:4700::1111\nDNS=2606:4700:4700::1001\nDNS=2001:4860:4860::8888\nDNS=2001:4860:4860::8844\n\nIPv6DuplicateAddressDetection=0\nAddress=192.168.1.100/30\nGateway=192.168.1.1\nDNS=1.1.1.1\nDNS=1.0.0.1\nDNS=8.8.8.8\nDNS=8.8.4.4\n\n";
        assert_eq!(result, expected_output);
    }

    #[test]
    fn test_generate_networkd_config_contents_with_no_networking_or_nameservers() {
        let network_info = NetworkInfo {
            ipv6_info: None,
            ipv4_info: None,
        };
        let interface_name = "enp65s0f1";

        let result = generate_networkd_config_contents(network_info, interface_name, false);

        let expected_output =
            "[Match]\nName=enp65s0f1\nVirtualization=!container\n[Network]\nIPv6AcceptRA=true\n";
        assert_eq!(result, expected_output);
    }
}
