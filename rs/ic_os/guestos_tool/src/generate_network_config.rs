use std::collections::HashMap;
use std::fs::write;
use std::net::Ipv6Addr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{bail, Context, Result};

use config::config_map_from_path;
use network::interfaces::{get_interface_name as get_valid_interface_name, get_interface_paths};
use network::systemd::{generate_nameserver_list, restart_systemd_networkd};
use utils::get_command_stdout;

pub static DEFAULT_GUESTOS_NETWORK_CONFIG_PATH: &str = "/boot/config/network.conf";

#[derive(Debug)]
struct IPv6Info {
    ipv6_address: String,
    ipv6_gateway: String,
}

#[derive(Debug)]
struct NetworkInfo {
    ipv6_info: Option<IPv6Info>,
    ipv6_name_servers_list: Option<String>,
}

/// Generate network configuration for systemd networkd based on the provided network configuration and then restarts the systemd networkd
pub fn regenerate_networkd_config(network_config: &Path, systemd_network_dir: &Path) -> Result<()> {
    generate_networkd_config(network_config, systemd_network_dir)?;

    eprintln!("Restarting systemd networkd");
    restart_systemd_networkd();

    Ok(())
}

/// Generate network configuration for systemd networkd based on the provided network configuration.
pub fn generate_networkd_config(network_config: &Path, systemd_network_dir: &Path) -> Result<()> {
    eprintln!("Network config file: {}", network_config.display());
    eprintln!(
        "Systemd network directory: {}",
        systemd_network_dir.display()
    );

    std::fs::create_dir_all(systemd_network_dir)?;

    let network_parameters: HashMap<String, String> = config_map_from_path(network_config)?;
    eprintln!("Network parameters {:#?}", network_parameters);

    let network_info: NetworkInfo = fetch_network_info(&network_parameters)?;
    eprintln!("{:#?}", network_info);

    let network_interface_name = get_interface_name()?;

    let disable_dad = is_k8s_testnet()?;

    let networkd_config_file_contents =
        generate_networkd_config_contents(network_info, &network_interface_name, disable_dad);
    eprintln!(
        "Networkd config contents: {:#?}",
        networkd_config_file_contents
    );

    let networkd_config_file_path =
        systemd_network_dir.join(format!("10-{network_interface_name}.network"));

    eprintln!(
        "Writing systemd networkd config to {}",
        networkd_config_file_path.display()
    );
    write(networkd_config_file_path, networkd_config_file_contents)?;

    Ok(())
}

fn fetch_network_info(network_config_variables: &HashMap<String, String>) -> Result<NetworkInfo> {
    let ipv6_info = match (
        network_config_variables.get("ipv6_address"),
        network_config_variables.get("ipv6_gateway"),
    ) {
        (Some(ipv6_address), Some(ipv6_gateway)) => {
            process_ipv6_address_and_gateway(ipv6_address, ipv6_gateway)?
        }
        (Some(_), None) | (None, Some(_)) => {
            // Either IPv6 address or gateway is provided, but not both
            bail!("ERROR: Incomplete configuration - both an IPv6 address and a gateway are required. Please specify both.");
        }
        _ => None,
    };

    let ipv6_name_servers_list = network_config_variables
        .get("name_servers")
        .map(|ipv6_name_servers| ipv6_name_servers.split_whitespace())
        .map(generate_nameserver_list)
        .transpose()?;

    Ok(NetworkInfo {
        ipv6_info,
        ipv6_name_servers_list,
    })
}

fn process_ipv6_address_and_gateway(
    ipv6_address: &str,
    ipv6_gateway: &str,
) -> Result<Option<IPv6Info>> {
    let ipv6_address_stripped = ipv6_address
        .strip_suffix("/64")
        .context("ERROR: IPv6 address does not have the expected '/64' suffix")?;
    if Ipv6Addr::from_str(ipv6_address_stripped).is_ok() && Ipv6Addr::from_str(ipv6_gateway).is_ok()
    {
        Ok(Some(IPv6Info {
            ipv6_address: ipv6_address.to_string(),
            ipv6_gateway: ipv6_gateway.to_string(),
        }))
    } else if ipv6_address.is_empty() && ipv6_gateway.is_empty() {
        eprintln!("Both IPv6 address and gateway are unspecified. Proceeding with network configuration using Router Advertisements.");
        Ok(None)
    } else {
        bail!("ERROR: invalid ipv6 address and/or gateway:\nAddress: {ipv6_address}\n: {ipv6_gateway}")
    }
}

fn generate_networkd_config_contents(
    network_info: NetworkInfo,
    interface_name: &str,
    disable_dad: bool,
) -> String {
    let match_contents = generate_network_config_match_contents(interface_name);
    let ipv6_contents = generate_network_config_ipv6_contents(network_info.ipv6_info, disable_dad);
    let dns_contents = generate_network_config_dns_contents(network_info.ipv6_name_servers_list);

    format!("{}{}{}", match_contents, ipv6_contents, dns_contents)
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

fn generate_network_config_ipv6_contents(ipv6_info: Option<IPv6Info>, disable_dad: bool) -> String {
    match ipv6_info {
        Some(ipv6_info) => {
            let (ipv6_address, ipv6_gateway) = (ipv6_info.ipv6_address, ipv6_info.ipv6_gateway);
            let ipv6_contents = indoc::formatdoc!(
                r#"
                    [Network]
                    Address={ipv6_address}
                    Gateway={ipv6_gateway}
                    IPv6AcceptRA=false
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

fn generate_network_config_dns_contents(ipv6_name_servers_list: Option<String>) -> String {
    ipv6_name_servers_list.unwrap_or_default()
}

fn get_interface_name() -> Result<String> {
    let interfaces: Vec<PathBuf> = get_interface_paths();
    eprintln!("Found raw network interfaces: {:?}", interfaces);

    let valid_interfaces: Vec<_> = interfaces
        .iter()
        .filter(is_valid_network_interface)
        .collect();
    eprintln!("Found valid network interfaces: {:?}", valid_interfaces);

    let first_valid_interface = valid_interfaces
        .first()
        .context("ERROR: No valid network interfaces found.")?;

    let interface_name = get_valid_interface_name(first_valid_interface)?;
    eprintln!("Chosen interface name: {:?}", interface_name);
    Ok(interface_name)
}

fn is_valid_network_interface(path: &&PathBuf) -> bool {
    let Some(filename) = path.file_name() else {
        eprintln!("ERROR: Invalid network interface path: {:#?}", path);
        return false;
    };
    let filename = filename.to_string_lossy();

    let first3_chars = filename.chars().take(3).collect::<String>().to_lowercase();
    matches!(first3_chars.as_str(), "enp")
}

// Turn off duplicate address detection for testnets running on k8s
fn is_k8s_testnet() -> Result<bool> {
    let output = get_command_stdout("lsblk", ["--nodeps", "-o", "name,serial"])?;
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

    #[test]
    fn test_fetch_network_info_with_valid_ipv6() {
        let mut network_config_variables = HashMap::new();
        network_config_variables.insert("ipv6_address".to_string(), "2001:db8::1/64".to_string());
        network_config_variables.insert("ipv6_gateway".to_string(), "2001:db8::1".to_string());
        network_config_variables.insert(
            "name_servers".to_string(),
            "2606:4700:4700::1111 2606:4700:4700::1001 2001:4860:4860::8888 2001:4860:4860::8844"
                .to_string(),
        );

        eprintln!("network_config_variables: {:?}", network_config_variables);

        let result = fetch_network_info(&network_config_variables).unwrap();
        assert!(result.ipv6_info.is_some());

        let ipv6_info = result.ipv6_info.as_ref().unwrap();
        assert_eq!(ipv6_info.ipv6_address, "2001:db8::1/64");
        assert_eq!(ipv6_info.ipv6_gateway, "2001:db8::1");

        assert!(result.ipv6_name_servers_list.is_some());
        let ipv6_name_servers_list = result.ipv6_name_servers_list.unwrap();
        assert_eq!(ipv6_name_servers_list, "DNS=2606:4700:4700::1111\nDNS=2606:4700:4700::1001\nDNS=2001:4860:4860::8888\nDNS=2001:4860:4860::8844\n");
    }

    #[test]
    fn test_fetch_network_info_with_invalid_ipv6() {
        let mut network_config_variables = HashMap::new();
        network_config_variables.insert("ipv6_address".to_string(), "invalid_address".to_string());
        network_config_variables.insert("ipv6_gateway".to_string(), "invalid_gateway".to_string());
        network_config_variables.insert(
            "name_servers".to_string(),
            "2606:4700:4700::1111 2606:4700:4700::1001 2001:4860:4860::8888 2001:4860:4860::8844"
                .to_string(),
        );

        let result = fetch_network_info(&network_config_variables);

        assert!(result.is_err(), "Invalid ipv6 address configuration");
    }

    #[test]
    fn test_fetch_network_info_with_missing_ipv6_gateway() {
        let mut network_config_variables = HashMap::new();
        network_config_variables.insert("ipv6_address".to_string(), "invalid_address".to_string());
        // ipv6 gateway omitted intentionally
        // network_config_variables.insert("ipv6_gateway".to_string(), "invalid_gateway".to_string());
        network_config_variables.insert(
            "name_servers".to_string(),
            "2606:4700:4700::1111 2606:4700:4700::1001 2001:4860:4860::8888 2001:4860:4860::8844"
                .to_string(),
        );

        let result = fetch_network_info(&network_config_variables);

        assert!(
            result.is_err(),
            "Expected an error when IPv6 gateway is missing"
        );
    }

    #[test]
    fn test_fetch_network_info_without_ipv6_or_nameservers() {
        let network_config_variables = HashMap::new();

        let result = fetch_network_info(&network_config_variables).unwrap();
        assert!(result.ipv6_info.is_none());
        assert!(result.ipv6_name_servers_list.is_none());
    }

    #[test]
    fn test_generate_networkd_config_contents_with_full_info() {
        let network_info = NetworkInfo {
            ipv6_info: Some(IPv6Info {
                ipv6_address: "2001:db8::1/64".to_string(),
                ipv6_gateway: "2001:db8::1".to_string(),
            }),
            ipv6_name_servers_list: Some("DNS=2606:4700:4700::1111\nDNS=2606:4700:4700::1001\nDNS=2001:4860:4860::8888\nDNS=2001:4860:4860::8844\n".to_string()),
        };
        let interface_name = "enp65s0f1";

        let result = generate_networkd_config_contents(network_info, interface_name, false);

        let expected_output = "[Match]\nName=enp65s0f1\nVirtualization=!container\n[Network]\nAddress=2001:db8::1/64\nGateway=2001:db8::1\nIPv6AcceptRA=false\nDNS=2606:4700:4700::1111\nDNS=2606:4700:4700::1001\nDNS=2001:4860:4860::8888\nDNS=2001:4860:4860::8844\n";
        assert_eq!(result, expected_output);
    }

    #[test]
    fn test_generate_networkd_config_contents_with_full_info_disable_dad() {
        let network_info = NetworkInfo {
            ipv6_info: Some(IPv6Info {
                ipv6_address: "2001:db8::1/64".to_string(),
                ipv6_gateway: "2001:db8::1".to_string(),
            }),
            ipv6_name_servers_list: Some("DNS=2606:4700:4700::1111\nDNS=2606:4700:4700::1001\nDNS=2001:4860:4860::8888\nDNS=2001:4860:4860::8844\n".to_string()),
        };
        let interface_name = "enp65s0f1";

        let result = generate_networkd_config_contents(network_info, interface_name, true);

        let expected_output = "[Match]\nName=enp65s0f1\nVirtualization=!container\n[Network]\nAddress=2001:db8::1/64\nGateway=2001:db8::1\nIPv6AcceptRA=false\nIPv6DuplicateAddressDetection=0\nDNS=2606:4700:4700::1111\nDNS=2606:4700:4700::1001\nDNS=2001:4860:4860::8888\nDNS=2001:4860:4860::8844\n";
        assert_eq!(result, expected_output);
    }

    #[test]
    fn test_generate_networkd_config_contents_with_no_ipv6_or_nameservers() {
        let network_info = NetworkInfo {
            ipv6_info: None,
            ipv6_name_servers_list: None,
        };
        let interface_name = "enp65s0f1";

        let result = generate_networkd_config_contents(network_info, interface_name, false);

        let expected_output =
            "[Match]\nName=enp65s0f1\nVirtualization=!container\n[Network]\nIPv6AcceptRA=true\n";
        assert_eq!(result, expected_output);
    }
}
