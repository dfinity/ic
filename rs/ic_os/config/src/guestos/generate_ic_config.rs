use anyhow::{Context, Result, ensure};
use askama::Template;
use config_types::{GuestOSConfig, Ipv6Config};
use get_if_addrs::get_if_addrs;
use serde_json;
use std::fs::write;
use std::net::Ipv6Addr;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

// See build.rs
include!(concat!(env!("OUT_DIR"), "/ic_config_template.rs"));

/// Generate IC configuration from template and guestos config
pub fn generate_ic_config(guestos_config: &GuestOSConfig, output_path: &Path) -> Result<()> {
    let template = get_config_vars(guestos_config)?;

    let output_content = render_ic_config(template)?;

    write(output_path, &output_content)
        .with_context(|| format!("Failed to write output file: {}", output_path.display()))?;

    // umask for service is set to be restricted, but this file needs to be
    // world-readable
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(output_path)?.permissions();
    perms.set_mode(0o644);
    std::fs::set_permissions(output_path, perms)?;

    // Generate and inject a self-signed TLS certificate and key for ic-boundary
    // for the given domain name. To be used in system tests only.
    if let Some(domain_name) = &guestos_config
        .guestos_settings
        .guestos_dev_settings
        .generate_ic_boundary_tls_cert
        && !domain_name.is_empty()
    {
        generate_tls_certificate(domain_name)?;
    }

    Ok(())
}

/// Render IC configuration from template.
pub fn render_ic_config(template: IcConfigTemplate) -> Result<String> {
    template
        .render()
        .context("Failed to render config template")
}

fn generate_ipv6_prefix(ipv6_address: &str) -> String {
    let segments: Vec<&str> = ipv6_address.split(':').collect();
    if segments.len() >= 4 {
        // Join first 4 segments and append ::/64
        let prefix = segments[..4].join(":");
        format!("{prefix}::/64")
    } else {
        // Fallback to loopback for easy templating
        "::1/128".to_string()
    }
}

fn configure_ipv6(guestos_config: &GuestOSConfig) -> Result<(String, String)> {
    match &guestos_config.network_settings.ipv6_config {
        Ipv6Config::Deterministic(_) => {
            anyhow::bail!("GuestOS IPv6 configuration should not be 'Deterministic'.");
        }
        Ipv6Config::Fixed(fixed_config) => {
            // Remove the subnet part from the IPv6 address
            let ipv6_address = fixed_config
                .address
                .split('/')
                .next()
                .unwrap_or(&fixed_config.address)
                .to_string();

            let ipv6_prefix = generate_ipv6_prefix(&ipv6_address);
            Ok((ipv6_address, ipv6_prefix))
        }
        Ipv6Config::RouterAdvertisement => {
            let ipv6_address = get_router_advertisement_ipv6_address()?;

            let ipv6_prefix = generate_ipv6_prefix(&ipv6_address);
            Ok((ipv6_address, ipv6_prefix))
        }
        Ipv6Config::Unknown => {
            anyhow::bail!("Unknown IPv6 configuration type.");
        }
    }
}

fn configure_ipv4(guestos_config: &GuestOSConfig) -> (String, String) {
    match &guestos_config.network_settings.ipv4_config {
        Some(ipv4_config) => {
            let ipv4_address = format!("{}/{}", ipv4_config.address, ipv4_config.prefix_length);
            let ipv4_gateway = ipv4_config.gateway.to_string();
            (ipv4_address, ipv4_gateway)
        }
        None => (String::new(), String::new()),
    }
}

fn get_config_vars(guestos_config: &GuestOSConfig) -> Result<IcConfigTemplate> {
    let (ipv6_address, ipv6_prefix) = configure_ipv6(guestos_config)?;

    let (ipv4_address, ipv4_gateway) = configure_ipv4(guestos_config);

    // Helper function to set default value if empty
    fn with_default(value: String, default: &str) -> String {
        if value.is_empty() {
            default.to_string()
        } else {
            value
        }
    }

    let nns_urls = guestos_config
        .icos_settings
        .nns_urls
        .iter()
        .map(|url| url.to_string())
        .collect::<Vec<_>>()
        .join(",");

    let backup_retention_time_secs = guestos_config
        .guestos_settings
        .guestos_dev_settings
        .backup_spool
        .as_ref()
        .and_then(|spool| spool.backup_retention_time_seconds)
        .map(|secs| secs.to_string())
        .unwrap_or_default();

    let backup_purging_interval_secs = guestos_config
        .guestos_settings
        .guestos_dev_settings
        .backup_spool
        .as_ref()
        .and_then(|spool| spool.backup_purging_interval_seconds)
        .map(|secs| secs.to_string())
        .unwrap_or_default();

    let query_stats_epoch_length = guestos_config
        .guestos_settings
        .guestos_dev_settings
        .query_stats_epoch_length
        .map(|epoch| epoch.to_string())
        .unwrap_or_default();

    let jaeger_addr = guestos_config
        .guestos_settings
        .guestos_dev_settings
        .jaeger_addr
        .clone()
        .unwrap_or_default();

    let domain_name = guestos_config
        .network_settings
        .domain_name
        .clone()
        .unwrap_or_default();

    let node_reward_type = guestos_config
        .icos_settings
        .node_reward_type
        .clone()
        .unwrap_or_default();

    let malicious_behavior = guestos_config
        .guestos_settings
        .guestos_dev_settings
        .malicious_behavior
        .as_ref()
        .map(|mb| serde_json::to_string(mb).unwrap_or_default())
        .unwrap_or_default();

    Ok(IcConfigTemplate {
        ipv6_address,
        ipv6_prefix,
        ipv4_address,
        ipv4_gateway,
        nns_urls: with_default(nns_urls, "http://[::1]:8080"),
        backup_retention_time_secs: with_default(backup_retention_time_secs, "86400"), // 24h
        backup_purging_interval_secs: with_default(backup_purging_interval_secs, "3600"), // 1h
        query_stats_epoch_length: with_default(query_stats_epoch_length, "600"), // Default is 600 blocks (around 10min)
        jaeger_addr,
        domain_name,
        node_reward_type,
        malicious_behavior: with_default(malicious_behavior, "null"),
    })
}

fn get_router_advertisement_ipv6_address() -> Result<String> {
    const MAX_RETRIES: usize = 12;
    const RETRY_DELAY: Duration = Duration::from_secs(10);

    for attempt in 1..=MAX_RETRIES {
        match get_router_advertisement_ipv6_address_helper() {
            Ok(ipv6_addr) => return Ok(ipv6_addr.to_string()),
            Err(e) => {
                if attempt < MAX_RETRIES {
                    eprintln!(
                        "Retrying {} more times... (Failed to get IPv6 address: {})",
                        MAX_RETRIES - attempt,
                        e
                    );
                    std::thread::sleep(RETRY_DELAY);
                } else {
                    return Err(e.context("Failed to get IPv6 address after all retries"));
                }
            }
        }
    }

    anyhow::bail!("Cannot determine an IPv6 address, aborting");
}

fn get_router_advertisement_ipv6_address_helper() -> Result<Ipv6Addr> {
    let ifaces = get_if_addrs().context("Failed to get network interfaces")?;
    let ipv6_addr = ifaces
        .iter()
        .find_map(|iface| {
            // Filter out virtual interfaces
            if is_virtual_interface(&iface.name) {
                return None;
            }

            match &iface.addr {
                get_if_addrs::IfAddr::V6(addr) => Some(addr.ip),
                _ => None,
            }
        })
        .context("No suitable network interface with IPv6 address found")?;

    Ok(ipv6_addr)
}

fn is_virtual_interface(interface_name: &str) -> bool {
    let device_path = format!("/sys/class/net/{interface_name}/device");
    !Path::new(&device_path).exists()
}

fn generate_tls_certificate(domain_name: &str) -> Result<()> {
    let tls_key_path = "/var/lib/ic/data/ic-boundary-tls.key";
    let tls_cert_path = "/var/lib/ic/data/ic-boundary-tls.crt";

    let status = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            tls_key_path,
            "-out",
            tls_cert_path,
            "-sha256",
            "-days",
            "3650",
            "-nodes",
            "-subj",
            &format!(
                "/C=CH/ST=Zurich/L=Zurich/O=InternetComputer/OU=ApiBoundaryNodes/CN={domain_name}"
            ),
        ])
        .status()
        .context("Failed to generate TLS certificate")?;

    if !status.success() {
        anyhow::bail!("openssl command failed with status: {}", status);
    }

    let status = Command::new("chown")
        .args(["ic-replica:nogroup", tls_key_path, tls_cert_path])
        .status()
        .context("Failed to set ownership of TLS files")?;

    if !status.success() {
        anyhow::bail!("chown command failed with status: {}", status);
    }

    let status = Command::new("chmod")
        .args(["644", tls_key_path, tls_cert_path])
        .status()
        .context("Failed to set permissions of TLS files")?;

    ensure!(
        status.success(),
        "chmod command failed with status: {status}"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use config_types::{FixedIpv6Config, GuestOSConfig, Ipv6Config, NetworkSettings};
    use ic_config::{ConfigOptional, config_parser::ConfigSource};

    #[test]
    fn test_generate_ipv6_prefix() {
        let result = generate_ipv6_prefix("2001:db8:1234:5678:9abc:def0:1234:5678");
        assert_eq!(result, "2001:db8:1234:5678::/64");

        // Test IPv6 address with less than 4 segments (should fallback)
        let result = generate_ipv6_prefix("2001:db8");
        assert_eq!(result, "::1/128");
    }

    #[test]
    fn test_template_substitution_with_default_config() {
        let guestos_config = create_test_guestos_config();
        let template = get_config_vars(&guestos_config).unwrap();
        let output_content = render_ic_config(template).unwrap();

        // Verify that all placeholders were replaced
        assert!(!output_content.contains("{{ ipv6_address }}"));
        assert!(!output_content.contains("{{ ipv6_prefix }}"));
        assert!(!output_content.contains("{{ ipv4_address }}"));
        assert!(!output_content.contains("{{ ipv4_gateway }}"));
        assert!(!output_content.contains("{{ domain_name }}"));
        assert!(!output_content.contains("{{ nns_urls }}"));
        assert!(!output_content.contains("{{ backup_retention_time_secs }}"));
        assert!(!output_content.contains("{{ backup_purging_interval_secs }}"));
        assert!(!output_content.contains("{{ malicious_behavior }}"));
        assert!(!output_content.contains("{{ query_stats_epoch_length }}"));
        assert!(!output_content.contains("{{ node_reward_type }}"));
        assert!(!output_content.contains("{{ jaeger_addr }}"));

        // Verify that the expected values were substituted
        assert!(output_content.contains("node_ip: \"2001:db8::1\""));
        assert!(output_content.contains("public_address: \"\""));
        assert!(output_content.contains("public_gateway: \"\""));
        assert!(output_content.contains("domain: \"\""));
        assert!(output_content.contains("nns_url: \"http://[::1]:8080\""));
        assert!(output_content.contains("retention_time_secs: 86400"));
        assert!(output_content.contains("purging_interval_secs: 3600"));
        assert!(output_content.contains("malicious_behavior: null"));
        assert!(output_content.contains("query_stats_epoch_length: 600"));
        assert!(output_content.contains("node_reward_type: \"\""));
        assert!(output_content.contains("jaeger_addr: \"\""));

        // Parse the generated result as ConfigOptional and check that it succeeds
        let config_source = ConfigSource::Literal(output_content);
        let parsed_config: ConfigOptional = config_source
            .load()
            .expect("Failed to parse generated config");

        assert_eq!(parsed_config.domain, Some("".to_string()));
        assert_eq!(parsed_config.malicious_behavior, None);

        let registration_config = parsed_config.registration.as_ref().unwrap();
        assert_eq!(
            registration_config.nns_url,
            Some("http://[::1]:8080".to_string())
        );
        assert_eq!(registration_config.node_reward_type, Some("".to_string()));

        let artifact_pool_config = parsed_config.artifact_pool.as_ref().unwrap();
        let backup_config = artifact_pool_config.backup.as_ref().unwrap();
        assert_eq!(backup_config.retention_time_secs, 86400);
        assert_eq!(backup_config.purging_interval_secs, 3600);

        let hypervisor_config = parsed_config.hypervisor.as_ref().unwrap();
        assert_eq!(hypervisor_config.query_stats_epoch_length, 600);

        let tracing_config = parsed_config.tracing.as_ref().unwrap();
        assert_eq!(tracing_config.jaeger_addr, Some("".to_string()));
    }

    fn create_test_guestos_config() -> GuestOSConfig {
        GuestOSConfig {
            network_settings: NetworkSettings {
                ipv6_config: Ipv6Config::Fixed(FixedIpv6Config {
                    address: "2001:db8::1/64".to_string(),
                    gateway: "2001:db8::1".parse().unwrap(),
                }),
                ..Default::default()
            },
            ..GuestOSConfig::test_config()
        }
    }
}
