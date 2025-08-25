use anyhow::{Context, Result};
use config_types::{GuestOSConfig, Ipv6Config};
use serde_json;
use std::fs::{read_to_string, write};
use std::path::Path;
use std::process::Command;

/// Generate IC configuration from template and guestos config
pub fn generate_ic_config(
    guestos_config: &GuestOSConfig,
    template_path: &Path,
    output_path: &Path,
) -> Result<()> {
    let template_content = read_to_string(template_path)
        .with_context(|| format!("Failed to read template file: {}", template_path.display()))?;

    let config_vars = get_config_vars(guestos_config)?;

    let output_content = substitute_template(&template_content, &config_vars);

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
    if let Some(domain_name) = &config_vars.generate_ic_boundary_tls_cert {
        if !domain_name.is_empty() && domain_name != "null" {
            generate_tls_certificate(domain_name)?;
        }
    }

    Ok(())
}

#[derive(Debug)]
struct ConfigVariables {
    ipv6_address: String,
    ipv6_prefix: String,
    ipv4_address: String,
    ipv4_gateway: String,
    nns_urls: String,
    backup_retention_time_secs: String,
    backup_purging_interval_secs: String,
    query_stats_epoch_length: String,
    jaeger_addr: String,
    domain_name: String,
    node_reward_type: String,
    malicious_behavior: String,
    generate_ic_boundary_tls_cert: Option<String>,
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
                .unwrap_or(&fixed_config.address);
            let ipv6_address = ipv6_address.to_string();

            let ipv6_prefix = generate_ipv6_prefix(&ipv6_address);
            Ok((ipv6_address, ipv6_prefix))
        }
        Ipv6Config::RouterAdvertisement => {
            let interface = get_network_interface()?;
            let ipv6_address = get_interface_ipv6_address(&interface)?;

            if ipv6_address.is_empty() {
                anyhow::bail!("Cannot determine an IPv6 address, aborting");
            }

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

fn get_config_vars(guestos_config: &GuestOSConfig) -> Result<ConfigVariables> {
    let (ipv6_address, ipv6_prefix) = configure_ipv6(guestos_config)?;

    let (ipv4_address, ipv4_gateway) = configure_ipv4(guestos_config);

    // Helper function to set default value if empty or "null"
    fn with_default(value: String, default: &str) -> String {
        if value.is_empty() || value == "null" {
            default.to_string()
        } else {
            value
        }
    }

    // Helper function to set empty string as default
    fn with_empty_default(value: String) -> String {
        with_default(value, "")
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

    let generate_ic_boundary_tls_cert = guestos_config
        .guestos_settings
        .guestos_dev_settings
        .generate_ic_boundary_tls_cert
        .clone();

    Ok(ConfigVariables {
        ipv6_address,
        ipv6_prefix,
        ipv4_address,
        ipv4_gateway,
        nns_urls: with_default(nns_urls, "http://[::1]:8080"),
        backup_retention_time_secs: with_default(backup_retention_time_secs, "86400"), // 24h
        backup_purging_interval_secs: with_default(backup_purging_interval_secs, "3600"), // 1h
        query_stats_epoch_length: with_default(query_stats_epoch_length, "600"), // Default is 600 blocks (around 10min)
        jaeger_addr: with_empty_default(jaeger_addr),
        domain_name: with_empty_default(domain_name),
        node_reward_type: with_empty_default(node_reward_type),
        malicious_behavior: with_default(malicious_behavior, "null"),
        generate_ic_boundary_tls_cert,
    })
}

fn substitute_template(template_content: &str, config_vars: &ConfigVariables) -> String {
    let mut content = template_content.to_string();

    content = content.replace("{{ ipv6_address }}", &config_vars.ipv6_address);
    content = content.replace("{{ ipv6_prefix }}", &config_vars.ipv6_prefix);
    content = content.replace("{{ ipv4_address }}", &config_vars.ipv4_address);
    content = content.replace("{{ ipv4_gateway }}", &config_vars.ipv4_gateway);
    content = content.replace("{{ domain_name }}", &config_vars.domain_name);
    content = content.replace("{{ nns_urls }}", &config_vars.nns_urls);
    content = content.replace(
        "{{ backup_retention_time_secs }}",
        &config_vars.backup_retention_time_secs,
    );
    content = content.replace(
        "{{ backup_purging_interval_secs }}",
        &config_vars.backup_purging_interval_secs,
    );
    content = content.replace("{{ malicious_behavior }}", &config_vars.malicious_behavior);
    content = content.replace(
        "{{ query_stats_epoch_length }}",
        &config_vars.query_stats_epoch_length,
    );
    content = content.replace("{{ node_reward_type }}", &config_vars.node_reward_type);
    content = content.replace("{{ jaeger_addr }}", &config_vars.jaeger_addr);

    content
}

fn get_network_interface() -> Result<String> {
    // Find network interfaces (excluding virtual ones)
    let output = Command::new("find")
        .args([
            "/sys/class/net",
            "-type",
            "l",
            "-not",
            "-lname",
            "*virtual*",
            "-exec",
            "basename",
            "{}",
            ";",
        ])
        .output()
        .context("Failed to find network interfaces")?;

    let interfaces: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|s| s.to_string())
        .collect();

    if interfaces.is_empty() {
        anyhow::bail!("No network interfaces found");
    }

    // Return the first interface
    Ok(interfaces[0].clone())
}

fn get_interface_ipv6_address(interface: &str) -> Result<String> {
    // Try to get IPv6 address with retries
    for retry in 0..12 {
        let output = Command::new("ip")
            .args([
                "-o", "-6", "addr", "show", "up", "primary", "scope", "global", interface,
            ])
            .output()
            .context("Failed to get IPv6 address")?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        if let Some(line) = output_str.lines().next() {
            if let Some(addr_part) = line.split_whitespace().nth(3) {
                if let Some(addr) = addr_part.split('/').next() {
                    return Ok(addr.to_string());
                }
            }
        }

        if retry < 11 {
            eprintln!("Retrying {} ...", 11 - retry);
            std::thread::sleep(std::time::Duration::from_secs(10));
        }
    }

    Ok(String::new())
}

fn generate_tls_certificate(domain_name: &str) -> Result<()> {
    let tls_key_path = "/var/lib/ic/data/ic-boundary-tls.key";
    let tls_cert_path = "/var/lib/ic/data/ic-boundary-tls.crt";

    // Generate certificate using openssl
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

    // Set ownership and permissions
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

    if !status.success() {
        anyhow::bail!("chmod command failed with status: {}", status);
    }

    Ok(())
}
