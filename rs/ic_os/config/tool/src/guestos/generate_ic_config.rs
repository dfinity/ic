use anyhow::{Context, Result, bail, ensure};
use askama::Template;
use config_types::{DeploymentEnvironment, GuestOSConfig, Ipv6Config, is_multi_vm_node};
use ic_types::malicious_behavior::MaliciousBehavior;
use ipnet::Ipv6Net;
use std::fs::write;
use std::net::Ipv6Addr;
use std::path::Path;
use std::process::Command;
use std::str::FromStr;
use std::time::Duration;

use crate::guestos::network::{get_best_interface_name, get_interface_addresses};
use crate::validation::{validate_domain_name, validate_node_reward_type};

const TLS_KEY_PATH: &str = "/var/lib/ic/data/ic-boundary-tls.key";
const TLS_CERT_PATH: &str = "/var/lib/ic/data/ic-boundary-tls.crt";

/// The values substituted into `ic.json5.template`.
///
/// Most of them come from the GuestOS config, which the HostOS writes, and the
/// template is rendered without escaping. So the template renders every field
/// that can hold arbitrary text (strings, options, structs) through the `json`
/// filter, which turns it into a single JSON5 value. The remaining fields are
/// typed so that their `Display` output cannot contain quotes, comments or any
/// other JSON5 syntax.
#[derive(Template)]
#[template(path = "ic.json5.template", escape = "none")]
pub struct IcConfigTemplate {
    pub ipv6_prefix: Ipv6Net,
    pub ipv4_address: String,
    pub ipv4_gateway: String,
    pub nns_urls: String,
    pub backup_retention_time_secs: u64,
    pub backup_purging_interval_secs: u64,
    pub query_stats_epoch_length: u64,
    pub jaeger_addr: String,
    pub domain_name: String,
    pub node_reward_type: String,
    pub malicious_behavior: Option<MaliciousBehavior>,
    pub extra_api_boundary_node_trust_anchors_pem: Option<String>,
    pub engine_management_canister_id: Option<String>,
    /// IPv6 address of the peer Guest VM (the Upgrade VM inside the Default VM
    /// and vice versa).
    pub peer_guest_vm_address: Option<Ipv6Addr>,
}

impl IcConfigTemplate {
    /// Used by the template to pick the GuestOS metrics firewall rule. Derived
    /// rather than stored so it cannot contradict `node_reward_type`.
    fn multi_vm_guest(&self) -> bool {
        is_multi_vm_node(&self.node_reward_type)
    }
}

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

    // Set up TLS certificate and key for ic-boundary (system test use only).
    // A pre-generated cert (e.g. from a playnet) takes priority over self-signed generation.
    let dev_settings = &guestos_config.guestos_settings.guestos_dev_settings;
    if let Some(tls_cert) = &dev_settings.ic_boundary_tls_cert {
        write_tls_certificate(&tls_cert.cert_pem, &tls_cert.key_pem)?;
    } else if let Some(domain_name) = &dev_settings.generate_ic_boundary_tls_cert
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

fn generate_ipv6_prefix(ipv6_address: Ipv6Addr) -> Ipv6Net {
    if ipv6_address.is_loopback() {
        return Ipv6Net::new_assert(ipv6_address, 128);
    }

    Ipv6Net::new_assert(ipv6_address, 64).trunc()
}

fn configure_ipv6(guestos_config: &GuestOSConfig) -> Result<(String, Ipv6Net)> {
    match &guestos_config.network_settings.ipv6_config {
        Ipv6Config::Deterministic(_) => {
            bail!("GuestOS IPv6 configuration should not be 'Deterministic'.");
        }
        Ipv6Config::Fixed(fixed_config) => {
            let ipv6_net = Ipv6Net::from_str(&fixed_config.address)
                .context("unable to parse fixed config as IPv6 subnet")?;

            let ipv6_address = ipv6_net.addr();
            let ipv6_prefix = generate_ipv6_prefix(ipv6_address);

            Ok((ipv6_address.to_string(), ipv6_prefix))
        }
        Ipv6Config::RouterAdvertisement => {
            let ipv6_address = get_best_interface_ipv6_address()?;
            let ipv6_prefix = generate_ipv6_prefix(ipv6_address);

            Ok((ipv6_address.to_string(), ipv6_prefix))
        }
        Ipv6Config::Unknown => {
            bail!("Unknown IPv6 configuration type.");
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
    let (_, ipv6_prefix) = configure_ipv6(guestos_config)?;
    let (ipv4_address, ipv4_gateway) = configure_ipv4(guestos_config);

    let nns_urls = guestos_config
        .icos_settings
        .nns_urls
        .iter()
        .map(|url| url.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let nns_urls = if nns_urls.is_empty() {
        "http://[::1]:8080".to_string()
    } else {
        nns_urls
    };

    let dev_settings = &guestos_config.guestos_settings.guestos_dev_settings;
    let backup_spool = dev_settings.backup_spool.as_ref();

    let backup_retention_time_secs = backup_spool
        .and_then(|spool| spool.backup_retention_time_seconds)
        .unwrap_or(86400); // 24h

    let backup_purging_interval_secs = backup_spool
        .and_then(|spool| spool.backup_purging_interval_seconds)
        .unwrap_or(3600); // 1h

    // Default is 600 blocks (around 10min)
    let query_stats_epoch_length = dev_settings.query_stats_epoch_length.unwrap_or(600);

    let jaeger_addr = dev_settings.jaeger_addr.clone().unwrap_or_default();

    // An empty value means the same as an unset one, so only non-empty values
    // are validated.
    let domain_name = guestos_config
        .network_settings
        .domain_name
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !domain_name.is_empty() {
        validate_domain_name(&domain_name)?;
    }

    let node_reward_type = guestos_config
        .icos_settings
        .node_reward_type
        .clone()
        .unwrap_or_default();
    if !node_reward_type.is_empty() {
        validate_node_reward_type(&node_reward_type)?;
    }

    let engine_management_canister_id = match &guestos_config
        .guestos_settings
        .engine_management_canister_id
    {
        Some(id) => Some(id.clone()),
        // Mainnet's engine management canister is well-known, so mainnet
        // nodes do not have to configure it explicitly.
        None if guestos_config.icos_settings.deployment_environment
            == DeploymentEnvironment::Mainnet =>
        {
            Some(ic_config::cloud_engine::MAINNET_ENGINE_MANAGEMENT_CANISTER_ID.to_string())
        }
        None => None,
    };

    Ok(IcConfigTemplate {
        // TODO https://dfinity.atlassian.net/browse/NODE-1909
        ipv6_prefix,
        ipv4_address,
        ipv4_gateway,
        nns_urls,
        backup_retention_time_secs,
        backup_purging_interval_secs,
        query_stats_epoch_length,
        jaeger_addr,
        domain_name,
        node_reward_type,
        malicious_behavior: dev_settings.malicious_behavior.clone(),
        extra_api_boundary_node_trust_anchors_pem: dev_settings
            .extra_api_boundary_node_trust_anchors_pem
            .clone(),
        engine_management_canister_id,
        peer_guest_vm_address: guestos_config.upgrade_config.peer_guest_vm_address,
    })
}

/// Picks the best matching interface and tries to get its IPv6 address
pub fn get_best_interface_ipv6_address() -> Result<Ipv6Addr> {
    let interface = get_best_interface_name().context("unable to pick an interface")?;

    const MAX_RETRIES: usize = 5;
    let mut delay = Duration::from_secs(1);

    for attempt in 0..MAX_RETRIES {
        match get_interface_addresses(&interface) {
            Ok((_, Some(ipv6_addr))) => {
                return Ok(ipv6_addr);
            }

            Ok((_, None)) => {
                eprintln!(
                    "No IPv6 addresses configured (retries left: {})",
                    MAX_RETRIES - attempt,
                );
            }

            Err(e) => {
                eprintln!(
                    "Failed to get IPv6 address: {} (retries left: {})",
                    e,
                    MAX_RETRIES - attempt,
                );
            }
        }

        std::thread::sleep(delay);
        delay *= 2;
    }

    bail!("Cannot determine an IPv6 address, aborting");
}

fn write_tls_certificate(cert_pem: &str, key_pem: &str) -> Result<()> {
    write(TLS_CERT_PATH, cert_pem).context("Failed to write TLS certificate")?;
    write(TLS_KEY_PATH, key_pem).context("Failed to write TLS key")?;
    set_tls_file_ownership_and_permissions()
}

fn generate_tls_certificate(domain_name: &str) -> Result<()> {
    let status = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            TLS_KEY_PATH,
            "-out",
            TLS_CERT_PATH,
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
        bail!("openssl command failed with status: {}", status);
    }

    set_tls_file_ownership_and_permissions()
}

fn set_tls_file_ownership_and_permissions() -> Result<()> {
    let status = Command::new("chown")
        .args(["ic-replica:nogroup", TLS_KEY_PATH, TLS_CERT_PATH])
        .status()
        .context("Failed to set ownership of TLS files")?;

    if !status.success() {
        bail!("chown command failed with status: {}", status);
    }

    let status = Command::new("chmod")
        .args(["644", TLS_KEY_PATH, TLS_CERT_PATH])
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
        let result =
            generate_ipv6_prefix("2001:db8:1234:5678:9abc:def0:1234:5678".parse().unwrap());
        assert_eq!(result.to_string(), "2001:db8:1234:5678::/64");

        let result = generate_ipv6_prefix(Ipv6Addr::LOCALHOST);
        assert_eq!(result.to_string(), "::1/128");
    }

    /// Renders the template without the validation in `get_config_vars`, so
    /// that tests can check the template on its own.
    fn render_and_parse(modify: impl FnOnce(&mut IcConfigTemplate)) -> ConfigOptional {
        let mut template = get_config_vars(&create_test_guestos_config()).unwrap();
        modify(&mut template);
        let output_content = render_ic_config(template).unwrap();
        ConfigSource::Literal(output_content.clone())
            .load()
            .unwrap_or_else(|e| panic!("Failed to parse generated config: {e}\n{output_content}"))
    }

    /// Strings from the GuestOS config must each end up as a single JSON5
    /// string, so that they cannot override other parts of `ic.json5`, e.g.
    /// redirect the registry local store to a HostOS-controlled directory.
    #[test]
    fn test_template_substitution_is_injection_safe() {
        // If substituted verbatim between quotes, `domain_name` opens a block
        // comment and `node_reward_type` closes it at the top level, adds its
        // own `registry_client` section and reopens `registration` so that the
        // rest of the document still parses.
        let domain_name = r#"x", /*"#;
        let node_reward_type = r#"*/ registry_client: { local_store: "/run/config/bootstrap/evil" }, registration: { node_reward_type: "type1"#;

        let parsed_config = render_and_parse(|template| {
            template.domain_name = domain_name.to_string();
            template.node_reward_type = node_reward_type.to_string();
        });

        assert_eq!(parsed_config.domain.as_deref(), Some(domain_name));
        assert_eq!(
            parsed_config
                .registration
                .unwrap()
                .node_reward_type
                .as_deref(),
            Some(node_reward_type)
        );

        // The paths that the replica keeps its trusted state in are unchanged.
        assert_eq!(
            parsed_config.registry_client.unwrap().local_store,
            Path::new("/var/lib/ic/data/ic_registry_local_store/")
        );
        assert_eq!(
            parsed_config.state_manager.unwrap().state_root,
            Path::new("/var/lib/ic/data/ic_state")
        );
        assert_eq!(
            parsed_config.crypto.unwrap().crypto_root,
            Path::new("/var/lib/ic/crypto")
        );
    }

    /// Every string field comes back exactly as it went in, whatever JSON5
    /// syntax it contains.
    #[test]
    fn test_template_substitution_escapes_strings() {
        let s = "a\"b\\c'd\ne */ f // g /* h <i>&j";

        let parsed_config = render_and_parse(|template| {
            template.ipv4_address = s.to_string();
            template.ipv4_gateway = s.to_string();
            template.nns_urls = s.to_string();
            template.jaeger_addr = s.to_string();
            template.domain_name = s.to_string();
            template.node_reward_type = s.to_string();
            template.extra_api_boundary_node_trust_anchors_pem = Some(s.to_string());
        });

        let ipv4_config = parsed_config.initial_ipv4_config.unwrap();
        assert_eq!(ipv4_config.public_address, s);
        assert_eq!(ipv4_config.public_gateway, s);
        let registration = parsed_config.registration.unwrap();
        assert_eq!(registration.nns_url.as_deref(), Some(s));
        assert_eq!(registration.node_reward_type.as_deref(), Some(s));
        assert_eq!(
            parsed_config.tracing.unwrap().jaeger_addr.as_deref(),
            Some(s)
        );
        assert_eq!(parsed_config.domain.as_deref(), Some(s));
        assert_eq!(
            parsed_config
                .http_handler
                .unwrap()
                .extra_api_boundary_node_trust_anchors_pem
                .as_deref(),
            Some(s)
        );
    }

    #[test]
    fn test_get_config_vars_rejects_invalid_domain_name() {
        let mut guestos_config = create_test_guestos_config();
        guestos_config.network_settings.domain_name = Some(r#"x", /*"#.to_string());
        assert!(get_config_vars(&guestos_config).is_err());

        guestos_config.network_settings.domain_name = Some("Node.Example.COM".to_string());
        assert_eq!(
            get_config_vars(&guestos_config).unwrap().domain_name,
            "node.example.com"
        );
    }

    #[test]
    fn test_get_config_vars_rejects_invalid_node_reward_type() {
        let mut guestos_config = create_test_guestos_config();
        guestos_config.icos_settings.node_reward_type =
            Some(r#"*/ registry_client: { local_store: "/tmp" }, z: ""#.to_string());
        assert!(get_config_vars(&guestos_config).is_err());

        guestos_config.icos_settings.node_reward_type = Some("type3.1".to_string());
        assert_eq!(
            get_config_vars(&guestos_config).unwrap().node_reward_type,
            "type3.1"
        );
    }

    #[test]
    fn test_template_substitution_with_default_config() {
        let guestos_config = create_test_guestos_config();
        let template = get_config_vars(&guestos_config).unwrap();
        let output_content = render_ic_config(template).unwrap();

        // Verify that all placeholders were replaced
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
        assert!(!output_content.contains("{{ peer_guest_vm_address }}"));

        // Without a peer Guest VM address in the config, the disk encryption
        // key exchange port rule is omitted entirely, leaving the port closed.
        // (19522 still appears in the ic-http-adapter output blacklist.)
        assert!(!output_content.contains("tcp dport { 19522 }"));

        // Verify that the expected values were substituted
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

    #[test]
    fn test_template_substitution_with_peer_guest_vm_address() {
        let mut guestos_config = create_test_guestos_config();
        guestos_config.upgrade_config.peer_guest_vm_address =
            Some("2001:db8::6802:94ff:feef:2978".parse().unwrap());
        let template = get_config_vars(&guestos_config).unwrap();
        let output_content = render_ic_config(template).unwrap();

        // With a peer Guest VM address in the config, the disk encryption key
        // exchange port is opened to exactly that address.
        assert!(output_content.contains(
            "ip6 saddr { 2001:db8::6802:94ff:feef:2978 } ct state { new } tcp dport { 19522 } accept"
        ));
    }

    #[test]
    fn test_template_substitution_with_engine_management_canister_id() {
        let mut guestos_config = create_test_guestos_config();
        guestos_config
            .guestos_settings
            .engine_management_canister_id = Some("q6cfj-fyaaa-aaaar-qb77q-cai".to_string());
        let template = get_config_vars(&guestos_config).unwrap();
        let output_content = render_ic_config(template).unwrap();

        // A bare principal is not a JSON5 value, so an unquoted one here makes
        // the whole file unparseable and the replica refuses to start.
        assert!(
            output_content
                .contains(r#"engine_management_canister_id: "q6cfj-fyaaa-aaaar-qb77q-cai""#),
            "{output_content}"
        );

        let parsed_config: ConfigOptional = ConfigSource::Literal(output_content)
            .load()
            .expect("Failed to parse generated config");
        assert_eq!(
            parsed_config
                .cloud_engine
                .as_ref()
                .unwrap()
                .engine_management_canister_id
                .unwrap()
                .to_string(),
            "q6cfj-fyaaa-aaaar-qb77q-cai"
        );
    }

    #[test]
    fn test_template_substitution_with_mainnet_engine_management_canister_id() {
        let mut guestos_config = create_test_guestos_config();
        guestos_config.icos_settings.deployment_environment = DeploymentEnvironment::Mainnet;
        let template = get_config_vars(&guestos_config).unwrap();
        let output_content = render_ic_config(template).unwrap();

        // Mainnet takes the id from the well-known constant instead of the
        // config, and that one has to end up quoted just the same.
        let parsed_config: ConfigOptional = ConfigSource::Literal(output_content)
            .load()
            .expect("Failed to parse generated config");
        assert_eq!(
            parsed_config
                .cloud_engine
                .as_ref()
                .unwrap()
                .engine_management_canister_id
                .unwrap()
                .to_string(),
            ic_config::cloud_engine::MAINNET_ENGINE_MANAGEMENT_CANISTER_ID
        );
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
            ..GuestOSConfig::default()
        }
    }
}
