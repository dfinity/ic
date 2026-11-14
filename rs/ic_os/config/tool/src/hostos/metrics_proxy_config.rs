use anyhow::{Context, Result, bail};
use askama::Template;
use config_types::{HostOSConfig, Ipv6Config, VmSlot, guest_vm_count};
use deterministic_ips::node_type::NodeType;
use deterministic_ips::{MacAddr6Ext, calculate_deterministic_mac};
use std::fs::{Permissions, create_dir_all, set_permissions, write};
use std::net::Ipv6Addr;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// One GuestOS VM for HostOS to chainload metrics from.
pub struct GuestProxyTarget {
    /// Appended to the listen path. Empty on a single-VM node.
    pub path_suffix: String,
    pub address: Ipv6Addr,
}

#[derive(Template)]
#[template(path = "metrics-proxy-hostos.yaml.template", escape = "none")]
pub struct MetricsProxyTemplate {
    pub guests: Vec<GuestProxyTarget>,
}

/// Generate the HostOS metrics-proxy configuration, one proxy pair per guest.
pub fn generate_metrics_proxy_config(config: &HostOSConfig, output_path: &Path) -> Result<()> {
    let template = MetricsProxyTemplate {
        guests: guest_proxy_targets(config)?,
    };

    let output_content = render_metrics_proxy_config(template)?;

    if let Some(parent) = output_path.parent() {
        create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
    }

    write(output_path, &output_content)
        .with_context(|| format!("Failed to write output file: {}", output_path.display()))?;

    // metrics-proxy reads this as an unprivileged user.
    set_permissions(output_path, Permissions::from_mode(0o644))
        .with_context(|| format!("Failed to chmod output file: {}", output_path.display()))
}

pub fn render_metrics_proxy_config(template: MetricsProxyTemplate) -> Result<String> {
    template
        .render()
        .context("Failed to render metrics-proxy template")
}

fn guest_proxy_targets(config: &HostOSConfig) -> Result<Vec<GuestProxyTarget>> {
    let Ipv6Config::Deterministic(ipv6_config) = &config.network_settings.ipv6_config else {
        bail!("Ipv6Config is not of type Deterministic. Cannot derive GuestOS addresses.");
    };

    guest_vm_slots(config)
        .into_iter()
        .map(|slot| {
            let mac = calculate_deterministic_mac(
                &config.icos_settings.mgmt_mac,
                config.icos_settings.deployment_environment,
                NodeType::GuestOS,
                slot,
            );
            let address = mac.calculate_slaac(&ipv6_config.prefix)?;

            let suffix = slot.to_suffix();
            let path_suffix = if suffix.is_empty() {
                String::new()
            } else {
                format!("/{suffix}")
            };

            Ok(GuestProxyTarget {
                path_suffix,
                address,
            })
        })
        .collect()
}

/// A single-VM node holds one guest in [`VmSlot::Plain`], a multi-VM node
/// holds its guests in slots 1..=count.
fn guest_vm_slots(config: &HostOSConfig) -> Vec<VmSlot> {
    let count = config
        .icos_settings
        .node_reward_type
        .as_deref()
        .map_or(1, guest_vm_count);

    if count == 1 {
        return vec![VmSlot::Plain];
    }

    (1..=count)
        .filter_map(|slot| u8::try_from(slot).ok())
        .map(VmSlot::new)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use config_types::{
        DeploymentEnvironment, DeterministicIpv6Config, HostOSSettings, ICOSSettings, Ipv6Config,
        NetworkSettings,
    };

    fn test_config(node_reward_type: Option<&str>) -> HostOSConfig {
        HostOSConfig {
            config_version: "1".to_string(),
            network_settings: NetworkSettings {
                ipv6_config: Ipv6Config::Deterministic(DeterministicIpv6Config {
                    prefix: "2602:ffe4:801:17".to_string(),
                    prefix_length: 64,
                    gateway: "2602:ffe4:801:17::1".parse().unwrap(),
                }),
                ipv4_config: None,
                domain_name: None,
            },
            icos_settings: ICOSSettings {
                node_reward_type: node_reward_type.map(str::to_string),
                mgmt_mac: "b0:7b:25:c8:f6:c0".parse().unwrap(),
                deployment_environment: DeploymentEnvironment::Mainnet,
                ..Default::default()
            },
            hostos_settings: HostOSSettings::default(),
            guestos_settings: Default::default(),
        }
    }

    #[test]
    fn single_vm_node_keeps_unsuffixed_paths() {
        for reward_type in [None, Some("type3.1"), Some("type4"), Some("type4.5")] {
            let targets = guest_proxy_targets(&test_config(reward_type)).unwrap();
            assert_eq!(targets.len(), 1, "{reward_type:?}");
            assert_eq!(targets[0].path_suffix, "", "{reward_type:?}");
        }
    }

    #[test]
    fn multi_vm_node_gets_one_target_per_slot() {
        for (reward_type, count) in [("type4.1", 60), ("type4.2", 15), ("type4.4", 2)] {
            let targets = guest_proxy_targets(&test_config(Some(reward_type))).unwrap();
            assert_eq!(targets.len(), count, "{reward_type}");
            assert_eq!(targets[0].path_suffix, "/1", "{reward_type}");
            assert_eq!(
                targets[count - 1].path_suffix,
                format!("/{count}"),
                "{reward_type}"
            );
        }
    }

    #[test]
    fn guest_addresses_are_distinct() {
        let targets = guest_proxy_targets(&test_config(Some("type4.2"))).unwrap();
        let mut addresses: Vec<_> = targets.iter().map(|t| t.address).collect();
        addresses.sort();
        addresses.dedup();
        assert_eq!(addresses.len(), targets.len());
    }

    #[test]
    fn rendered_config_has_no_unresolved_guestos_name() {
        let template = MetricsProxyTemplate {
            guests: guest_proxy_targets(&test_config(Some("type4.4"))).unwrap(),
        };
        let rendered = render_metrics_proxy_config(template).unwrap();

        assert!(!rendered.contains("https://guestos:"));
        assert!(rendered.contains("/metrics/guestos_replica/1"));
        assert!(rendered.contains("/metrics/guestos_node_exporter/2"));
        assert!(rendered.contains("/metrics/hostos_node_exporter"));
        assert!(rendered.trim_end().ends_with("node_exporter.key"));
    }

    #[derive(serde::Deserialize)]
    struct ProxyConfig {
        proxies: Vec<Proxy>,
        metrics: Endpoint,
    }

    #[derive(serde::Deserialize)]
    struct Proxy {
        listen_on: Endpoint,
        connect_to: Endpoint,
    }

    #[derive(serde::Deserialize)]
    struct Endpoint {
        url: String,
    }

    fn render_for(reward_type: Option<&str>) -> (Vec<GuestProxyTarget>, String) {
        let targets = guest_proxy_targets(&test_config(reward_type)).unwrap();
        let rendered = render_metrics_proxy_config(MetricsProxyTemplate {
            guests: guest_proxy_targets(&test_config(reward_type)).unwrap(),
        })
        .unwrap();
        (targets, rendered)
    }

    #[test]
    fn rendered_config_parses_as_yaml() {
        for reward_type in [None, Some("type4.4"), Some("type4.2")] {
            let (targets, rendered) = render_for(reward_type);
            let config: ProxyConfig = serde_yaml::from_str(&rendered)
                .unwrap_or_else(|e| panic!("{reward_type:?} did not parse: {e}"));

            // One HostOS proxy, then a replica and a node_exporter proxy per guest.
            assert_eq!(
                config.proxies.len(),
                1 + 2 * targets.len(),
                "{reward_type:?}"
            );
            assert!(
                config.metrics.url.ends_with(":19100/metrics"),
                "{reward_type:?}"
            );
        }
    }

    #[test]
    fn listen_urls_are_unique_and_carry_the_slot() {
        for reward_type in [None, Some("type4.4"), Some("type4.2")] {
            let (targets, rendered) = render_for(reward_type);
            let config: ProxyConfig = serde_yaml::from_str(&rendered).unwrap();

            let mut listen: Vec<_> = config.proxies.iter().map(|p| &p.listen_on.url).collect();
            let total = listen.len();
            listen.sort();
            listen.dedup();
            assert_eq!(listen.len(), total, "{reward_type:?}: duplicate listen URL");

            for target in &targets {
                for metric in ["guestos_replica", "guestos_node_exporter"] {
                    let expected =
                        format!("https://[::]:42372/metrics/{metric}{}", target.path_suffix);
                    assert!(
                        config.proxies.iter().any(|p| p.listen_on.url == expected),
                        "{reward_type:?}: no proxy listening on {expected}"
                    );
                }
            }
        }
    }

    #[test]
    fn connect_urls_target_each_guest_address() {
        for reward_type in [None, Some("type4.4"), Some("type4.2")] {
            let (targets, rendered) = render_for(reward_type);
            let config: ProxyConfig = serde_yaml::from_str(&rendered).unwrap();

            for target in &targets {
                for metric in ["guestos_replica", "guestos_node_exporter"] {
                    let expected = format!("https://[{}]:42372/metrics/{metric}", target.address);
                    assert!(
                        config.proxies.iter().any(|p| p.connect_to.url == expected),
                        "{reward_type:?}: nothing connects to {expected}"
                    );
                }
            }

            let guest_connects = config
                .proxies
                .iter()
                .filter(|p| p.connect_to.url.contains(":42372/"))
                .count();
            assert_eq!(guest_connects, 2 * targets.len(), "{reward_type:?}");
        }
    }

    /// Strip comments and blank lines, leaving only what metrics-proxy acts on.
    fn directives(yaml: &str) -> Vec<String> {
        yaml.lines()
            .map(str::trim_end)
            .filter(|line| !line.trim_start().starts_with('#') && !line.trim().is_empty())
            .map(str::to_string)
            .collect()
    }

    /// Generation must be a no-op for single-VM nodes. The golden is the
    /// static file this replaced, with `guestos` swapped for the real address.
    #[test]
    fn single_vm_render_matches_retired_static_file() {
        let targets = guest_proxy_targets(&test_config(None)).unwrap();
        let address = targets[0].address;

        let rendered =
            render_metrics_proxy_config(MetricsProxyTemplate { guests: targets }).unwrap();

        let golden = include_str!("../../testdata/metrics-proxy-hostos-single-vm.yaml.golden")
            .replace(
                "https://guestos:42372",
                &format!("https://[{address}]:42372"),
            );

        assert_eq!(directives(&rendered), directives(&golden));
        assert!(rendered.ends_with('\n'), "config must end with a newline");
    }
}
