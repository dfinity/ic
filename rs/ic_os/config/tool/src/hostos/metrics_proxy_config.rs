use anyhow::{Context, Result, bail};
use askama::Template;
use config_types::{HostOSConfig, Ipv6Config, VmSlot};
use deterministic_ips::node_type::NodeType;
use std::fs::write;
use std::net::Ipv6Addr;
use std::path::Path;

use crate::hostos::guestos_config::node_ipv6_address;

#[derive(Template)]
#[template(path = "metrics-proxy.yaml.template", escape = "none")]
pub struct MetricsProxyConfigTemplate {
    pub guest_vms: Vec<GuestVmProxy>,
}

pub struct GuestVmProxy {
    /// Empty for a single GuestOS, so it keeps serving the paths clients
    /// scrape today.
    pub path_suffix: String,
    pub address: Ipv6Addr,
}

pub fn generate_metrics_proxy_config(
    hostos_config: &HostOSConfig,
    output_path: &Path,
) -> Result<()> {
    let output_content = render_metrics_proxy_config(get_config_vars(hostos_config)?)?;

    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    write(output_path, &output_content)
        .with_context(|| format!("Failed to write output file: {}", output_path.display()))
}

pub fn render_metrics_proxy_config(template: MetricsProxyConfigTemplate) -> Result<String> {
    template
        .render()
        .context("Failed to render metrics-proxy config template")
}

fn get_config_vars(hostos_config: &HostOSConfig) -> Result<MetricsProxyConfigTemplate> {
    let Ipv6Config::Deterministic(deterministic_ipv6_config) =
        &hostos_config.network_settings.ipv6_config
    else {
        bail!("HostOSConfig Ipv6Config should always be of type Deterministic.");
    };

    let node_reward_type = hostos_config.icos_settings.node_reward_type.as_deref();

    let guest_vms = VmSlot::all_for_node_reward_type(node_reward_type)
        .into_iter()
        .map(|slot| {
            Ok(GuestVmProxy {
                path_suffix: match slot {
                    VmSlot::Plain => String::new(),
                    VmSlot::Multi(_) => format!("/{}", slot.to_suffix()),
                },
                address: node_ipv6_address(
                    slot,
                    NodeType::GuestOS,
                    hostos_config,
                    deterministic_ipv6_config,
                )?,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(MetricsProxyConfigTemplate { guest_vms })
}

#[cfg(test)]
mod tests {
    use super::*;
    use config_types::{DeterministicIpv6Config, ICOSSettings, NetworkSettings};

    fn hostos_config(node_reward_type: Option<&str>) -> HostOSConfig {
        HostOSConfig {
            network_settings: NetworkSettings {
                ipv6_config: Ipv6Config::Deterministic(DeterministicIpv6Config {
                    prefix: "2001:db8::".to_string(),
                    prefix_length: 64,
                    gateway: "2001:db8::1".parse().unwrap(),
                }),
                ..Default::default()
            },
            icos_settings: ICOSSettings {
                node_reward_type: node_reward_type.map(str::to_string),
                ..Default::default()
            },
            ..HostOSConfig::default()
        }
    }

    fn render(node_reward_type: Option<&str>) -> String {
        render_metrics_proxy_config(get_config_vars(&hostos_config(node_reward_type)).unwrap())
            .unwrap()
    }

    #[test]
    fn test_single_guest_vm_keeps_unsuffixed_paths() {
        let rendered = render(Some("type3.1"));

        assert!(rendered.contains("url: https://[::]:42372/metrics/guestos_replica\n"));
        assert!(rendered.contains("url: https://[::]:42372/metrics/guestos_node_exporter\n"));
        assert!(!rendered.contains("/metrics/guestos_replica/"));
    }

    #[test]
    fn test_multi_guest_vms_get_one_path_each() {
        let rendered = render(Some("type4.4"));

        for slot in 1..=2 {
            assert!(rendered.contains(&format!(
                "url: https://[::]:42372/metrics/guestos_replica/{slot}\n"
            )));
            assert!(rendered.contains(&format!(
                "url: https://[::]:42372/metrics/guestos_node_exporter/{slot}\n"
            )));
        }
        assert!(!rendered.contains("url: https://[::]:42372/metrics/guestos_replica\n"));
    }

    #[test]
    fn test_guest_vm_addresses_are_distinct() {
        let config = hostos_config(Some("type4.1"));
        let mut addresses: Vec<_> = get_config_vars(&config)
            .unwrap()
            .guest_vms
            .iter()
            .map(|vm| vm.address)
            .collect();

        assert_eq!(addresses.len(), 60);
        addresses.sort();
        addresses.dedup();
        assert_eq!(addresses.len(), 60);
    }

    #[test]
    fn test_single_guest_vm_address_matches_nss_icos() {
        let config = hostos_config(None);
        let Ipv6Config::Deterministic(deterministic) = &config.network_settings.ipv6_config else {
            unreachable!()
        };
        let host =
            node_ipv6_address(VmSlot::Plain, NodeType::HostOS, &config, deterministic).unwrap();

        let mut segments = host.segments();
        segments[4] = 0x6801;

        assert_eq!(
            get_config_vars(&config).unwrap().guest_vms[0].address,
            Ipv6Addr::from(segments)
        );
    }
}
