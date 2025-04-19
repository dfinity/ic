use config_types::*;
use serde_json;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

pub struct ConfigFixture {
    version: String,
    hostos_config: HostOSConfig,
    guestos_config: GuestOSConfig,
}

impl ConfigFixture {
    pub fn generate_for_version(version: &str) -> Self {
        let base_config = generate_test_base_config(version);

        let hostos_config = HostOSConfig {
            config_version: base_config.0.clone(),
            network_settings: base_config.1.clone(),
            icos_settings: base_config.2.clone(),
            hostos_settings: base_config.3.clone(),
            guestos_settings: base_config.4.clone(),
        };

        let guestos_config = GuestOSConfig {
            config_version: base_config.0.clone(),
            network_settings: base_config.1.clone(),
            icos_settings: base_config.2.clone(),
            guestos_settings: base_config.4.clone(),
        };

        Self {
            version: version.to_string(),
            hostos_config,
            guestos_config,
        }
    }

    pub fn save_to_directory(&self, dir: &Path) -> std::io::Result<()> {
        fs::create_dir_all(dir)?;

        serde_json::to_writer_pretty(
            fs::File::create(dir.join(format!("hostos_v{}.json", self.version)))?,
            &self.hostos_config,
        )?;

        serde_json::to_writer_pretty(
            fs::File::create(dir.join(format!("guestos_v{}.json", self.version)))?,
            &self.guestos_config,
        )?;

        Ok(())
    }
}

fn generate_test_base_config(
    version: &str,
) -> (
    String,
    NetworkSettings,
    ICOSSettings,
    HostOSSettings,
    GuestOSSettings,
) {
    use url::Url;

    let ipv6_config = Ipv6Config::Fixed(FixedIpv6Config {
        address: "2a00:fb01:400:200::1/64".to_string(),
        gateway: "2a00:fb01:400:200::1".parse::<Ipv6Addr>().unwrap(),
    });

    let network_settings = NetworkSettings {
        ipv6_config,
        ipv4_config: Some(Ipv4Config {
            address: Ipv4Addr::new(192, 168, 1, 1),
            gateway: Ipv4Addr::new(192, 168, 1, 254),
            prefix_length: 24,
        }),
        domain_name: Some("ic.test".to_string()),
    };

    let icos_settings = ICOSSettings {
        node_reward_type: Some("default".to_string()),
        mgmt_mac: "00:00:00:00:00:01".parse().unwrap(),
        deployment_environment: DeploymentEnvironment::Testnet,
        logging: Logging::default(),
        use_nns_public_key: false,
        nns_urls: vec![Url::parse("http://localhost:8080").unwrap()],
        use_node_operator_private_key: false,
        use_ssh_authorized_keys: false,
        icos_dev_settings: ICOSDevSettings::default(),
    };

    let hostos_settings = HostOSSettings {
        vm_memory: 4096,
        vm_cpu: "host".to_string(),
        vm_nr_of_vcpus: 4,
        verbose: false,
    };

    let guestos_settings = GuestOSSettings::default();

    (
        version.to_string(),
        network_settings,
        icos_settings,
        hostos_settings,
        guestos_settings,
    )
}
