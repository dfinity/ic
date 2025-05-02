use config_types::*;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

/// Generates fixtures for the current version, enforcing version increment if config_types has been modified
pub fn generate_fixtures(fixtures_dir: &Path) -> std::io::Result<()> {
    let fixture_path = fixtures_dir.join(format!("hostos_v{}.json", CONFIG_VERSION));
    if config_structure_changed(&fixture_path) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("CONFIG_VERSION in lib.rs ({}) already has a fixture, but the config structure has changed. Please increment config_types CONFIG_VERSION before generating a new fixture.", CONFIG_VERSION)
        ));
    }

    let hostos_config = generate_default_hostos_config();

    serde_json::to_writer_pretty(fs::File::create(fixture_path)?, &hostos_config)?;

    Ok(())
}

/// Checks if the current config_types structure has changed compared to the existing fixture version
fn config_structure_changed(existing_hostos_fixture: &Path) -> bool {
    let new_hostos_fixture = generate_default_hostos_config();

    // If an existing fixture doesn't exist, this is a new config version
    if !existing_hostos_fixture.exists() {
        return false;
    }

    let file = fs::File::open(existing_hostos_fixture).unwrap_or_else(|_| {
        panic!(
            "Failed to open existing fixture: {}",
            existing_hostos_fixture.display()
        )
    });

    match serde_json::from_reader::<_, HostOSConfig>(file) {
        Ok(existing_config) => existing_config != new_hostos_fixture,
        Err(_) => true, // If we can't parse the existing fixture, assume structure changed
    }
}

fn generate_default_hostos_config() -> HostOSConfig {
    let network_settings = NetworkSettings {
        ipv6_config: Ipv6Config::Fixed(FixedIpv6Config {
            address: "2a00:fb01:400:200::1/64".to_string(),
            gateway: "2a00:fb01:400:200::1".parse::<Ipv6Addr>().unwrap(),
        }),
        ipv4_config: Some(Ipv4Config {
            address: Ipv4Addr::new(192, 168, 1, 1),
            gateway: Ipv4Addr::new(192, 168, 1, 254),
            prefix_length: 24,
        }),
        domain_name: Some("ic.test".to_string()),
    };

    let icos_settings = ICOSSettings {
        node_reward_type: Some("type3.1".to_string()),
        mgmt_mac: "00:00:00:00:00:01".parse().unwrap(),
        deployment_environment: DeploymentEnvironment::Mainnet,
        logging: Logging::default(),
        use_nns_public_key: false,
        nns_urls: vec![
            url::Url::parse("https://icp-api.io,https://icp0.io,https://ic0.app").unwrap(),
        ],
        use_node_operator_private_key: true,
        use_ssh_authorized_keys: false,
        icos_dev_settings: ICOSDevSettings::default(),
    };

    let hostos_settings = HostOSSettings {
        vm_memory: 4096,
        vm_cpu: "kvm".to_string(),
        vm_nr_of_vcpus: 64,
        verbose: false,
    };

    HostOSConfig {
        config_version: CONFIG_VERSION.to_string(),
        network_settings,
        icos_settings,
        hostos_settings,
        guestos_settings: GuestOSSettings::default(),
    }
}
