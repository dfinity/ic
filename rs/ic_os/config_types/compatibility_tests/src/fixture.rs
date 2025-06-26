use anyhow::{bail, Result};
use config_types::*;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

/// Generates fixtures for the current version, enforcing version increment if config_types has been modified
pub fn generate_fixtures(fixtures_dir: &Path) -> Result<()> {
    generate_fixture_for_config(fixtures_dir, "hostos", generate_default_hostos_config())?;
    generate_fixture_for_config(fixtures_dir, "guestos", generate_default_guestos_config())?;

    Ok(())
}

fn generate_fixture_for_config<T>(fixtures_dir: &Path, config_type: &str, config: T) -> Result<()>
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq,
{
    let fixture_path = fixtures_dir.join(format!("{config_type}_v{CONFIG_VERSION}.json"));

    if config_structure_changed(&fixture_path, &config)? {
        bail!(
            "CONFIG_VERSION in lib.rs ({CONFIG_VERSION}) already has a fixture, but the config \
            structure has changed. Please increment config_types CONFIG_VERSION before generating \
            a new fixture.",
        );
    }

    serde_json::to_writer_pretty(fs::File::create(&fixture_path)?, &config)?;
    Ok(())
}

/// Checks if the current config_types structure has changed compared to the existing fixture version
fn config_structure_changed<T>(existing_fixture_path: &Path, new_config: &T) -> Result<bool>
where
    T: serde::de::DeserializeOwned + PartialEq,
{
    // If an existing fixture doesn't exist, this is a new config version
    if !existing_fixture_path.exists() {
        return Ok(false);
    }

    let file = fs::File::open(existing_fixture_path)?;

    match serde_json::from_reader::<_, T>(file) {
        Ok(existing_config) => Ok(existing_config != *new_config),
        Err(_) => Ok(true), // If we can't parse the existing fixture, assume structure changed
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
        enable_trusted_execution_environment: false,
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

fn generate_default_guestos_config() -> GuestOSConfig {
    let default_hostos_config = generate_default_hostos_config();
    GuestOSConfig {
        config_version: CONFIG_VERSION.to_string(),
        network_settings: default_hostos_config.network_settings,
        icos_settings: default_hostos_config.icos_settings,
        guestos_settings: default_hostos_config.guestos_settings,
        guest_vm_type: GuestVMType::Default,
        upgrade_config: GuestOSUpgradeConfig {
            peer_guest_vm_address: Some("2a00:fb01:400:200:6801:95ff:fed7:d475".parse().unwrap()),
        },
    }
}
