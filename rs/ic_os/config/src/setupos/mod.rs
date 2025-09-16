pub mod config_ini;
pub mod deployment_json;

use config_types::*;
use deployment_json::VmResources;
use macaddr::MacAddr6;
use url::Url;

pub fn create_setupos_config(
    node_reward_type: Option<String>,
    mgmt_mac: MacAddr6,
    deployment_environment: DeploymentEnvironment,
    nns_urls: &[Url],
    vm_resources: VmResources,
    enable_trusted_execution_environment: bool,
    use_node_operator_private_key: bool,
    use_ssh_authorized_keys: bool,
    verbose: bool,
    network_settings: NetworkSettings,
) -> SetupOSConfig {
    let icos_settings = ICOSSettings {
        node_reward_type,
        mgmt_mac,
        deployment_environment,
        logging: Logging {},
        use_nns_public_key: false,
        nns_urls: nns_urls.to_vec(),
        use_node_operator_private_key,
        enable_trusted_execution_environment,
        use_ssh_authorized_keys,
        icos_dev_settings: ICOSDevSettings::default(),
    };

    let setupos_settings = SetupOSSettings;

    // Only allow choosing VM memory for dev.
    #[cfg(feature = "dev")]
    let memory = vm_resources.memory.unwrap_or(PROD_GUEST_VM_MEMORY);

    #[cfg(not(feature = "dev"))]
    let memory = PROD_GUEST_VM_MEMORY;

    let hostos_settings = HostOSSettings {
        vm_memory: memory,
        vm_cpu: vm_resources.cpu,
        vm_nr_of_vcpus: vm_resources.nr_of_vcpus,
        verbose,
    };

    let guestos_settings = GuestOSSettings::default();

    SetupOSConfig {
        config_version: CONFIG_VERSION.to_string(),
        network_settings,
        icos_settings,
        setupos_settings,
        hostos_settings,
        guestos_settings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEV_MEM_VALUE: u32 = 42;

    #[allow(clippy::type_complexity)]
    fn test_config_components() -> (
        Option<String>,
        MacAddr6,
        DeploymentEnvironment,
        Vec<Url>,
        VmResources,
        bool,
        bool,
        bool,
        bool,
        NetworkSettings,
    ) {
        (
            // node_reward_type: Option<String>,
            Some("type3.1".to_string()),
            // mgmt_mac: MacAddr6,
            "00:00:00:00:00:01".parse().unwrap(),
            // deployment_environment: DeploymentEnvironment,
            DeploymentEnvironment::Mainnet,
            // nns_urls: &[Url],
            vec![
                "https://icp-api.io".parse().unwrap(),
                "https://icp0.io".parse().unwrap(),
                "https://ic0.app".parse().unwrap(),
            ],
            // vm_resources: VmResources,
            VmResources {
                memory: Some(DEV_MEM_VALUE),
                cpu: "kvm".to_string(),
                nr_of_vcpus: 64,
            },
            // enable_trusted_execution_environment: bool,
            false,
            // use_node_operator_private_key: bool,
            true,
            // use_ssh_authorized_keys: bool,
            false,
            // verbose: bool,
            false,
            // network_settings: NetworkSettings,
            NetworkSettings {
                ipv6_config: Ipv6Config::Deterministic(DeterministicIpv6Config {
                    prefix: "2a00:fb01:400:44".to_string(),
                    prefix_length: 64,
                    gateway: "2a00:fb01:400:44::1".parse().unwrap(),
                }),
                ipv4_config: None,
                domain_name: Some("ic.test".to_string()),
            },
        )
    }

    #[cfg(feature = "dev")]
    #[test]
    fn dev_config_creation() {
        let (
            node_reward_type,
            mgmt_mac,
            deployment_environment,
            nns_urls,
            vm_resources,
            enable_trusted_execution_environment,
            use_node_operator_private_key,
            use_ssh_authorized_keys,
            verbose,
            network_settings,
        ) = test_config_components();

        let setupos_config = create_setupos_config(
            node_reward_type,
            mgmt_mac,
            deployment_environment,
            &nns_urls,
            vm_resources,
            enable_trusted_execution_environment,
            use_node_operator_private_key,
            use_ssh_authorized_keys,
            verbose,
            network_settings,
        );

        assert_ne!(PROD_GUEST_VM_MEMORY, DEV_MEM_VALUE);
        assert_eq!(setupos_config.hostos_settings.vm_memory, DEV_MEM_VALUE);
    }

    #[cfg(not(feature = "dev"))]
    #[test]
    fn prod_config_creation() {
        let (
            node_reward_type,
            mgmt_mac,
            deployment_environment,
            nns_urls,
            vm_resources,
            enable_trusted_execution_environment,
            use_node_operator_private_key,
            use_ssh_authorized_keys,
            verbose,
            network_settings,
        ) = test_config_components();

        let setupos_config = create_setupos_config(
            node_reward_type,
            mgmt_mac,
            deployment_environment,
            &nns_urls,
            vm_resources,
            enable_trusted_execution_environment,
            use_node_operator_private_key,
            use_ssh_authorized_keys,
            verbose,
            network_settings,
        );

        assert_ne!(PROD_GUEST_VM_MEMORY, DEV_MEM_VALUE);
        assert_ne!(setupos_config.hostos_settings.vm_memory, DEV_MEM_VALUE);
    }
}
