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
