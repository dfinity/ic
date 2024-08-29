use ic_types::malicious_behaviour::MaliciousBehaviour;
use std::path::PathBuf;

pub struct SetuposConfig {
    hostos_config: HostOSConfig,
}

pub struct HostOSConfig {
    vm_memory: u32,
    vm_cpu: String,
    ic_config: IcConfig,
}

// todo: fix types and separate dev/prod
pub struct IcConfig {
    networking: Networking,
    nns_public_key_path: PathBuf,
    nns_url: String,
    elasticsearch_hosts: String,
    elasticsearch_tags: Option<String>,
    hostname: String,
    node_operator_private_key_path: Option<PathBuf>,

    // todo: update file paths to Path
    verbose: Option<String>,
    ic_crypto_path: Option<String>,
    ic_state_path: Option<String>,
    ic_registry_local_store_path: Option<String>,
    accounts_ssh_authorized_keys_path: Option<String>,
    backup_retention_time_seconds: Option<String>,
    backup_purging_interval_seconds: Option<String>,
    malicious_behavior: Option<MaliciousBehaviour>,
    query_stats_epoch_length: Option<String>,
    bitcoind_addr: Option<String>,
    jaeger_addr: Option<String>,
    socks_proxy: Option<String>,
}

pub struct Networking {
    ipv6_address: String,
    ipv6_gateway: String,
    ipv4_address: Option<String>,
    ipv4_gateway: Option<String>,
    domain: Option<String>,
}


impl SetuposConfig {
    pub fn new(
        vm_memory: u32,
        vm_cpu: String,
        nns_public_key_path: PathBuf,
        nns_url: String,
        elasticsearch_hosts: String,
        elasticsearch_tags: Option<String>,
        hostname: String,
        node_operator_private_key_path: Option<PathBuf>,
        ipv6_address: String,
        ipv6_gateway: String,
        ipv4_address: Option<String>,
        ipv4_gateway: Option<String>,
        domain: Option<String>,
        // todo: change verbose to a bool
        verbose: Option<String>,
        ic_crypto_path: Option<String>,
        ic_state_path: Option<String>,
        ic_registry_local_store_path: Option<String>,
        accounts_ssh_authorized_keys_path: Option<String>,
        backup_retention_time_seconds: Option<String>,
        backup_purging_interval_seconds: Option<String>,
        malicious_behavior: Option<MaliciousBehaviour>,
        query_stats_epoch_length: Option<String>,
        bitcoind_addr: Option<String>,
        jaeger_addr: Option<String>,
        socks_proxy: Option<String>,
    ) -> Self {
        let ic_config = IcConfig::new(
            nns_public_key_path,
            nns_url,
            elasticsearch_hosts,
            elasticsearch_tags,
            hostname,
            node_operator_private_key_path,
            ipv6_address,
            ipv6_gateway,
            ipv4_address,
            ipv4_gateway,
            domain,
            verbose,
            ic_crypto_path,
            ic_state_path,
            ic_registry_local_store_path,
            accounts_ssh_authorized_keys_path,
            backup_retention_time_seconds,
            backup_purging_interval_seconds,
            malicious_behavior,
            query_stats_epoch_length,
            bitcoind_addr,
            jaeger_addr,
            socks_proxy,
        );

        let hostos_config = HostOSConfig::new(vm_memory, vm_cpu, ic_config);

        SetuposConfig { hostos_config }
    }
}

impl HostOSConfig {
    pub fn new(vm_memory: u32, vm_cpu: String, ic_config: IcConfig) -> Self {
        HostOSConfig {
            vm_memory,
            vm_cpu,
            ic_config,
        }
    }
}

impl IcConfig {
    pub fn new(
        nns_public_key_path: PathBuf,
        nns_url: String,
        elasticsearch_hosts: String,
        elasticsearch_tags: Option<String>,
        hostname: String,
        node_operator_private_key_path: Option<PathBuf>,
        ipv6_address: String,
        ipv6_gateway: String,
        ipv4_address: Option<String>,
        ipv4_gateway: Option<String>,
        domain: Option<String>,
        verbose: Option<String>,
        ic_crypto_path: Option<String>,
        ic_state_path: Option<String>,
        ic_registry_local_store_path: Option<String>,
        accounts_ssh_authorized_keys_path: Option<String>,
        backup_retention_time_seconds: Option<String>,
        backup_purging_interval_seconds: Option<String>,
        malicious_behavior: Option<MaliciousBehaviour>,
        query_stats_epoch_length: Option<String>,
        bitcoind_addr: Option<String>,
        jaeger_addr: Option<String>,
        socks_proxy: Option<String>,
    ) -> Self {
        let networking = Networking::new(
            ipv6_address,
            ipv6_gateway,
            ipv4_address,
            ipv4_gateway,
            domain,
        );

        IcConfig {
            networking,
            nns_public_key_path,
            nns_url,
            elasticsearch_hosts,
            elasticsearch_tags,
            hostname,
            node_operator_private_key_path,
            verbose,
            ic_crypto_path,
            ic_state_path,
            ic_registry_local_store_path,
            accounts_ssh_authorized_keys_path,
            backup_retention_time_seconds,
            backup_purging_interval_seconds,
            malicious_behavior,
            query_stats_epoch_length,
            bitcoind_addr,
            jaeger_addr,
            socks_proxy,
        }
    }
}

impl Networking {
    fn new(
        ipv6_address: String,
        ipv6_gateway: String,
        ipv4_address: Option<String>,
        ipv4_gateway: Option<String>,
        domain: Option<String>,
    ) -> Self {
        Networking {
            ipv6_address,
            ipv6_gateway,
            ipv4_address,
            ipv4_gateway,
            domain,
        }
    }
}