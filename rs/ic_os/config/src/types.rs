use ic_types::malicious_behaviour::MaliciousBehaviour;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use url::Url;

#[derive(Debug)]
pub struct SetuposConfig {
    hostos_config: HostOSConfig,
}

#[derive(Debug)]
pub struct HostOSConfig {
    vm_memory: u32,
    vm_cpu: String,
    ic_config: IcConfig,
}

// todo: fix types and separate dev/prod
#[derive(Debug)]
pub struct IcConfig {
    networking: Networking,
    nns_public_key_path: PathBuf,
    nns_url: Vec<Url>,
    elasticsearch_hosts: String,
    elasticsearch_tags: Option<String>,
    hostname: String,
    node_operator_private_key_path: Option<PathBuf>,

    // todo: update file paths to Path
    verbose: Option<String>,
    ic_crypto_path: Option<String>,
    ic_state_path: Option<String>,
    ic_registry_local_store_path: Option<String>,
    ssh_authorized_keys_path: Option<PathBuf>,
    backup_retention_time_seconds: Option<String>,
    backup_purging_interval_seconds: Option<String>,
    malicious_behavior: Option<MaliciousBehaviour>,
    query_stats_epoch_length: Option<String>,
    bitcoind_addr: Option<String>,
    jaeger_addr: Option<String>,
    socks_proxy: Option<String>,
}

#[derive(Debug)]
pub struct Networking {
    pub ipv6_prefix: Option<String>,
    pub ipv6_address: Option<Ipv6Addr>,
    pub ipv6_gateway: Ipv6Addr,
    pub ipv4_address: Option<Ipv4Addr>,
    pub ipv4_gateway: Option<Ipv4Addr>,
    pub ipv4_prefix_length: Option<u8>,
    pub domain: Option<String>,
}

impl SetuposConfig {
    pub fn new(
        vm_memory: u32,
        vm_cpu: String,
        nns_public_key_path: PathBuf,
        nns_url: Vec<Url>,
        elasticsearch_hosts: String,
        elasticsearch_tags: Option<String>,
        hostname: String,
        node_operator_private_key_path: Option<PathBuf>,
        ipv6_prefix: Option<String>,
        ipv6_address: Option<Ipv6Addr>,
        ipv6_gateway: Ipv6Addr,
        ipv4_address: Option<Ipv4Addr>,
        ipv4_gateway: Option<Ipv4Addr>,
        ipv4_prefix_length: Option<u8>,
        domain: Option<String>,
        // todo: change verbose to a bool
        verbose: Option<String>,
        ic_crypto_path: Option<String>,
        ic_state_path: Option<String>,
        ic_registry_local_store_path: Option<String>,
        ssh_authorized_keys_path: Option<PathBuf>,
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
            ipv6_prefix,
            ipv6_address,
            ipv6_gateway,
            ipv4_address,
            ipv4_gateway,
            ipv4_prefix_length,
            domain,
            verbose,
            ic_crypto_path,
            ic_state_path,
            ic_registry_local_store_path,
            ssh_authorized_keys_path,
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
        nns_url: Vec<Url>,
        elasticsearch_hosts: String,
        elasticsearch_tags: Option<String>,
        hostname: String,
        node_operator_private_key_path: Option<PathBuf>,
        ipv6_prefix: Option<String>,
        ipv6_address: Option<Ipv6Addr>,
        ipv6_gateway: Ipv6Addr,
        ipv4_address: Option<Ipv4Addr>,
        ipv4_gateway: Option<Ipv4Addr>,
        ipv4_prefix_length: Option<u8>,
        domain: Option<String>,
        verbose: Option<String>,
        ic_crypto_path: Option<String>,
        ic_state_path: Option<String>,
        ic_registry_local_store_path: Option<String>,
        ssh_authorized_keys_path: Option<PathBuf>,
        backup_retention_time_seconds: Option<String>,
        backup_purging_interval_seconds: Option<String>,
        malicious_behavior: Option<MaliciousBehaviour>,
        query_stats_epoch_length: Option<String>,
        bitcoind_addr: Option<String>,
        jaeger_addr: Option<String>,
        socks_proxy: Option<String>,
    ) -> Self {
        let networking = Networking::new(
            ipv6_prefix,
            ipv6_address,
            ipv6_gateway,
            ipv4_address,
            ipv4_gateway,
            ipv4_prefix_length,
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
            ssh_authorized_keys_path,
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
    pub fn new(
        ipv6_prefix: Option<String>,
        ipv6_address: Option<Ipv6Addr>,
        ipv6_gateway: Ipv6Addr,
        ipv4_address: Option<Ipv4Addr>,
        ipv4_gateway: Option<Ipv4Addr>,
        ipv4_prefix_length: Option<u8>,
        domain: Option<String>,
    ) -> Self {
        Networking {
            ipv6_prefix,
            ipv6_address,
            ipv6_gateway,
            ipv4_address,
            ipv4_gateway,
            ipv4_prefix_length,
            domain,
        }
    }
}
