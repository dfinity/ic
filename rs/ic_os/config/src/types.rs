use ic_types::malicious_behaviour::MaliciousBehaviour;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use url::Url;

#[allow(dead_code)]
#[derive(Serialize, Deserialize, Debug)]
pub struct SetuposConfig {
    hostos_config: HostOSConfig,
}

impl SetuposConfig {
    pub fn new(vm_memory: u32, vm_cpu: String, ic_config: IcConfig) -> Self {
        let hostos_config = HostOSConfig{vm_memory, vm_cpu, ic_config};
        SetuposConfig { hostos_config }
    }
}
#[allow(dead_code)]
#[derive(Serialize, Deserialize, Debug)]
pub struct HostOSConfig {
    vm_memory: u32,
    vm_cpu: String,
    ic_config: IcConfig,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Networking {
    pub ipv6_prefix: Option<Ipv6Addr>,
    pub ipv6_address: Option<Ipv6Addr>,
    pub ipv6_gateway: Ipv6Addr,
    pub ipv4_address: Option<Ipv4Addr>,
    pub ipv4_gateway: Option<Ipv4Addr>,
    pub ipv4_prefix_length: Option<u8>,
    pub domain: Option<String>,
}

#[allow(dead_code)]
#[derive(Serialize, Deserialize, Debug)]
pub struct IcConfig {
    networking: Networking,
    nns_public_key_path: PathBuf,
    nns_url: Vec<Url>,
    elasticsearch_hosts: String,
    // help: elasticsearch_tags is a dev field?
    elasticsearch_tags: Option<String>,
    hostname: String,
    node_operator_private_key_path: Option<PathBuf>,

    // Semi-dev, semi-prod:
    ssh_authorized_keys_path: Option<PathBuf>,
    verbose: bool,
    ic_crypto_path: Option<PathBuf>,
    ic_state_path: Option<PathBuf>,
    ic_registry_local_store_path: Option<PathBuf>,

    // Dev:
    ic_config_dev: IcConfigDev,
}

#[allow(dead_code)]
#[derive(Serialize, Deserialize, Debug)]
pub struct IcConfigDev {
    backup_retention_time_seconds: Option<String>,
    backup_purging_interval_seconds: Option<String>,
    malicious_behavior: Option<MaliciousBehaviour>,
    query_stats_epoch_length: Option<String>,
    bitcoind_addr: Option<String>,
    jaeger_addr: Option<String>,
    socks_proxy: Option<String>,
}

#[derive(Debug, Default)]
pub struct IcConfigBuilder {
    networking: Option<Networking>,
    nns_public_key_path: Option<PathBuf>,
    nns_url: Option<Vec<Url>>,
    elasticsearch_hosts: Option<String>,
    elasticsearch_tags: Option<String>,
    hostname: Option<String>,
    node_operator_private_key_path: Option<PathBuf>,
    ssh_authorized_keys_path: Option<PathBuf>,
    verbose: Option<bool>,
    ic_crypto_path: Option<PathBuf>,
    ic_state_path: Option<PathBuf>,
    ic_registry_local_store_path: Option<PathBuf>,
    backup_retention_time_seconds: Option<String>,
    backup_purging_interval_seconds: Option<String>,
    malicious_behavior: Option<MaliciousBehaviour>,
    query_stats_epoch_length: Option<String>,
    bitcoind_addr: Option<String>,
    jaeger_addr: Option<String>,
    socks_proxy: Option<String>,
}

impl IcConfigBuilder {
    pub fn new() -> Self {
        IcConfigBuilder::default()
    }

    pub fn networking(mut self, networking: Networking) -> Self {
        self.networking = Some(networking);
        self
    }

    pub fn nns_public_key_path(mut self, path: PathBuf) -> Self {
        self.nns_public_key_path = Some(path);
        self
    }

    pub fn nns_url(mut self, url: Vec<Url>) -> Self {
        self.nns_url = Some(url);
        self
    }

    pub fn elasticsearch_hosts(mut self, hosts: String) -> Self {
        self.elasticsearch_hosts = Some(hosts);
        self
    }

    pub fn elasticsearch_tags(mut self, tags: Option<String>) -> Self {
        self.elasticsearch_tags = tags;
        self
    }

    pub fn hostname(mut self, hostname: String) -> Self {
        self.hostname = Some(hostname);
        self
    }

    pub fn node_operator_private_key_path(mut self, path: Option<PathBuf>) -> Self {
        self.node_operator_private_key_path = path;
        self
    }

    pub fn ssh_authorized_keys_path(mut self, path: Option<PathBuf>) -> Self {
        self.ssh_authorized_keys_path = path;
        self
    }

    pub fn verbose(mut self, verbose: bool) -> Self {
        self.verbose = Some(verbose);
        self
    }

    pub fn ic_crypto_path(mut self, path: Option<PathBuf>) -> Self {
        self.ic_crypto_path = path;
        self
    }

    pub fn ic_state_path(mut self, path: Option<PathBuf>) -> Self {
        self.ic_state_path = path;
        self
    }

    pub fn ic_registry_local_store_path(mut self, path: Option<PathBuf>) -> Self {
        self.ic_registry_local_store_path = path;
        self
    }

    pub fn backup_retention_time_seconds(mut self, time: Option<String>) -> Self {
        self.backup_retention_time_seconds = time;
        self
    }

    pub fn backup_purging_interval_seconds(mut self, interval: Option<String>) -> Self {
        self.backup_purging_interval_seconds = interval;
        self
    }

    pub fn malicious_behavior(mut self, behavior: Option<MaliciousBehaviour>) -> Self {
        self.malicious_behavior = behavior;
        self
    }

    pub fn query_stats_epoch_length(mut self, length: Option<String>) -> Self {
        self.query_stats_epoch_length = length;
        self
    }

    pub fn bitcoind_addr(mut self, addr: Option<String>) -> Self {
        self.bitcoind_addr = addr;
        self
    }

    pub fn jaeger_addr(mut self, addr: Option<String>) -> Self {
        self.jaeger_addr = addr;
        self
    }

    pub fn socks_proxy(mut self, proxy: Option<String>) -> Self {
        self.socks_proxy = proxy;
        self
    }

    pub fn build(self) -> Result<IcConfig, &'static str> {
        Ok(IcConfig {
            networking: self.networking.ok_or("Networking is required")?,
            nns_public_key_path: self
                .nns_public_key_path
                .ok_or("NNS public key path is required")?,
            nns_url: self.nns_url.ok_or("NNS URL is required")?,
            elasticsearch_hosts: self
                .elasticsearch_hosts
                .ok_or("Elasticsearch hosts are required")?,
            elasticsearch_tags: self.elasticsearch_tags,
            hostname: self.hostname.ok_or("Hostname is required")?,
            node_operator_private_key_path: self.node_operator_private_key_path,
            ssh_authorized_keys_path: self.ssh_authorized_keys_path,
            verbose: self.verbose.ok_or("Verbose flag is required")?,
            ic_crypto_path: self.ic_crypto_path,
            ic_state_path: self.ic_state_path,
            ic_registry_local_store_path: self.ic_registry_local_store_path,
            ic_config_dev: IcConfigDev {
                backup_retention_time_seconds: self.backup_retention_time_seconds,
                backup_purging_interval_seconds: self.backup_purging_interval_seconds,
                malicious_behavior: self.malicious_behavior,
                query_stats_epoch_length: self.query_stats_epoch_length,
                bitcoind_addr: self.bitcoind_addr,
                jaeger_addr: self.jaeger_addr,
                socks_proxy: self.socks_proxy,
            },
        })
    }
}
