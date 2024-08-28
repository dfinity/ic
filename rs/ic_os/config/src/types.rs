use ic_types::malicious_behaviour::MaliciousBehaviour;

struct SetuposConfig {
    hostos_config: HostOSConfig,
}

struct HostOSConfig {
    vm_memory: u32,
    vm_cpu: String,
    ic_config: IcConfig,
}

// todo: fix types and separate dev/prod
struct IcConfig {
    networking: Networking,
    nns_public_key_path: String,
    nns_url: String,
    elasticsearch_hosts: String,
    elasticsearch_tags: Option<String>,
    hostname: String,
    node_operator_private_key_path: Option<String>,

    ic_crypto_path: String,
    ic_state_path: String,
    ic_registry_local_store_path: String,
    accounts_ssh_authorized_keys_path: String,
    backup_retention_time_seconds: String,
    backup_puging_interval_seconds: String,
    malicious_behavior: MaliciousBehaviour,
    query_stats_epoch_length: String,
    bitcoind_addr: String,
    jaeger_addr: String,
    socks_proxy: String,
}

struct Networking {
    ipv6_address: String,
    ipv6_gateway: String,
    ipv4_address: Option<String>,
    ipv4_gateway: Option<String>,
    domain: Option<String>,
}