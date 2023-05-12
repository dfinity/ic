//! A parser for the configuration file.
// Here we can crash as we cannot proceed with an invalid config.
#![allow(clippy::expect_used)]

use crate::config::{Config, OnchainObservabilityAdapterSpecificConfig};
use clap::Parser;
use ic_config::{Config as ReplicaConfig, ConfigSource};
use slog::Level;
use std::{fs::File, io, path::PathBuf};
use tempfile::Builder;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FlagsError {
    #[error("{0}")]
    Io(io::Error),
    #[error("An error occurred while deserialized the provided configuration: {0}")]
    Deserialize(String),
    #[error("An error occurred while validating the provided configuration: {0}")]
    Validation(String),
}

/// This struct is use to provide a command line interface to the adapter.
#[derive(Parser)]
#[clap(version = "0.1.0", author = "DFINITY team <team@dfinity.org>")]
pub struct Flags {
    /// Config specific to the onchain observability adapter. This will be combined with replica config to generate overall config.
    #[clap(long = "adapter-specific-config-file", parse(from_os_str))]
    pub adapter_specific_config: PathBuf,
    /// We also want to stay in sync with replica filepaths for crypto, registry
    #[clap(long = "replica-config-file", parse(from_os_str))]
    pub replica_config: PathBuf,
    /// This field represents if the adapter should run in verbose.
    #[clap(short, long)]
    pub verbose: bool,
}

impl Flags {
    /// Gets the log filter level by checking the verbose field.
    pub fn get_logging_level(&self) -> Level {
        if self.verbose {
            Level::Debug
        } else {
            Level::Info
        }
    }

    /// Loads the adapter specific config and replica config and synthesizes into a final config
    pub fn get_config(&self) -> Result<Config, FlagsError> {
        let adapter_specific_config_file =
            File::open(&self.adapter_specific_config).map_err(FlagsError::Io)?;
        let adapter_specific_config: OnchainObservabilityAdapterSpecificConfig =
            serde_json::from_reader(adapter_specific_config_file)
                .map_err(|err| FlagsError::Deserialize(err.to_string()))?;

        let replica_config = get_replica_config(self.replica_config.clone());

        Ok(Config {
            logger: adapter_specific_config.logger,
            crypto_config: replica_config.crypto,
            registry_config: replica_config.registry_client,
            report_length_sec: adapter_specific_config.report_length_sec,
            sampling_interval_sec: adapter_specific_config.sampling_interval_sec,
            canister_client_url: adapter_specific_config.canister_client_url,
            canister_id: adapter_specific_config.canister_id,
            uds_socket_path: adapter_specific_config.uds_socket_path,
        })
    }
}

fn get_replica_config(replica_config_file: PathBuf) -> ReplicaConfig {
    let tmpdir = Builder::new()
        .prefix("ic_config")
        .tempdir()
        .expect("failed to create temporary directory for replica config")
        .path()
        .to_path_buf();

    ReplicaConfig::load_with_tmpdir(ConfigSource::File(replica_config_file), tmpdir)
}

#[cfg(test)]
pub mod test {
    use crate::{
        config::{default_report_length, default_sampling_interval, default_url},
        flags::{Flags, FlagsError},
    };
    use std::{io::Write, path::PathBuf};

    // Tests that an invalid config path throws error
    #[test]
    fn test_invalid_adapter_config_path() {
        let fake_adapter_config_path = PathBuf::from("fake/path");

        let mut replica_config_file =
            tempfile::NamedTempFile::new().expect("Failed to create tmp file");
        writeln!(replica_config_file, "{}", SAMPLE_REPLICA_CONFIG)
            .expect("Failed to write to tmp file");

        let flags = Flags {
            replica_config: replica_config_file.path().to_owned(),
            adapter_specific_config: fake_adapter_config_path,
            verbose: false,
        };

        let result = flags.get_config();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FlagsError::Io(_)));
    }

    // Tests that a config with json syntax errors throws error
    #[test]
    fn test_ill_formatted_adapter_config() {
        // last field shouldn't have trailing comma
        let json_with_extra_comma = r#"{
            "logger": {
                "format": "json",
                "level": "info"
            },
            "report_length_sec": 180,
            "sampling_interval_sec": 60,
        }
        "#;

        let mut adapter_config_file =
            tempfile::NamedTempFile::new().expect("Failed to create tmp file");
        writeln!(adapter_config_file, "{}", json_with_extra_comma)
            .expect("Failed to write to tmp file");

        let mut replica_config_file =
            tempfile::NamedTempFile::new().expect("Failed to create tmp file");
        writeln!(replica_config_file, "{}", SAMPLE_REPLICA_CONFIG)
            .expect("Failed to write to tmp file");

        let flags = Flags {
            replica_config: replica_config_file.path().to_owned(),
            adapter_specific_config: adapter_config_file.path().to_owned(),
            verbose: false,
        };

        let result = flags.get_config();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FlagsError::Deserialize(_)));
    }

    // Tests that an input config with all fields set correctly is correctly parsed
    #[test]
    fn test_adapter_config_all_fields_set() {
        let json_minimum_fields = r#"{
            "logger": {
                "format": "json",
                "level": "info"
            },
            "report_length_sec": 500,
            "sampling_interval_sec": 500,
            "canister_client_url": "test_url.com",
            "canister_id": "xyz123"
        }
        "#;

        let mut adapter_config_file =
            tempfile::NamedTempFile::new().expect("Failed to create tmp file");
        writeln!(adapter_config_file, "{}", json_minimum_fields)
            .expect("Failed to write to tmp file");

        let mut replica_config_file =
            tempfile::NamedTempFile::new().expect("Failed to create tmp file");
        writeln!(replica_config_file, "{}", SAMPLE_REPLICA_CONFIG)
            .expect("Failed to write to tmp file");

        let flags = Flags {
            replica_config: replica_config_file.path().to_owned(),
            adapter_specific_config: adapter_config_file.path().to_owned(),
            verbose: true,
        };

        let result = flags.get_config();
        assert!(result.is_ok());
        let config = result.unwrap();

        assert_eq!(config.report_length_sec.as_secs(), 500);
        assert_eq!(config.sampling_interval_sec.as_secs(), 500);
        assert_eq!(config.canister_client_url, "test_url.com");
        assert_eq!(config.canister_id, "xyz123");
    }

    // Tests that an input config with missing fields will be filled in with default values
    #[test]
    fn test_adapter_config_defaults_set() {
        let json_minimum_fields = r#"{
            "logger": {
                "format": "json",
                "level": "info"
            }
        }
        "#;

        let mut adapter_config_file =
            tempfile::NamedTempFile::new().expect("Failed to create tmp file");
        writeln!(adapter_config_file, "{}", json_minimum_fields)
            .expect("Failed to write to tmp file");

        let mut replica_config_file =
            tempfile::NamedTempFile::new().expect("Failed to create tmp file");
        writeln!(replica_config_file, "{}", SAMPLE_REPLICA_CONFIG)
            .expect("Failed to write to tmp file");

        let flags = Flags {
            replica_config: replica_config_file.path().to_owned(),
            adapter_specific_config: adapter_config_file.path().to_owned(),
            verbose: true,
        };

        let result = flags.get_config();
        assert!(result.is_ok());
        let config = result.unwrap();

        assert_eq!(config.report_length_sec, default_report_length());
        assert_eq!(config.sampling_interval_sec, default_sampling_interval());
        assert_eq!(config.canister_client_url, default_url());
        // Canister id must be explictly set
        assert_eq!(config.canister_id, "");
    }

    pub const SAMPLE_REPLICA_CONFIG: &str = r#"
    {
        // ============================================
        // Global Replica Configuration
        // ============================================
        
        node_id: "0",
        
        // =======================================================
        // Configuration of transport parameters and node identity
        // =======================================================
        transport: {
            node_ip: "2a0b:21c0:4003:2:509c:e5ff:fe45:ab4f",
            listening_port: 4100,
        },
        // ============================================
        // Configuration of registry client
        // ============================================
        registry_client: {
            // The default is not to specify it.
            local_store: "/var/lib/ic/data/ic_registry_local_store/"
        },
        // ============================================
        // Configuration of the node state persistence.
        // ============================================
        state_manager: {
            // The directory that should be used to persist node state.
            state_root: "/var/lib/ic/data/ic_state",
        },
        
        // ============================================
        // Configuration of the artifact pool state persistence.
        // ============================================
        artifact_pool: {
            consensus_pool_path: "/var/lib/ic/data/ic_consensus_pool",
            ingress_pool_max_count: 10000,
            ingress_pool_max_bytes: 100000000,
            // Backup configuration
            backup: {
                spool_path: "/var/lib/ic/backup",
                // How long the artifacts stay in the pool before they get purged.
                retention_time_secs: 86400,
                // How often the purging is triggered.
                purging_interval_secs: 3600,
            }
        },
        
        // ============================================
        // Consensus related config.
        // ============================================
        consensus: {
            detect_starvation: true,
        },
        
        // ============================================
        // Configuration of the crypto state persistence.
        // ============================================
        crypto: {
            // The directory that should be used to persist crypto state.
            crypto_root: "/var/lib/ic/crypto",
            csp_vault_type: { unix_socket: "/run/ic-node/crypto-csp/socket" },
        },
        
        // ========================================
        // Configuration of the message scheduling.
        // ========================================
        scheduler: {
            // Maximum amount of instructions a single round can consume.
            max_instructions_per_round: 26843545600,
            // Maximum number of instructions a single message's execution
            // can consume.
            max_instructions_per_message: 5368709120,
        },
        
        // ================================================
        // Configuration of the Wasm execution environment.
        // ================================================
        hypervisor: {
            // A whitelist of principal IDs that are allowed to call the
            // "dev_create_canister_with_funds" and "dev_set_funds" methods on
            // the subnet.
            //
            // * The list should be a comma-separated list of principal IDs.
            // * Setting the value to "*" = the methods are calleable by all IDs.
            // * Setting the value to an empty string = the methods are
            //   calleable by no one.
            //
            // The principal id below is used by the wallet CLI, the workload
            // generator and scenario tests (corresponds to the hardcoded,
                // DER-encoded keypair that these tools use).
                create_funds_whitelist: "5o66h-77qch-43oup-7aaui-kz5ty-tww4j-t2wmx-e3lym-cbtct-l3gpw-wae",
            },
            
            // ====================================
            // Configuration of the HTTP endpoint.
            // ====================================
            http_handler: {
                listen_addr: "[2a0b:21c0:4003:2:509c:e5ff:fe45:ab4f]:8080",
            },
            
            // ====================================
            // Configuration of various adapters. 
            // ====================================
            adapters_config: {
                // IPC socket and metrics path for BTC Testnet adapter. This UDS path has to be the same as
                // specified in the systemd socket file.
                // The BTC adapter socket file is: /ic-os/guestos/rootfs/etc/systemd/system/ic-btc-testnet-adapter.socket
                bitcoin_testnet_uds_path: "/run/ic-node/bitcoin-testnet-adapter/socket",
                bitcoin_testnet_uds_metrics_path: "/run/ic-node/bitcoin-testnet-adapter/metrics",
                // IPC socket and metrics path for BTC Mainnet adapter. This UDS path has to be the same as
                // specified in the systemd socket file.
                bitcoin_mainnet_uds_path: "/run/ic-node/bitcoin-mainnet-adapter/socket",
                bitcoin_mainnet_uds_metrics_path: "/run/ic-node/bitcoin-mainnet-adapter/metrics",
                // IPC socket and metrics path for canister http adapter. These UDS path has to be the same as
                // specified in the systemd socket file.
                // The canister http adapter socket file is: /ic-os/guestos/rootfs/etc/systemd/system/ic-https-outcalls-adapter.socket
                https_outcalls_uds_path: "/run/ic-node/https-outcalls-adapter/socket",
                https_outcalls_uds_metrics_path: "/run/ic-node/https-outcalls-adapter/metrics",
            },
            
            // ==================================================
            // Configuration of the metrics collection subsystem.
            // ==================================================
            metrics: {
                // How to export metrics.
                // Supported values are:
                // - "log"  — periodically write prometheus metrics to the application log
                // - { http: <port> } — expose prometheus metrics on the specified port
                // - { file: <path> } — dump prometheus metrics to the specified file on shutdown
                exporter: { http: "[2a0b:21c0:4003:2:509c:e5ff:fe45:ab4f]:9090", },
            },
            
            // ===================================
            // Configuration of the logging setup.
            // ===================================
            logger: {
                // The node id to append to log lines.
                node_id: 0,
                // The datacenter id to append to log lines.
                dc_id: 200,
                // The log level to use.
                level: "info",
                // The format of emitted log lines
                format: "json",
                debug_overrides: [],
            },
            
            // ==================================
            // Configuration for Message Routing.
            // ==================================
            message_routing: {
                xnet_ip_addr: "2a0b:21c0:4003:2:509c:e5ff:fe45:ab4f",
                xnet_port: 2497,
            },
            
            firewall: {
                config_file: "/run/ic-node/nftables-ruleset/nftables.conf",
                file_template: "table filter {\n\
                    chain INPUT {\n\
                        type filter hook input priority 0; policy drop;\n\
                        iif lo accept\n\
                        icmp type parameter-problem accept\n\
                        icmp type echo-request accept\n\
                        icmp type echo-reply accept\n\
                        <<IPv4_RULES>>\n\
                    }\n\
                    \n\
                    chain FORWARD {\n\
                        type filter hook forward priority 0; policy drop;\n\
                    }\n\
                    \n\
                    chain OUTPUT {\n\
                        type filter hook output priority 0; policy accept;\n\
                        meta skuid ic-http-adapter ip daddr { 127.0.0.0/8 } ct state { new } tcp dport { 1-19999 } reject # Block restricted localhost ic-http-adapter HTTPS access\n\
                        <<IPv4_OUTBOUND_RULES>>\n\
                    }\n\
                }\n\
                \n\
                table ip6 filter {\n\
                    chain INPUT {\n\
                        type filter hook input priority 0; policy drop;\n\
                        iif lo accept\n\
                        ct state { invalid } drop\n\
                        ct state { established, related } accept\n\
                        icmpv6 type destination-unreachable accept\n\
                        icmpv6 type packet-too-big accept\n\
                        icmpv6 type time-exceeded accept\n\
                        icmpv6 type parameter-problem accept\n\
                        icmpv6 type echo-request accept\n\
                        icmpv6 type echo-reply accept\n\
                        icmpv6 type nd-router-advert accept\n\
                        icmpv6 type nd-neighbor-solicit accept\n\
                        icmpv6 type nd-neighbor-advert accept\n\
                        <<IPv6_RULES>>\n\
                    }\n\
                    \n\
                    chain FORWARD {\n\
                        type filter hook forward priority 0; policy drop;\n\
                    }\n\
                    \n\
                    chain OUTPUT {\n\
                        type filter hook output priority 0; policy accept;\n\
                        meta skuid ic-http-adapter ip6 daddr { ::1/128 } ct state { new } tcp dport { 1-19999 } reject # Block restricted localhost ic-http-adapter HTTPS access\n\
                        meta skuid ic-http-adapter ip6 daddr { 2a00:fb01:400:42::/64, 2001:4d78:40d::/48, 2607:fb58:9005::/48, 2602:fb2b:100::/48, 2607:f6f0:3004::/48, 2a05:d01c:d9:2b00::/56, 2a05:d01c:e2c:a700::/56 } ct state { new } tcp dport { 1-19999 } reject # Block restricted outbound ic-http-adapter HTTPS access\n\
                        <<IPv6_OUTBOUND_RULES>>\n\
                    }\n\
                }\n",
                ipv4_rule_template: "ip saddr {<<IPv4_PREFIXES>>} ct state { new } tcp dport {<<PORTS>>} <<ACTION>> # <<COMMENT>>",
                ipv6_rule_template: "ip6 saddr {<<IPv6_PREFIXES>>} ct state { new } tcp dport {<<PORTS>>} <<ACTION>> # <<COMMENT>>",
                ipv4_user_output_rule_template: "meta skuid <<USER>> ip daddr {<<IPv4_PREFIXES>>} ct state { new } tcp dport {<<PORTS>>} <<ACTION>> # <<COMMENT>>",
                ipv6_user_output_rule_template: "meta skuid <<USER>> ip6 daddr {<<IPv6_PREFIXES>>} ct state { new } tcp dport {<<PORTS>>} <<ACTION>> # <<COMMENT>>",
                default_rules: [{
                    ipv4_prefixes: [],
                    ipv6_prefixes: [
                    "2001:438:fffd:11c::/64",
                    "2001:470:1:c76::/64",
                    "2001:4d78:400:10a::/64",
                    "2001:4d78:40d::/48",
                    "2001:920:401a:1706::/64",
                    "2001:920:401a:1708::/64",
                    "2001:920:401a:1710::/64",
                    "2401:3f00:1000:22::/64",
                    "2401:3f00:1000:23::/64",
                    "2401:3f00:1000:24::/64",
                    "2600:2c01:21::/64",
                    "2600:3000:1300:1300::/64",
                    "2600:3000:6100:200::/64",
                    "2600:3004:1200:1200::/56",
                    "2600:3006:1400:1500::/64",
                    "2600:c00:2:100::/64",
                    "2600:c02:b002:15::/64",
                    "2600:c0d:3002:4::/64",
                    "2602:ffe4:801:16::/64",
                    "2602:ffe4:801:17::/64",
                    "2602:ffe4:801:18::/64",
                    "2604:1380:4091:3000::/64",
                    "2604:1380:40e1:4700::/64",
                    "2604:1380:40f1:1700::/64",
                    "2604:1380:45d1:bf00::/64",
                    "2604:1380:45e1:a600::/64",
                    "2604:1380:45f1:9400::/64",
                    "2604:1380:4601:6200::/64",
                    "2604:1380:4601:6201::/64",
                    "2604:1380:4601:6202::/64",
                    "2604:1380:4641:6101::/64",
                    "2604:1380:4641:6102::/64",
                    "2604:1380:4091:3001::/64",
                    "2604:1380:4091:3002::/64",
                    "2604:1380:45e1:a601::/64",
                    "2604:1380:45e1:a602::/64",
                    "2604:1380:4641:6100::/64",
                    "2604:3fc0:2001::/48",
                    "2604:3fc0:3002::/48",
                    "2604:6800:258:1::/64",
                    "2604:7e00:30:3::/64",
                    "2604:7e00:50::/64",
                    "2604:b900:4001:76::/64",
                    "2607:f1d0:10:1::/64",
                    "2607:f6f0:3004::/48",
                    "2607:f758:1220::/64",
                    "2607:f758:c300::/64",
                    "2607:fb58:9005::/48",
                    "2602:fb2b:100::/48",
                    "2607:ff70:3:2::/64",
                    "2610:190:6000:1::/64",
                    "2610:190:df01:5::/64",
                    "2a00:fa0:3::/48",
                    "2a00:fb01:400:100::/56",
                    "2a00:fb01:400::/56",
                    "2a00:fc0:5000:300::/64",
                    "2a01:138:900a::/48",
                    "2a01:2a8:a13c:1::/64",
                    "2a01:2a8:a13d:1::/64",
                    "2a01:2a8:a13e:1::/64",
                    "2a02:418:3002:0::/64",
                    "2a02:41b:300e::/48",
                    "2a02:800:2:2003::/64",
                    "2a04:9dc0:0:108::/64",
                    "2a05:d014:939:bf00::/56",
                    "2a05:d01c:d9:2b00::/56",
                    "2a05:d01c:e2c:a700::/56",
                    "2a0b:21c0:4003:2::/64",
                    "2a0b:21c0:b002:2::/64",
                    "2a0f:cd00:0002::/56",
                    "fd00:2:1:1::/64",
                    ],
                    ports: [22, 2497, 4100, 7070, 8080, 9090, 9091, 9100, 19531],
                    action: 1,
                    comment: "Default rule from template",
                    direction: 1,
                }],
                ports_for_node_whitelist: [2497, 4100, 8080],
                ports_for_http_adapter_blacklist: [22, 2497, 4100, 7070, 8080, 9090, 9091, 9100, 19531],
            },
            
            registration: {
                nns_url: "http://[::1]:8080",
                nns_pub_key_pem: "/var/lib/ic/data/nns_public_key.pem",
                node_operator_pem: "/var/lib/ic/data/node_operator_private_key.pem"
            },
            
            malicious_behaviour: null,
        }
        "#;
}
