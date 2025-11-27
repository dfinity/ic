/// This constant contains a configuration of ic-replica with extra
/// comments describing the purpose and possible values of every
/// field.
///
/// This configuration is displayed as-is if the replica binary is
/// run with the `--sample-config` flag.
///
/// There are tests detecting significant deviations of this
/// configuration from the default configuration.  For example, the
/// test should break if:
///
/// * New sections/fields are added/removed.
/// * Types of leaf values are changed.
///
/// # Checking alternative values of options
///
/// For options having several fixed alternatives, there are tests
/// verifying that every alternative parses with the rest of the
/// config.
///
/// In order to take advantage of this feature, prefix alternatives
/// with a special "EXAMPLE:" marker in the comment above the
/// option.
///
/// For example, for a config of the following form
///
/// ```text
/// <prefix>
/// # EXAMPLE: y: "a"
/// # Some docs
/// #
/// # EXAMPLE: x: "b"
/// # More docs
/// #
/// # >>> NOTE: all the examples need to be defined in a single
/// #     continuous block of comments.
/// #
/// # >>> NOTE: there should be no blank line between the comment
/// #     and the value in the config.
/// y: "c"
/// <suffix>
/// ```
///
/// the tests will check that the following config files can be parsed
/// successfully:
///   * `<prefix> y: "a" <suffix>`
///   * `<prefix> x: "b" <suffix>`
///   * `<prefix> y: "c" <suffix>`
///
/// If the field is not set by default, leave an empty line after the
/// comment with alternatives:
///
/// ```text
/// # field x docs
/// # EXAMPLE: x: "a"
/// # EXAMPLE: x: "b"
/// # >>> The empty line below means that the field is not set by default.
///
/// # field y docs
/// # EXAMPLE: y: "bad"
/// y: "good"
/// ```
pub const SAMPLE_CONFIG: &str = r#"
{
    // ============================================
    // Global Replica Configuration
    // ============================================

    // Id of the subnet this node belongs to. This will be removed as soon as the replica can
    // retrieve its own subnet id from the registry.
    subnet_id: 0,

    // ============================================
    // Configuration of node transport
    // ============================================
    transport: {
        // IP address to bind if p2p_connections is not empty.
        node_ip: "127.0.0.1",
        // Listening port used by transport to establish peer connections.
        listening_port: 3000,
    },
    // =========================================================
    // Configuration of IPv4 networking (provided at first boot)
    // =========================================================
    initial_ipv4_config: {
        public_address: "",
        public_gateway: "",
    },
    // ============================================
    // Configuration of the domain name
    // ============================================
    domain: "",
    // ============================================
    // Configuration of registry client
    // ============================================
    registry_client: {
        // The directory that should be used to persist registry content.
        local_store: "/var/lib/ic/data/ic_registry_local_store/"
    },
    // ============================================
    // Configuration of the node state persistence.
    // ============================================
    state_manager: {
        // The directory that should be used to persist node state.
        state_root: "/tmp/ic_state"
    },
    // ============================================
    // Configuration of the node artifact pool persistence.
    // ============================================
    artifact_pool: {
        // The directory that should be used to persist consensus artifacts.
        consensus_pool_path: "/tmp/ic_consensus_pool",
        // usize::MAX on 64-bit
        ingress_pool_max_count: 9223372036854775807,
        ingress_pool_max_bytes: 9223372036854775807,
        backup: {
            // The directory for the blockchain backup.
            spool_path: "/tmp/ic_backup/",
            // How long the backup artifact stay on the disk before they get purged.
            retention_time_secs: 3600,
            // How often we purge.
            purging_interval_secs: 3600
        }
    },
    // ============================================
    // Configuration of the node state persistence.
    // ============================================
    crypto: {
        // The directory that should be used to persist node's cryptographic keys.
        crypto_root: "/tmp/ic_crypto",
        // The type of CspVault to be used.
        // Alternatives:
        // - EXAMPLE: csp_vault_type: "in_replica",
        //   CspVault is an internal structure of the replica process.
        // - EXAMPLE: csp_vault_type: { unix_socket: { logic: "/some/path/to/socket", metrics: "/some/path/to/another_socket" } },
        //   CspVault is run as a separate process, which can be reached via a Unix socket.
        //   It also has an optional Unix socket for exporting metrics.
        csp_vault_type: { unix_socket: { logic: "/some/path/to/socket", metrics: "/some/path/to/another_socket" } },
    },
    // ========================================
    // Configuration of the message scheduling.
    // ========================================
    scheduler: {
        // The max number of cores to use for canister code execution.
        scheduler_cores: 2,

        // Maximum amount of instructions a single round can consume.
        max_instructions_per_round: 26843545600,

        // Maximum amount of instructions a single message's execution can consume.
        // This should be significantly smaller than `max_instructions_per_round`.
        max_instructions_per_message: 5368709120,
    },
    // ================================================
    // Configuration of the execution environment.
    // ================================================
    hypervisor: {
    },
    // ==================================
    // Configuration for replica tracing.
    // ==================================
    tracing: {
    },
    // ====================================
    // Configuration of the HTTPS endpoint.
    // ====================================
    http_handler: {
        // The address to listen on.
        listen_addr: "127.0.0.1:8080"
    },
    // ==================================================
    // Configuration of the metrics collection subsystem.
    // ==================================================
    metrics: {
        // How to export metrics.
        //
        // Alternatives:
        // - EXAMPLE: exporter: "log",
        //   Periodically write prometheus metrics to the application log.
        // - EXAMPLE: exporter: { http: "127.0.0.1:9000" },
        //   Expose prometheus metrics on the specified address.
        // - EXAMPLE: exporter: { file: "/path/to/file" },
        //   Dump prometheus metrics to the specified file on shutdown.
        exporter: "log",
        connection_read_timeout_seconds: 300,
        max_concurrent_requests: 50,
        request_timeout_seconds: 30,
    },
    // ===================================
    // Configuration of the logging setup.
    // ===================================
    logger: {
        // The log level to use.
        // EXAMPLE: level: "critical",
        // EXAMPLE: level: "error",
        // EXAMPLE: level: "warning",
        // EXAMPLE: level: "info",
        // EXAMPLE: level: "debug",
        // EXAMPLE: level: "trace",
        level: "info",

        // The format of emitted log lines
        // EXAMPLE: format: "text_full",
        // EXAMPLE: format: "json",
        format: "text_full",

        // If `true` the async channel for low-priority messages will block instead of drop messages.
        // This behavior is required for instrumentation in System Testing until we have a
        // dedicated solution for instrumentation.
        //
        // The default for this value is `false` and thus matches the previously expected behavior in
        // production use cases.
        block_on_overflow: false,
    },
    // ===================================
    // Configuration of the logging setup for the orchestrator.
    // ===================================
    orchestrator_logger: {
        // The log level to use.
        // EXAMPLE: level: "critical",
        // EXAMPLE: level: "error",
        // EXAMPLE: level: "warning",
        // EXAMPLE: level: "info",
        // EXAMPLE: level: "debug",
        // EXAMPLE: level: "trace",
        level: "info",

        // The format of emitted log lines
        // EXAMPLE: format: "text_full",
        // EXAMPLE: format: "json",
        format: "text_full",

        // If `true` the async channel for low-priority messages will block instead of drop messages.
        // This behavior is required for instrumentation in System Testing until we have a
        // dedicated solution for instrumentation.
        //
        // The default for this value is `false` and thus matches the previously expected behavior in
        // production use cases.
        block_on_overflow: false,
    },
    // ===================================
    // Configuration of the logging setup for the CSP vault.
    // ===================================
    csp_vault_logger: {
        // The log level to use.
        // EXAMPLE: level: "critical",
        // EXAMPLE: level: "error",
        // EXAMPLE: level: "warning",
        // EXAMPLE: level: "info",
        // EXAMPLE: level: "debug",
        // EXAMPLE: level: "trace",
        level: "info",

        // The format of emitted log lines
        // EXAMPLE: format: "text_full",
        // EXAMPLE: format: "json",
        format: "text_full",

        // If `true` the async channel for low-priority messages will block instead of drop messages.
        // This behavior is required for instrumentation in System Testing until we have a
        // dedicated solution for instrumentation.
        //
        // The default for this value is `false` and thus matches the previously expected behavior in
        // production use cases.
        block_on_overflow: false,
    },
    // =================================
    // Configuration of Message Routing.
    // =================================
    message_routing: {
        // Currently empty, but will contain timeouts, max slice sizes etc.
    },
    // =================================
    // Configuration of Malicious behavior.
    // =================================
    malicious_behavior: {
       allow_malicious_behavior: false,
       maliciously_seg_fault: false,

       malicious_flags: {
         maliciously_propose_equivocating_blocks: false,
         maliciously_propose_empty_blocks: false,
         maliciously_finalize_all: false,
         maliciously_notarize_all: false,
         maliciously_tweak_dkg: false,
         maliciously_certify_invalid_hash: false,
         maliciously_malfunctioning_xnet_endpoint: false,
         maliciously_disable_execution: false,
         maliciously_corrupt_own_state_at_heights: [],
         maliciously_disable_ingress_validation: false,
         maliciously_corrupt_idkg_dealings: false,
         maliciously_alter_certified_hash: false,
         maliciously_alter_state_sync_chunk_sending_side: false,
       },
    },

    firewall: {
        config_file: "/path/to/nftables/config",
        file_template: "",
        ipv4_tcp_rule_template: "",
        ipv4_udp_rule_template: "",
        ipv6_tcp_rule_template: "",
        ipv6_udp_rule_template: "",
        ipv4_user_output_rule_template: "",
        ipv6_user_output_rule_template: "",
        default_rules: [],
        tcp_ports_for_node_whitelist: [],
        udp_ports_for_node_whitelist: [],
        ports_for_http_adapter_blacklist: [],
        max_simultaneous_connections_per_ip_address: 0,
    },

    boundary_node_firewall: {
        config_file: "/path/to/nftables/config",
        file_template: "",
        ipv4_tcp_rule_template: "",
        ipv4_udp_rule_template: "",
        ipv6_tcp_rule_template: "",
        ipv6_udp_rule_template: "",
        default_rules: [],
        max_simultaneous_connections_per_ip_address: 0,
    },

    // =================================
    // Configuration of registration parameters.
    // =================================
    registration: {
      pkcs11_keycard_transport_pin: "358138",
    },
    // =================================
    // NNS Registry Replicator
    // =================================
    nns_registry_replicator: {
      poll_delay_duration_ms: 5000
    },
    // ====================================
    // Configuration of various adapters.
    // ====================================
    adapters_config: {
        bitcoin_testnet_uds_path: "/tmp/bitcoin_uds",
        // IPC socket path for canister http adapter. This UDS path has to be the same as
        // specified in the systemd socket file.
        // The canister http adapter socket file is: ic-https-outcalls-adapter.socket
        https_outcalls_uds_path: "/run/ic-node/https-outcalls-adapter/socket",
    },
    bitcoin_payload_builder_config: {
    },
}
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    // This test verifies that the sample config can be loaded into
    // the replica.
    fn sample_config_is_deserializable() {
        let _ =
            json5::from_str::<Config>(SAMPLE_CONFIG).expect("sample config cannot be deserialized");
    }

    #[test]
    fn check_all_alternatives_parse() {
        const EXAMPLE_MARKER: &str = "EXAMPLE:";

        let mut line_variants: Vec<Vec<&str>> = Vec::new();
        let mut last_group: Vec<&str> = Vec::new();

        for line in SAMPLE_CONFIG.lines() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                if let Some(pos) = line.find(EXAMPLE_MARKER) {
                    last_group.push(line[pos + EXAMPLE_MARKER.len()..].trim())
                }
            } else if !trimmed.is_empty() || !last_group.is_empty() {
                if trimmed.starts_with('}') && !last_group.is_empty() {
                    line_variants.push(std::mem::take(&mut last_group));
                }
                last_group.push(line);
                line_variants.push(std::mem::take(&mut last_group));
            }
        }
        if !last_group.is_empty() {
            line_variants.push(last_group);
        }

        for (i, group) in line_variants.iter().enumerate() {
            if group.len() > 1 {
                let prefix = line_variants[..i]
                    .iter()
                    .map(|g| g[g.len() - 1])
                    .collect::<Vec<_>>()
                    .join("\n");
                let suffix = line_variants[i + 1..]
                    .iter()
                    .map(|g| g[g.len() - 1])
                    .collect::<Vec<_>>()
                    .join("\n");

                for &alternative in group.iter() {
                    let full_config = [&prefix, alternative, &suffix].join("\n");
                    if let Err(err) = json5::from_str::<Config>(&full_config) {
                        panic!("Failed to parse config variant {full_config}: {err}");
                    }
                }
            }
        }
    }
}
