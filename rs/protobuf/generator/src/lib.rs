use prost_build::Config;
use std::path::Path;

/// Creates a base Config, which should always be used in lieu of Config::new(),
/// to avoid any risk of non-determinism. Indeed, with Config::new(), the
/// generated code for proto's "map" fields are HashMaps. use `base_config()` to
/// eliminate this risk.
fn base_config(out: &Path, prefix: &str) -> Config {
    let mut config = Config::new();
    let proto_out = out.join(prefix);
    std::fs::create_dir_all(&proto_out)
        .unwrap_or_else(|e| panic!("Failed to create directory {}: {}", proto_out.display(), e));
    config.out_dir(&proto_out);
    // Use BTreeMap for all proto map fields.
    config.btree_map(&["."]);
    config.protoc_arg("--experimental_allow_proto3_optional");
    config
}

/// Derives fields for protobuf log messages and optional fields
macro_rules! add_log_proto_derives {
    ($prost_build:expr, $message_type:ident, $package:expr, $log_entry_field:ident $(,$message_field:ident)*) => {{
        $prost_build.type_attribute(
            std::concat!($package, ".", std::stringify!($message_type)),
            "#[derive(serde::Serialize, serde::Deserialize)]"
        );

        $prost_build.field_attribute(
            std::concat!("log.log_entry.v1.LogEntry.", std::stringify!($log_entry_field)),
            "#[serde(skip_serializing_if = \"Option::is_none\")]",
        );

        $(
            $prost_build.field_attribute(
                std::concat!($package, ".", std::stringify!($message_type), ".", std::stringify!($message_field)),
                "#[serde(skip_serializing_if = \"Option::is_none\")]"
            );
        )*
    }};
}

pub fn generate_prost_files(def: &Path, out: &Path) {
    build_crypto_proto(def, out);
    build_types_proto(def, out);
    build_log_proto(def, out);
    build_registry_proto(def, out);
    build_messaging_proto(def, out);
    build_state_proto(def, out);
    build_p2p_proto(def, out);
    build_bitcoin_proto(def, out);
    build_canister_http_proto(def, out);
}

/// Generates Rust structs from logging Protobuf messages.
fn build_log_proto(def: &Path, out: &Path) {
    let mut config = base_config(out, "log");

    config.type_attribute(
        "log.log_entry.v1.LogEntry",
        "#[derive(serde::Serialize, serde::Deserialize)]",
    );

    add_log_proto_derives!(
        config,
        ReplicaConfig,
        "log.replica_config.v1",
        replica_config
    );
    add_log_proto_derives!(
        config,
        ConsensusLogEntry,
        "log.consensus_log_entry.v1",
        consensus,
        height,
        hash,
        replica_version
    );

    add_log_proto_derives!(
        config,
        CryptoLogEntry,
        "log.crypto_log_entry.v1",
        crypto,
        trait_name,
        dkg_id,
        request_id,
        public_key,
        registry_version,
        method_name,
        description,
        is_ok,
        error,
        subnet_id,
        dkg_config,
        dkg_dealing,
        dkg_dealer,
        dkg_transcript,
        allowed_tls_clients,
        tls_server,
        dkg_epoch
    );

    add_log_proto_derives!(
        config,
        P2PLogEntry,
        "log.p2p_log_entry.v1",
        p2p,
        event,
        src,
        dest,
        artifact_id,
        chunk_id,
        advert,
        request,
        artifact,
        height,
        disconnect_elapsed
    );

    add_log_proto_derives!(
        config,
        MessagingLogEntry,
        "log.messaging_log_entry.v1",
        messaging,
        round,
        core
    );

    add_log_proto_derives!(
        config,
        IngressMessageLogEntry,
        "log.ingress_message_log_entry.v1",
        ingress_message,
        canister_id,
        compute_allocation,
        desired_id,
        expiry_time,
        memory_allocation,
        message_id,
        method_name,
        mode,
        reason,
        request_type,
        sender,
        size,
        batch_time,
        batch_time_plus_ttl
    );

    add_log_proto_derives!(
        config,
        BlockLogEntry,
        "log.block_log_entry.v1",
        block,
        byte_size,
        certified_height,
        dkg_payload_type,
        hash,
        height,
        parent_hash,
        rank,
        registry_version,
        time
    );

    add_log_proto_derives!(
        config,
        ExecutionLogEntry,
        "log.execution_log_entry.v1",
        execution,
        canister_id
    );

    add_log_proto_derives!(
        config,
        MaliciousBehaviourLogEntry,
        "log.malicious_behaviour_log_entry.v1",
        malicious_behaviour
    );

    compile_protos(config, def, &[def.join("log/log_entry/v1/log_entry.proto")]);
}

/// Generates Rust structs from registry Protobuf messages.
fn build_registry_proto(def: &Path, out: &Path) {
    let mut config = base_config(out, "registry");

    config.type_attribute(
        ".registry.crypto",
        "#[derive(serde::Serialize, serde::Deserialize)]",
    );
    config.type_attribute(
        ".registry.crypto.v1.EcdsaCurve",
        "#[derive(candid::CandidType)]",
    );
    config.type_attribute(
        ".registry.crypto.v1.EcdsaKeyId",
        "#[derive(candid::CandidType, Eq)]",
    );
    config.type_attribute(
        ".registry.node_operator",
        "#[derive(candid::CandidType, serde::Serialize, candid::Deserialize, Eq, Hash)]",
    );
    config.type_attribute(
        ".registry.nns",
        "#[derive(serde::Serialize, serde::Deserialize)]",
    );
    config.type_attribute(
        ".registry.node",
        "#[derive(serde::Serialize, serde::Deserialize)]",
    );
    config.type_attribute(
        ".registry.firewall",
        "#[derive(candid::CandidType, serde::Serialize, serde::Deserialize)]",
    );
    config.type_attribute(
        ".registry.routing_table",
        "#[derive(serde::Serialize, serde::Deserialize)]",
    );
    config.type_attribute(
        ".registry.provisional_whitelist",
        "#[derive(serde::Serialize, serde::Deserialize)]",
    );
    config.type_attribute(
        ".registry.subnet",
        "#[derive(serde::Serialize, serde::Deserialize)]",
    );
    config.type_attribute(
        ".registry.subnet.v1.EcdsaConfig",
        "#[derive(candid::CandidType, Eq)]",
    );
    config.type_attribute(
        ".registry.replica_version",
        "#[derive(serde::Serialize, serde::Deserialize)]",
    );

    config.type_attribute(
        ".registry.node_rewards.v2",
        "#[derive(candid::CandidType, serde::Serialize, candid::Deserialize)]",
    );

    config.type_attribute(
        ".registry.dc",
        "#[derive(candid::CandidType, serde::Serialize, candid::Deserialize)]",
    );

    config.type_attribute(
        ".registry.unassigned_nodes_config",
        "#[derive(serde::Serialize, serde::Deserialize)]",
    );

    let registry_files = [
        def.join("registry/crypto/v1/crypto.proto"),
        def.join("registry/node_operator/v1/node_operator.proto"),
        def.join("registry/nns/v1/nns.proto"),
        def.join("registry/node/v1/node.proto"),
        def.join("registry/firewall/v1/firewall.proto"),
        def.join("registry/routing_table/v1/routing_table.proto"),
        def.join("registry/provisional_whitelist/v1/provisional_whitelist.proto"),
        def.join("registry/subnet/v1/subnet.proto"),
        def.join("registry/replica_version/v1/replica_version.proto"),
        def.join("registry/node_rewards/v1/node_rewards.proto"),
        def.join("registry/node_rewards/v2/node_rewards.proto"),
        def.join("registry/dc/v1/dc.proto"),
        def.join("registry/unassigned_nodes_config/v1/unassigned_nodes_config.proto"),
    ];

    compile_protos(config, def, &registry_files);
}

/// Generates Rust structs from messaging Protobuf messages.
fn build_messaging_proto(def: &Path, out: &Path) {
    let mut config = base_config(out, "messaging");
    config.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");

    let messaging_files = [
        def.join("messaging/xnet/v1/certification.proto"),
        def.join("messaging/xnet/v1/certified_stream_slice.proto"),
        def.join("messaging/xnet/v1/labeled_tree.proto"),
        def.join("messaging/xnet/v1/mixed_hash_tree.proto"),
        def.join("messaging/xnet/v1/witness.proto"),
    ];

    compile_protos(config, def, &messaging_files);
}

/// Generates Rust structs from state Protobuf messages.
fn build_state_proto(def: &Path, out: &Path) {
    let config = base_config(out, "state");

    let state_files = [
        def.join("state/ingress/v1/ingress.proto"),
        def.join("state/metadata/v1/metadata.proto"),
        def.join("state/canister_state_bits/v1/canister_state_bits.proto"),
        def.join("state/queues/v1/queues.proto"),
        def.join("state/sync/v1/manifest.proto"),
        def.join("state/v1/metadata.proto"),
    ];

    compile_protos(config, def, &state_files);
}

/// Generates Rust structs from types Protobuf messages.
fn build_types_proto(def: &Path, out: &Path) {
    let mut config = base_config(out, "types");
    config.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");
    config.type_attribute(".types.v1.CatchUpPackage", "#[derive(Eq, Hash)]");
    config.type_attribute(".types.v1.SubnetId", "#[derive(Eq, Hash)]");
    config.type_attribute(".types.v1.NiDkgId", "#[derive(Eq, Hash)]");
    config.type_attribute(".types.v1.PrincipalId", "#[derive(Eq, Hash)]");
    let files = [
        def.join("types/v1/types.proto"),
        def.join("types/v1/dkg.proto"),
        def.join("types/v1/consensus.proto"),
        def.join("types/v1/ecdsa.proto"),
    ];
    compile_protos(config, def, &files);
}

/// Generates Rust structs from crypto Protobuf messages.
fn build_crypto_proto(def: &Path, out: &Path) {
    let mut config = base_config(out, "crypto");
    config.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");
    let files = [def.join("crypto/v1/crypto.proto")];
    compile_protos(config, def, &files);
}

/// Generates Rust structs from crypto Protobuf messages.
fn build_p2p_proto(def: &Path, out: &Path) {
    let mut config = base_config(out, "p2p");
    config.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");
    let files = [def.join("p2p/v1/p2p.proto")];
    compile_protos(config, def, &files);
}

/// Generates Rust structs from Bitcoin adapter Protobuf messages.
fn build_bitcoin_proto(def: &Path, out: &Path) {
    let mut config = base_config(out, "bitcoin");
    config.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");
    let files = [def.join("bitcoin/v1/bitcoin.proto")];
    compile_protos(config, def, &files);
}

/// Generates Rust structs from HTTP from canister adapter Protobuf messages.
fn build_canister_http_proto(def: &Path, out: &Path) {
    let mut config = base_config(out, "canister_http");
    config.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");
    let files = [def.join("canister_http/v1/canister_http.proto")];
    compile_protos(config, def, &files);
}

/// Compiles the given `proto_files`.
fn compile_protos<P: AsRef<Path>>(mut config: Config, def: &Path, proto_files: &[P]) {
    config.compile_protos(proto_files, &[def]).unwrap();
}
