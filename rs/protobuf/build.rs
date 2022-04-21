use prost_build::Config;
use std::env;
use std::path::PathBuf;

/// Creates a base Config, which should always be used in lieu of Config::new(),
/// to avoid any risk of non-determinism. Indeed, with Config::new(), the
/// generated code for proto's "map" fields are HashMaps. use `base_config()` to
/// eliminate this risk.
fn base_config() -> Config {
    let mut config = Config::new();
    // Use BTreeMap for all proto map fields.
    config.btree_map(&["."]);
    config.file_descriptor_set_path(
        // OUT_DIR is set by cargo
        // https://doc.rust-lang.org/cargo/reference/environment-variables.html
        PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR environment variable not set"))
            .join("protoc_file_descriptor_set.bin"),
    );
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

fn main() {
    build_crypto_proto();
    build_types_proto();
    build_log_proto();
    build_registry_proto();
    build_messaging_proto();
    build_state_proto();
    build_p2p_proto();
    build_bitcoin_proto();
    build_canister_http_proto();
}

/// Generates Rust structs from logging Protobuf messages.
fn build_log_proto() {
    let mut config = base_config();
    config.out_dir("gen/log");

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

    compile_protos(config, &["def/log/log_entry/v1/log_entry.proto"]);
}

/// Generates Rust structs from registry Protobuf messages.
fn build_registry_proto() {
    let mut config = base_config();
    config.out_dir("gen/registry");

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
        "#[derive(serde::Serialize, serde::Deserialize)]",
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
        "def/registry/crypto/v1/crypto.proto",
        "def/registry/node_operator/v1/node_operator.proto",
        "def/registry/nns/v1/nns.proto",
        "def/registry/node/v1/node.proto",
        "def/registry/firewall/v1/firewall.proto",
        "def/registry/routing_table/v1/routing_table.proto",
        "def/registry/provisional_whitelist/v1/provisional_whitelist.proto",
        "def/registry/subnet/v1/subnet.proto",
        "def/registry/replica_version/v1/replica_version.proto",
        "def/registry/node_rewards/v1/node_rewards.proto",
        "def/registry/node_rewards/v2/node_rewards.proto",
        "def/registry/dc/v1/dc.proto",
        "def/registry/unassigned_nodes_config/v1/unassigned_nodes_config.proto",
    ];

    compile_protos(config, &registry_files);
}

/// Generates Rust structs from messaging Protobuf messages.
fn build_messaging_proto() {
    let mut config = base_config();
    config.out_dir("gen/messaging");
    config.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");

    let messaging_files = [
        "def/messaging/xnet/v1/certification.proto",
        "def/messaging/xnet/v1/certified_stream_slice.proto",
        "def/messaging/xnet/v1/labeled_tree.proto",
        "def/messaging/xnet/v1/mixed_hash_tree.proto",
        "def/messaging/xnet/v1/witness.proto",
    ];

    compile_protos(config, &messaging_files);
}

/// Generates Rust structs from state Protobuf messages.
fn build_state_proto() {
    let mut config = base_config();
    config.out_dir("gen/state");

    let state_files = [
        "def/state/ingress/v1/ingress.proto",
        "def/state/metadata/v1/metadata.proto",
        "def/state/canister_state_bits/v1/canister_state_bits.proto",
        "def/state/queues/v1/queues.proto",
        "def/state/sync/v1/manifest.proto",
        "def/state/v1/metadata.proto",
    ];

    compile_protos(config, &state_files);
}

/// Generates Rust structs from types Protobuf messages.
fn build_types_proto() {
    let mut config = base_config();
    config.out_dir("gen/types");
    config.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");
    config.type_attribute(".types.v1.CatchUpPackage", "#[derive(Eq, Hash)]");
    config.type_attribute(".types.v1.SubnetId", "#[derive(Eq, Hash)]");
    config.type_attribute(".types.v1.NiDkgId", "#[derive(Eq, Hash)]");
    config.type_attribute(".types.v1.PrincipalId", "#[derive(Eq, Hash)]");
    let files = [
        "def/types/v1/types.proto",
        "def/types/v1/dkg.proto",
        "def/types/v1/consensus.proto",
        "def/types/v1/ecdsa.proto",
    ];
    compile_protos(config, &files);
}

/// Generates Rust structs from crypto Protobuf messages.
fn build_crypto_proto() {
    let mut config = base_config();
    config.out_dir("gen/crypto");
    config.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");
    let files = ["def/crypto/v1/crypto.proto"];
    compile_protos(config, &files);
}

/// Generates Rust structs from crypto Protobuf messages.
fn build_p2p_proto() {
    let mut config = base_config();
    config.out_dir("gen/p2p");
    config.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");
    let files = ["def/p2p/v1/p2p.proto"];
    compile_protos(config, &files);
}

/// Generates Rust structs from Bitcoin adapter Protobuf messages.
fn build_bitcoin_proto() {
    let mut config = base_config();
    config.out_dir("gen/bitcoin");
    config.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");
    let files = ["def/bitcoin/v1/bitcoin.proto"];
    compile_protos(config, &files);
}

/// Generates Rust structs from HTTP from canister adapter Protobuf messages.
fn build_canister_http_proto() {
    let mut config = base_config();
    config.out_dir("gen/canister_http");
    config.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");
    let files = ["def/canister_http/v1/canister_http.proto"];
    compile_protos(config, &files);
}

/// Compiles the given `proto_files` and emits `cargo:rerun-if-changed` outputs
/// for each of them.
fn compile_protos(mut config: Config, proto_files: &[&str]) {
    for proto_file in proto_files {
        println!("cargo:rerun-if-changed={}", proto_file);
    }
    config.compile_protos(proto_files, &["def/"]).unwrap();
}
