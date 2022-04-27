use prost_build::Config;
use std::env;

// Build protos using prost_build.
fn main() {
    let proto_file = "proto/ic_registry_transport/pb/v1/transport.proto";

    println!("cargo:rerun-if-changed={}", proto_file);

    let ic_protos =
        env::var("IC_PROTOBUF_PROTO_INCLUDES").unwrap_or_else(|_| "../../protobuf/def".into());

    let mut config = Config::new();
    config.extern_path(".messaging.xnet.v1", "::ic_protobuf::messaging::xnet::v1");
    config.type_attribute(
        "ic_registry_transport.pb.v1.RegistryAtomicMutateRequest",
        "#[derive(candid::CandidType, candid::Deserialize, Eq)]",
    );
    config.type_attribute(
        "ic_registry_transport.pb.v1.RegistryMutation",
        "#[derive(candid::CandidType, candid::Deserialize, Eq)]",
    );
    config.type_attribute(
        "ic_registry_transport.pb.v1.Precondition",
        "#[derive(candid::CandidType, candid::Deserialize, Eq)]",
    );
    config
        .compile_protos(&[proto_file], &["proto", &ic_protos])
        .unwrap();
}
