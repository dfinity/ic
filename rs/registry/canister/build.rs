use prost_build::Config;
use std::env;

// Build protos using prost_build.
fn main() {
    let proto_file = "proto/ic_registry_canister/pb/v1/registry.proto";

    // On CI we get the protobufs from transport from nix, through a var set
    // on overrides.nix, but locally we can just refer to the transport crate
    // through relative paths.
    let transport_proto_dir = env::var("REGISTRY_TRANSPORT_PROTO_INCLUDES")
        .unwrap_or_else(|_| "../transport/proto".into());

    let base_types_proto_dir = match env::var("IC_BASE_TYPES_PROTO_INCLUDES") {
        Ok(dir) => dir,
        Err(_) => "../../types/base_types/proto".into(),
    };

    let ic_protos =
        env::var("IC_PROTOBUF_PROTO_INCLUDES").unwrap_or_else(|_| "../../protobuf/def".into());

    let common_proto_dir = match env::var("IC_NNS_COMMON_PROTO_INCLUDES") {
        Ok(dir) => dir,
        Err(_) => "../../nns/common/proto".into(),
    };

    let mut config = Config::new();
    config.protoc_arg("--experimental_allow_proto3_optional");

    config.extern_path(
        ".ic_registry_transport.pb.v1",
        "::ic-registry-transport::pb::v1",
    );
    config.extern_path(".ic_nns_common.pb.v1", "::ic-nns-common::pb::v1");
    config.out_dir("gen");

    config.type_attribute(
        "ic_registry_canister.pb.v1.NodeProvidersMonthlyXdrRewards",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );

    println!("cargo:rerun-if-changed={}", proto_file);
    config
        .compile_protos(
            &[proto_file],
            &[
                "proto",
                &transport_proto_dir,
                &ic_protos,
                &common_proto_dir,
                &base_types_proto_dir,
            ],
        )
        .unwrap();
}
