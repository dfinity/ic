use prost_build::Config;
use std::path::Path;

pub struct ProtoPaths<'a> {
    pub transport: &'a Path,
    pub base_types: &'a Path,
    pub protobuf: &'a Path,
    pub nns_common: &'a Path,
    pub registry_canister: &'a Path,
}

/// Build protos using prost_build.
pub fn generate_prost_files(proto: ProtoPaths<'_>, out: &Path) {
    let proto_file = proto
        .registry_canister
        .join("ic_registry_canister/pb/v1/registry.proto");

    let mut config = Config::new();
    config.protoc_arg("--experimental_allow_proto3_optional");

    config.extern_path(
        ".ic_registry_transport.pb.v1",
        "::ic-registry-transport::pb::v1",
    );
    config.extern_path(".ic_nns_common.pb.v1", "::ic-nns-common::pb::v1");

    config.type_attribute(
        "ic_registry_canister.pb.v1.NodeProvidersMonthlyXdrRewards",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );

    std::fs::create_dir_all(out).expect("failed to create output directory");
    config.out_dir(out);

    config
        .compile_protos(
            &[proto_file],
            &[
                proto.registry_canister,
                proto.transport,
                proto.protobuf,
                proto.nns_common,
                proto.base_types,
            ],
        )
        .unwrap();
}
