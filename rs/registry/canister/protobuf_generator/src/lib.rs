use prost_build::Config;
use std::path::Path;

pub struct ProtoPaths<'a> {
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

    config.extern_path(".ic_base_types.pb.v1", "::ic-base-types");

    for type_name in [
        "ApiBoundaryNodeIdRecord",
        "Chunk",
        "GetApiBoundaryNodeIdsRequest",
        "GetChunkRequest",
        "GetSubnetForCanisterRequest",
        "NodeProvidersMonthlyXdrRewards",
        "SubnetForCanister",
    ] {
        config.type_attribute(
            format!("ic_registry_canister.pb.v1.{type_name}"),
            "#[derive(candid::CandidType, candid::Deserialize)]",
        );
    }

    // Speed up deserialization of `opt blob`/`Option<Vec<u8>>` fields.
    for option_blob_field_name in [
        "GetChunkRequest.content_sha256", // This is small, but why not.
        "Chunk.content",
    ] {
        config.field_attribute(
            format!("ic_registry_canister.pb.v1.{option_blob_field_name}"),
            r#"#[serde(deserialize_with = "ic_utils::deserialize::deserialize_option_blob")]"#,
        );
    }

    std::fs::create_dir_all(out).expect("failed to create output directory");
    config.out_dir(out);

    config
        .compile_protos(
            &[proto_file],
            &[
                proto.registry_canister,
                proto.protobuf,
                proto.nns_common,
                proto.base_types,
            ],
        )
        .unwrap();

    ic_utils_rustfmt::rustfmt(out).expect("failed to rustfmt protobufs");
}
