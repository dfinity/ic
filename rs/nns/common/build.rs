use prost_build::Config;
use std::env;

// Build protos using prost_build.
// We cannot use relative paths, which break on Hydra.
// During the build CARGO_MANIFEST_DIR is the directory that contains the
// build.rs file, so we can use that to construct absolute paths.
fn main() {
    let proto_file = "proto/ic_nns_common/pb/v1/types.proto";

    let base_types_proto_dir = match env::var("IC_BASE_TYPES_PROTO_INCLUDES") {
        Ok(dir) => dir,
        Err(_) => "../../types/base_types/proto".into(),
    };

    let mut config = Config::new();
    config.extern_path(".ic_base_types.pb.v1", "::ic-base-types");
    config.type_attribute(
        "ic_nns_common.pb.v1.CanisterId",
        [
            "#[derive(candid::CandidType, candid::Deserialize, Eq)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable), self_describing)]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_common.pb.v1.NeuronId",
        [
            "#[derive(candid::CandidType, candid::Deserialize, Eq, std::hash::Hash)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable), self_describing)]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_common.pb.v1.PrincipalId",
        [
            "#[derive(candid::CandidType, candid::Deserialize, Eq, PartialOrd, Ord, std::hash::Hash)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable), self_describing)]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_common.pb.v1.ProposalId",
        [
            "#[derive(candid::CandidType, candid::Deserialize, Eq, Copy)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable), self_describing)]",
        ]
        .join(" "),
    );
    config.type_attribute(
        "ic_nns_common.pb.v1.MethodAuthzInfo",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );
    config.type_attribute(
        "ic_nns_common.pb.v1.CanisterAuthzInfo",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );

    println!("cargo:rerun-if-changed={}", proto_file);

    config
        .compile_protos(&[proto_file], &["proto", &base_types_proto_dir])
        .unwrap();
}
