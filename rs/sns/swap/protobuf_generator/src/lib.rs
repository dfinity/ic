use prost_build::Config;
use std::path::Path;

pub struct ProtoPaths<'a> {
    pub swap: &'a Path,

    // TODO(NNS1-1589): Uncomment.
    // pub sns_root: &'a Path,

    // These are indirect dependencies.
    pub base_types: &'a Path,
    pub ledger: &'a Path,
}

/// Build protos using prost_build.
pub fn generate_prost_files(proto: ProtoPaths<'_>, out: &Path) {
    let proto_file = proto.swap.join("ic_sns_swap/pb/v1/swap.proto");

    let mut config = Config::new();
    config.protoc_arg("--experimental_allow_proto3_optional");

    // Imports.
    // TODO(NNS1-1589): Uncomment.
    // config.extern_path(".ic_sns_root.pb.v1", "::ic_sns_root::pb::v1");
    // Indirect imports.
    config.extern_path(".ic_base_types.pb.v1", "::ic-base-types");
    config.extern_path(".ic_ledger.pb.v1", "::ledger-canister::protobuf");

    // Use BTreeMap for all maps to enforce determinism and to be able to use reverse
    // iterators.
    config.btree_map(&["."]);

    // Candid-ify Rust types generated from swap.proto.
    config.type_attribute(
        ".",
        ["#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]"].join(" "),
    );

    config.type_attribute(".ic_sns_swap.pb.v1.TimeWindow", "#[derive(Copy)]");

    std::fs::create_dir_all(out).expect("failed to create output directory");
    config.out_dir(out);

    config
        .compile_protos(
            &[proto_file],
            &[
                proto.swap,
                // TODO(NNS1-1589): Uncomment.
                // proto.sns_root,
                proto.base_types,
                proto.ledger,
            ],
        )
        .unwrap();

    ic_utils_rustfmt::rustfmt(out).expect("failed to rustfmt protobufs");
}
