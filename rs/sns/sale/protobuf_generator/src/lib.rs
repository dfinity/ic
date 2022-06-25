use prost_build::Config;
use std::path::Path;

pub struct ProtoPaths<'a> {
    pub sale: &'a Path,
}

/// Build protos using prost_build.
pub fn generate_prost_files(proto: ProtoPaths<'_>, out: &Path) {
    let proto_file = proto.sale.join("ic_sns_sale/pb/v1/sale.proto");

    let mut config = Config::new();
    config.protoc_arg("--experimental_allow_proto3_optional");

    // Use BTreeMap for all maps to enforce determinism and to be able to use reverse
    // iterators.
    config.btree_map(&["."]);

    // Candid-ify Rust types generated from sale.proto.
    config.type_attribute(
        ".ic_sns_sale.pb.v1",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );

    config.type_attribute(
        "ic_sns_sale.pb.v1.ErrorRefundIcpRequest",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );

    config.type_attribute(
        "ic_sns_sale.pb.v1.ErrorRefundIcpResponse",
        "#[derive(candid::CandidType, candid::Deserialize)]",
    );

    std::fs::create_dir_all(out).expect("failed to create output directory");
    config.out_dir(out);

    config.compile_protos(&[proto_file], &[proto.sale]).unwrap();
}
