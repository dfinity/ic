use prost_build::Config;
use std::path::Path;

pub struct ProtoPaths<'a> {
    pub ledger: &'a Path,
    pub base_types: &'a Path,
}

pub fn generate_prost_files(paths: ProtoPaths<'_>, out: &Path) {
    let proto_file = paths.ledger.join("ic_ledger/pb/v1/types.proto");

    let mut config = Config::new();
    config.extern_path(".ic_base_types.pb.v1", "::ic-base-types");

    config.type_attribute(
        "ic_ledger.pb.v1.AccountIdentifier",
        [
            "#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );

    config.type_attribute(
        "ic_ledger.pb.v1.TimeStamp",
        "#[derive(Eq, PartialOrd, Ord, Hash, Copy, candid::CandidType, serde::Deserialize, serde::Serialize)]",
    );

    std::fs::create_dir_all(out).expect("failed to create output directory");
    config.out_dir(out);

    config
        .compile_protos(&[proto_file], &[paths.ledger, paths.base_types])
        .unwrap();
}
