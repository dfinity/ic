use prost_build::Config;
use std::path::Path;

pub struct ProtoPaths<'a> {
    pub nns_common: &'a Path,
    pub base_types: &'a Path,
}

/// Build protos using prost_build.
pub fn generate_prost_files(proto: ProtoPaths<'_>, out: &Path) {
    let proto_file = proto.nns_common.join("ic_nns_common/pb/v1/types.proto");

    let mut config = Config::new();
    config.extern_path(".ic_base_types.pb.v1", "::ic-base-types");

    config.type_attribute(".", "#[derive(serde::Serialize)]");

    for message_name in ["NeuronId", "ProposalId"] {
        config.type_attribute(
            format!("ic_nns_common.pb.v1.{message_name}"),
            [
                "#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable, Eq)]",
                "#[derive(PartialOrd, Ord, std::hash::Hash)]",
                "#[self_describing]",
            ]
            .join(" "),
        );
    }

    std::fs::create_dir_all(out).expect("failed to create output directory");
    config.out_dir(out);

    config
        .compile_protos(&[proto_file], &[proto.nns_common, proto.base_types])
        .unwrap();

    ic_utils_rustfmt::rustfmt(out).expect("failed to rustfmt protobufs");
}
