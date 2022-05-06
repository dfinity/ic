use prost_build::Config;
use std::path::Path;

pub struct ProtoPaths<'a> {
    pub root: &'a Path,
    pub nns_common: &'a Path,
    pub base_types: &'a Path,
}

/// Build protos using prost_build.
pub fn generate_prost_files(proto: ProtoPaths<'_>, out: &Path) {
    let proto_file = proto.root.join("ic_nns_handler_root/pb/v1/root.proto");

    let mut config = Config::new();
    config.extern_path(".ic_nns_common.pb.v1", "::ic-nns-common::pb::v1");
    config.extern_path(".ic_base_types.pb.v1", "::ic-base-types");

    std::fs::create_dir_all(out).expect("failed to create output directory");
    config.out_dir(out);

    config
        .compile_protos(
            &[proto_file],
            &[proto.root, proto.nns_common, proto.base_types],
        )
        .unwrap();
}
