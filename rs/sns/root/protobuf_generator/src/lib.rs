use std::path::Path;

pub struct ProtoPaths<'a> {
    pub sns: &'a Path,
    pub base_types: &'a Path,
}

pub fn generate_prost_files(proto: ProtoPaths<'_>, out: &Path) {
    let mut config = prost_build::Config::new();
    config.protoc_arg("--experimental_allow_proto3_optional");
    std::fs::create_dir_all(out).expect("failed to created out directory");
    config.out_dir(out);

    // Make all PB types also Candid types.
    config.type_attribute(".", "#[derive(candid::CandidType, candid::Deserialize)]");

    // Imported stuff.
    config.extern_path(".ic_base_types.pb.v1", "::ic-base-types");

    let root_proto = proto.sns.join("ic_sns_root/pb/v1/root.proto");

    config
        .compile_protos(&[root_proto], &[proto.sns, proto.base_types])
        .unwrap();
}
