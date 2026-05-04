use std::path::Path;

/// Search paths used by Prost.
pub struct ProtoPaths<'a> {
    pub nervous_system: &'a Path,
    pub base_types: &'a Path,
}

impl ProtoPaths<'_> {
    fn to_vec(&self) -> Vec<&Path> {
        vec![self.nervous_system, self.base_types]
    }
}

/// Build protos using prost_build.
pub fn generate_prost_files(proto_paths: ProtoPaths<'_>, out_dir: &Path) {
    let mut config = prost_build::Config::new();
    config.protoc_arg("--experimental_allow_proto3_optional");
    config.extern_path(".ic_base_types.pb.v1", "::ic-base-types");

    // Frankly, I'm kind of surprised that Prost doesn't blanket everything with
    // Eq. OTOH, I suppose in PB, it's not very clear whether None and Some(0)
    // should be considered "equal".
    config.type_attribute(".", "#[derive(Eq)]");

    // Candid-ify generated Rust types.
    config.type_attribute(".", "#[derive(candid::CandidType, candid::Deserialize)]");
    // Because users of the types we supply put these on their types, we must
    // also add these derives.
    config.type_attribute(".", "#[derive(comparable::Comparable, serde::Serialize)]");

    config.type_attribute(
        "ic_nervous_system.pb.v1.Canister",
        "#[derive(Ord, PartialOrd)]",
    );

    let src_file = proto_paths
        .nervous_system
        .join("ic_nervous_system/pb/v1/nervous_system.proto");

    config.type_attribute("ic_nervous_system.pb.v1.Canister", "#[derive(Copy)]");

    config.type_attribute(
        "ic_nervous_system.pb.v1.Percentage",
        "#[derive(PartialOrd, Ord)]",
    );

    // Assert that all files and directories exist.
    assert!(src_file.exists());
    let search_paths = proto_paths.to_vec();
    for p in search_paths {
        assert!(p.exists());
    }

    config.out_dir(out_dir);
    std::fs::create_dir_all(out_dir).expect("failed to create output directory");
    config.out_dir(out_dir);

    config
        .compile_protos(&[src_file], &proto_paths.to_vec())
        .unwrap();

    ic_utils_rustfmt::rustfmt(out_dir).expect("failed to rustfmt protobufs");
}
