use prost_build::Config;
use std::path::Path;

/// Build protos using prost_build.
pub fn generate_prost_files(def: &Path, out: &Path) {
    let proto_file = def.join("ic_base_types/pb/v1/types.proto");

    let mut config = Config::new();
    config.protoc_arg("--experimental_allow_proto3_optional");
    std::fs::create_dir_all(out).expect("failed to create output directory");
    config.out_dir(out);

    config.type_attribute(
        "ic_base_types.pb.v1.PrincipalId",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    config.compile_protos(&[proto_file], &[def]).unwrap();
}
