use prost_build::Config;
use std::path::Path;

#[derive(Debug)]
pub struct ProtoPaths<'a> {
    pub sns_init: &'a Path,
    pub base_types: &'a Path,
}

/// Build protos using prost_build.
pub fn generate_prost_files(proto: ProtoPaths<'_>, out: &Path) {
    let proto_files = [proto.sns_init.join("ic_sns_init/pb/v1/sns_init.proto")];

    let mut config = Config::new();
    config.protoc_arg("--experimental_allow_proto3_optional");
    std::fs::create_dir_all(out).expect("failed to create output directory");
    config.out_dir(out);

    config.extern_path(".ic_base_types.pb.v1", "::ic-base-types");

    // Add universally needed types to all definitions in this namespace
    config.type_attribute(
        ".ic_sns_init.pb.v1",
        "#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, Eq)]",
    );

    config
        .compile_protos(&proto_files, &[proto.sns_init, proto.base_types])
        .unwrap();
}

/// Convenience function to add the correct namespace to our class names
#[allow(dead_code)]
fn ic_sns_type_attr<A>(cfg: &mut Config, class: &str, attributes: A)
where
    A: AsRef<str>,
{
    cfg.type_attribute("ic_sns_init.pb.v1.".to_owned() + class, attributes);
}
