use prost_build::Config;

// Build protos using prost_build.
fn main() {
    let proto_file = "proto/ic_base_types/pb/v1/types.proto";

    let mut config = Config::new();
    config.protoc_arg("--experimental_allow_proto3_optional");

    config.out_dir("gen");
    config.type_attribute(
        "ic_base_types.pb.v1.PrincipalId",
        [
            "#[derive(candid::CandidType, candid::Deserialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );
    println!("cargo:rerun-if-changed={}", proto_file);
    config.compile_protos(&[proto_file], &["proto"]).unwrap();
}
