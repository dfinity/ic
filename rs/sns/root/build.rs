fn main() {
    compile_protos();
}

fn compile_protos() {
    let mut config = prost_build::Config::new();
    config.protoc_arg("--experimental_allow_proto3_optional");

    // Make all PB types also Candid types.
    config.type_attribute(".", "#[derive(candid::CandidType, candid::Deserialize)]");

    // Imported stuff.
    config.extern_path(".ic_base_types.pb.v1", "::ic-base-types");

    let source_file = "proto/ic_sns_root/pb/v1/root.proto";
    println!("cargo:rerun-if-changed={}", source_file);
    config
        .compile_protos(&[source_file], &["proto", "../../types/base_types/proto"])
        .unwrap();
}
