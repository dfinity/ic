use prost_build::Config;

// Build protos using prost_build.
fn main() {
    let proto_files = [
        "proto/ic_registry_common/pb/local_store/v1/local_store.proto",
        "proto/ic_registry_common/pb/proto_registry/v1/proto_registry.proto",
        "proto/ic_registry_common/pb/test_protos/v1/test_protos.proto",
    ];

    proto_files.iter().for_each(|p| {
        println!("cargo:rerun-if-changed={}", p);
    });

    let mut config = Config::new();
    config.out_dir("gen");
    config.compile_protos(&proto_files, &["proto"]).unwrap();
}
