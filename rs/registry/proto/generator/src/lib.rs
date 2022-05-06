use prost_build::Config;
use std::path::Path;

/// Build protos using prost_build.
pub fn generate_prost_files(def: &Path, out: &Path) {
    let proto_files = [
        def.join("ic_registry_common/pb/local_store/v1/local_store.proto"),
        def.join("ic_registry_common/pb/proto_registry/v1/proto_registry.proto"),
        def.join("ic_registry_common/pb/test_protos/v1/test_protos.proto"),
    ];

    let mut config = Config::new();
    std::fs::create_dir_all(out).expect("failed to create output directory");
    config.out_dir(out);
    config.compile_protos(&proto_files, &[def]).unwrap();
}
