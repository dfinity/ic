use ic_sns_wasm_protobuf_generator::{generate_prost_files, ProtoPaths};
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR")
            .expect("CARGO_MANIFEST_DIR env variable is not defined"),
    );
    let out_internal = &manifest_dir.join("../src/gen");
    let out_api = &manifest_dir.join("../api/src/gen");
    let sns_wasm_proto = manifest_dir.join("../proto");
    let base_types_proto = manifest_dir.join("../../../types/base_types/proto");
    let nervous_system_proto = manifest_dir.join("../../../nervous_system/proto/proto");
    let sns_init_proto = manifest_dir.join("../../../sns/init/proto");
    let sns_swap_proto = manifest_dir.join("../../../sns/swap/proto");

    match std::fs::remove_dir_all(out_internal) {
        Ok(_) => (),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => panic!(
            "failed to clean up internal protobuf output directory {}: {}",
            out_internal.display(),
            e
        ),
    }
    match std::fs::remove_dir_all(out_api) {
        Ok(_) => (),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => panic!(
            "failed to clean up api protobuf output directory {}: {}",
            out_api.display(),
            e
        ),
    }

    let proto_paths = ProtoPaths {
        sns_wasm: &sns_wasm_proto,
        base_types: &base_types_proto,
        nervous_system: &nervous_system_proto,
        sns_init: &sns_init_proto,
        sns_swap: &sns_swap_proto,
    };
    generate_prost_files(proto_paths, out_internal.as_ref());
    generate_prost_files(proto_paths, out_api.as_ref());
}
