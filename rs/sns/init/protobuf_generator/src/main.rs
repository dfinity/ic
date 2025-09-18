use ic_sns_init_protobuf_generator::{ProtoPaths, generate_prost_files};
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR")
            .expect("CARGO_MANIFEST_DIR env variable is not defined"),
    );
    let out = &manifest_dir.join("../src/gen");
    let sns_init_proto = manifest_dir.join("../proto");
    let base_types_proto = manifest_dir.join("../../../types/base_types/proto");
    let nervous_system_proto = manifest_dir.join("../../../nervous_system/proto/proto");
    let sns_swap_proto = manifest_dir.join("../../swap/proto");

    match std::fs::remove_dir_all(out) {
        Ok(_) => (),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => panic!(
            "failed to clean up output directory {}: {}",
            out.display(),
            e
        ),
    }
    generate_prost_files(
        ProtoPaths {
            sns_init: &sns_init_proto,
            base_types: &base_types_proto,
            nervous_system: &nervous_system_proto,
            sns_swap: &sns_swap_proto,
        },
        out.as_ref(),
    );
}
