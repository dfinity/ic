use ic_nervous_system_proto_protobuf_generator::{ProtoPaths, generate_prost_files};
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR")
            .expect("CARGO_MANIFEST_DIR env variable is not defined"),
    );
    let primary_search_path = manifest_dir.join("../proto");
    let out_dir = manifest_dir.join("../src/gen");
    let base_types_proto = manifest_dir.join("../../../types/base_types/proto");

    // Delete contents of the output directory.
    match std::fs::remove_dir_all(&out_dir) {
        Ok(_) => (),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => panic!(
            "failed to clean up output directory {}: {}",
            out_dir.display(),
            e
        ),
    }

    generate_prost_files(
        ProtoPaths {
            nervous_system: &primary_search_path,
            base_types: &base_types_proto,
        },
        out_dir.as_ref(),
    );
}
