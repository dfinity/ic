use ic_base_types_protobuf_generator::generate_prost_files;
use std::path::PathBuf;

fn main() {
    let manifest_dir = match std::env::var("CARGO_MANIFEST_DIR") {
        Ok(path) => PathBuf::from(path),
        Err(_) => match std::env::var("BUILD_WORKSPACE_DIRECTORY") {
            Ok(path) => PathBuf::from(path).join("rs/types/base_types/protobuf_generator"),
            Err(_) => panic!(
                "Neither CARGO_MANIFEST_DIR nor BUILD_WORKSPACE_DIRECTORY env variable is defined"
            ),
        },
    };
    let out = PathBuf::from(&manifest_dir).join("../gen");
    let def = PathBuf::from(&manifest_dir).join("../proto");
    match std::fs::remove_dir_all(&out) {
        Ok(_) => (),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => panic!(
            "failed to clean up output directory {}: {}",
            out.display(),
            e
        ),
    }
    generate_prost_files(def.as_ref(), out.as_ref());
}
