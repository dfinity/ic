use ic_sns_wasm_proto_generator::generate_prost_files;
use std::path::PathBuf;

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR env variable is not defined");
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
