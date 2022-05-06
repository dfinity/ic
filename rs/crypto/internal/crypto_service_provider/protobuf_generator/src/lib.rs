use prost_build::Config;
use std::path::Path;

/// Build crypto protos using prost_build.
pub fn generate_prost_files(def: &Path, out: &Path) {
    let mut config = Config::new();

    std::fs::create_dir_all(out).expect("failed to create output directory");
    config.out_dir(out);

    let proto_file = def.join("ic/crypto/v1/sks.proto");
    config.compile_protos(&[proto_file], &[def]).unwrap();
}
