use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let dest_path = out_dir.join("reload_icos_cmd.rs");

    if env::var("RELOAD_ICOS_CMD").is_ok() {
        // Bazel build: include the actual file
        fs::write(
            &dest_path,
            r#"const RELOAD_ICOS_CMD: &[u8] = include_bytes!(env!("RELOAD_ICOS_CMD"));"#,
        )
        .unwrap();
    } else {
        // Cargo build: use empty bytes
        fs::write(&dest_path, r#"const RELOAD_ICOS_CMD: &[u8] = b"";"#).unwrap();
    }
}
