use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let dest_path = out_dir.join("reload_hostos_cmd.rs");

    if let Ok(path) = env::var("RELOAD_HOSTOS_CMD") {
        // Bazel build: include the actual file
        let code = format!(
            r#"const RELOAD_HOSTOS_CMD: &[u8] = include_bytes!("{}");"#,
            path
        );
        fs::write(&dest_path, code).unwrap();
    } else {
        // Cargo build: use empty bytes
        fs::write(&dest_path, r#"const RELOAD_HOSTOS_CMD: &[u8] = b"";"#).unwrap();
    }
}
