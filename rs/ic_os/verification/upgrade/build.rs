use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos(
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("proto/api.proto"),
    )?;
    Ok(())
}
