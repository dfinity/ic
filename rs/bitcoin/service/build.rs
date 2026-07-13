use std::{io::Result, path::PathBuf};
fn main() -> Result<()> {
    let proto = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("proto/btc_service/v1/proto.proto");
    tonic_prost_build::configure()
        .compile_protos(&[proto.as_path()], &[proto.parent().unwrap()])?;
    Ok(())
}
