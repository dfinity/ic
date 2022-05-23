use std::{io::Result, path::PathBuf};
fn main() -> Result<()> {
    tonic_build::compile_protos(
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("proto/btc_service/v1/proto.proto"),
    )?;
    Ok(())
}
