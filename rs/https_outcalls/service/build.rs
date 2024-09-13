use std::{io::Result, path::PathBuf};
fn main() -> Result<()> {
    let proto = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("proto/https_outcalls_service/v1/proto.proto");
    tonic_build::configure().compile(&[&proto], &[&proto.parent().unwrap()])?;
    Ok(())
}
