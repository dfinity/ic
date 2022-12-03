use std::{io::Result, path::PathBuf};
fn main() -> Result<()> {
    let proto = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("proto/btc_service/v1/proto.proto");
    tonic_build::configure()
        .type_attribute(".", "#[allow(clippy::derive_partial_eq_without_eq)]")
        .compile(&[&proto], &[&proto.parent().unwrap()])?;
    Ok(())
}
