use std::{io::Result, path::PathBuf};
fn main() -> Result<()> {
    let proto = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("proto/onchain_observability_service/v1/service_interface.proto");
    // Ignore clippy warning due to prost issue from https://github.com/tokio-rs/prost/issues/661
    tonic_build::configure()
        .type_attribute(".", "#[allow(clippy::derive_partial_eq_without_eq)]")
        .compile(&[&proto], &[&proto.parent().unwrap()])?;
    Ok(())
}
