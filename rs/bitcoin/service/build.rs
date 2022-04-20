use std::io::Result;
fn main() -> Result<()> {
    tonic_build::configure().compile(&["proto/btc_service/v1/proto.proto"], &["proto/"])?;
    Ok(())
}
