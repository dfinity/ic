use std::io::Result;
fn main() -> Result<()> {
    tonic_build::compile_protos("src/proto.proto")?;
    Ok(())
}
