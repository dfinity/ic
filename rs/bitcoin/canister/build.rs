use std::io::Result;
fn main() -> Result<()> {
    prost_build::compile_protos(&["src/proto.proto"], &["src/"])?;
    #[cfg(feature = "tonic-build")]
    tonic_build::compile_protos("src/proto.proto")?;
    Ok(())
}
