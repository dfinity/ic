use std::io::Result;
fn main() -> Result<()> {
    tonic_build::compile_protos("proto/canister_http_service/v1/proto.proto")?;
    Ok(())
}
