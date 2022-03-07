use std::io::Result;
fn main() -> Result<()> {
    let bitcoin_public_protos = "../../protobuf/def";
    tonic_build::configure()
        .extern_path(".bitcoin.v1", "::ic-protobuf::bitcoin::v1")
        .compile(&["src/proto.proto"], &["src/", bitcoin_public_protos])?;
    Ok(())
}
