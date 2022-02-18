use prost_build::Config;
use std::io::Result;

fn main() -> Result<()> {
    let mut config = Config::new();
    config.extern_path(".bitcoin.v1", "::ic-protobuf::bitcoin::v1");

    let bitcoin_public_protos = "../../protobuf/def";

    config.compile_protos(&["src/proto.proto"], &["src/", bitcoin_public_protos])?;
    Ok(())
}
