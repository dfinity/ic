use std::io::Result;
fn main() -> Result<()> {
    let public_protos = "../../protobuf/def";
    tonic_build::configure()
        //.proto_path("::ic_protobuf::canister_http::v1")
        .extern_path(".canister_http.v1", "::ic-protobuf::canister_http::v1")
        .compile(&["src/proto.proto"], &["src/", public_protos])?;

    Ok(())
}
