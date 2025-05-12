use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    tonic_build::configure()
        .extern_path(".verification.attestation", "::attestation::types")
        .extern_path(".types.v1", "::ic_protobuf::types::v1")
        .compile_protos(
            &[manifest.join("proto/api.proto")],
            &[
                manifest.join("proto"),
                manifest.join("../attestation/proto"),
                manifest.join("../../../protobuf/def"),
            ],
        )?;
    // tonic_build::compile_protos(
    //     PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("proto/api.proto"),
    // )?;
    Ok(())
}
