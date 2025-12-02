use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    tonic_build::configure()
        .extern_path(".attestation", "::attestation")
        .compile_protos(
            &[manifest.join("proto/api.proto")],
            &[
                manifest.join("proto"),
                manifest.join("../../attestation/proto"),
            ],
        )?;

    Ok(())
}
