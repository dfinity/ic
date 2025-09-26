use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());

    // Rebuild if protos change
    println!("cargo::rerun-if-changed=proto/remote_attestation.proto");

    tonic_build::configure()
        .extern_path(".attestation", "::attestation")
        .build_transport(true)
        .compile_protos(
            &[manifest_dir.join("proto/remote_attestation.proto")],
            &[
                manifest_dir.join("proto"),
                manifest_dir.join("../../attestation/proto"),
            ],
        )?;

    Ok(())
}
