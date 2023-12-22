use std::path::PathBuf;

fn main() {
    let proto = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("proto/adapter_metrics/v1/proto.proto");
    tonic_build::configure()
        .compile(&[&proto], &[&proto.parent().unwrap()])
        .expect("failed to compile tonic protos");
}
