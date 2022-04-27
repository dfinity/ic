use prost_build::Config;

// Build crypto protos using prost_build.
fn main() {
    let mut config = Config::new();

    let proto_file = "proto/ic/crypto/v1/sks.proto";
    println!("cargo:rerun-if-changed={}", proto_file);

    config.compile_protos(&[proto_file], &["proto"]).unwrap();
}
