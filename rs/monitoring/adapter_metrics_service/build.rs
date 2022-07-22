fn main() {
    tonic_build::compile_protos("proto/adapter_metrics/v1/proto.proto")
        .expect("failed to compile tonic protos");
}
