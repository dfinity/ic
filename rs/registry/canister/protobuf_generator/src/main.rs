use registry_canister_protobuf_generator::{generate_prost_files, ProtoPaths};
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR")
            .expect("CARGO_MANIFEST_DIR env variable is not defined"),
    );
    let out = manifest_dir.join("../gen");
    let registry_canister_proto = manifest_dir.join("../proto");
    let base_types_proto = manifest_dir.join("../../../types/base_types/proto");
    let protobuf_proto = manifest_dir.join("../../../protobuf/def");
    let nns_common_proto = manifest_dir.join("../../../nns/common/proto");
    let transport_proto = manifest_dir.join("../../../registry/transport/proto");

    match std::fs::remove_dir_all(&out) {
        Ok(_) => (),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => panic!(
            "failed to clean up output directory {}: {}",
            out.display(),
            e
        ),
    }
    generate_prost_files(
        ProtoPaths {
            registry_canister: &registry_canister_proto,
            base_types: &base_types_proto,
            transport: &transport_proto,
            protobuf: &protobuf_proto,
            nns_common: &nns_common_proto,
        },
        out.as_ref(),
    );
}
