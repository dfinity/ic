use ic_nns_governance_protobuf_generator::{generate_prost_files, ProtoPaths};
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR")
            .expect("CARGO_MANIFEST_DIR env variable is not defined"),
    );
    let out = manifest_dir.join("../gen");
    let governance_proto = manifest_dir.join("../proto");
    let base_types_proto = manifest_dir.join("../../../types/base_types/proto");
    let ledger_proto = manifest_dir.join("../../../rosetta-api/ledger_canister/proto");
    let nns_common_proto = manifest_dir.join("../../common/proto");

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
            governance: &governance_proto,
            ledger: &ledger_proto,
            base_types: &base_types_proto,
            nns_common: &nns_common_proto,
        },
        out.as_ref(),
    );
}
