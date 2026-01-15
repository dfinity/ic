use ic_nns_governance_protobuf_generator::{ProtoPaths, generate_prost_files};
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR")
            .expect("CARGO_MANIFEST_DIR env variable is not defined"),
    );
    let out = manifest_dir.join("../src/gen");

    // Delete the output directory.
    match std::fs::remove_dir_all(&out) {
        Ok(_) => (),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => panic!(
            "failed to clean up output directory {}: {}",
            out.display(),
            e
        ),
    }

    let repo_root = manifest_dir.join("../../../..");

    let base_types_proto = repo_root.join("rs/types/base_types/proto");
    let governance_proto = repo_root.join("rs/nns/governance/proto");
    let ic_protobuf_proto = repo_root.join("rs/protobuf/def");
    let ledger_proto = repo_root.join("rs/ledger_suite/icp/proto");
    let nervous_system_proto = repo_root.join("rs/nervous_system/proto/proto");
    let nns_common_proto = repo_root.join("rs/nns/common/proto");
    let sns_root_proto = repo_root.join("rs/sns/root/proto");
    let sns_swap_proto = repo_root.join("rs/sns/swap/proto");

    generate_prost_files(
        ProtoPaths {
            base_types: &base_types_proto,
            governance: &governance_proto,
            ic_protobuf: &ic_protobuf_proto,
            ledger: &ledger_proto,
            nervous_system: &nervous_system_proto,
            nns_common: &nns_common_proto,
            sns_root: &sns_root_proto,
            sns_swap: &sns_swap_proto,
        },
        out.as_ref(),
    );
}
