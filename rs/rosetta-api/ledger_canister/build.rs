use prost_build::Config;
use std::env::{self, VarError};
use std::path::PathBuf;

fn main() {
    let proto_file = "proto/ic_ledger/pb/v1/types.proto";
    println!("cargo:rerun-if-changed={}", proto_file);

    let base_types_proto_dir = match env::var("IC_BASE_TYPES_PROTO_INCLUDES") {
        Ok(dir) => dir,
        Err(_) => "../../types/base_types/proto".into(),
    };

    let mut config = Config::new();
    config.extern_path(".ic_base_types.pb.v1", "::ic-base-types");
    config.out_dir("gen");

    config.type_attribute(
        "ic_ledger.pb.v1.AccountIdentifier",
        [
            "#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]",
            "#[cfg_attr(feature = \"test\", derive(comparable::Comparable))]",
        ]
        .join(" "),
    );

    config.type_attribute(
        "ic_ledger.pb.v1.TimeStamp",
        "#[derive(Eq, PartialOrd, Ord, Hash, Copy, candid::CandidType, serde::Deserialize, serde::Serialize)]",
    );

    config
        .compile_protos(&[proto_file], &["proto/", &base_types_proto_dir])
        .unwrap();

    let archive_path = match env::var("LEDGER_ARCHIVE_NODE_CANISTER_WASM_PATH") {
        Ok(wasm_path) => PathBuf::from(wasm_path),
        Err(VarError::NotPresent) => PathBuf::from("wasm/ledger-archive-node-canister.wasm")
            .canonicalize()
            .expect("failed to canonicalize a path"),
        Err(VarError::NotUnicode(path)) => panic!(
            "Ledger archive node Wasm path contains non-unicode characters: {:?}",
            path
        ),
    };

    println!("cargo:rerun-if-changed={}", archive_path.display());
    println!("cargo:rerun-if-env-changed=LEDGER_ARCHIVE_NODE_CANISTER_WASM_PATH");
    println!(
        "cargo:rustc-env=LEDGER_ARCHIVE_NODE_CANISTER_WASM_PATH={}",
        archive_path.display()
    );
}
