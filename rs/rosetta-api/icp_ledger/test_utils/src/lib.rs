use canister_test::{Project, Wasm};

/// Build Wasm for ICP Ledger Archive canister
pub fn build_ledger_archive_wasm() -> Wasm {
    let features = [];
    Project::cargo_bin_maybe_from_env("ledger-archive-node-canister", &features)
}
