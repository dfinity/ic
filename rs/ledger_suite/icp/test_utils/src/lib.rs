use canister_test::{Project, Wasm};

pub mod pocket_ic_helpers;
pub mod state_machine_helpers;

/// Build Wasm for NNS Ledger canister
pub fn build_ledger_wasm() -> Wasm {
    let features = ["notify-method"];
    Project::cargo_bin_maybe_from_env("ledger-canister", &features)
}

/// Build Wasm for ICP Ledger Archive canister
pub fn build_ledger_archive_wasm() -> Wasm {
    let features = [];
    Project::cargo_bin_maybe_from_env("ledger-archive-node-canister", &features)
}

/// Build Wasm for NNS Ledger Index canister
pub fn build_ledger_index_wasm() -> Wasm {
    let features = [];
    Project::cargo_bin_maybe_from_env("ic-icp-index-canister", &features)
}

/// Build mainnet Wasm for NNS Ledger Canister
pub fn build_mainnet_ledger_wasm() -> Wasm {
    Project::cargo_bin_maybe_from_env("mainnet-icp-ledger-canister", &[])
}

/// Build mainnet Wasm for NNS Ledger Archive Canister
pub fn build_mainnet_ledger_archive_wasm() -> Wasm {
    Project::cargo_bin_maybe_from_env("mainnet-icp-ledger-archive-node-canister", &[])
}

/// Build mainnet Wasm for NNS Ledger Index Canister
pub fn build_mainnet_ledger_index_wasm() -> Wasm {
    Project::cargo_bin_maybe_from_env("mainnet-icp-index-canister", &[])
}
