use candid::{Nat, Principal};
use ic_ledger_suite_orchestrator::candid::{
    AddErc20Arg, Erc20Contract, InitArg, InstalledCanister, InstalledLedgerSuite, LedgerInitArg,
};
use ic_ledger_suite_orchestrator::state::{ArchiveWasm, IndexWasm, LedgerWasm, Wasm};
pub use icrc_ledger_types::icrc::generic_metadata_value::MetadataValue as LedgerMetadataValue;
pub use icrc_ledger_types::icrc::metadata_key::MetadataKey as LedgerMetadataKey;
pub use icrc_ledger_types::icrc1::account::Account as LedgerAccount;

pub mod pocket_ic;

const MAX_TICKS: usize = 10;
const GIT_COMMIT_HASH: &str = "6a8e5fca2c6b4e12966638c444e994e204b42989";
pub const GIT_COMMIT_HASH_UPGRADE: &str = "b7fef0f57ca246b18deda3efd34a24bb605c8199";
pub const CKERC20_TRANSFER_FEE: u64 = 4_000; //0.004 USD for ckUSDC/ckUSDT
pub const DECIMALS: u8 = 6;

pub const NNS_ROOT_PRINCIPAL: Principal = Principal::from_slice(&[0_u8]);
pub const MINTER_PRINCIPAL: Principal =
    Principal::from_slice(&[0_u8, 0, 0, 0, 2, 48, 0, 156, 1, 1]);

pub fn default_init_arg() -> InitArg {
    InitArg {
        more_controller_ids: vec![NNS_ROOT_PRINCIPAL],
        minter_id: Some(MINTER_PRINCIPAL),
        cycles_management: None,
    }
}

pub fn ledger_suite_orchestrator_wasm() -> Vec<u8> {
    let wasm_path = std::env::var("LEDGER_SUITE_ORCHESTRATOR_WASM_PATH").unwrap();
    std::fs::read(wasm_path).unwrap()
}

pub fn ledger_suite_orchestrator_get_blocks_disabled_wasm() -> Vec<u8> {
    let wasm_path =
        std::env::var("LEDGER_SUITE_ORCHESTRATOR_GET_BLOCKS_DISABLED_WASM_PATH").unwrap();
    std::fs::read(wasm_path).unwrap()
}

pub fn ledger_wasm() -> LedgerWasm {
    let wasm_path = std::env::var("LEDGER_CANISTER_WASM_PATH").unwrap();
    let wasm = std::fs::read(wasm_path).unwrap();
    LedgerWasm::from(wasm)
}

fn ledger_get_blocks_disabled_wasm() -> LedgerWasm {
    let wasm_path = std::env::var("LEDGER_CANISTER_GET_BLOCKS_DISABLED_WASM_PATH").unwrap();
    let wasm = std::fs::read(wasm_path).unwrap();
    LedgerWasm::from(wasm)
}

pub fn index_wasm() -> IndexWasm {
    let wasm_path = std::env::var("INDEX_CANISTER_WASM_PATH").unwrap();
    let wasm = std::fs::read(wasm_path).unwrap();
    IndexWasm::from(wasm)
}

fn archive_wasm() -> ArchiveWasm {
    let wasm_path = std::env::var("LEDGER_ARCHIVE_NODE_CANISTER_WASM_PATH").unwrap();
    let wasm = std::fs::read(wasm_path).unwrap();
    ArchiveWasm::from(wasm)
}

fn is_gzipped_blob(blob: &[u8]) -> bool {
    (blob.len() > 4)
        // Has magic bytes.
        && (blob[0..2] == [0x1F, 0x8B])
}

fn modify_wasm<T>(wasm: Wasm<T>) -> Wasm<T> {
    let wasm_bytes = wasm.to_bytes();
    // wasm_bytes are gzipped and the subslice [4..8]
    // is the little endian representation of a timestamp
    // so we just flip a bit in the timestamp
    assert!(is_gzipped_blob(&wasm_bytes));
    let mut new_wasm_bytes = wasm_bytes.clone();
    *new_wasm_bytes.get_mut(7).expect("cannot be empty") ^= 1;
    assert_ne!(wasm_bytes, new_wasm_bytes);
    Wasm::from(new_wasm_bytes)
}

pub fn tweak_ledger_suite_wasms() -> (LedgerWasm, IndexWasm, ArchiveWasm) {
    (
        LedgerWasm::from(modify_wasm(ledger_wasm())),
        IndexWasm::from(modify_wasm(index_wasm())),
        ArchiveWasm::from(modify_wasm(archive_wasm())),
    )
}

pub fn supported_erc20_tokens() -> Vec<AddErc20Arg> {
    vec![usdc(), usdt()]
}

pub fn usdc() -> AddErc20Arg {
    AddErc20Arg {
        contract: usdc_erc20_contract(),
        ledger_init_arg: ledger_init_arg("Chain-Key USD Coin", "ckUSDC"),
    }
}

pub fn usdc_erc20_contract() -> Erc20Contract {
    Erc20Contract {
        chain_id: Nat::from(1_u8),
        address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
    }
}

pub fn usdt() -> AddErc20Arg {
    AddErc20Arg {
        contract: usdt_erc20_contract(),
        ledger_init_arg: ledger_init_arg("Chain-Key Tether USD", "ckUSDT"),
    }
}

pub fn usdt_erc20_contract() -> Erc20Contract {
    Erc20Contract {
        chain_id: Nat::from(1_u8),
        address: "0xdAC17F958D2ee523a2206206994597C13D831ec7".to_string(),
    }
}

pub fn cketh_installed_canisters() -> InstalledLedgerSuite {
    InstalledLedgerSuite {
        token_symbol: "ckETH".to_string(),
        ledger: InstalledCanister {
            canister_id: "ss2fx-dyaaa-aaaar-qacoq-cai".parse().unwrap(),
            installed_wasm_hash: "8457289d3b3179aa83977ea21bfa2fc85e402e1f64101ecb56a4b963ed33a1e6"
                .to_string(),
        },
        index: InstalledCanister {
            canister_id: "s3zol-vqaaa-aaaar-qacpa-cai".parse().unwrap(),
            installed_wasm_hash: "eb3096906bf9a43996d2ca9ca9bfec333a402612f132876c8ed1b01b9844112a"
                .to_string(),
        },
        archives: Some(vec!["xob7s-iqaaa-aaaar-qacra-cai".parse().unwrap()]),
    }
}

fn ledger_init_arg<U: Into<String>, V: Into<String>>(
    token_name: U,
    token_symbol: V,
) -> LedgerInitArg {
    LedgerInitArg {
        transfer_fee: CKERC20_TRANSFER_FEE.into(),
        decimals: DECIMALS,
        token_name: token_name.into(),
        token_symbol: token_symbol.into(),
        token_logo: "".to_string(),
    }
}
