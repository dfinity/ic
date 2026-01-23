use candid::Encode;
use ic_base_types::{CanisterId, PrincipalId};
use ic_icp_index::{InitArg, UpgradeArg};
use ic_ledger_canister_core::archive::ArchiveOptions;
use ic_ledger_core::Tokens;
use ic_ledger_suite_state_machine_tests::index::{
    self, IndexTestConfig, arb_account, icp_index_get_num_blocks_synced, icp_ledger_get_chain_length,
};
use ic_state_machine_tests::StateMachine;
use icp_ledger::{AccountIdentifier, FeatureFlags, LedgerCanisterInitPayload};
use icrc_ledger_types::icrc1::account::Account;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

/// Corresponds to ic_icp_index::DEFAULT_RETRIEVE_BLOCKS_FROM_LEDGER_INTERVAL
const DEFAULT_RETRIEVE_BLOCKS_FROM_LEDGER_INTERVAL_SECS: u64 = 1;
const GENESIS_NANOS: u64 = 1_620_328_630_000_000_000;
const INDEX_SYNC_TIME_TO_ADVANCE: Duration = Duration::from_secs(60);
const MAX_ATTEMPTS_FOR_INDEX_SYNC_WAIT: u8 = 100;

const FEE: u64 = 10_000;
const ARCHIVE_TRIGGER_THRESHOLD: u64 = 10;
const NUM_BLOCKS_TO_ARCHIVE: usize = 5;

const MINTER_PRINCIPAL: PrincipalId = PrincipalId::new(0, [0u8; 29]);

fn index_wasm() -> Vec<u8> {
    ic_test_utilities_load_wasm::load_wasm(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "ic-icp-index",
        &[],
    )
}

fn ledger_wasm() -> Vec<u8> {
    ic_test_utilities_load_wasm::load_wasm(
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .parent()
            .unwrap()
            .join("ledger"),
        "ledger-canister",
        &[],
    )
}

fn default_archive_options() -> ArchiveOptions {
    ArchiveOptions {
        trigger_threshold: ARCHIVE_TRIGGER_THRESHOLD as usize,
        num_blocks_to_archive: NUM_BLOCKS_TO_ARCHIVE,
        node_max_memory_size_bytes: None,
        max_message_size_bytes: None,
        controller_id: PrincipalId::new_user_test_id(100),
        more_controller_ids: None,
        cycles_for_archive_creation: None,
        max_transactions_per_response: None,
    }
}

fn config() -> IndexTestConfig {
    IndexTestConfig {
        genesis_nanos: GENESIS_NANOS,
        default_interval_secs: DEFAULT_RETRIEVE_BLOCKS_FROM_LEDGER_INTERVAL_SECS,
        index_sync_time_to_advance: INDEX_SYNC_TIME_TO_ADVANCE,
        max_attempts_for_index_sync_wait: MAX_ATTEMPTS_FOR_INDEX_SYNC_WAIT,
    }
}

fn encode_init_args(ledger_id: CanisterId, _interval: Option<u64>) -> InitArg {
    // Note: ICP InitArg doesn't support interval in init, only via upgrade
    InitArg {
        ledger_id: ledger_id.into(),
    }
}

fn encode_upgrade_args(interval: Option<u64>) -> Option<UpgradeArg> {
    Some(UpgradeArg {
        retrieve_blocks_from_ledger_interval_seconds: interval,
    })
}

fn install_ledger_for_test(
    env: &StateMachine,
    _ledger_wasm: Vec<u8>,
    initial_balances: Vec<(Account, u64)>,
) -> CanisterId {
    let mut initial_values = HashMap::new();
    for (account, amount) in initial_balances {
        initial_values.insert(AccountIdentifier::from(account), Tokens::from_e8s(amount));
    }
    let init_args = LedgerCanisterInitPayload::builder()
        .minting_account(AccountIdentifier::new(MINTER_PRINCIPAL, None))
        .initial_values(initial_values)
        .archive_options(default_archive_options())
        .transfer_fee(Tokens::from_e8s(FEE))
        .token_symbol_and_name("ICP", "Internet Computer")
        .feature_flags(FeatureFlags { icrc2: true })
        .build()
        .unwrap();
    env.install_canister(ledger_wasm(), Encode!(&init_args).unwrap(), None)
        .unwrap()
}

#[test]
fn should_fail_to_install_and_upgrade_with_invalid_value() {
    index::test_should_fail_to_install_and_upgrade_with_invalid_value(
        &config(),
        ledger_wasm(),
        index_wasm(),
        encode_init_args,
        encode_upgrade_args,
        install_ledger_for_test,
        icp_index_get_num_blocks_synced,
        icp_ledger_get_chain_length,
    );
}

#[test]
fn should_install_and_upgrade_with_valid_values() {
    index::test_should_install_and_upgrade_with_valid_values(
        &config(),
        ledger_wasm(),
        index_wasm(),
        encode_init_args,
        encode_upgrade_args,
        install_ledger_for_test,
        icp_index_get_num_blocks_synced,
        icp_ledger_get_chain_length,
    );
}

#[test]
fn should_sync_according_to_interval() {
    index::test_should_sync_according_to_interval(
        &config(),
        ledger_wasm(),
        index_wasm(),
        encode_init_args,
        encode_upgrade_args,
        install_ledger_for_test,
        icp_index_get_num_blocks_synced,
        arb_account(),
    );
}
