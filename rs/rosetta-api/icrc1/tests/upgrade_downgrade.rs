use crate::common::{ledger_wasm, load_wasm_using_env_var};
use candid::{Encode, Principal};
use ic_base_types::{CanisterId, PrincipalId};
use ic_icrc1_index_ng::{IndexArg, InitArg as IndexInitArg, UpgradeArg as IndexUpgradeArg};
use ic_icrc1_ledger::{FeatureFlags, InitArgsBuilder, LedgerArgument};
use ic_icrc1_ledger_sm_tests::{
    BLOB_META_KEY, BLOB_META_VALUE, FEE, INT_META_KEY, INT_META_VALUE, NAT_META_KEY,
    NAT_META_VALUE, TEXT_META_KEY, TEXT_META_VALUE, TOKEN_NAME, TOKEN_SYMBOL,
};
use ic_ledger_canister_core::archive::ArchiveOptions;
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder};
use icrc_ledger_types::icrc1::account::Account;
use std::time::{Duration, SystemTime};

mod common;

const MINTER_PRINCIPAL: Principal = Principal::from_slice(&[3_u8; 29]);
const STARTING_CYCLES_PER_CANISTER: u128 = 2_000_000_000_000_000;
const ARCHIVE_TRIGGER_THRESHOLD: u64 = 10;
const NUM_BLOCKS_TO_ARCHIVE: usize = 5;
const MAX_BLOCKS_FROM_ARCHIVE: u64 = 10;

#[test]
fn should_upgrade_and_downgrade_ledger_canister_suite() {
    let now = SystemTime::now();
    let env = &StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .with_subnet_size(28)
        .build();
    env.set_time(now);

    let ledger_id = install_ledger(
        env,
        vec![],
        default_archive_options(),
        None,
        MINTER_PRINCIPAL,
    );
    let index_id = install_index_ng(
        env,
        IndexInitArg {
            ledger_id: Principal::from(ledger_id),
            retrieve_blocks_from_ledger_interval_seconds: None,
        },
    );

    env.advance_time(Duration::from_secs(60));
    env.tick();

    let index_upgrade_arg = IndexArg::Upgrade(IndexUpgradeArg {
        ledger_id: None,
        retrieve_blocks_from_ledger_interval_seconds: None,
    });
    env.upgrade_canister(
        index_id,
        index_ng_wasm(),
        Encode!(&index_upgrade_arg).unwrap(),
    )
    .unwrap();

    let ledger_upgrade_arg = LedgerArgument::Upgrade(None);
    env.upgrade_canister(
        ledger_id,
        ledger_wasm(),
        Encode!(&ledger_upgrade_arg).unwrap(),
    )
    .unwrap();

    env.advance_time(Duration::from_secs(60));
    env.tick();

    env.upgrade_canister(
        index_id,
        index_ng_mainnet_wasm(),
        Encode!(&index_upgrade_arg).unwrap(),
    )
    .unwrap();

    env.upgrade_canister(
        ledger_id,
        ledger_mainnet_wasm(),
        Encode!(&ledger_upgrade_arg).unwrap(),
    )
    .unwrap();
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
        max_transactions_per_response: Some(MAX_BLOCKS_FROM_ARCHIVE),
    }
}

fn index_ng_mainnet_wasm() -> Vec<u8> {
    load_wasm_using_env_var("IC_ICRC1_INDEX_NG_DEPLOYED_VERSION_WASM_PATH")
}

fn index_ng_wasm() -> Vec<u8> {
    load_wasm_using_env_var("IC_ICRC1_INDEX_NG_WASM_PATH")
}

fn install_ledger(
    env: &StateMachine,
    initial_balances: Vec<(Account, u64)>,
    archive_options: ArchiveOptions,
    fee_collector_account: Option<Account>,
    minter_principal: Principal,
) -> CanisterId {
    let mut builder = InitArgsBuilder::with_symbol_and_name(TOKEN_SYMBOL, TOKEN_NAME)
        .with_minting_account(minter_principal)
        .with_transfer_fee(FEE)
        .with_metadata_entry(NAT_META_KEY, NAT_META_VALUE)
        .with_metadata_entry(INT_META_KEY, INT_META_VALUE)
        .with_metadata_entry(TEXT_META_KEY, TEXT_META_VALUE)
        .with_metadata_entry(BLOB_META_KEY, BLOB_META_VALUE)
        .with_archive_options(archive_options)
        .with_feature_flags(FeatureFlags { icrc2: true });
    if let Some(fee_collector_account) = fee_collector_account {
        builder = builder.with_fee_collector_account(fee_collector_account);
    }
    for (account, amount) in initial_balances {
        builder = builder.with_initial_balance(account, amount);
    }
    env.install_canister_with_cycles(
        ledger_mainnet_wasm(),
        Encode!(&LedgerArgument::Init(builder.build())).unwrap(),
        None,
        ic_state_machine_tests::Cycles::new(STARTING_CYCLES_PER_CANISTER),
    )
    .unwrap()
}

fn install_index_ng(env: &StateMachine, init_arg: IndexInitArg) -> CanisterId {
    let args = IndexArg::Init(init_arg);
    env.install_canister_with_cycles(
        index_ng_mainnet_wasm(),
        Encode!(&args).unwrap(),
        None,
        ic_state_machine_tests::Cycles::new(STARTING_CYCLES_PER_CANISTER),
    )
    .unwrap()
}

fn ledger_mainnet_wasm() -> Vec<u8> {
    load_wasm_using_env_var("IC_ICRC1_LEDGER_DEPLOYED_VERSION_WASM_PATH")
}
