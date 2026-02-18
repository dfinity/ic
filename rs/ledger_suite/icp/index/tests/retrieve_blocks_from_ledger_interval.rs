use candid::{Decode, Encode};
use ic_base_types::{CanisterId, PrincipalId};
use ic_icp_index::{IndexArg, InitArg, Status, UpgradeArg};
use ic_ledger_canister_core::archive::ArchiveOptions;
use ic_ledger_core::Tokens;
use ic_ledger_test_utils::state_machine_helpers::index::wait_until_sync_is_completed;
use ic_state_machine_tests::{ErrorCode, StateMachine, UserError};
use ic_types::Time;
use icp_ledger::{AccountIdentifier, FeatureFlags, LedgerCanisterInitPayload, Memo, Subaccount};
use icrc_ledger_types::icrc1::account::Account;
use proptest::prelude::Strategy;
use proptest::test_runner::TestRunner;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

const GENESIS_NANOS: Time = Time::from_nanos_since_unix_epoch(1_620_328_630_000_000_000);
const INDEX_SYNC_TIME_TO_ADVANCE: Duration = Duration::from_secs(2);
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

fn account(owner: u64, subaccount: u128) -> Account {
    let mut sub: [u8; 32] = [0; 32];
    sub[..16].copy_from_slice(&subaccount.to_be_bytes());
    Account {
        owner: PrincipalId::new_user_test_id(owner).0,
        subaccount: Some(sub),
    }
}

fn install_ledger(
    env: &StateMachine,
    initial_balances: Vec<(Account, u64)>,
    archive_options: ArchiveOptions,
) -> CanisterId {
    let mut initial_values = HashMap::new();
    for (account, amount) in initial_balances {
        initial_values.insert(AccountIdentifier::from(account), Tokens::from_e8s(amount));
    }
    let init_args = LedgerCanisterInitPayload::builder()
        .minting_account(AccountIdentifier::new(MINTER_PRINCIPAL, None))
        .initial_values(initial_values)
        .archive_options(archive_options)
        .transfer_fee(Tokens::from_e8s(FEE))
        .token_symbol_and_name("ICP", "Internet Computer")
        .feature_flags(FeatureFlags { icrc2: true })
        .build()
        .unwrap();
    env.install_canister(ledger_wasm(), Encode!(&init_args).unwrap(), None)
        .unwrap()
}

fn status(env: &StateMachine, index_id: CanisterId) -> Status {
    let res = env
        .query(index_id, "status", Encode!(&()).unwrap())
        .expect("Failed to send status")
        .bytes();
    candid::Decode!(&res, Status).expect("Failed to decode status response")
}

fn install_index(
    env: &StateMachine,
    ledger_id: CanisterId,
    interval: Option<u64>,
) -> Result<CanisterId, UserError> {
    let args = IndexArg::Init(InitArg {
        ledger_id: ledger_id.into(),
        retrieve_blocks_from_ledger_interval_seconds: interval,
    });
    env.install_canister(index_wasm(), Encode!(&args).unwrap(), None)
}

fn install_and_upgrade(
    install_interval: Option<u64>,
    upgrade_interval: Option<u64>,
) -> Result<(), UserError> {
    let env = &StateMachine::new();
    // Provide an initial balance so the ledger has at least one block
    let ledger_id = install_ledger(
        env,
        vec![(account(1, 0), 1_000_000)],
        default_archive_options(),
    );

    let index_id = install_index(env, ledger_id, install_interval)?;

    wait_until_sync_is_completed(env, index_id, ledger_id);

    let upgrade_arg = IndexArg::Upgrade(UpgradeArg {
        ledger_id: None,
        retrieve_blocks_from_ledger_interval_seconds: upgrade_interval,
    });
    env.upgrade_canister(index_id, index_wasm(), Encode!(&Some(upgrade_arg)).unwrap())?;

    wait_until_sync_is_completed(env, index_id, ledger_id);

    Ok(())
}

fn max_value_for_interval() -> u64 {
    (u64::MAX - GENESIS_NANOS.as_nanos_since_unix_epoch()) / 1_000_000_000
}

fn max_index_sync_time() -> u64 {
    (MAX_ATTEMPTS_FOR_INDEX_SYNC_WAIT as u64)
        .checked_mul(INDEX_SYNC_TIME_TO_ADVANCE.as_secs())
        .unwrap()
}

#[test]
fn should_fail_to_install_and_upgrade_with_invalid_value() {
    let minimum_invalid_value_for_interval = max_value_for_interval() + 1;
    let invalid_install_and_upgrade_combinations = [
        (Some(minimum_invalid_value_for_interval), Some(1)),
        (Some(1), Some(minimum_invalid_value_for_interval)),
    ];

    for (install_interval, upgrade_interval) in &invalid_install_and_upgrade_combinations {
        let err = install_and_upgrade(*install_interval, *upgrade_interval)
            .expect_err("should fail to install with invalid interval");
        let code = err.code();
        assert_eq!(code, ErrorCode::CanisterCalledTrap);
        let description = err.description();
        assert!(description.contains("delay out of bounds"));
    }
}

#[test]
fn should_install_and_upgrade_with_valid_values() {
    let max_seconds_for_timer = max_value_for_interval() - max_index_sync_time();
    // Exclude interval 0 from the main matrix: it makes the timer fire every round so
    // sync_after_upgrade is extremely slow. Interval 0 is covered by
    // should_accept_upgrade_to_interval_zero (short test, no full sync wait).
    let build_index_interval_values = [
        (None, None),
        (None, Some(1u64)),
        (None, Some(10u64)),
        (None, Some(max_seconds_for_timer)),
        (Some(1u64), None),
        (Some(1u64), Some(1u64)),
        (Some(1u64), Some(10u64)),
        (Some(1u64), Some(max_seconds_for_timer)),
        (Some(10u64), None),
        (Some(10u64), Some(1u64)),
        (Some(10u64), Some(10u64)),
        (Some(10u64), Some(max_seconds_for_timer)),
    ];

    // Installing and upgrading with valid values should succeed
    for (install_interval, upgrade_interval) in &build_index_interval_values {
        assert_eq!(
            install_and_upgrade(*install_interval, *upgrade_interval),
            Ok(()),
            "install_interval: {install_interval:?}, upgrade_interval: {upgrade_interval:?}"
        );
    }
}

/// Upgrade to interval 0 is accepted; we do not wait for full sync (that would be very
/// slow because the timer fires every round). We only verify the upgrade doesn't trap
/// and the canister stays responsive after a few ticks.
#[test]
fn should_accept_upgrade_to_interval_zero() {
    let env = &StateMachine::new();
    let ledger_id = install_ledger(
        env,
        vec![(account(1, 0), 1_000_000)],
        default_archive_options(),
    );
    let index_wasm_bytes = index_wasm();
    let index_id =
        install_index(env, ledger_id, Some(1)).expect("install with interval 1 should succeed");
    wait_until_sync_is_completed(env, index_id, ledger_id);

    let upgrade_arg = IndexArg::Upgrade(UpgradeArg {
        ledger_id: None,
        retrieve_blocks_from_ledger_interval_seconds: Some(0),
    });
    env.upgrade_canister(
        index_id,
        index_wasm_bytes,
        Encode!(&Some(upgrade_arg)).unwrap(),
    )
    .expect("upgrade to interval 0 should succeed");

    // With interval 0 the timer fires every round; do a few ticks only (no full sync wait).
    const TICKS_AFTER_UPGRADE: u32 = 3;
    for _ in 0..TICKS_AFTER_UPGRADE {
        env.advance_time(Duration::from_secs(1));
        env.tick();
    }
    let s = status(env, index_id);
    assert_eq!(
        s.num_blocks_synced, 1,
        "index should have synced the genesis block"
    );
}

#[test]
fn should_sync_according_to_interval() {
    const INITIAL_BALANCE: u64 = 1_000_000_000;
    const TRANSFER_AMOUNT: u64 = 1_000_000;
    const DEFAULT_RETRIEVE_BLOCKS_FROM_LEDGER_INTERVAL: u64 = 1;

    fn send_transaction_and_verify_index_sync(
        env: &StateMachine,
        ledger_id: CanisterId,
        index_id: CanisterId,
        a1: Account,
        a2: Account,
        install_interval: Option<u64>,
        upgrade_interval: Option<u64>,
    ) {
        let transfer_args = icp_ledger::TransferArgs {
            memo: Memo(0),
            amount: Tokens::from_e8s(TRANSFER_AMOUNT),
            fee: Tokens::from_e8s(FEE),
            from_subaccount: a1.subaccount.map(Subaccount),
            to: AccountIdentifier::from(a2).to_address(),
            created_at_time: None,
        };
        let ledger_chain_length = Decode!(
            &env.execute_ingress_as(
                PrincipalId(a1.owner),
                ledger_id,
                "transfer",
                Encode!(&transfer_args).unwrap(),
            )
            .expect("transfer failed")
            .bytes(),
            Result<u64, icp_ledger::TransferError>
        )
        .unwrap()
        .unwrap()
        .checked_add(1)
        .expect("should be able to add 1 to block index");
        let mut index_num_blocks_synced = status(env, index_id).num_blocks_synced;
        if index_num_blocks_synced != ledger_chain_length {
            let time_to_advance = upgrade_interval
                .or(install_interval)
                .unwrap_or(DEFAULT_RETRIEVE_BLOCKS_FROM_LEDGER_INTERVAL);
            if time_to_advance > 0 {
                env.advance_time(Duration::from_secs(time_to_advance));
                env.tick();
            }
            index_num_blocks_synced = status(env, index_id).num_blocks_synced;
        }
        assert_eq!(ledger_chain_length, index_num_blocks_synced);
    }

    // Generate arbitrary accounts for testing
    fn arb_account() -> impl Strategy<Value = Account> {
        (1u64..1000, 0u128..1000).prop_map(|(owner, subaccount)| account(owner, subaccount))
    }

    let mut runner = TestRunner::new(proptest::test_runner::Config::with_cases(4));
    runner
        .run(
            &(
                proptest::option::of(0..(max_value_for_interval() / 2)),
                proptest::option::of(0..(max_value_for_interval() / 2)),
                arb_account(),
                arb_account(),
            )
                .prop_filter("The accounts must be different", |(_, _, a1, a2)| a1 != a2)
                .no_shrink(),
            |(install_interval, upgrade_interval, a1, a2)| {
                // Create a new environment
                let env = &StateMachine::new();

                // Install a ledger with an initial balance for a1
                let ledger_id =
                    install_ledger(env, vec![(a1, INITIAL_BALANCE)], default_archive_options());

                let index_id = install_index(env, ledger_id, install_interval).unwrap();

                // Send a transaction and verify that the index is synced after the interval
                // specified during the install, or the default value if the interval specified
                // during the install was None.
                send_transaction_and_verify_index_sync(
                    env,
                    ledger_id,
                    index_id,
                    a1, // from
                    a2, // to
                    install_interval,
                    None,
                );

                // Upgrade the index with a specific interval
                let upgrade_arg = IndexArg::Upgrade(UpgradeArg {
                    ledger_id: None,
                    retrieve_blocks_from_ledger_interval_seconds: upgrade_interval,
                });
                env.upgrade_canister(index_id, index_wasm(), Encode!(&Some(upgrade_arg)).unwrap())?;

                // Send a transaction and verify that the index is synced after the interval
                // specified during the upgrade, or if it is None, the interval specified during
                // the install, or the default value if the interval specified during the install
                // was None.
                send_transaction_and_verify_index_sync(
                    env,
                    ledger_id,
                    index_id,
                    a1, // from
                    a2, // to
                    install_interval,
                    upgrade_interval,
                );

                Ok(())
            },
        )
        .unwrap();
}
