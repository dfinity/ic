//! Shared tests for index canisters (ICP and ICRC1).
//!
//! This module provides common test functions that can be used by both
//! the ICP index and ICRC1 index-ng test suites. The tests use function
//! pointers to abstract over ledger-specific operations.

use candid::{CandidType, Encode, Nat};
use ic_base_types::{CanisterId, PrincipalId};
use ic_ledger_suite_state_machine_helpers::send_transfer;
use ic_state_machine_tests::{ErrorCode, StateMachine, UserError};
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::TransferArg;
use proptest::prelude::Strategy;
use proptest::test_runner::TestRunner;
use std::time::Duration;

/// Configuration for index interval tests.
pub struct IndexTestConfig {
    /// The genesis time in nanoseconds since Unix epoch.
    pub genesis_nanos: u64,
    /// The default interval in seconds for retrieving blocks from the ledger.
    pub default_interval_secs: u64,
}

impl IndexTestConfig {
    /// Returns the maximum valid value for the interval configuration.
    /// Values larger than this will cause timer overflow.
    pub fn max_value_for_interval(&self) -> u64 {
        (u64::MAX - self.genesis_nanos) / 1_000_000_000
    }
}

/// Test that installation and upgrade fail with invalid interval values.
///
/// This test verifies that:
/// - Installing with an interval value that's too large fails
/// - Upgrading with an interval value that's too large fails
pub fn test_should_fail_to_install_and_upgrade_with_invalid_value<I, U>(
    config: &IndexTestConfig,
    ledger_wasm: Vec<u8>,
    index_wasm: Vec<u8>,
    encode_init_args: fn(CanisterId, Option<u64>) -> I,
    encode_upgrade_args: fn(Option<u64>) -> U,
    install_ledger: fn(&StateMachine, Vec<u8>, Vec<(Account, u64)>) -> CanisterId,
    wait_until_sync_is_completed: fn(&StateMachine, CanisterId, CanisterId),
) where
    I: CandidType,
    U: CandidType,
{
    let minimum_invalid_value_for_interval = config.max_value_for_interval() + 1;
    let invalid_install_and_upgrade_combinations = [
        (Some(minimum_invalid_value_for_interval), Some(1)),
        (Some(1), Some(minimum_invalid_value_for_interval)),
    ];

    for (install_interval, upgrade_interval) in &invalid_install_and_upgrade_combinations {
        let err = install_and_upgrade(
            ledger_wasm.clone(),
            index_wasm.clone(),
            encode_init_args,
            encode_upgrade_args,
            install_ledger,
            wait_until_sync_is_completed,
            *install_interval,
            *upgrade_interval,
        )
        .expect_err("should fail to install with invalid interval");
        let code = err.code();
        assert_eq!(code, ErrorCode::CanisterCalledTrap);
        let description = err.description();
        assert!(
            description.contains("delay out of bounds"),
            "Expected error to contain 'delay out of bounds', got: {}",
            description
        );
    }
}

/// Test that installation and upgrade succeed with valid interval values.
///
/// This test verifies that the index canister can be installed and upgraded
/// with various valid interval values including None, 0, 1, 10, and the maximum.
pub fn test_should_install_and_upgrade_with_valid_values<I, U>(
    config: &IndexTestConfig,
    max_index_sync_time: u64,
    ledger_wasm: Vec<u8>,
    index_wasm: Vec<u8>,
    encode_init_args: fn(CanisterId, Option<u64>) -> I,
    encode_upgrade_args: fn(Option<u64>) -> U,
    install_ledger: fn(&StateMachine, Vec<u8>, Vec<(Account, u64)>) -> CanisterId,
    wait_until_sync_is_completed: fn(&StateMachine, CanisterId, CanisterId),
) where
    I: CandidType,
    U: CandidType,
{
    let max_seconds_for_timer = config.max_value_for_interval() - max_index_sync_time;
    let build_index_interval_values = [
        None,
        Some(0u64),
        Some(1u64),
        Some(10u64),
        Some(max_seconds_for_timer),
    ];

    // Installing and upgrading with valid values should succeed
    for install_interval in &build_index_interval_values {
        for upgrade_interval in &build_index_interval_values {
            assert_eq!(
                install_and_upgrade(
                    ledger_wasm.clone(),
                    index_wasm.clone(),
                    encode_init_args,
                    encode_upgrade_args,
                    install_ledger,
                    wait_until_sync_is_completed,
                    *install_interval,
                    *upgrade_interval,
                ),
                Ok(()),
                "install_interval: {install_interval:?}, upgrade_interval: {upgrade_interval:?}"
            );
        }
    }
}

/// Test that the index syncs according to the configured interval.
///
/// This test uses property-based testing to verify that:
/// - After a transfer, the index syncs within the expected interval
/// - The interval can be changed via upgrade
/// - The new interval takes effect after upgrade
pub fn test_should_sync_according_to_interval<I, U, S>(
    config: &IndexTestConfig,
    ledger_wasm: Vec<u8>,
    index_wasm: Vec<u8>,
    encode_init_args: fn(CanisterId, Option<u64>) -> I,
    encode_upgrade_args: fn(Option<u64>) -> U,
    install_ledger: fn(&StateMachine, Vec<u8>, Vec<(Account, u64)>) -> CanisterId,
    get_num_blocks_synced: fn(&StateMachine, CanisterId) -> u64,
    arb_account: S,
) where
    I: CandidType,
    U: CandidType,
    S: Strategy<Value = Account> + Clone,
{
    const INITIAL_BALANCE: u64 = 1_000_000_000;
    const TRANSFER_AMOUNT: u64 = 1_000_000;

    let mut runner = TestRunner::new(proptest::test_runner::Config::with_cases(4));
    runner
        .run(
            &(
                proptest::option::of(0..(config.max_value_for_interval() / 2)),
                proptest::option::of(0..(config.max_value_for_interval() / 2)),
                arb_account.clone(),
                arb_account,
            )
                .prop_filter("The accounts must be different", |(_, _, a1, a2)| a1 != a2)
                .no_shrink(),
            |(install_interval, upgrade_interval, a1, a2)| {
                // Create a new environment
                let env = &StateMachine::new();

                // Install a ledger with an initial balance for a1
                let ledger_id =
                    install_ledger(env, ledger_wasm.clone(), vec![(a1, INITIAL_BALANCE)]);

                // Install an index with a specific interval
                let init_args = encode_init_args(ledger_id, install_interval);
                let index_id = env
                    .install_canister(index_wasm.clone(), Encode!(&init_args).unwrap(), None)
                    .unwrap();

                // Send a transaction and verify that the index is synced after the interval
                // specified during the install, or the default value if the interval specified
                // during the install was None.
                send_transaction_and_verify_index_sync(
                    env,
                    config,
                    ledger_id,
                    index_id,
                    a1, // from
                    a2, // to
                    TRANSFER_AMOUNT,
                    install_interval,
                    None,
                    get_num_blocks_synced,
                );

                // Upgrade the index with a specific interval
                let upgrade_args = encode_upgrade_args(upgrade_interval);
                env.upgrade_canister(
                    index_id,
                    index_wasm.clone(),
                    Encode!(&upgrade_args).unwrap(),
                )?;

                // Send a transaction and verify that the index is synced after the interval
                // specified during the upgrade, or if it is None, the interval specified during
                // the install, or the default value if the interval specified during the install
                // was None.
                send_transaction_and_verify_index_sync(
                    env,
                    config,
                    ledger_id,
                    index_id,
                    a1, // from
                    a2, // to
                    TRANSFER_AMOUNT,
                    install_interval,
                    upgrade_interval,
                    get_num_blocks_synced,
                );

                Ok(())
            },
        )
        .unwrap();
}

/// Helper function to install and upgrade an index canister with specified intervals.
fn install_and_upgrade<I, U>(
    ledger_wasm: Vec<u8>,
    index_wasm: Vec<u8>,
    encode_init_args: fn(CanisterId, Option<u64>) -> I,
    encode_upgrade_args: fn(Option<u64>) -> U,
    install_ledger: fn(&StateMachine, Vec<u8>, Vec<(Account, u64)>) -> CanisterId,
    wait_until_sync_is_completed: fn(&StateMachine, CanisterId, CanisterId),
    install_interval: Option<u64>,
    upgrade_interval: Option<u64>,
) -> Result<(), UserError>
where
    I: CandidType,
    U: CandidType,
{
    let env = &StateMachine::new();
    let account = Account {
        owner: PrincipalId::new_user_test_id(1).0,
        subaccount: None,
    };

    // Ledger needs at least one block to function properly (for ICP ledger)
    let ledger_id = install_ledger(env, ledger_wasm, vec![(account, 1_000_000_000)]);

    // Install index with init args
    let init_args = encode_init_args(ledger_id, install_interval);
    let index_id = env.install_canister(index_wasm.clone(), Encode!(&init_args).unwrap(), None)?;

    wait_until_sync_is_completed(env, index_id, ledger_id);

    // Upgrade with new interval
    let upgrade_args = encode_upgrade_args(upgrade_interval);
    env.upgrade_canister(index_id, index_wasm, Encode!(&upgrade_args).unwrap())?;

    wait_until_sync_is_completed(env, index_id, ledger_id);

    Ok(())
}

/// Helper function to send a transfer and verify that the index syncs within the expected interval.
fn send_transaction_and_verify_index_sync(
    env: &StateMachine,
    config: &IndexTestConfig,
    ledger_id: CanisterId,
    index_id: CanisterId,
    from: Account,
    to: Account,
    amount: u64,
    install_interval: Option<u64>,
    upgrade_interval: Option<u64>,
    get_num_blocks_synced: fn(&StateMachine, CanisterId) -> u64,
) {
    // Use icrc1_transfer (standard endpoint that works for both ICP and ICRC1 ledgers)
    let ledger_chain_length = send_transfer(
        env,
        ledger_id,
        from.owner,
        &TransferArg {
            from_subaccount: from.subaccount,
            to,
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(amount),
        },
    )
    .expect("send_transfer should succeed")
    .checked_add(1)
    .expect("should be able to add 1 to block index");

    let mut index_num_blocks_synced = get_num_blocks_synced(env, index_id);

    if index_num_blocks_synced != ledger_chain_length {
        let time_to_advance = upgrade_interval
            .or(install_interval)
            .unwrap_or(config.default_interval_secs);
        if time_to_advance > 0 {
            env.advance_time(Duration::from_secs(time_to_advance));
            env.tick();
        }
        index_num_blocks_synced = get_num_blocks_synced(env, index_id);
    }

    assert_eq!(ledger_chain_length, index_num_blocks_synced);
}

/// Helper to create an account for testing.
pub fn account(owner: u64, subaccount: u128) -> Account {
    let mut sub: [u8; 32] = [0; 32];
    sub[..16].copy_from_slice(&subaccount.to_be_bytes());
    Account {
        owner: PrincipalId::new_user_test_id(owner).0,
        subaccount: Some(sub),
    }
}

/// Generate arbitrary accounts for property-based testing.
pub fn arb_account() -> impl Strategy<Value = Account> + Clone {
    (1u64..1000, 0u128..1000).prop_map(|(owner, subaccount)| account(owner, subaccount))
}
