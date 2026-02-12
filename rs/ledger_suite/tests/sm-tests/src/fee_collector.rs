use super::*;
use crate::{
    ChangeFeeCollector, FEE, InitArgs, LedgerArgument, MINTER, UpgradeArgs, arb_account,
    install_ledger, total_supply, transfer,
};
use candid::{CandidType, Encode};
use ic_icrc1_ledger::GetFeeCollectorError;
use ic_state_machine_tests::StateMachine;
use proptest::prelude::Strategy;
use proptest::test_runner::TestRunner;
use std::collections::HashSet;

pub fn test_fee_collector<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    let env = StateMachine::new();
    // By default the fee collector is not set.
    let ledger_id = install_ledger(&env, ledger_wasm.clone(), encode_init_args, vec![]);
    // Only 1 test case because we modify the ledger within the test.
    let mut runner = TestRunner::new(TestRunnerConfig::with_cases(1));
    runner
        .run(
            &(
                arb_account(),
                arb_account(),
                arb_account(),
                1..10_000_000u64,
            )
                .prop_filter("The three accounts must be different", |(a1, a2, a3, _)| {
                    HashSet::from([a1, a2, a3]).len() == 3
                }),
            |(account_from, account_to, fee_collector, amount)| {
                // Test 1: with no fee collector the fee should be burned.

                // Mint some tokens for a user.
                transfer(&env, ledger_id, MINTER, account_from, 3 * (amount + FEE))
                    .expect("Unable to mint tokens");

                // Record the previous total_supply and make the transfer.
                let total_supply_before = total_supply(&env, ledger_id);
                transfer(&env, ledger_id, account_from, account_to, amount)
                    .expect("Unable to perform transfer");

                // If the fee was burned then the total_supply after the
                // transfer should be the one before plus the (burned) FEE.
                assert_eq!(
                    total_supply_before,
                    total_supply(&env, ledger_id) + FEE,
                    "Total supply should have been decreased of the (burned) fee {FEE}"
                );

                // Test 2: upgrade the ledger to have a fee collector.
                //         The fee should be collected by the fee collector.

                // Set the fee collector.
                let ledger_upgrade_arg = LedgerArgument::Upgrade(Some(UpgradeArgs {
                    change_fee_collector: Some(ChangeFeeCollector::SetTo(fee_collector)),
                    ..UpgradeArgs::default()
                }));
                env.upgrade_canister(
                    ledger_id,
                    ledger_wasm.clone(),
                    Encode!(&ledger_upgrade_arg).unwrap(),
                )
                .unwrap();

                // Record the previous total_supply and make the transfer.
                let total_supply_before = total_supply(&env, ledger_id);
                transfer(&env, ledger_id, account_from, account_to, amount)
                    .expect("Unable to perform transfer");

                // If the fee was burned then the total_supply after the
                // transfer should be the one before (nothing burned).
                assert_eq!(
                    total_supply_before,
                    total_supply(&env, ledger_id),
                    "Total supply shouldn't have changed"
                );

                // The fee collector must have collected the fee.
                assert_eq!(
                    FEE,
                    balance_of(&env, ledger_id, fee_collector),
                    "The fee_collector should have collected the fee"
                );

                // Test 3: upgrade the ledger to not have a fee collector.
                //         The fee should once again be burned.

                // Unset the fee collector.
                let ledger_upgrade_arg = LedgerArgument::Upgrade(Some(UpgradeArgs {
                    change_fee_collector: Some(ChangeFeeCollector::Unset),
                    ..UpgradeArgs::default()
                }));
                env.upgrade_canister(
                    ledger_id,
                    ledger_wasm.clone(),
                    Encode!(&ledger_upgrade_arg).unwrap(),
                )
                .unwrap();

                // Record the previous total_supply and make the transfer.
                let total_supply_before = total_supply(&env, ledger_id);
                transfer(&env, ledger_id, account_from, account_to, amount)
                    .expect("Unable to perform transfer");

                // If the fee was burned then the total_supply after the
                // transfer should be the one before plus the (burned) FEE.
                assert_eq!(
                    total_supply_before,
                    total_supply(&env, ledger_id) + FEE,
                    "Total supply should have been decreased of the (burned) fee {FEE}"
                );

                // The fee collector must have collected no fee this time.
                assert_eq!(
                    FEE,
                    balance_of(&env, ledger_id, fee_collector),
                    "The fee_collector should have collected the fee"
                );

                Ok(())
            },
        )
        .unwrap();
}

pub fn test_fee_collector_107_access_denied<T>(
    ledger_wasm: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
) where
    T: CandidType,
{
    let (env, canister_id) = setup(ledger_wasm, encode_init_args, vec![]);

    let fee_collector = Account::from(PrincipalId::new_user_test_id(1).0);
    let non_controller = Account::from(PrincipalId::new_user_test_id(2).0);
    let result = set_fc_107(
        &env,
        canister_id,
        non_controller.owner.into(),
        Some(fee_collector),
    );

    let err = result.unwrap_err();
    assert_eq!(err, SetFeeCollectorError::AccessDenied("The `icrc107_set_fee_collector` endpoint can only be called by the canister controller".to_string()));
}

pub fn test_fee_collector_107_minting_account<T>(
    ledger_wasm: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
) where
    T: CandidType,
{
    let (env, canister_id) = setup(ledger_wasm.clone(), encode_init_args, vec![]);

    // Setting fee collector to minter with endpoint should fail
    let controllers = env
        .get_controllers(canister_id)
        .expect("ledger should have a controller");
    assert_eq!(controllers.len(), 1);
    let controller = controllers[0];
    let err = set_fc_107(&env, canister_id, controller, Some(MINTER)).unwrap_err();
    assert_eq!(
        err,
        SetFeeCollectorError::InvalidAccount(
            "The fee collector cannot be set to minting account".to_string()
        )
    );

    // Setting fee collector to minter during upgrade should fail
    let upgrade_args = LedgerArgument::Upgrade(Some(UpgradeArgs {
        change_fee_collector: Some(ChangeFeeCollector::SetTo(MINTER)),
        ..UpgradeArgs::default()
    }));
    let error = env
        .upgrade_canister(
            canister_id,
            ledger_wasm.clone(),
            Encode!(&upgrade_args).unwrap(),
        )
        .expect_err("upgrade should fail");
    assert!(
        error.description().contains(
            "The fee collector account cannot be the same account as the minting account"
        )
    );

    // Setting fee collector to minter during install should fail
    let args = encode_init_args(InitArgs {
        fee_collector_account: Some(MINTER),
        ..init_args(vec![])
    });
    let args = Encode!(&args).unwrap();
    let error = env
        .install_canister(ledger_wasm, args, None)
        .expect_err("install should fail");
    assert!(
        error
            .description()
            .contains("The fee collector account cannot be the same as the minting account")
    );
}

pub fn test_fee_collector_107_anonymous<T>(
    ledger_wasm: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
) where
    T: CandidType,
{
    let (env, canister_id) = setup(ledger_wasm, encode_init_args, vec![]);

    let fee_collector = Account {
        owner: Principal::anonymous(),
        subaccount: Some([1; 32]),
    };

    let controllers = env
        .get_controllers(canister_id)
        .expect("ledger should have a controller");
    assert_eq!(controllers.len(), 1);
    let controller = controllers[0];
    let result = set_fc_107(&env, canister_id, controller, Some(fee_collector));

    let err = result.unwrap_err();
    assert_eq!(
        err,
        SetFeeCollectorError::InvalidAccount(
            "The fee collector cannot be set to an anonymous account".to_string()
        )
    );
}

fn get_fc_107_from_ledger(env: &StateMachine, canister_id: CanisterId) -> Option<Account> {
    Decode!(
        &env.query(canister_id, "icrc107_get_fee_collector", Encode!().unwrap())
            .expect("failed to query 107 fee collector")
            .bytes(),
        Result<Option<Account>, GetFeeCollectorError>
    )
    .expect("failed to decode icrc107_get_fee_collector response")
    .expect("icrc107_get_fee_collector should not fail")
}

fn send_tx_and_verify_fee_collection(
    env: &StateMachine,
    canister_id: CanisterId,
    active_fc: Option<Account>,
    inactive_fcs: Vec<Account>,
    legacy_fc: bool,
) {
    if !legacy_fc {
        assert_eq!(get_fc_107_from_ledger(env, canister_id), active_fc);
    }

    let from = Account::from(PrincipalId::new_user_test_id(1001).0);
    let spender = Account::from(PrincipalId::new_user_test_id(1002).0);
    let to = Account::from(PrincipalId::new_user_test_id(1003).0);
    let from_balance = balance_of(env, canister_id, from);

    let active_fc_balance = if let Some(fc) = active_fc {
        assert_ne!(from, fc);
        assert_ne!(spender, fc);
        assert_ne!(to, fc);
        Some(balance_of(env, canister_id, fc))
    } else {
        None
    };
    let mut inactive_fcs_balances = vec![];
    for fc in &inactive_fcs {
        inactive_fcs_balances.push(balance_of(env, canister_id, *fc));
        assert_ne!(from, *fc);
        assert_ne!(spender, *fc);
        assert_ne!(to, *fc);
    }
    let tot_supply = total_supply(env, canister_id);

    const NUM_FEE_DEDUCTED: u64 = 3;
    let num_fee_collected = if legacy_fc { 2u64 } else { 3u64 };
    const MINT_AMOUNT: u64 = 1_000_000;
    const BURN_AMOUNT: u64 = 12_000;

    transfer(env, canister_id, MINTER, from, MINT_AMOUNT).expect("failed to mint funds");
    transfer(env, canister_id, from, to, 1).expect("failed to transfer funds");
    let approve_args = default_approve_args(spender.owner, u64::MAX);
    send_approval(env, canister_id, from.owner, &approve_args).expect("approval failed");
    let transfer_from_args = default_transfer_from_args(from.owner, to.owner, 1);
    send_transfer_from(env, canister_id, spender.owner, &transfer_from_args)
        .expect("transfer from failed");
    transfer(env, canister_id, from, MINTER, BURN_AMOUNT).expect("failed to burn funds");

    assert_eq!(
        balance_of(env, canister_id, from),
        from_balance + MINT_AMOUNT - BURN_AMOUNT - 2 - NUM_FEE_DEDUCTED * FEE
    );
    if let Some(active_fc) = active_fc {
        assert_eq!(
            balance_of(env, canister_id, active_fc),
            active_fc_balance.unwrap() + num_fee_collected * FEE
        );
        assert_eq!(
            total_supply(env, canister_id),
            tot_supply + MINT_AMOUNT - BURN_AMOUNT - NUM_FEE_DEDUCTED * FEE
                + num_fee_collected * FEE
        );
    } else {
        assert_eq!(
            total_supply(env, canister_id),
            tot_supply + MINT_AMOUNT - BURN_AMOUNT - NUM_FEE_DEDUCTED * FEE
        );
    }

    for (fc, balance) in inactive_fcs.iter().zip(inactive_fcs_balances.iter()) {
        assert_eq!(balance_of(env, canister_id, *fc), *balance);
    }
}

pub fn test_fee_collector_107_smoke<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    let (env, canister_id) = setup(ledger_wasm, encode_init_args, vec![]);

    let fee_collector_1 = Account::from(PrincipalId::new_user_test_id(1).0);
    let fee_collector_2 = Account::from(PrincipalId::new_user_test_id(2).0);

    send_tx_and_verify_fee_collection(
        &env,
        canister_id,
        None,
        vec![fee_collector_1, fee_collector_2],
        false,
    );

    set_fc_107_by_controller(&env, canister_id, Some(fee_collector_1));

    send_tx_and_verify_fee_collection(
        &env,
        canister_id,
        Some(fee_collector_1),
        vec![fee_collector_2],
        false,
    );

    set_fc_107_by_controller(&env, canister_id, Some(fee_collector_2));

    send_tx_and_verify_fee_collection(
        &env,
        canister_id,
        Some(fee_collector_2),
        vec![fee_collector_1],
        false,
    );

    set_fc_107_by_controller(&env, canister_id, None);

    send_tx_and_verify_fee_collection(
        &env,
        canister_id,
        None,
        vec![fee_collector_1, fee_collector_2],
        false,
    );
}

pub fn test_fee_collector_107_with_proptest<Tokens>(
    ledger_wasm_current: Vec<u8>,
    init_args: Vec<u8>,
    minter: Arc<BasicIdentity>,
) where
    Tokens: TokensType + Default + std::fmt::Display + From<u64>,
{
    let mut runner = TestRunner::new(TestRunnerConfig::with_cases(1));
    let now = SystemTime::now();
    let minter_principal: Principal = minter.sender().unwrap();
    const TX_COUNT: usize = 150;
    runner
        .run(
            &(
                valid_transactions_strategy(minter, FEE, TX_COUNT, now).no_shrink(),
                proptest::collection::vec(
                    proptest::option::of(proptest::option::of(arb_account())),
                    TX_COUNT..=TX_COUNT,
                )
                .no_shrink(),
            ),
            |(transactions, fee_collectors)| {
                let env = StateMachine::new();
                env.set_time(now);
                let ledger_id = env
                    .install_canister(ledger_wasm_current.clone(), init_args.clone(), None)
                    .unwrap();

                let mut in_memory_ledger = InMemoryLedger::<Account, Tokens>::default();

                let mut total_blocks = 0u64;
                for tx_index in 0..TX_COUNT {
                    total_blocks += 1;
                    if let Some(fee_collector) = fee_collectors[tx_index] {
                        total_blocks += 1;
                        in_memory_ledger.set_fee_collector_107(
                            TimeStamp::from_nanos_since_unix_epoch(system_time_to_nanos(
                                env.time(),
                            )),
                            &fee_collector,
                        );
                        set_fc_107_by_controller(&env, ledger_id, fee_collector);
                    }
                    in_memory_ledger.apply_arg_with_caller(
                        &transactions[tx_index],
                        TimeStamp::from_nanos_since_unix_epoch(system_time_to_nanos(env.time())),
                        minter_principal,
                        Some(FEE.into()),
                    );
                    apply_arg_with_caller(&env, ledger_id, &transactions[tx_index]);
                }
                in_memory_ledger.verify_balances_and_allowances(
                    &env,
                    ledger_id,
                    total_blocks,
                    AllowancesRecentlyPurged::Yes,
                );

                verify_ledger_state::<Tokens>(&env, ledger_id, None, AllowancesRecentlyPurged::Yes);

                Ok(())
            },
        )
        .unwrap();
}

pub fn test_fee_collector_107_upgrade<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    let (env, canister_id) = setup(ledger_wasm.clone(), encode_init_args, vec![]);

    let fee_collector_1 = Account::from(PrincipalId::new_user_test_id(1).0);

    send_tx_and_verify_fee_collection(&env, canister_id, None, vec![fee_collector_1], false);

    let upgrade_args = LedgerArgument::Upgrade(Some(UpgradeArgs::default()));
    env.upgrade_canister(
        canister_id,
        ledger_wasm.clone(),
        Encode!(&upgrade_args).unwrap(),
    )
    .expect("failed to upgrade the ledger");

    send_tx_and_verify_fee_collection(&env, canister_id, None, vec![fee_collector_1], false);

    let upgrade_args = LedgerArgument::Upgrade(Some(UpgradeArgs {
        change_fee_collector: Some(ChangeFeeCollector::SetTo(fee_collector_1)),
        ..UpgradeArgs::default()
    }));
    env.upgrade_canister(
        canister_id,
        ledger_wasm.clone(),
        Encode!(&upgrade_args).unwrap(),
    )
    .expect("failed to upgrade the ledger");

    send_tx_and_verify_fee_collection(&env, canister_id, Some(fee_collector_1), vec![], false);

    let upgrade_args = LedgerArgument::Upgrade(Some(UpgradeArgs::default()));
    env.upgrade_canister(
        canister_id,
        ledger_wasm.clone(),
        Encode!(&upgrade_args).unwrap(),
    )
    .expect("failed to upgrade the ledger");

    send_tx_and_verify_fee_collection(&env, canister_id, Some(fee_collector_1), vec![], false);

    let upgrade_args = LedgerArgument::Upgrade(Some(UpgradeArgs {
        change_fee_collector: Some(ChangeFeeCollector::Unset),
        ..UpgradeArgs::default()
    }));
    env.upgrade_canister(canister_id, ledger_wasm, Encode!(&upgrade_args).unwrap())
        .expect("failed to upgrade the ledger");

    send_tx_and_verify_fee_collection(&env, canister_id, None, vec![fee_collector_1], false);
}

pub fn test_fee_collector_107_init<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    let fee_collector = Account::from(PrincipalId::new_user_test_id(1).0);

    for fee_collector_account in [None, Some(fee_collector)] {
        let env = StateMachine::new();

        let args = encode_init_args(InitArgs {
            fee_collector_account,
            ..init_args(vec![])
        });
        let args = Encode!(&args).unwrap();
        let canister_id = env
            .install_canister(ledger_wasm.clone(), args, None)
            .unwrap();

        send_tx_and_verify_fee_collection(&env, canister_id, fee_collector_account, vec![], false);
    }
}

pub fn test_fee_collector_107_upgrade_legacy<T, Tokens>(
    ledger_wasm_legacy_fc: Vec<u8>,
    ledger_wasm: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
) where
    T: CandidType,
    Tokens: TokensType + Default + std::fmt::Display,
{
    let fee_col_legacy = Account::from(PrincipalId::new_user_test_id(1).0);
    let fee_col_107 = Account::from(PrincipalId::new_user_test_id(2).0);

    let init_params = [None, Some(fee_col_legacy)];
    let upgrade_params = [
        None,
        Some(ChangeFeeCollector::Unset),
        Some(ChangeFeeCollector::SetTo(fee_col_107)),
    ];

    for init_fee_collector in init_params {
        for upgrade_fee_collector in &upgrade_params {
            let env = StateMachine::new();
            let args = encode_init_args(InitArgs {
                fee_collector_account: init_fee_collector,
                ..init_args(vec![])
            });
            let args = Encode!(&args).unwrap();
            let canister_id = env
                .install_canister(ledger_wasm_legacy_fc.clone(), args, None)
                .unwrap();

            send_tx_and_verify_fee_collection(&env, canister_id, init_fee_collector, vec![], true);

            let upgrade_args = LedgerArgument::Upgrade(Some(UpgradeArgs {
                change_fee_collector: upgrade_fee_collector.clone(),
                ..UpgradeArgs::default()
            }));
            env.upgrade_canister(
                canister_id,
                ledger_wasm.clone(),
                Encode!(&upgrade_args).unwrap(),
            )
            .expect("failed to upgrade the ledger");

            let active_fc = match upgrade_fee_collector {
                Some(ChangeFeeCollector::SetTo(fee_collector)) => Some(*fee_collector),
                Some(ChangeFeeCollector::Unset) => None,
                None => init_fee_collector,
            };
            let mut inactive_fcs = vec![];
            if active_fc != Some(fee_col_legacy) {
                inactive_fcs.push(fee_col_legacy);
            }
            if active_fc != Some(fee_col_107) {
                inactive_fcs.push(fee_col_107);
            }

            send_tx_and_verify_fee_collection(&env, canister_id, active_fc, inactive_fcs, false);

            verify_ledger_state::<Tokens>(&env, canister_id, None, AllowancesRecentlyPurged::Yes);
        }
    }
}
