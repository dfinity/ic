use super::*;
use crate::{
    ChangeFeeCollector, FEE, InitArgs, LedgerArgument, MINTER, UpgradeArgs, arb_account,
    install_ledger, total_supply, transfer,
};
use candid::{CandidType, Encode};
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
