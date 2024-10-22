use super::*;
use crate::{
    arb_account, install_ledger, total_supply, transfer, ChangeFeeCollector, InitArgs,
    LedgerArgument, UpgradeArgs, FEE, MINTER,
};
use candid::{CandidType, Encode};
use ic_state_machine_tests::StateMachine;
use proptest::prelude::Strategy;
use proptest::test_runner::TestRunner;

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
                    a1 != a2 && a2 != a3 && a1 != a3
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
                    "Total supply should have been decreased of the (burned) fee {}",
                    FEE
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
                    "Total supply should have been decreased of the (burned) fee {}",
                    FEE
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

pub fn test_fee_collector_blocks<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    fn value_as_u64(value: icrc_ledger_types::icrc::generic_value::Value) -> u64 {
        use icrc_ledger_types::icrc::generic_value::Value;
        match value {
            Value::Nat64(n) => n,
            Value::Nat(n) => n.0.to_u64().expect("block index should fit into u64"),
            Value::Int(int) => int.0.to_u64().expect("block index should fit into u64"),
            value => panic!("Expected a numeric value but found {:?}", value),
        }
    }

    fn value_as_account(value: icrc_ledger_types::icrc::generic_value::Value) -> Account {
        use icrc_ledger_types::icrc::generic_value::Value;

        match value {
            Value::Array(array) => match &array[..] {
                [Value::Blob(principal_bytes)] => Account {
                    owner: Principal::try_from(principal_bytes.as_ref())
                        .expect("failed to parse account owner"),
                    subaccount: None,
                },
                [Value::Blob(principal_bytes), Value::Blob(subaccount_bytes)] => Account {
                    owner: Principal::try_from(principal_bytes.as_ref())
                        .expect("failed to parse account owner"),
                    subaccount: Some(
                        Subaccount::try_from(subaccount_bytes.as_ref())
                            .expect("failed to parse subaccount"),
                    ),
                },
                _ => panic!("Unexpected account representation: {:?}", array),
            },
            value => panic!("Expected Value::Array but found {:?}", value),
        }
    }

    fn fee_collector_from_block(
        block: icrc_ledger_types::icrc::generic_value::Value,
    ) -> (Option<Account>, Option<u64>) {
        match block {
            icrc_ledger_types::icrc::generic_value::Value::Map(block_map) => {
                let fee_collector = block_map
                    .get("fee_col")
                    .map(|fee_collector| value_as_account(fee_collector.clone()));
                let fee_collector_block_index = block_map
                    .get("fee_col_block")
                    .map(|value| value_as_u64(value.clone()));
                (fee_collector, fee_collector_block_index)
            }
            _ => panic!("A block should be a map!"),
        }
    }

    let env = StateMachine::new();
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
                    a1 != a2 && a2 != a3 && a1 != a3
                }),
            |(account_from, account_to, fee_collector_account, amount)| {
                let args = encode_init_args(InitArgs {
                    fee_collector_account: Some(fee_collector_account),
                    initial_balances: vec![(account_from, Nat::from((amount + FEE) * 6))],
                    ..init_args(vec![])
                });
                let args = Encode!(&args).unwrap();
                let ledger_id = env
                    .install_canister(ledger_wasm.clone(), args, None)
                    .unwrap();

                // The block at index 0 is the minting operation for account_from and
                // has the fee collector set.
                // Make 2 more transfers that should point to the first block index.
                transfer(&env, ledger_id, account_from, account_to, amount)
                    .expect("Unable to perform the transfer");
                transfer(&env, ledger_id, account_from, account_to, amount)
                    .expect("Unable to perform the transfer");

                let blocks = get_blocks(&env, ledger_id.get().0, 0, 4).blocks;

                // The first block must have the fee collector explicitly defined.
                assert_eq!(
                    fee_collector_from_block(blocks.first().unwrap().clone()),
                    (Some(fee_collector_account), None)
                );
                // The other two blocks must have a pointer to the first block.
                assert_eq!(
                    fee_collector_from_block(blocks.get(1).unwrap().clone()),
                    (None, Some(0))
                );
                assert_eq!(
                    fee_collector_from_block(blocks.get(2).unwrap().clone()),
                    (None, Some(0))
                );

                // Change the fee collector to a new one. The next block must have
                // the fee collector set while the ones that follow will point
                // to that one.
                let ledger_upgrade_arg = LedgerArgument::Upgrade(Some(UpgradeArgs {
                    change_fee_collector: Some(ChangeFeeCollector::SetTo(account_from)),
                    ..UpgradeArgs::default()
                }));
                env.upgrade_canister(
                    ledger_id,
                    ledger_wasm.clone(),
                    Encode!(&ledger_upgrade_arg).unwrap(),
                )
                .unwrap();

                let block_id = transfer(&env, ledger_id, account_from, account_to, amount)
                    .expect("Unable to perform the transfer");
                transfer(&env, ledger_id, account_from, account_to, amount)
                    .expect("Unable to perform the transfer");
                transfer(&env, ledger_id, account_from, account_to, amount)
                    .expect("Unable to perform the transfer");
                let blocks = get_blocks(&env, ledger_id.get().0, block_id, 3).blocks;
                assert_eq!(
                    fee_collector_from_block(blocks.first().unwrap().clone()),
                    (Some(account_from), None)
                );
                assert_eq!(
                    fee_collector_from_block(blocks.get(1).unwrap().clone()),
                    (None, Some(block_id))
                );
                assert_eq!(
                    fee_collector_from_block(blocks.get(2).unwrap().clone()),
                    (None, Some(block_id))
                );

                Ok(())
            },
        )
        .unwrap()
}
