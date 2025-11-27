use super::*;
use crate::{
    ChangeFeeCollector, FEE, InitArgs, LedgerArgument, MINTER, UpgradeArgs, arb_account,
    install_ledger, total_supply, transfer,
};
use candid::{CandidType, Encode};
use ic_state_machine_tests::StateMachine;
use icrc_ledger_types::icrc3::blocks::GenericBlock;
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

pub enum BlockRetrieval {
    Legacy,
    Icrc3,
}

pub fn test_fee_collector_blocks<T>(
    ledger_wasm: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
    block_retrieval: BlockRetrieval,
) where
    T: CandidType,
{
    fn retrieve_blocks_from_ledger(
        env: &StateMachine,
        ledger_id: CanisterId,
        start: u64,
        length: usize,
        block_retrieval: &BlockRetrieval,
    ) -> Vec<GenericBlock> {
        match block_retrieval {
            BlockRetrieval::Legacy => get_blocks(env, ledger_id.get().0, start, length).blocks,
            BlockRetrieval::Icrc3 => icrc3_get_blocks(env, ledger_id, start, length)
                .blocks
                .into_iter()
                .map(|b| GenericBlock::from(b.block))
                .collect(),
        }
    }

    fn value_as_u64(value: &icrc_ledger_types::icrc::generic_value::Value) -> u64 {
        use icrc_ledger_types::icrc::generic_value::Value;
        match value {
            Value::Nat64(n) => *n,
            Value::Nat(n) => n.0.to_u64().expect("block index should fit into u64"),
            Value::Int(int) => int.0.to_u64().expect("block index should fit into u64"),
            value => panic!("Expected a numeric value but found {value:?}"),
        }
    }

    fn value_as_account(value: &icrc_ledger_types::icrc::generic_value::Value) -> Account {
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
                _ => panic!("Unexpected account representation: {array:?}"),
            },
            value => panic!("Expected Value::Array but found {value:?}"),
        }
    }

    fn fee_collector_from_block(
        block: &icrc_ledger_types::icrc::generic_value::Value,
    ) -> (Option<Account>, Option<u64>) {
        match block {
            icrc_ledger_types::icrc::generic_value::Value::Map(block_map) => {
                let fee_collector = block_map.get("fee_col").map(value_as_account);
                let fee_collector_block_index = block_map.get("fee_col_block").map(value_as_u64);
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
                arb_account(),
                1..10_000_000u64,
            )
                .prop_filter(
                    "The four accounts must be different",
                    |(a1, a2, a3, a4, _)| HashSet::from([a1, a2, a3, a4]).len() == 4,
                )
                .no_shrink(),
            |(account_from, account_to, account_spender, fee_collector_account, amount)| {
                let args = encode_init_args(InitArgs {
                    fee_collector_account: Some(fee_collector_account),
                    initial_balances: vec![(account_from, Nat::from((amount + FEE) * 7))],
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

                let blocks = retrieve_blocks_from_ledger(&env, ledger_id, 0, 4, &block_retrieval);

                // The first block must have the fee collector explicitly defined.
                assert_eq!(
                    fee_collector_from_block(blocks.first().unwrap()),
                    (Some(fee_collector_account), None)
                );
                // The other two blocks must have a pointer to the first block.
                assert_eq!(
                    fee_collector_from_block(blocks.get(1).unwrap()),
                    (None, Some(0))
                );
                assert_eq!(
                    fee_collector_from_block(blocks.get(2).unwrap()),
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
                send_approval(
                    &env,
                    ledger_id,
                    account_from.owner,
                    &ApproveArgs {
                        from_subaccount: account_from.subaccount,
                        spender: account_spender,
                        amount: Nat::from(amount + FEE),
                        expected_allowance: None,
                        expires_at: None,
                        fee: None,
                        memo: None,
                        created_at_time: None,
                    },
                )
                .expect("Unable to perform the approval");
                send_transfer_from(
                    &env,
                    ledger_id,
                    account_spender.owner,
                    &TransferFromArgs {
                        spender_subaccount: account_spender.subaccount,
                        from: account_from,
                        to: account_to,
                        amount: Nat::from(amount),
                        fee: None,
                        memo: None,
                        created_at_time: None,
                    },
                )
                .expect("Unable to perform the transfer_from");

                let blocks =
                    retrieve_blocks_from_ledger(&env, ledger_id, block_id, 4, &block_retrieval);

                assert_eq!(
                    fee_collector_from_block(blocks.first().unwrap()),
                    (Some(account_from), None)
                );
                assert_eq!(
                    fee_collector_from_block(blocks.get(1).unwrap()),
                    (None, Some(block_id))
                );
                // Expect the fee collector to be set in an approve block.
                assert_eq!(
                    fee_collector_from_block(blocks.get(2).unwrap()),
                    (None, Some(block_id))
                );
                // Expect the fee collector to be set in a transfer_from block.
                assert_eq!(
                    fee_collector_from_block(blocks.get(3).unwrap()),
                    (None, Some(block_id))
                );

                Ok(())
            },
        )
        .unwrap()
}
