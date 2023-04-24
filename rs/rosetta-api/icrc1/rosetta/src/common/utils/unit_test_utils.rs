use ic_ledger_core::Tokens;
use tempfile;
pub const E8: u64 = 100_000_000;
pub const DEFAULT_TRANSFER_FEE: Tokens = Tokens::from_e8s(10_000);

pub fn create_tmp_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("test_tmp_")
        .tempdir_in(".")
        .unwrap()
}

pub mod strategies {
    use crate::common::utils::unit_test_utils::DEFAULT_TRANSFER_FEE;
    use candid::Principal;
    use ic_icrc1::{Block, Operation, Transaction};
    use ic_ledger_core::block::BlockType;
    use icrc_ledger_types::icrc1::account::Account;
    use icrc_ledger_types::icrc1::transfer::{Memo, TransferArg};
    use proptest::prelude::*;
    use rand;
    use serde_bytes::ByteBuf;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    pub fn principal_strategy() -> impl Strategy<Value = Principal> {
        let bytes_strategy = prop::collection::vec(0..=255u8, 29);
        bytes_strategy.prop_map(|bytes| Principal::from_slice(bytes.as_slice()))
    }

    pub fn account_strategy() -> impl Strategy<Value = Account> {
        let bytes_strategy = prop::option::of(prop::collection::vec(0..=255u8, 32));
        let principal_strategy = principal_strategy();
        (bytes_strategy, principal_strategy).prop_map(|(bytes, principal)| Account {
            owner: principal,
            subaccount: bytes.map(|x| x.as_slice().try_into().unwrap()),
        })
    }

    fn operation_strategy() -> impl Strategy<Value = Operation> {
        prop_oneof![
            (any::<u16>(), account_strategy()).prop_map(|(amount, to)| Operation::Mint {
                to,
                amount: amount.into()
            }),
            (any::<u16>(), account_strategy()).prop_map(|(amount, from)| Operation::Burn {
                from,
                amount: amount.into()
            }),
            (
                any::<u16>(),
                account_strategy(),
                account_strategy(),
                prop::option::of(Just(DEFAULT_TRANSFER_FEE.get_e8s()))
            )
                .prop_map(|(amount, to, from, fee)| Operation::Transfer {
                    from,
                    to,
                    amount: amount.into(),
                    fee
                }),
        ]
    }

    fn transaction_strategy() -> impl Strategy<Value = Transaction> {
        let operation_strategy = operation_strategy();
        let memo_strategy = prop::option::of(
            prop::collection::vec(0..=255u8, 32).prop_map(|x| Memo(ByteBuf::from(x))),
        );
        let created_at_time_strategy = prop::option::of(Just({
            let end = SystemTime::now();
            // Ledger takes transactions that were created in the last 24 hours (5 minute window to submit valid transactions)
            let day_in_sec = 24 * 60 * 60 - 60 * 5;
            let start = end - Duration::from_secs(day_in_sec);
            let mut rng = rand::thread_rng(); // initialize random number generator
            let random_duration = Duration::from_secs(rng.gen_range(0..=day_in_sec));
            let random_time = start + random_duration; // calculate the random time
            random_time.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64
        }));
        (operation_strategy, memo_strategy, created_at_time_strategy).prop_map(
            |(operation, memo, created_at_time)| Transaction {
                operation,
                created_at_time,
                memo,
            },
        )
    }

    pub fn blocks_strategy() -> impl Strategy<Value = Block> {
        let transaction_strategy = transaction_strategy();
        let fee_collector_strategy = prop::option::of(account_strategy());
        let fee_collector_block_index_strategy = prop::option::of(prop::num::u64::ANY);
        let effective_fee_strategy = prop::option::of(prop::num::u64::ANY);
        let timestamp_strategy = prop::num::u64::ANY;
        (
            transaction_strategy,
            effective_fee_strategy,
            timestamp_strategy,
            fee_collector_strategy,
            fee_collector_block_index_strategy,
        )
            .prop_map(
                |(
                    transaction,
                    effective_fee,
                    timestamp,
                    fee_collector,
                    fee_collector_block_index,
                )| {
                    Block {
                        parent_hash: Some(Block::block_hash(
                            &Block {
                                parent_hash: None,
                                transaction: transaction.clone(),
                                effective_fee,
                                timestamp,
                                fee_collector,
                                fee_collector_block_index,
                            }
                            .encode(),
                        )),
                        transaction,
                        effective_fee,
                        timestamp,
                        fee_collector,
                        fee_collector_block_index,
                    }
                },
            )
    }

    // Construct a valid blockchain strategy
    pub fn valid_blockchain_strategy(size: usize) -> impl Strategy<Value = Vec<Block>> {
        let blocks = prop::collection::vec(blocks_strategy(), 0..size);
        blocks.prop_map(|mut blocks| {
            let mut parent_hash = None;
            for block in blocks.iter_mut() {
                block.parent_hash = parent_hash;
                parent_hash = Some(Block::block_hash(&(block.clone().encode())));
            }
            blocks
        })
    }

    pub fn transfer_args_with_sender(
        num: usize,
        sender: Account,
    ) -> impl Strategy<Value = Vec<TransferArg>> {
        let blocks_strategy = prop::collection::vec(blocks_strategy(), 0..num);
        blocks_strategy.prop_map(move |blocks| {
            blocks
                .into_iter()
                .map(|block| match block.transaction.operation {
                    Operation::Mint { to, amount } => TransferArg {
                        from_subaccount: None,
                        to,
                        fee: None,
                        created_at_time: block.transaction.created_at_time,
                        memo: block.transaction.memo,
                        amount: amount.into(),
                    },
                    Operation::Transfer {
                        from: _,
                        to,
                        amount,
                        fee: _,
                    } => TransferArg {
                        from_subaccount: sender.subaccount,
                        to,
                        fee: None,
                        created_at_time: block.transaction.created_at_time,
                        memo: block.transaction.memo,
                        amount: amount.into(),
                    },
                    Operation::Burn { from: _, amount } => TransferArg {
                        from_subaccount: sender.subaccount,
                        to: Principal::anonymous().into(),
                        fee: None,
                        created_at_time: block.transaction.created_at_time,
                        memo: block.transaction.memo,
                        amount: amount.into(),
                    },
                })
                .collect()
        })
    }
}
