use ic_ledger_core::Tokens;

pub const E8: u64 = 100_000_000;
pub const DEFAULT_TRANSFER_FEE: Tokens = Tokens::from_e8s(10_000);

pub fn create_tmp_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("test_tmp_")
        .tempdir_in(".")
        .unwrap()
}

pub mod strategies {
    use candid::Principal;

    use ic_icrc1::{Block, Operation, Transaction};

    use ic_ledger_core::block::BlockType;
    use icrc_ledger_types::icrc1::account::Account;
    use icrc_ledger_types::icrc1::transfer::Memo;
    use proptest::prelude::*;
    use serde_bytes::ByteBuf;

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
            (any::<u64>(), account_strategy())
                .prop_map(|(amount, to)| Operation::Mint { to, amount }),
            (any::<u64>(), account_strategy())
                .prop_map(|(amount, from)| Operation::Burn { from, amount }),
            (
                any::<u64>(),
                account_strategy(),
                account_strategy(),
                prop::option::of(prop::num::u64::ANY)
            )
                .prop_map(|(amount, to, from, fee)| Operation::Transfer {
                    from,
                    to,
                    amount,
                    fee
                }),
        ]
    }

    fn transaction_strategy() -> impl Strategy<Value = Transaction> {
        let operation_strategy = operation_strategy();
        let memo_strategy = prop::option::of(
            prop::collection::vec(0..=255u8, 32).prop_map(|x| Memo(ByteBuf::from(x))),
        );
        let created_at_time_strategy = prop::option::of(any::<u64>());
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
}
