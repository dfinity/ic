use candid::Principal;
use ic_icrc1::{Block, Operation, Transaction};
use ic_ledger_core::block::BlockType;
use ic_ledger_core::Tokens;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::{Memo, TransferArg};
use num_traits::cast::ToPrimitive;
use proptest::prelude::*;
use proptest::sample::select;
use serde_bytes::ByteBuf;
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const E8: u64 = 100_000_000;
pub const DEFAULT_TRANSFER_FEE: Tokens = Tokens::from_e8s(10_000);

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

pub fn transaction_strategy() -> impl Strategy<Value = Transaction> {
    let operation_strategy = operation_strategy();
    let memo_strategy =
        prop::option::of(prop::collection::vec(0..=255u8, 32).prop_map(|x| Memo(ByteBuf::from(x))));
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
            |(transaction, effective_fee, timestamp, fee_collector, fee_collector_block_index)| {
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

pub fn valid_blockchain_with_gaps_strategy(size: usize) -> impl Strategy<Value = Vec<Block>> {
    let blockchain_strategy = valid_blockchain_strategy(size);
    let random_indices = prop::collection::hash_set(any::<u8>().prop_map(|x| x as u64), 0..size);
    (blockchain_strategy, random_indices).prop_map(|(mut blockchain, indices)| {
        for index in indices.into_iter() {
            if !blockchain.is_empty() {
                let fitted_index = index % blockchain.len() as u64;
                blockchain.remove(fitted_index as usize);
            }
        }
        blockchain
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
                Operation::Approve { .. } => todo!(),
                Operation::TransferFrom { .. } => todo!(),
            })
            .collect()
    })
}

/// icrc1 TransferArg plus the caller
#[derive(Clone, Debug)]
pub struct CallerTransferArg {
    pub caller: Principal,
    pub transfer_arg: TransferArg,
}

impl CallerTransferArg {
    pub fn from(&self) -> Account {
        Account {
            owner: self.caller,
            subaccount: self.transfer_arg.from_subaccount,
        }
    }

    pub fn accounts(&self) -> Vec<Account> {
        vec![self.from(), self.transfer_arg.to]
    }
}

#[derive(Clone, Debug, Default)]
struct TransactionsAndBalances {
    transactions: Vec<CallerTransferArg>,
    balances: HashMap<Account, u64>,
}

impl TransactionsAndBalances {
    pub fn apply(&mut self, minter: Account, default_fee: u64, tx: CallerTransferArg) {
        if tx.transfer_arg.to != minter {
            self.credit(
                tx.transfer_arg.to,
                tx.transfer_arg.amount.0.to_u64().unwrap(),
            );
        }
        let from = tx.from();
        if from != minter {
            let amount =
                tx.transfer_arg.amount + tx.transfer_arg.fee.unwrap_or_else(|| default_fee.into());
            self.debit(from, amount.0.to_u64().unwrap());
        }
    }

    fn credit(&mut self, account: Account, amount: u64) {
        *self.balances.entry(account).or_insert(0) += amount;
    }

    fn debit(&mut self, account: Account, amount: u64) {
        use std::collections::hash_map::Entry;

        match self.balances.entry(account) {
            Entry::Occupied(e) if e.get() <= &amount => {
                e.remove();
            }
            Entry::Occupied(mut e) => {
                *e.get_mut() -= amount;
            }
            _ => {}
        }
    }

    pub fn non_dust_balances(&self, threshold: u64) -> Vec<(Account, u64)> {
        self.balances
            .iter()
            .filter(|(_, balance)| balance > &&(threshold + 1))
            .map(|(account, balance)| (*account, *balance))
            .collect()
    }
}

/// Generates a list of valid transaction args with the caller, i.e.
/// transaction args that the Ledger will accept and that have the
/// Principal that should send them.
///
/// TODO: generate the missing arguments created_at_time, fee and memo
/// TODO: replace amount generation with something that makes sense,
///       e.g. exponential distribution
/// TODO: allow to pass the account distribution
pub fn valid_transactions_strategy(
    minter: Account,
    default_fee: u64,
    length: usize,
) -> impl Strategy<Value = Vec<CallerTransferArg>> {
    fn mint_strategy(minter: Account) -> impl Strategy<Value = CallerTransferArg> {
        (account_strategy(), any::<u64>()).prop_map(move |(to, amount)| CallerTransferArg {
            caller: minter.owner,
            transfer_arg: TransferArg {
                from_subaccount: minter.subaccount,
                to,
                amount: amount.into(),
                created_at_time: None,
                fee: None,
                memo: None,
            },
        })
    }

    fn burn_or_transfer_strategy(
        balances: Vec<(Account, u64)>,
        minter: Account,
        default_fee: u64,
    ) -> impl Strategy<Value = CallerTransferArg> {
        select(balances).prop_flat_map(move |(from, balance)| {
            (0..=(balance - default_fee + 1)).prop_flat_map(move |amount| {
                let arb_burn = Just(CallerTransferArg {
                    caller: from.owner,
                    transfer_arg: TransferArg {
                        from_subaccount: from.subaccount,
                        to: minter,
                        amount: amount.into(),
                        created_at_time: None,
                        fee: Some(default_fee.into()),
                        memo: None,
                    },
                });
                let arb_transfer = account_strategy().prop_map(move |to| CallerTransferArg {
                    caller: from.owner,
                    transfer_arg: TransferArg {
                        from_subaccount: from.subaccount,
                        to,
                        amount: amount.into(),
                        created_at_time: None,
                        fee: Some(default_fee.into()),
                        memo: None,
                    },
                });
                proptest::strategy::Union::new_weighted(vec![
                    (1, arb_burn.boxed()),
                    (1000, arb_transfer.boxed()),
                ])
            })
        })
    }

    fn generate_strategy(
        state: TransactionsAndBalances,
        minter: Account,
        default_fee: u64,
        additional_length: usize,
    ) -> BoxedStrategy<TransactionsAndBalances> {
        if additional_length == 0 {
            return Just(TransactionsAndBalances::default()).boxed();
        }

        // The next transaction is based on the non-dust balances in the state.
        // If there are no balances bigger than default_fees then the only next
        // transaction possible is minting, otherwise we can also burn or transfer.

        let balances = state.non_dust_balances(default_fee);

        let arb_tx = if balances.is_empty() {
            mint_strategy(minter).boxed()
        } else {
            // there are many more transfers than burns and mints
            proptest::strategy::Union::new_weighted(vec![
                (1, mint_strategy(minter).boxed()),
                (
                    1000,
                    burn_or_transfer_strategy(balances, minter, default_fee).boxed(),
                ),
            ])
            .boxed()
        };

        (Just(state), arb_tx)
            .prop_flat_map(move |(mut state, tx)| {
                state.apply(minter, default_fee, tx);
                generate_strategy(state, minter, default_fee, additional_length - 1)
            })
            .boxed()
    }

    generate_strategy(
        TransactionsAndBalances::default(),
        minter,
        default_fee,
        length,
    )
    .prop_map(|res| res.transactions)
}
