use candid::{Nat, Principal};
use ic_agent::Identity;
use ic_agent::identity::BasicIdentity;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_ed25519::{PrivateKey as Ed25519SecretKey, PrivateKeyFormat};
use ic_icrc1::{Block, Operation, Transaction};
use ic_ledger_core::Tokens;
use ic_ledger_core::block::BlockType;
use ic_ledger_core::tokens::TokensType;
use ic_ledger_hash_of::HashOf;
use ic_secp256k1::PrivateKey as Secp256k1PrivateKey;
use icrc_ledger_types::icrc::generic_metadata_value::MetadataValue;
use icrc_ledger_types::icrc1::account::{Account, Subaccount};
use icrc_ledger_types::icrc1::transfer::{Memo, TransferArg};
use icrc_ledger_types::icrc2::approve::ApproveArgs;
use icrc_ledger_types::icrc2::transfer_from::TransferFromArgs;
use num_traits::cast::ToPrimitive;
use proptest::prelude::*;
use proptest::sample::select;
use rand::Rng;
use rand::RngCore;
use rand::SeedableRng;
use rosetta_core::models::Secp256k1KeyPair;
use rosetta_core::models::{Ed25519KeyPair, RosettaSupportedKeyPair};
use rosetta_core::objects::Currency;
use rosetta_core::objects::ObjectMap;
use serde_bytes::ByteBuf;
use serde_json::json;
use std::collections::HashSet;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::ops::Bound::Included;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use strum::EnumCount;

pub mod icrc3;

pub const E8: u64 = 100_000_000;
pub const DEFAULT_TRANSFER_FEE: u64 = 10_000;

const MIN_ACCOUNT: Account = Account {
    owner: Principal::from_slice(&[0; 29]),
    subaccount: None,
};
const MAX_ACCOUNT: Account = Account {
    owner: Principal::from_slice(&[255; 29]),
    subaccount: Some([255; 32]),
};

pub fn minter_identity() -> BasicIdentity {
    let keypair = Ed25519KeyPair::generate(reproducible_rng().next_u64());
    BasicIdentity::from_pem(keypair.to_pem().as_bytes()).unwrap()
}

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

fn token_amount<Tokens: TokensType>(n: u64) -> Tokens {
    Tokens::try_from(candid::Nat::from(n))
        .unwrap_or_else(|e| panic!("failed to convert {n} to tokens: {e}"))
}

pub fn arb_small_amount<Tokens: TokensType>() -> impl Strategy<Value = Tokens> {
    any::<u16>().prop_map(|v| token_amount(v as u64))
}

pub fn arb_amount<Tokens: TokensType>() -> impl Strategy<Value = Tokens> {
    any::<u64>().prop_map(|v| token_amount(v))
}

fn arb_memo() -> impl Strategy<Value = Option<Memo>> {
    prop::option::of(prop::collection::vec(0..=255u8, 32).prop_map(|x| Memo(ByteBuf::from(x))))
}

fn operation_strategy<Tokens: TokensType>(
    amount_strategy: impl Strategy<Value = Tokens>,
) -> impl Strategy<Value = Operation<Tokens>> {
    amount_strategy.prop_flat_map(|amount| {
        // Clone amount due to move
        let mint_amount = amount.clone();
        let mint_strategy = (
            account_strategy(),
            prop::option::of(Just(token_amount(DEFAULT_TRANSFER_FEE))),
        )
            .prop_map(move |(to, fee)| Operation::Mint {
                to,
                amount: mint_amount.clone(),
                fee,
            });
        let burn_amount = amount.clone();
        let burn_strategy = (
            account_strategy(),
            prop::option::of(Just(token_amount(DEFAULT_TRANSFER_FEE))),
        )
            .prop_map(move |(from, fee)| Operation::Burn {
                from,
                spender: None,
                amount: burn_amount.clone(),
                fee,
            });
        let transfer_amount = amount.clone();
        let transfer_strategy = (
            account_strategy(),
            account_strategy(),
            prop::option::of(Just(token_amount(DEFAULT_TRANSFER_FEE))),
        )
            .prop_map(move |(to, from, fee)| Operation::Transfer {
                from,
                to,
                spender: None,
                amount: transfer_amount.clone(),
                fee,
            });
        let approve_amount = amount.clone();
        let approve_strategy = (
            account_strategy(),
            account_strategy(),
            prop::option::of(Just(token_amount(DEFAULT_TRANSFER_FEE))),
            prop::option::of(Just({
                (SystemTime::now()
                    + Duration::from_secs(rand::thread_rng().gen_range(0..=u32::MAX as u64)))
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64
            })),
        )
            .prop_map(move |(spender, from, fee, expires_at)| Operation::Approve {
                from,
                spender,
                amount: approve_amount.clone(),
                expected_allowance: Some(amount.clone()),
                expires_at,
                fee,
            });

        let fee_collector_strategy = (
            prop::option::of(principal_strategy()),
            prop::option::of(account_strategy()),
            prop_oneof![
                Just(None),
                Just(Some("107set_fee_collector".to_string())),
                Just(Some("other_mthd".to_string())),
            ],
        )
            .prop_map(
                move |(caller, fee_collector, mthd)| Operation::FeeCollector {
                    fee_collector,
                    caller,
                    mthd,
                },
            );

        prop_oneof![
            mint_strategy,
            burn_strategy,
            transfer_strategy,
            approve_strategy,
            fee_collector_strategy,
        ]
    })
}

fn valid_created_at_time_strategy(now: SystemTime) -> impl Strategy<Value = Option<u64>> {
    let day_in_sec = 24 * 60 * 60 - 60 * 5;
    prop::option::of((0..=day_in_sec).prop_map(move |duration| {
        let start = now - Duration::from_secs(day_in_sec);
        // Ledger takes transactions that were created in the last 24 hours (5 minute window to submit valid transactions)
        let random_time = start + Duration::from_secs(duration); // calculate the random time
        random_time.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64
    }))
}

fn valid_expires_at_strategy(now: SystemTime) -> impl Strategy<Value = Option<u64>> {
    prop::option::of((0..=u32::MAX as u64).prop_map(move |duration| {
        let random_time = now + Duration::from_secs(duration);
        random_time.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64
    }))
}

pub fn transaction_strategy<Tokens: TokensType>(
    amount_strategy: impl Strategy<Value = Tokens>,
) -> impl Strategy<Value = Transaction<Tokens>> {
    let operation_strategy = operation_strategy(amount_strategy);
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
    (operation_strategy, arb_memo(), created_at_time_strategy).prop_map(
        |(operation, memo, created_at_time)| Transaction {
            operation,
            created_at_time,
            memo,
        },
    )
}

pub fn blocks_strategy<Tokens: TokensType>(
    amount_strategy: impl Strategy<Value = Tokens>,
) -> impl Strategy<Value = Block<Tokens>> {
    let transaction_strategy = transaction_strategy(amount_strategy);
    let fee_collector_strategy = prop::option::of(account_strategy());
    let effective_fee_strategy = arb_small_amount::<Tokens>();
    let timestamp_strategy = Just({
        let end = SystemTime::now();
        // Ledger takes transactions that were created in the last 24 hours (5 minute window to submit valid transactions)
        let day_in_sec = 24 * 60 * 60 - 60 * 5;
        let start = end - Duration::from_secs(day_in_sec);
        let mut rng = rand::thread_rng(); // initialize random number generator
        let random_duration = Duration::from_secs(rng.gen_range(0..=day_in_sec));
        let random_time = start + random_duration; // calculate the random time
        random_time.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64
    });
    (
        transaction_strategy,
        effective_fee_strategy,
        timestamp_strategy,
        fee_collector_strategy,
    )
        .prop_map(|(transaction, arb_fee, timestamp, fee_collector)| {
            let effective_fee = match transaction.operation {
                Operation::Transfer { ref fee, .. } => fee.clone().is_none().then_some(arb_fee),
                Operation::Approve { ref fee, .. } => fee.clone().is_none().then_some(arb_fee),
                Operation::Burn { ref fee, .. } => fee.clone().is_none().then_some(arb_fee),
                Operation::Mint { ref fee, .. } => fee.clone().is_none().then_some(arb_fee),
                Operation::FeeCollector { .. } => None,
            };

            Block {
                parent_hash: Some(Block::<Tokens>::block_hash(
                    &Block {
                        parent_hash: None,
                        transaction: transaction.clone(),
                        effective_fee: effective_fee.clone(),
                        timestamp,
                        fee_collector,
                        fee_collector_block_index: None,
                        btype: None,
                    }
                    .encode(),
                )),
                transaction,
                effective_fee,
                timestamp,
                fee_collector,
                fee_collector_block_index: None,
                btype: None,
            }
        })
}

// Construct a valid blockchain strategy
pub fn valid_blockchain_strategy<Tokens: TokensType>(
    size: usize,
) -> impl Strategy<Value = Vec<Block<Tokens>>> {
    let blocks = prop::collection::vec(blocks_strategy(arb_amount()), 0..size);
    blocks.prop_map(|mut blocks| {
        let mut parent_hash = None;
        let mut fee_collector_block_index = None;
        for (block_index, block) in blocks.iter_mut().enumerate() {
            block.parent_hash = parent_hash;
            if block.fee_collector.is_some() {
                fee_collector_block_index = Some(block_index as u64);
            } else {
                block.fee_collector_block_index = fee_collector_block_index;
            }
            parent_hash = Some(Block::<Tokens>::block_hash(&(block.clone().encode())));
        }
        blocks
    })
}

pub fn valid_blockchain_with_gaps_strategy<Tokens: TokensType>(
    size: usize,
) -> impl Strategy<Value = (Vec<Block<Tokens>>, Vec<usize>)> {
    let blockchain_strategy = valid_blockchain_strategy(size).prop_filter(
        "There must be at least two blocks for there to be a gap",
        |blocks| blocks.len() > 1,
    );
    let gaps = prop::collection::vec(0..5usize, size);
    (blockchain_strategy, gaps)
        .prop_map(|(blockchain, gaps)| {
            let block_indices: Vec<usize> = gaps
                .into_iter()
                .enumerate()
                .scan(0, |acc, (index, gap)| {
                    *acc += gap;
                    Some(index + *acc)
                })
                .collect();
            (blockchain, block_indices)
        })
        .prop_filter(
            "There must be at least one gap before the last block",
            |(blockchain, block_indexes)| {
                let mut index_iter = block_indexes.iter();
                let mut previous_index = -1;
                loop {
                    let Some(current_index) = index_iter.next() else {
                        // no more indexes but also no gaps
                        return false;
                    };
                    let current_index = (*current_index) as i32;
                    if previous_index + 1 == current_index {
                        // no gap
                        previous_index = current_index;
                    } else {
                        // gap - make sure it is before the last block of the blockchain
                        return current_index < blockchain.len() as i32;
                    }
                }
            },
        )
}

pub fn transfer_arg(sender: Account) -> impl Strategy<Value = TransferArg> {
    (any::<u16>(), arb_memo(), account_strategy()).prop_map(move |(amount, memo, to)| TransferArg {
        from_subaccount: sender.subaccount,
        to,
        amount: candid::Nat::from(amount),
        created_at_time: None,
        fee: None,
        memo,
    })
}

pub fn transfer_args_with_sender(
    num: usize,
    sender: Account,
) -> impl Strategy<Value = Vec<TransferArg>> {
    prop::collection::vec(transfer_arg(sender), 0..num)
}

#[derive(Clone, Debug)]
pub enum LedgerEndpointArg {
    ApproveArg(ApproveArgs),
    TransferArg(TransferArg),
    TransferFromArg(TransferFromArgs),
}

impl LedgerEndpointArg {
    fn subaccount_from(&self) -> Option<Subaccount> {
        match self {
            Self::ApproveArg(arg) => arg.from_subaccount,
            Self::TransferArg(arg) => arg.from_subaccount,
            Self::TransferFromArg(arg) => arg.spender_subaccount,
        }
    }
}

#[derive(Clone)]
pub struct ArgWithCaller {
    pub caller: Arc<BasicIdentity>,
    pub principal_to_basic_identity: HashMap<Principal, Arc<BasicIdentity>>,
    pub arg: LedgerEndpointArg,
}

impl fmt::Debug for ArgWithCaller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArgWithCaller")
            .field(
                "account_to_basic_identity",
                &self.principal_to_basic_identity,
            )
            .field("arg", &self.principal_to_basic_identity)
            .field("caller", &self.caller.sender().unwrap())
            .finish_non_exhaustive()
    }
}

impl ArgWithCaller {
    pub fn from(&self) -> Account {
        Account {
            owner: self.caller.sender().unwrap(),
            subaccount: self.arg.subaccount_from(),
        }
    }

    pub fn accounts(&self) -> Vec<Account> {
        let mut res = vec![self.from()];
        match &self.arg {
            LedgerEndpointArg::TransferArg(arg) => {
                res.push(arg.to);
            }
            LedgerEndpointArg::TransferFromArg(arg) => {
                res.push(arg.from);
                res.push(arg.to);
            }
            LedgerEndpointArg::ApproveArg(_) => {
                // Approve doesn't add additional accounts beyond the caller
            }
        }
        res
    }

    pub fn fee(&self) -> Option<u64> {
        let fee = match &self.arg {
            LedgerEndpointArg::ApproveArg(arg) => arg.fee.as_ref(),
            LedgerEndpointArg::TransferArg(arg) => arg.fee.as_ref(),
            LedgerEndpointArg::TransferFromArg(arg) => arg.fee.as_ref(),
        };
        fee.as_ref().map(|fee| fee.0.to_u64().unwrap())
    }
    pub fn to_transaction<T>(&self, minter: Account) -> Transaction<T>
    where
        T: TokensType,
    {
        let caller = self.from();
        let (operation, created_at_time, memo) = match self.arg.clone() {
            LedgerEndpointArg::ApproveArg(approve_arg) => {
                let operation = Operation::<T>::Approve {
                    amount: T::try_from(approve_arg.amount.clone()).unwrap(),
                    expires_at: approve_arg.expires_at,
                    fee: approve_arg
                        .fee
                        .clone()
                        .map(|f| T::try_from(f.clone()).unwrap()),
                    expected_allowance: approve_arg
                        .expected_allowance
                        .clone()
                        .map(|a| T::try_from(a.clone()).unwrap()),
                    spender: approve_arg.spender,
                    from: caller,
                };
                (operation, approve_arg.created_at_time, approve_arg.memo)
            }
            LedgerEndpointArg::TransferArg(transfer_arg) => {
                let burn_operation = transfer_arg.to == minter;
                let mint_operation = caller == minter;
                let operation = if mint_operation {
                    Operation::Mint {
                        amount: T::try_from(transfer_arg.amount.clone()).unwrap(),
                        to: transfer_arg.to,
                        fee: transfer_arg.fee.clone().map(|f| T::try_from(f).unwrap()),
                    }
                } else if burn_operation {
                    Operation::Burn {
                        amount: T::try_from(transfer_arg.amount.clone()).unwrap(),
                        from: caller,
                        spender: None,
                        fee: transfer_arg.fee.clone().map(|f| T::try_from(f).unwrap()),
                    }
                } else {
                    Operation::Transfer {
                        amount: T::try_from(transfer_arg.amount.clone()).unwrap(),
                        to: transfer_arg.to,
                        from: caller,
                        spender: None,
                        fee: transfer_arg.fee.clone().map(|f| T::try_from(f).unwrap()),
                    }
                };

                (operation, transfer_arg.created_at_time, transfer_arg.memo)
            }
            LedgerEndpointArg::TransferFromArg(transfer_from_arg) => {
                let operation = Operation::Transfer {
                    from: transfer_from_arg.from,
                    to: transfer_from_arg.to,
                    spender: Some(caller),
                    amount: T::try_from(transfer_from_arg.amount.clone()).unwrap(),
                    fee: transfer_from_arg
                        .fee
                        .clone()
                        .map(|f| T::try_from(f).unwrap()),
                };
                (
                    operation,
                    transfer_from_arg.created_at_time,
                    transfer_from_arg.memo,
                )
            }
        };
        Transaction::<T> {
            operation,
            created_at_time,
            memo,
        }
    }
}

#[derive(Clone, Debug, Default)]
struct TransactionsAndBalances {
    transactions: Vec<ArgWithCaller>,
    balances: HashMap<Account, u64>,
    txs: HashSet<Transaction<Tokens>>,
    principal_to_basic_identity: HashMap<Principal, Arc<BasicIdentity>>,
    allowances: BTreeMap<(Account, Account), Tokens>,
    /// Accounts which are the `from` account in at least one allowance, having a balances of at
    /// least `default_fee`. Even though the `approve_strategy` currently only creates allowances
    /// with the amount limited to the account balance at the time of the transaction, that balance
    /// may have decreased by the time a subsequent `transfer_from` transaction makes use of (some
    /// of) the allowance.
    valid_allowance_from: HashSet<Account>,
}

impl TransactionsAndBalances {
    pub fn apply(
        &mut self,
        minter_identity: Arc<BasicIdentity>,
        default_fee: u64,
        tx: ArgWithCaller,
    ) {
        let fee = tx.fee().unwrap_or(default_fee);
        let minter: Account = minter_identity.sender().unwrap().into();
        let transaction = tx.to_transaction(minter);
        self.principal_to_basic_identity
            .extend(tx.principal_to_basic_identity.clone());
        self.principal_to_basic_identity
            .entry(tx.from().owner)
            .or_insert(tx.caller.clone());
        if self.duplicate(
            transaction.operation.clone(),
            transaction.created_at_time,
            transaction.memo.clone(),
        ) {
            return;
        };

        // Store operation reference for incremental update
        let operation = &transaction.operation;
        match transaction.operation {
            Operation::Mint { to, amount, .. } => {
                self.credit(to, amount.get_e8s());
            }
            Operation::Burn { from, amount, .. } => {
                assert_eq!(tx.from(), from);
                self.debit(from, amount.get_e8s());
            }
            Operation::Transfer {
                from,
                to,
                amount,
                spender,
                ..
            } => {
                self.credit(to, amount.get_e8s());
                let caller = spender.unwrap_or(from);
                assert_eq!(tx.from(), caller);
                self.debit(from, amount.get_e8s() + fee);

                // If spender is Some, this is a transfer_from operation - update allowances
                if let Some(spender_account) = spender {
                    let used_allowance = amount.get_e8s() + fee;
                    self.allowances.entry((from, spender_account)).and_modify(
                        |current_allowance| {
                            let current_amount = current_allowance.get_e8s();
                            *current_allowance = Tokens::from_e8s(
                                current_amount
                                    .checked_sub(used_allowance)
                                    .unwrap_or_else(|| {
                                        panic!(
                                            "Allowance {current_amount} not enough to cover amount and fee {used_allowance} - from: {from}, to: {to}, spender: {spender_account}"
                                        )
                                    }),
                            );
                        },
                    );

                    // Remove allowance entry if it's now zero
                    if let Some(allowance) = self.allowances.get(&(from, spender_account))
                        && allowance.get_e8s() == 0
                    {
                        self.allowances.remove(&(from, spender_account));
                    }
                }
            }
            Operation::Approve {
                from,
                spender,
                amount,
                ..
            } => {
                assert_eq!(tx.from(), from);
                self.allowances
                    .entry((from, spender))
                    .and_modify(|current_allowance| {
                        *current_allowance =
                            Tokens::from_e8s((*current_allowance).get_e8s() + amount.get_e8s())
                    })
                    .or_insert(amount);
                self.debit(from, fee);
            }
            Operation::FeeCollector { .. } => {
                panic!("FeeCollector107 not implemented")
            }
        };
        self.transactions.push(tx);

        // Update valid_allowance_from based on the specific transaction
        self.update_valid_allowance_from(operation, default_fee);
    }

    fn update_valid_allowance_from(&mut self, operation: &Operation<Tokens>, default_fee: u64) {
        match operation {
            Operation::Mint { to, .. } => {
                // Check if the credited account should be added to valid_allowance_from
                self.check_and_update_account_validity(*to, default_fee);
            }
            Operation::Burn { from, .. } => {
                // Check if the debited account should be removed from valid_allowance_from
                self.check_and_update_account_validity(*from, default_fee);
            }
            Operation::Transfer { from, to, .. } => {
                // Check both accounts that had balance changes
                self.check_and_update_account_validity(*from, default_fee);
                self.check_and_update_account_validity(*to, default_fee);
            }
            Operation::Approve { from, .. } => {
                // Check if the from account should be added/removed from valid_allowance_from
                // (allowance was added/modified for this account)
                self.check_and_update_account_validity(*from, default_fee);
            }
            Operation::FeeCollector { .. } => {
                panic!("FeeCollector107 not implemented")
            }
        }
    }

    fn check_and_update_account_validity(&mut self, account: Account, default_fee: u64) {
        // Check if there are any valid allowances where the `from` is the provided account, and
        // the `spender` is any account.
        let has_valid_allowances = self
            .allowances
            .range((
                Included((account, MIN_ACCOUNT)),
                Included((account, MAX_ACCOUNT)),
            ))
            .any(|((_from, _spender), allowance)| allowance.get_e8s() >= default_fee);

        if has_valid_allowances
            && self
                .balances
                .get(&account)
                .is_some_and(|&balance| balance >= default_fee)
        {
            // There is at least one valid allowance for this account, and the account has a
            // non-dust balance - make sure it exists in `valid_allowance_from`.
            self.valid_allowance_from.insert(account);
        } else {
            // The account either has no valid allowances or a dust balance - remove it from
            // `valid_allowance_from`.
            self.valid_allowance_from.remove(&account);
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

    fn duplicate(
        &mut self,
        operation: Operation<Tokens>,
        created_at_time: Option<u64>,
        memo: Option<Memo>,
    ) -> bool {
        if created_at_time.is_some() {
            let tx = Transaction {
                operation,
                created_at_time,
                memo,
            };
            if self.txs.contains(&tx) {
                return true;
            }
            self.txs.insert(tx);
        }
        false
    }
}

fn amount_strategy() -> impl Strategy<Value = u64> {
    0..100_000_000_000u64 // max is 1M ICP
}

pub fn basic_identity_strategy() -> impl Strategy<Value = BasicIdentity> {
    prop::num::u64::ANY.prop_map(|ran| {
        let keypair = Ed25519KeyPair::generate(ran);
        BasicIdentity::from_pem(keypair.to_pem().as_bytes()).unwrap()
    })
}

#[derive(Debug)]
struct SigningAccount {
    identity: BasicIdentity,
    subaccount: Option<Subaccount>,
}

impl SigningAccount {
    fn account(&self) -> Account {
        Account {
            owner: self.identity.sender().unwrap(),
            subaccount: self.subaccount,
        }
    }
}

fn basic_identity_and_account_strategy() -> impl Strategy<Value = SigningAccount> {
    let bytes_strategy = prop::option::of(prop::collection::vec(0..=255u8, 32));
    let identity_strategy = basic_identity_strategy();
    (bytes_strategy, identity_strategy).prop_map(|(bytes, identity)| SigningAccount {
        identity,
        subaccount: bytes.map(|x| x.as_slice().try_into().unwrap()),
    })
}

#[derive(EnumCount, PartialEq, Clone)]
pub enum TransactionTypes {
    Mint,
    Burn,
    Transfer,
    Approve,
    TransferFrom,
}

pub fn valid_transactions_strategy(
    minter_identity: Arc<BasicIdentity>,
    default_fee: u64,
    length: usize,
    now: SystemTime,
) -> impl Strategy<Value = Vec<ArgWithCaller>> {
    valid_transactions_strategy_with_excluded_transaction_types(
        minter_identity,
        default_fee,
        length,
        now,
        vec![],
    )
}

/// Generates a list of valid transaction args with the caller, i.e.
/// transaction args that the Ledger will accept and that have the
/// Principal that should send them.
///
/// TODO: replace amount generation with something that makes sense,
///       e.g. exponential distribution
/// TODO: allow to pass the account distribution
pub fn valid_transactions_strategy_with_excluded_transaction_types(
    minter_identity: Arc<BasicIdentity>,
    default_fee: u64,
    length: usize,
    now: SystemTime,
    excluded_transaction_types: Vec<TransactionTypes>,
) -> impl Strategy<Value = Vec<ArgWithCaller>> {
    /// Generates a strategy for producing valid `mint` operations.
    ///
    /// The generated mint operations will:
    /// - Always use the minter as the caller.
    /// - Mint to a random account (not the minter).
    /// - Set the `amount` to a random value.
    /// - Optionally include `created_at_time` and `memo`.
    /// - Avoid duplicate transactions and minting to the minter.
    fn mint_strategy(
        minter_identity: Arc<BasicIdentity>,
        now: SystemTime,
        tx_hash_set_pointer: Arc<HashSet<Transaction<Tokens>>>,
    ) -> impl Strategy<Value = ArgWithCaller> {
        let minter: Account = minter_identity.sender().unwrap().into();
        (
            basic_identity_and_account_strategy(),
            amount_strategy(),
            valid_created_at_time_strategy(now),
            arb_memo(),
        )
            .prop_filter_map(
                "The minting account is set as to account or tx is a duplicate",
                move |(to_signer, amount, created_at_time, memo)| {
                    let to = to_signer.account();
                    let tx = Transaction {
                        operation: Operation::Mint::<Tokens> {
                            amount: Tokens::from_e8s(amount),
                            to,
                            fee: None,
                        },
                        created_at_time,
                        memo: memo.clone(),
                    };
                    if to == minter || tx_hash_set_pointer.contains(&tx) {
                        None
                    } else {
                        assert_eq!(minter_identity.sender().unwrap(), minter.owner);
                        Some(ArgWithCaller {
                            caller: minter_identity.clone(),
                            arg: LedgerEndpointArg::TransferArg(TransferArg {
                                from_subaccount: minter.subaccount,
                                to,
                                amount: amount.into(),
                                created_at_time,
                                fee: None,
                                memo,
                            }),
                            principal_to_basic_identity: HashMap::from([(
                                to.owner,
                                Arc::new(to_signer.identity),
                            )]),
                        })
                    }
                },
            )
    }

    /// Generates a strategy for producing valid `burn` operations.
    ///
    /// The generated burn operations will:
    /// - Use a random existing `from` account with sufficient balance to cover the minimum burn
    ///   amount (which is equal to the `default_fee`).
    /// - Set the `amount` to a random value within the allowed range for the account.
    /// - Optionally include `created_at_time` and `memo`.
    /// - Avoid duplicate transactions.
    /// - Ensures the caller matches the `from` account.
    fn burn_strategy(
        account_balance: impl Strategy<Value = (Account, u64)>,
        minter_identity: Arc<BasicIdentity>,
        default_fee: u64,
        now: SystemTime,
        tx_hash_set_pointer: Arc<HashSet<Transaction<Tokens>>>,
        account_to_basic_identity_pointer: Arc<HashMap<Principal, Arc<BasicIdentity>>>,
    ) -> impl Strategy<Value = ArgWithCaller> {
        let minter: Account = minter_identity.sender().unwrap().into();
        account_balance.prop_flat_map(move |(from, balance)| {
            let tx_hash_set = tx_hash_set_pointer.clone();
            let account_to_basic_identity = account_to_basic_identity_pointer.clone();
            (
                default_fee..=balance,
                valid_created_at_time_strategy(now),
                arb_memo(),
            )
                .prop_filter_map(
                    "Tx hash already exists",
                    move |(amount, created_at_time, memo)| {
                        let tx = Transaction {
                            operation: Operation::Burn::<Tokens> {
                                amount: Tokens::from_e8s(amount),
                                from,
                                spender: None,
                                fee: None,
                            },
                            created_at_time,
                            memo: memo.clone(),
                        };

                        if tx_hash_set.contains(&tx) {
                            None
                        } else {
                            let caller =
                                account_to_basic_identity.get(&from.owner).unwrap().clone();
                            assert_eq!(caller.sender().unwrap(), from.owner);
                            Some(ArgWithCaller {
                                caller,
                                arg: LedgerEndpointArg::TransferArg(TransferArg {
                                    from_subaccount: from.subaccount,
                                    to: minter,
                                    amount: amount.into(),
                                    created_at_time,
                                    fee: None,
                                    memo,
                                }),
                                principal_to_basic_identity: HashMap::new(),
                            })
                        }
                    },
                )
        })
    }

    /// Generates a strategy for producing valid `transfer` operations.
    ///
    /// The generated transfer operations will:
    /// - Use a random existing `from` account (with sufficient balance to cover the transfer fee)
    ///   and a random `to` account.
    /// - Set the `amount` to a random value within the allowed range for the account.
    /// - Optionally include a `fee`, `created_at_time`, and `memo`.
    /// - Avoid self-transfers, transfers involving the minter, and duplicate transactions.
    /// - Ensures the caller matches the `from` account.
    fn transfer_strategy(
        account_balance: impl Strategy<Value = (Account, u64)>,
        minter_identity: Arc<BasicIdentity>,
        default_fee: u64,
        now: SystemTime,
        tx_hash_set_pointer: Arc<HashSet<Transaction<Tokens>>>,
        account_to_basic_identity_pointer: Arc<HashMap<Principal, Arc<BasicIdentity>>>,
    ) -> impl Strategy<Value = ArgWithCaller> {
        let minter: Account = minter_identity.sender().unwrap().into();
        account_balance.prop_flat_map(move |(from, balance)| {
            let tx_hash_set = tx_hash_set_pointer.clone();
            let account_to_basic_identity = account_to_basic_identity_pointer.clone();
            (
                basic_identity_and_account_strategy(),
                0..=(balance - default_fee),
                valid_created_at_time_strategy(now),
                arb_memo(),
                prop::option::of(Just(default_fee)),
            )
                .prop_filter_map(
                    "Tx is a self transfer or duplicate",
                    move |(to_signer, amount, created_at_time, memo, fee)| {
                        let to = to_signer.account();
                        let tx = Transaction {
                            operation: Operation::Transfer::<Tokens> {
                                amount: Tokens::from_e8s(amount),
                                from,
                                fee: fee.map(Tokens::from_e8s),
                                spender: None,
                                to,
                            },
                            created_at_time,
                            memo: memo.clone(),
                        };

                        if to == minter || from == minter || tx_hash_set.contains(&tx) {
                            None
                        } else {
                            let caller =
                                account_to_basic_identity.get(&from.owner).unwrap().clone();
                            assert_eq!(caller.sender().unwrap(), from.owner);
                            Some(ArgWithCaller {
                                caller,
                                arg: LedgerEndpointArg::TransferArg(TransferArg {
                                    from_subaccount: from.subaccount,
                                    to,
                                    amount: amount.into(),
                                    created_at_time,
                                    fee: fee.map(Nat::from),
                                    memo,
                                }),
                                principal_to_basic_identity: HashMap::from([(
                                    to.owner,
                                    Arc::new(to_signer.identity),
                                )]),
                            })
                        }
                    },
                )
        })
    }

    /// Generates a strategy for producing valid `approve` operations.
    ///
    /// The generated approve operations will:
    /// - Use a random existing `from` account (with sufficient balance to at least cover the
    ///   creation of the allowance, i.e., at least `default_fee`), and a random `spender` account.
    /// - Set the `amount` to a random value within the allowed range.
    /// - Optionally include a `fee`, `expected_allowance`, `expires_at`, and `memo`.
    /// - Avoid duplicate or self-approve transactions, and ensure the minter is not involved as `from` or `spender`.
    fn approve_strategy(
        account_balance: impl Strategy<Value = (Account, u64)>,
        minter_identity: Arc<BasicIdentity>,
        default_fee: u64,
        now: SystemTime,
        tx_hash_set_pointer: Arc<HashSet<Transaction<Tokens>>>,
        account_to_basic_identity_pointer: Arc<HashMap<Principal, Arc<BasicIdentity>>>,
        allowance_map_pointer: Arc<BTreeMap<(Account, Account), Tokens>>,
    ) -> impl Strategy<Value = ArgWithCaller> {
        let minter: Account = minter_identity.sender().unwrap().into();
        account_balance.prop_flat_map(move |(from, _balance)| {
            let tx_hash_set = tx_hash_set_pointer.clone();
            let account_to_basic_identity = account_to_basic_identity_pointer.clone();
            let allowance_map = allowance_map_pointer.clone();
            (
                basic_identity_and_account_strategy(),
                amount_strategy(),
                valid_created_at_time_strategy(now),
                arb_memo(),
                prop::option::of(Just(default_fee)),
                valid_expires_at_strategy(now),
                proptest::bool::ANY,
            )
                .prop_filter_map(
                    "Tx is a duplicate or self approve",
                    move |(
                        spender_signer,
                        amount,
                        created_at_time,
                        memo,
                        fee,
                        expires_at,
                        expect_allowance,
                    )| {
                        let spender = spender_signer.account();
                        let expected_allowance = allowance_map.get(&(from, spender)).copied();
                        let tx = Transaction {
                            operation: Operation::Approve::<Tokens> {
                                from,
                                spender,
                                fee: fee.map(Tokens::from_e8s),
                                amount: Tokens::from_e8s(amount),
                                expected_allowance: if expect_allowance {
                                    expected_allowance
                                } else {
                                    None
                                },
                                expires_at,
                            },
                            created_at_time,
                            memo: memo.clone(),
                        };
                        if spender == from
                            || spender == minter
                            || from == minter
                            || tx_hash_set.contains(&tx)
                        {
                            None
                        } else {
                            let caller =
                                account_to_basic_identity.get(&from.owner).unwrap().clone();
                            assert_eq!(caller.sender().unwrap(), from.owner);
                            Some(ArgWithCaller {
                                caller,
                                arg: LedgerEndpointArg::ApproveArg(ApproveArgs {
                                    from_subaccount: from.subaccount,
                                    spender,
                                    amount: amount.into(),
                                    created_at_time,
                                    fee: fee.map(Nat::from),
                                    memo,
                                    expected_allowance: expected_allowance.map(Nat::from),
                                    expires_at,
                                }),
                                principal_to_basic_identity: HashMap::from([(
                                    spender.owner,
                                    Arc::new(spender_signer.identity),
                                )]),
                            })
                        }
                    },
                )
        })
    }

    /// Generates a strategy for producing valid `transfer_from` operations.
    ///
    /// The generated transfer_from operations will:
    /// - Use a random existing `from` account, for which there exists an allowance, and which has
    ///   a balance covering at least the `default_fee`.
    /// - Use a random `spender` account (the caller) with an existing allowance from `from`.
    /// - Set the `amount` to a value allowed by both the allowance and the current balance of the
    ///   `from` account.
    /// - Optionally include a `fee`, `created_at_time`, and `memo`.
    /// - Avoid self-transfers, transfers involving the minter, and duplicate transactions.
    /// - Ensures the caller matches the `spender` account.
    fn transfer_from_strategy(
        valid_allowance_from: HashSet<Account>,
        minter_identity: Arc<BasicIdentity>,
        default_fee: u64,
        now: SystemTime,
        tx_hash_set_pointer: Arc<HashSet<Transaction<Tokens>>>,
        account_to_basic_identity_pointer: Arc<HashMap<Principal, Arc<BasicIdentity>>>,
        allowance_map_pointer: Arc<BTreeMap<(Account, Account), Tokens>>,
        current_balances_pointer: Arc<HashMap<Account, u64>>,
    ) -> impl Strategy<Value = ArgWithCaller> {
        let minter: Account = minter_identity.sender().unwrap().into();

        // We shouldn't even be calling `transfer_from_strategy` if there are no valid allowances,
        // i.e., allowances where the `from` account doesn't hold a balance of at least
        // `default_fee`.
        assert!(
            !valid_allowance_from.is_empty(),
            "valid_allowance_from must not be empty"
        );

        // Select a from account that has valid allowances
        let valid_from_accounts: Vec<Account> = valid_allowance_from.into_iter().collect();
        select(valid_from_accounts)
            .prop_flat_map(move |from| {
                let current_balances = current_balances_pointer.clone();
                let allowance_map = allowance_map_pointer.clone();
                let tx_hash_set_ptr = tx_hash_set_pointer.clone();
                let account_to_basic_identity_ptr = account_to_basic_identity_pointer.clone();

                // Find all allowances for this from account
                let allowances_for_from: Vec<(Account, Tokens)> = allowance_map
                    .range((
                        Included((from, MIN_ACCOUNT)),
                        Included((from, MAX_ACCOUNT)),
                    ))
                    .map(|((allowance_from, spender), allowance)| {
                        // Ensure the from account in the allowance matches the selected from account
                        assert_eq!(&from, allowance_from);
                        (*spender, *allowance)
                    })
                    .collect();

                // Ensure there are valid allowances for the selected from account, which should
                // always be true, since otherwise the `from` account would not exist in
                // `valid_allowance_from`.
                assert!(
                    !allowances_for_from.is_empty(),
                    "No valid allowances found for the selected from account"
                );

                // Select one of the allowances for this from account
                select(allowances_for_from)
                    .prop_flat_map(move |(spender, allowance)| {
                        let tx_hash_set_ptr2 = tx_hash_set_ptr.clone();
                        let account_to_basic_identity_ptr2 = account_to_basic_identity_ptr.clone();
                        let allowance_amount = allowance.get_e8s();
                        let fee_amount = default_fee;

                        // Get the current balance for this account
                        let current_balance = current_balances.get(&from).copied().unwrap_or(0);

                        // Calculate max transferable amount considering both allowance and current
                        // account balance. Both allowance and from account balance must cover
                        // transfer amount (which can be 0) + fee
                        let allowance_max =
                            allowance_amount.checked_sub(fee_amount).unwrap_or_else(|| {
                                panic!(
                                    "allowance ({allowance_amount}) must be greater than or equal to the fee ({fee_amount})",
                                )
                            });
                        let balance_max = current_balance.checked_sub(fee_amount).unwrap_or_else(|| {
                            panic!(
                                "current balance ({current_balance}) must be greater than or equal to the fee ({fee_amount})",
                            )
                        });

                        let max_amount = std::cmp::min(allowance_max, balance_max);

                        // Select from valid amounts (0 to max_amount)
                        (0..=max_amount)
                            .prop_flat_map(move |amount| {
                                let tx_hash_set = tx_hash_set_ptr2.clone();
                                let account_to_basic_identity =
                                    account_to_basic_identity_ptr2.clone();
                                let fee_amount = default_fee;

                                (
                                    basic_identity_and_account_strategy(), // to account
                                    valid_created_at_time_strategy(now),
                                    arb_memo(),
                                    prop::option::of(Just(fee_amount)),
                                )
                                    .prop_filter_map(
                                        "Invalid transfer_from transaction",
                                        move |(to_signer, created_at_time, memo, fee)| {
                                            let to = to_signer.account();

                                            let tx = Transaction {
                                                operation: Operation::Transfer::<Tokens> {
                                                    from,
                                                    to,
                                                    spender: Some(spender),
                                                    amount: Tokens::from_e8s(amount),
                                                    fee: fee.map(Tokens::from_e8s),
                                                },
                                                created_at_time,
                                                memo: memo.clone(),
                                            };

                                            if from == minter
                                                || to == minter
                                                || spender == from
                                                || spender == to
                                                || tx_hash_set.contains(&tx)
                                            {
                                                None
                                            } else {
                                                let caller = account_to_basic_identity
                                                    .get(&spender.owner)
                                                    .unwrap()
                                                    .clone();
                                                assert_eq!(caller.sender().unwrap(), spender.owner);
                                                Some(ArgWithCaller {
                                                    caller,
                                                    arg: LedgerEndpointArg::TransferFromArg(
                                                        TransferFromArgs {
                                                            spender_subaccount: spender.subaccount,
                                                            from,
                                                            to,
                                                            amount: amount.into(),
                                                            fee: fee.map(Nat::from),
                                                            memo,
                                                            created_at_time,
                                                        },
                                                    ),
                                                    principal_to_basic_identity: HashMap::from([(
                                                        to.owner,
                                                        Arc::new(to_signer.identity),
                                                    )]),
                                                })
                                            }
                                        },
                                    )
                                    .boxed()
                            })
                            .boxed()
                    })
                    .boxed()
            })
            .boxed()
    }

    fn generate_strategy(
        state: TransactionsAndBalances,
        minter_identity: Arc<BasicIdentity>,
        default_fee: u64,
        additional_length: usize,
        now: SystemTime,
        excluded_transaction_types: Vec<TransactionTypes>,
    ) -> BoxedStrategy<TransactionsAndBalances> {
        if additional_length == 0 {
            return Just(state).boxed();
        }

        // The next transaction is based on the non-dust balances in the state.
        // If there are no balances bigger than default_fees then the only next
        // transaction possible is minting, otherwise we can also burn or transfer.
        let balances = state.non_dust_balances(default_fee);
        let tx_hashes_pointer = Arc::new(state.txs.clone());
        let account_to_basic_identity_pointer = Arc::new(state.principal_to_basic_identity.clone());
        let allowance_map_pointer = Arc::new(state.allowances.clone());
        let mint_strategy =
            mint_strategy(minter_identity.clone(), now, tx_hashes_pointer.clone()).boxed();
        let arb_tx = if balances.is_empty() {
            mint_strategy
        } else {
            let account_balance = Rc::new(select(balances.clone()));
            let approve_strategy = approve_strategy(
                account_balance.clone(),
                minter_identity.clone(),
                default_fee,
                now,
                tx_hashes_pointer.clone(),
                account_to_basic_identity_pointer.clone(),
                allowance_map_pointer.clone(),
            )
            .boxed();
            let burn_strategy = burn_strategy(
                account_balance.clone(),
                minter_identity.clone(),
                default_fee,
                now,
                tx_hashes_pointer.clone(),
                account_to_basic_identity_pointer.clone(),
            )
            .boxed();
            let transfer_strategy = transfer_strategy(
                account_balance.clone(),
                minter_identity.clone(),
                default_fee,
                now,
                tx_hashes_pointer.clone(),
                account_to_basic_identity_pointer.clone(),
            )
            .boxed();
            let mut options = vec![];

            if !excluded_transaction_types.contains(&TransactionTypes::Approve) {
                options.push((10, approve_strategy));
            }
            if !excluded_transaction_types.contains(&TransactionTypes::Burn) {
                options.push((1, burn_strategy));
            }
            if !excluded_transaction_types.contains(&TransactionTypes::Mint) {
                options.push((1, mint_strategy));
            }
            if !excluded_transaction_types.contains(&TransactionTypes::Transfer) {
                options.push((1000, transfer_strategy));
            }

            if !excluded_transaction_types.contains(&TransactionTypes::TransferFrom) {
                // Set transfer_from weight if valid allowances exist
                if !state.valid_allowance_from.is_empty() {
                    let transfer_from_strategy = transfer_from_strategy(
                        state.valid_allowance_from.clone(),
                        minter_identity.clone(),
                        default_fee,
                        now,
                        tx_hashes_pointer.clone(),
                        account_to_basic_identity_pointer.clone(),
                        allowance_map_pointer.clone(),
                        Arc::new(state.balances.clone()),
                    )
                    .boxed();
                    options.push((100, transfer_from_strategy));
                }
            }

            proptest::strategy::Union::new_weighted(options).boxed()
        };

        (Just(state), arb_tx)
            .prop_flat_map(move |(mut state, tx)| {
                state.apply(minter_identity.clone(), default_fee, tx);
                generate_strategy(
                    state,
                    minter_identity.clone(),
                    default_fee,
                    additional_length - 1,
                    now,
                    excluded_transaction_types.clone(),
                )
            })
            .boxed()
    }

    assert_ne!(
        excluded_transaction_types.len(),
        TransactionTypes::COUNT,
        "At least one transaction type must be included in the strategy"
    );

    generate_strategy(
        TransactionsAndBalances::default(),
        minter_identity.clone(),
        default_fee,
        length,
        now,
        excluded_transaction_types,
    )
    .prop_map(|res| res.transactions.clone())
}

pub fn decimals_strategy() -> impl Strategy<Value = u8> {
    0..u8::MAX
}

pub fn symbol_strategy() -> impl Strategy<Value = String> {
    prop::string::string_regex("[A-Za-z0-9]{1,5}").expect("failed to make generator")
}

pub fn metadata_strategy() -> impl Strategy<Value = Vec<(String, MetadataValue)>> {
    (symbol_strategy(), decimals_strategy()).prop_map(|(symbol, decimals)| {
        vec![
            ("icrc1:symbol".to_string(), MetadataValue::Text(symbol)),
            (
                "icrc1:decimals".to_string(),
                MetadataValue::Nat(candid::Nat::from(decimals)),
            ),
        ]
    })
}

pub fn arb_account() -> impl Strategy<Value = Account> {
    (
        proptest::collection::vec(any::<u8>(), 28),
        any::<Option<[u8; 32]>>(),
    )
        .prop_map(|(mut principal, subaccount)| {
            principal.push(0x00);
            Account {
                owner: Principal::try_from_slice(&principal[..]).unwrap(),
                subaccount,
            }
        })
}

pub fn arb_transfer<Tokens, S>(arb_tokens: fn() -> S) -> impl Strategy<Value = Operation<Tokens>>
where
    Tokens: TokensType,
    S: Strategy<Value = Tokens>,
{
    (
        arb_account(),
        arb_account(),
        arb_tokens(),
        proptest::option::of(arb_tokens()),
        proptest::option::of(arb_account()),
    )
        .prop_map(|(from, to, amount, fee, spender)| Operation::Transfer {
            from,
            to,
            amount,
            fee,
            spender,
        })
}

pub fn arb_approve<Tokens, S>(arb_tokens: fn() -> S) -> impl Strategy<Value = Operation<Tokens>>
where
    Tokens: TokensType,
    S: Strategy<Value = Tokens>,
{
    (
        arb_account(),
        arb_account(),
        arb_tokens(),
        proptest::option::of(arb_tokens()),
        proptest::option::of(arb_tokens()),
        proptest::option::of(any::<u64>()),
    )
        .prop_map(
            |(from, spender, amount, fee, expected_allowance, expires_at)| Operation::Approve {
                from,
                spender,
                amount,
                fee,
                expected_allowance,
                expires_at,
            },
        )
}

pub fn arb_mint<Tokens, S>(arb_tokens: fn() -> S) -> impl Strategy<Value = Operation<Tokens>>
where
    Tokens: TokensType,
    S: Strategy<Value = Tokens>,
{
    (
        arb_account(),
        arb_tokens(),
        proptest::option::of(arb_tokens()),
    )
        .prop_map(|(to, amount, fee)| Operation::Mint { to, amount, fee })
}

pub fn arb_burn<Tokens, S>(arb_tokens: fn() -> S) -> impl Strategy<Value = Operation<Tokens>>
where
    Tokens: TokensType,
    S: Strategy<Value = Tokens>,
{
    (
        arb_account(),
        proptest::option::of(arb_account()),
        arb_tokens(),
        proptest::option::of(arb_tokens()),
    )
        .prop_map(|(from, spender, amount, fee)| Operation::Burn {
            from,
            spender,
            amount,
            fee,
        })
}

pub fn arb_operation<Tokens, S>(arb_tokens: fn() -> S) -> impl Strategy<Value = Operation<Tokens>>
where
    Tokens: TokensType,
    S: Strategy<Value = Tokens>,
{
    prop_oneof![
        arb_transfer(arb_tokens),
        arb_mint(arb_tokens),
        arb_burn(arb_tokens),
        arb_approve(arb_tokens)
    ]
}

pub fn arb_transaction<Tokens, S>(
    arb_tokens: fn() -> S,
    max_memo_length: usize,
) -> impl Strategy<Value = Transaction<Tokens>>
where
    Tokens: TokensType,
    S: Strategy<Value = Tokens>,
{
    (
        arb_operation(arb_tokens),
        any::<Option<u64>>(),
        proptest::option::of(proptest::collection::vec(any::<u8>(), 0..=max_memo_length)),
    )
        .prop_map(|(operation, ts, memo)| Transaction {
            operation,
            created_at_time: ts,
            memo: memo.map(Memo::from),
        })
}

pub fn arb_block<Tokens, S>(
    arb_tokens: fn() -> S,
    max_memo_length: usize,
) -> impl Strategy<Value = Block<Tokens>>
where
    Tokens: TokensType,
    S: Strategy<Value = Tokens>,
{
    (
        any::<Option<[u8; 32]>>(),
        arb_transaction(arb_tokens, max_memo_length),
        proptest::option::of(arb_tokens()),
        any::<u64>(),
        proptest::option::of(arb_account()),
        proptest::option::of(any::<u64>()),
    )
        .prop_map(
            |(parent_hash, transaction, effective_fee, ts, fee_col, fee_col_block)| Block {
                parent_hash: parent_hash.map(HashOf::new),
                transaction,
                effective_fee,
                timestamp: ts,
                fee_collector: fee_col,
                fee_collector_block_index: fee_col_block,
                btype: None,
            },
        )
}

pub fn currency_strategy() -> impl Strategy<Value = Currency> {
    (decimals_strategy(), symbol_strategy()).prop_map(|(decimals, symbol)| Currency {
        symbol,
        decimals: decimals.into(),
        metadata: None,
    })
}

pub fn construction_payloads_request_metadata() -> impl Strategy<Value = ObjectMap> {
    let memo_strategy = arb_memo();
    let now = SystemTime::now();
    // We select the last and next 48 hours as an interval in which the ingress boundaries are set
    // They do not have to be valid
    let ingress_interval_start =
        now.duration_since(UNIX_EPOCH).unwrap() - Duration::from_secs(60 * 60 * 48);
    let ingress_interval_end =
        now.duration_since(UNIX_EPOCH).unwrap() + Duration::from_secs(60 * 60 * 48);
    let ingress_start_strategy =
        prop::option::of(ingress_interval_start.as_nanos()..ingress_interval_end.as_nanos());
    let ingress_end_strategy =
        prop::option::of(ingress_interval_start.as_nanos()..ingress_interval_end.as_nanos());
    let created_at_time =
        prop::option::of(ingress_interval_start.as_nanos()..ingress_interval_end.as_nanos());

    (
        memo_strategy,
        ingress_start_strategy,
        ingress_end_strategy,
        created_at_time,
    )
        .prop_map(|(memo, ingress_start, ingress_end, created_at_time)| {
            let mut map = ObjectMap::new();
            map.insert(
                "memo".to_string(),
                memo.map(|m| m.0.as_slice().to_vec()).into(),
            );
            map.insert("ingress_start".to_string(), json!(ingress_start));
            map.insert("ingress_end".to_string(), json!(ingress_end));
            map.insert("created_at_time".to_string(), json!(created_at_time));
            map
        })
}

pub trait KeyPairGenerator<K: RosettaSupportedKeyPair> {
    fn generate(seed: u64) -> K;
}

impl KeyPairGenerator<Ed25519KeyPair> for Ed25519KeyPair {
    fn generate(seed: u64) -> Ed25519KeyPair {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
        let secret_key = Ed25519SecretKey::generate_using_rng(&mut rng);
        Ed25519KeyPair::deserialize_raw(&secret_key.serialize_raw())
            .expect("failed to deserialize secret_key")
    }
}

impl KeyPairGenerator<Secp256k1KeyPair> for Secp256k1KeyPair {
    fn generate(seed: u64) -> Secp256k1KeyPair {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
        let secret_key = Secp256k1PrivateKey::generate_using_rng(&mut rng);
        Secp256k1KeyPair::deserialize_sec1(&secret_key.serialize_sec1())
            .expect("failed to deserialize secret_key")
    }
}

impl KeyPairGenerator<Arc<BasicIdentity>> for Arc<BasicIdentity> {
    fn generate(seed: u64) -> Arc<BasicIdentity> {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
        let secret_key = Ed25519SecretKey::generate_using_rng(&mut rng);
        Arc::new(
            BasicIdentity::from_pem(std::io::Cursor::new(
                secret_key
                    .serialize_pkcs8_pem(PrivateKeyFormat::Pkcs8v2)
                    .into_bytes(),
            ))
            .unwrap(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::KeyPairGenerator;
    use crate::{minter_identity, valid_transactions_strategy};
    use ic_agent::identity::BasicIdentity;
    use ic_types::PrincipalId;
    use proptest::{
        strategy::{Strategy, ValueTree},
        test_runner::TestRunner,
    };
    use rand::RngCore;
    use rosetta_core::models::Ed25519KeyPair;
    use rosetta_core::models::RosettaSupportedKeyPair;
    use rosetta_core::objects::PublicKey;
    use std::sync::Arc;
    use std::time::SystemTime;

    #[test]
    fn test_valid_transactions_strategy_generates_transaction() {
        let size = 10;
        let strategy = valid_transactions_strategy(
            Arc::new(minter_identity()),
            10_000,
            size,
            SystemTime::now(),
        );
        let tree = strategy
            .new_tree(&mut TestRunner::default())
            .expect("Unable to run valid_transactions_strategy");
        assert_eq!(tree.current().len(), size)
    }

    #[test]
    fn test_basic_identity_to_edwards() {
        let seed = ic_crypto_test_utils_reproducible_rng::reproducible_rng().next_u64();
        let edw = Arc::new(Ed25519KeyPair::generate(seed));
        let bi = Arc::<BasicIdentity>::generate(seed);

        assert_eq!(edw.get_curve_type(), bi.get_curve_type());

        assert_eq!(
            edw.generate_principal_id().unwrap(),
            bi.generate_principal_id().unwrap()
        );

        assert_eq!(edw.get_pb_key(), bi.get_pb_key());

        let bytes = b"Hello, World!";
        assert_eq!(edw.sign(bytes), bi.sign(bytes));

        assert_eq!(edw.hex_encode_pk(), bi.hex_encode_pk());

        assert_eq!(
            Arc::<Ed25519KeyPair>::der_encode_pk(edw.get_pb_key()).unwrap(),
            Arc::<BasicIdentity>::der_encode_pk(bi.get_pb_key()).unwrap()
        );

        assert_eq!(edw.hex_encode_pk(), bi.hex_encode_pk());

        assert_eq!(
            Arc::<Ed25519KeyPair>::get_principal_id(&edw.hex_encode_pk()).unwrap(),
            Arc::<BasicIdentity>::get_principal_id(&bi.hex_encode_pk()).unwrap()
        );

        assert_eq!(
            edw.generate_principal_id().unwrap(),
            PrincipalId::new_self_authenticating(
                &Arc::<Ed25519KeyPair>::der_encode_pk(edw.get_pb_key()).unwrap()
            )
        );
        assert_eq!(
            bi.generate_principal_id().unwrap(),
            PrincipalId::new_self_authenticating(
                &Arc::<Ed25519KeyPair>::der_encode_pk(bi.get_pb_key()).unwrap()
            )
        );

        let pk: PublicKey = (&edw).into();
        assert_eq!(
            pk.get_der_encoding().unwrap(),
            Arc::<Ed25519KeyPair>::der_encode_pk(edw.get_pb_key()).unwrap()
        );
        assert_eq!(
            pk.get_principal().unwrap(),
            edw.generate_principal_id().unwrap().0
        );
    }
}
