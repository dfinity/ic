pub mod blocks;
mod compact_account;
pub mod endpoints;
pub mod hash;
pub(crate) mod known_tags;

use candid::Principal;
use ciborium::tag::Required;
use ic_ledger_canister_core::ledger::{LedgerContext, LedgerTransaction, TxApplyError};
use ic_ledger_core::{
    approvals::{AllowanceTable, HeapAllowancesData},
    balances::Balances,
    block::{BlockType, EncodedBlock, FeeCollector},
    timestamp::TimeStamp,
    tokens::TokensType,
};
use ic_ledger_hash_of::HashOf;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::Memo;
use serde::{Deserialize, Serialize};

use std::collections::BTreeMap;

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
#[serde(bound = "")]
#[serde(tag = "op")]
pub enum Operation<Tokens: TokensType> {
    Mint {
        #[serde(with = "compact_account")]
        to: Account,
        #[serde(rename = "amt")]
        amount: Tokens,
        #[serde(skip_serializing_if = "Option::is_none")]
        fee: Option<Tokens>,
    },
    Transfer {
        #[serde(with = "compact_account")]
        from: Account,
        #[serde(with = "compact_account")]
        to: Account,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "compact_account::opt"
        )]
        spender: Option<Account>,
        #[serde(rename = "amt")]
        amount: Tokens,
        #[serde(skip_serializing_if = "Option::is_none")]
        fee: Option<Tokens>,
    },
    Burn {
        #[serde(with = "compact_account")]
        from: Account,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "compact_account::opt"
        )]
        spender: Option<Account>,
        #[serde(rename = "amt")]
        amount: Tokens,
        #[serde(skip_serializing_if = "Option::is_none")]
        fee: Option<Tokens>,
    },
    Approve {
        #[serde(with = "compact_account")]
        from: Account,
        #[serde(with = "compact_account")]
        spender: Account,
        #[serde(rename = "amt")]
        amount: Tokens,
        #[serde(skip_serializing_if = "Option::is_none")]
        expected_allowance: Option<Tokens>,
        #[serde(skip_serializing_if = "Option::is_none")]
        expires_at: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        fee: Option<Tokens>,
    },
    FeeCollector {
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "compact_account::opt"
        )]
        fee_collector: Option<Account>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        caller: Option<Principal>,
    },
}

// A [Transaction] but flattened meaning that [Operation]
// fields are mixed with [Transaction] fields.
// We have to flatten the structure as a workaround for
// https://github.com/serde-rs/json/issues/625.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(bound = "")]
struct FlattenedTransaction<Tokens: TokensType> {
    // [Transaction] fields.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "ts")]
    pub created_at_time: Option<u64>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memo: Option<Memo>,

    // [Operation] fields.
    pub op: String,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "compact_account::opt")]
    from: Option<Account>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "compact_account::opt")]
    to: Option<Account>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "compact_account::opt")]
    spender: Option<Account>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "amt")]
    amount: Option<Tokens>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    fee: Option<Tokens>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_allowance: Option<Tokens>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<u64>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "compact_account::opt")]
    fee_collector: Option<Account>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    caller: Option<Principal>,
}

impl<Tokens: TokensType> TryFrom<FlattenedTransaction<Tokens>> for Transaction<Tokens> {
    type Error = String;

    fn try_from(value: FlattenedTransaction<Tokens>) -> Result<Self, Self::Error> {
        let operation = match value.op.as_str() {
            "burn" => Operation::Burn {
                from: value
                    .from
                    .ok_or("`from` field required for `burn` operation")?,
                amount: value
                    .amount
                    .ok_or("`amount` required for `burn` operations")?,
                spender: value.spender,
                fee: value.fee,
            },
            "mint" => Operation::Mint {
                to: value.to.ok_or("`to` field required for `mint` operation")?,
                amount: value
                    .amount
                    .ok_or("`amount` required for `mint` operations")?,
                fee: value.fee,
            },
            "xfer" => Operation::Transfer {
                from: value
                    .from
                    .ok_or("`from` field required for `xfer` operation")?,
                spender: value.spender,
                to: value.to.ok_or("`to` field required for `xfer` operation")?,
                amount: value
                    .amount
                    .ok_or("`amount` required for `xfer` operations")?,
                fee: value.fee,
            },
            "approve" => Operation::Approve {
                from: value
                    .from
                    .ok_or("`from` field required for `approve` operation")?,
                spender: value
                    .spender
                    .ok_or("`spender` field required for `approve` operation")?,
                amount: value
                    .amount
                    .ok_or("`amount` required for `approve` operations")?,
                expected_allowance: value.expected_allowance,
                expires_at: value.expires_at,
                fee: value.fee,
            },
            "107set_fee_collector" => Operation::FeeCollector {
                fee_collector: value.fee_collector,
                caller: value.caller,
            },
            unknown_op => return Err(format!("Unknown operation name {unknown_op}")),
        };
        Ok(Transaction {
            operation,
            created_at_time: value.created_at_time,
            memo: value.memo,
        })
    }
}

impl<Tokens: TokensType> From<Transaction<Tokens>> for FlattenedTransaction<Tokens> {
    fn from(t: Transaction<Tokens>) -> Self {
        use Operation::*;

        FlattenedTransaction {
            created_at_time: t.created_at_time,
            memo: t.memo,
            op: match &t.operation {
                Burn { .. } => "burn",
                Mint { .. } => "mint",
                Transfer { .. } => "xfer",
                Approve { .. } => "approve",
                FeeCollector { .. } => "107set_fee_collector",
            }
            .into(),
            from: match &t.operation {
                Transfer { from, .. } | Burn { from, .. } | Approve { from, .. } => Some(*from),
                _ => None,
            },
            to: match &t.operation {
                Mint { to, .. } | Transfer { to, .. } => Some(*to),
                _ => None,
            },
            spender: match &t.operation {
                Transfer { spender, .. } | Burn { spender, .. } => spender.to_owned(),
                Approve { spender, .. } => Some(*spender),
                _ => None,
            },
            amount: match &t.operation {
                Burn { amount, .. }
                | Mint { amount, .. }
                | Transfer { amount, .. }
                | Approve { amount, .. } => Some(amount.clone()),
                FeeCollector { .. } => None,
            },
            fee: match &t.operation {
                Transfer { fee, .. }
                | Approve { fee, .. }
                | Mint { fee, .. }
                | Burn { fee, .. } => fee.to_owned(),
                FeeCollector { .. } => None,
            },
            expected_allowance: match &t.operation {
                Approve {
                    expected_allowance, ..
                } => expected_allowance.to_owned(),
                _ => None,
            },
            expires_at: match &t.operation {
                Approve { expires_at, .. } => expires_at.to_owned(),
                _ => None,
            },
            fee_collector: match &t.operation {
                FeeCollector { fee_collector, .. } => fee_collector.to_owned(),
                _ => None,
            },
            caller: match &t.operation {
                FeeCollector { caller, .. } => caller.to_owned(),
                _ => None,
            },
        }
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
#[serde(bound = "")]
#[serde(try_from = "FlattenedTransaction<Tokens>")]
#[serde(into = "FlattenedTransaction<Tokens>")]
pub struct Transaction<Tokens: TokensType> {
    pub operation: Operation<Tokens>,
    pub created_at_time: Option<u64>,
    pub memo: Option<Memo>,
}

impl<Tokens: TokensType> LedgerTransaction for Transaction<Tokens> {
    type AccountId = Account;
    type Tokens = Tokens;

    fn burn(
        from: Account,
        spender: Option<Account>,
        amount: Tokens,
        created_at_time: Option<TimeStamp>,
        memo: Option<u64>,
    ) -> Self {
        Self {
            operation: Operation::Burn {
                from,
                spender,
                amount,
                fee: None,
            },
            created_at_time: created_at_time.map(|t| t.as_nanos_since_unix_epoch()),
            memo: memo.map(Memo::from),
        }
    }

    fn approve(
        from: Self::AccountId,
        spender: Self::AccountId,
        amount: Self::Tokens,
        created_at_time: Option<TimeStamp>,
        memo: Option<u64>,
    ) -> Self {
        Self {
            operation: Operation::Approve {
                from,
                spender,
                amount,
                expected_allowance: None,
                expires_at: None,
                fee: None,
            },
            created_at_time: created_at_time.map(|t| t.as_nanos_since_unix_epoch()),
            memo: memo.map(Memo::from),
        }
    }

    fn created_at_time(&self) -> Option<TimeStamp> {
        self.created_at_time
            .map(TimeStamp::from_nanos_since_unix_epoch)
    }

    fn hash(&self) -> HashOf<Self> {
        let mut cbor_bytes = vec![];
        ciborium::ser::into_writer(self, &mut cbor_bytes)
            .expect("bug: failed to encode a transaction");
        hash::hash_cbor(&cbor_bytes)
            .map(HashOf::new)
            .unwrap_or_else(|err| {
                panic!(
                    "bug: transaction CBOR {} is not hashable: {}",
                    hex::encode(&cbor_bytes),
                    err
                )
            })
    }

    fn apply<C>(
        &self,
        context: &mut C,
        now: TimeStamp,
        effective_fee: Tokens,
    ) -> Result<(), TxApplyError<Tokens>>
    where
        C: LedgerContext<AccountId = Self::AccountId, Tokens = Tokens>,
    {
        let fee_collector = context.fee_collector().map(|fc| fc.fee_collector);
        let fee_collector = fee_collector.as_ref();
        match &self.operation {
            Operation::Transfer {
                from,
                to,
                spender,
                amount,
                fee,
            } => {
                let fee = fee.clone().unwrap_or(effective_fee);
                if spender.is_none() || from == &spender.unwrap() {
                    context.balances_mut().transfer(
                        from,
                        to,
                        amount.clone(),
                        fee,
                        fee_collector,
                    )?;
                    return Ok(());
                }

                let allowance = context.approvals().allowance(from, &spender.unwrap(), now);
                let used_allowance =
                    amount
                        .checked_add(&fee)
                        .ok_or(TxApplyError::InsufficientAllowance {
                            allowance: allowance.amount.clone(),
                        })?;
                if allowance.amount < used_allowance {
                    return Err(TxApplyError::InsufficientAllowance {
                        allowance: allowance.amount,
                    });
                }
                context
                    .balances_mut()
                    .transfer(from, to, amount.clone(), fee, fee_collector)?;
                context
                    .approvals_mut()
                    .use_allowance(from, &spender.unwrap(), used_allowance, now)
                    .expect("bug: cannot use allowance");
            }
            Operation::Burn {
                from,
                spender,
                amount,
                fee,
            } => {
                if fee.is_some() {
                    return Err(TxApplyError::BurnOrMintFee);
                }
                if spender.is_some() && from != &spender.unwrap() {
                    let allowance = context.approvals().allowance(from, &spender.unwrap(), now);
                    if allowance.amount < *amount {
                        return Err(TxApplyError::InsufficientAllowance {
                            allowance: allowance.amount,
                        });
                    }
                }
                context.balances_mut().burn(from, amount.clone())?;
                if spender.is_some() && from != &spender.unwrap() {
                    context
                        .approvals_mut()
                        .use_allowance(from, &spender.unwrap(), amount.clone(), now)
                        .expect("bug: cannot use allowance");
                }
            }
            Operation::Mint { to, amount, fee } => {
                if fee.is_some() {
                    return Err(TxApplyError::BurnOrMintFee);
                }
                context.balances_mut().mint(to, amount.clone())?;
            }
            Operation::Approve {
                from,
                spender,
                amount,
                expected_allowance,
                expires_at,
                fee,
            } => {
                context
                    .balances_mut()
                    .burn(from, fee.clone().unwrap_or(effective_fee.clone()))?;
                let result = context
                    .approvals_mut()
                    .approve(
                        from,
                        spender,
                        amount.clone(),
                        expires_at.map(TimeStamp::from_nanos_since_unix_epoch),
                        now,
                        expected_allowance.clone(),
                    )
                    .map_err(TxApplyError::from);
                if let Err(e) = result {
                    context
                        .balances_mut()
                        .mint(from, fee.clone().unwrap_or(effective_fee))
                        .expect("bug: failed to refund approval fee");
                    return Err(e);
                }
            }
            Operation::FeeCollector { .. } => {
                panic!("FeeCollector107 not implemented")
            }
        }
        Ok(())
    }
}

impl<Tokens: TokensType> Transaction<Tokens> {
    pub fn mint(
        to: Account,
        amount: Tokens,
        created_at_time: Option<TimeStamp>,
        memo: Option<Memo>,
    ) -> Self {
        Self {
            operation: Operation::Mint {
                to,
                amount,
                fee: None,
            },
            created_at_time: created_at_time.map(|t| t.as_nanos_since_unix_epoch()),
            memo,
        }
    }

    pub fn transfer(
        from: Account,
        to: Account,
        spender: Option<Account>,
        amount: Tokens,
        fee: Option<Tokens>,
        created_at_time: Option<TimeStamp>,
        memo: Option<Memo>,
    ) -> Self {
        Self {
            operation: Operation::Transfer {
                from,
                to,
                spender,
                amount,
                fee,
            },
            created_at_time: created_at_time.map(|t| t.as_nanos_since_unix_epoch()),
            memo,
        }
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct Block<Tokens: TokensType> {
    #[serde(rename = "phash")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_hash: Option<HashOf<EncodedBlock>>,

    #[serde(rename = "tx")]
    pub transaction: Transaction<Tokens>,

    #[serde(rename = "fee")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_fee: Option<Tokens>,

    #[serde(rename = "ts")]
    pub timestamp: u64,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "fee_col")]
    #[serde(with = "compact_account::opt")]
    pub fee_collector: Option<Account>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "fee_col_block")]
    pub fee_collector_block_index: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "btype")]
    pub btype: Option<String>,
}

type TaggedBlock<Tokens> = Required<Block<Tokens>, 55799>;

impl<Tokens: TokensType> BlockType for Block<Tokens> {
    type Transaction = Transaction<Tokens>;
    type AccountId = Account;
    type Tokens = Tokens;

    fn encode(self) -> EncodedBlock {
        let mut bytes = vec![];
        let value: TaggedBlock<Tokens> = Required(self);
        ciborium::ser::into_writer(&value, &mut bytes).expect("bug: failed to encode a block");
        EncodedBlock::from_vec(bytes)
    }

    fn decode(encoded_block: EncodedBlock) -> Result<Self, String> {
        let bytes = encoded_block.into_vec();
        let tagged_block: TaggedBlock<Tokens> = ciborium::de::from_reader(&bytes[..])
            .map_err(|e| format!("failed to decode a block: {e}"))?;
        Ok(tagged_block.0)
    }

    fn block_hash(encoded_block: &EncodedBlock) -> HashOf<EncodedBlock> {
        hash::hash_cbor(encoded_block.as_slice())
            .map(HashOf::new)
            .unwrap_or_else(|err| {
                panic!(
                    "bug: encoded block {} is not hashable cbor: {}",
                    hex::encode(encoded_block.as_slice()),
                    err
                )
            })
    }

    fn parent_hash(&self) -> Option<HashOf<EncodedBlock>> {
        self.parent_hash
    }

    fn timestamp(&self) -> TimeStamp {
        TimeStamp::from_nanos_since_unix_epoch(self.timestamp)
    }

    fn from_transaction(
        parent_hash: Option<HashOf<EncodedBlock>>,
        transaction: Self::Transaction,
        timestamp: TimeStamp,
        effective_fee: Tokens,
        fee_collector: Option<FeeCollector<Self::AccountId>>,
    ) -> Self {
        let effective_fee = match &transaction.operation {
            Operation::Transfer { fee, .. } => fee.is_none().then_some(effective_fee),
            Operation::Approve { fee, .. } => fee.is_none().then_some(effective_fee),
            Operation::FeeCollector { .. } => {
                panic!("FeeCollector107 not implemented")
            }
            _ => None,
        };
        let (fee_collector, fee_collector_block_index) = match fee_collector {
            Some(FeeCollector {
                fee_collector,
                block_index: None,
            }) => (Some(fee_collector), None),
            Some(FeeCollector { block_index, .. }) => (None, block_index),
            None => (None, None),
        };
        Self {
            parent_hash,
            transaction,
            effective_fee,
            timestamp: timestamp.as_nanos_since_unix_epoch(),
            fee_collector,
            fee_collector_block_index,
            btype: None,
        }
    }
}

pub type LedgerBalances<Tokens> = Balances<BTreeMap<Account, Tokens>>;
pub type LedgerAllowances<Tokens> = AllowanceTable<HeapAllowancesData<Account, Tokens>>;
