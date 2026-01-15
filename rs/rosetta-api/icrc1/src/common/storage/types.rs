use anyhow::anyhow;
use anyhow::bail;
use candid::CandidType;
use candid::Nat;
use candid::{Decode, Encode};
use ic_icrc1::blocks::encoded_block_to_generic_block;
use ic_ledger_core::block::EncodedBlock;
use ic_ledger_core::tokens::TokensType;
use icrc_ledger_types::icrc::generic_metadata_value::MetadataValue;
use icrc_ledger_types::icrc3::blocks::GenericBlock;
use icrc_ledger_types::{
    icrc::generic_value::Value,
    icrc1::{account::Account, transfer::Memo},
};
use rosetta_core::identifiers::BlockIdentifier;
use rusqlite::ToSql;
use rusqlite::types::{FromSql, FromSqlError, FromSqlResult};
use serde::ser::StdError;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::collections::BTreeMap;

/// Enum representing the different counter types used in the ICRC1 Rosetta storage system.
/// Each counter serves a specific purpose for tracking state and ensuring data integrity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RosettaCounter {
    /// Tracks the number of blocks that have been synchronized and stored in the database.
    ///
    /// - **Type**: INTEGER
    /// - **Initial value**: Set to the current count of blocks in the blocks table
    /// - **Updates**: Automatically incremented by 1 via database trigger when new blocks are inserted
    /// - **Usage**: Used by `get_block_count()` to efficiently retrieve the total number of synced blocks
    /// - **Reset**: Can be reset to match actual block count via `reset_blocks_counter()`
    SyncedBlocks,

    /// Flag indicating whether the fee collector balance repair has been completed.
    ///
    /// - **Type**: INTEGER (used as boolean flag)
    /// - **Value**: Set to 1 when the `repair_fee_collector_balances()` function has been executed
    /// - **Usage**: Prevents redundant execution of the balance repair process
    /// - **Context**: Used to fix account balances for databases created before the fee collector
    ///   block index fix (https://github.com/dfinity/ic/pull/5304) was implemented
    /// - **One-time operation**: Once set, this counter prevents the repair from running again
    CollectorBalancesFixed,
}

impl RosettaCounter {
    /// Returns the string name used to identify this counter in the database.
    pub fn name(&self) -> &'static str {
        match self {
            RosettaCounter::SyncedBlocks => "SyncedBlocks",
            RosettaCounter::CollectorBalancesFixed => "CollectorBalancesFixed",
        }
    }

    /// Returns the default initial value for this counter.
    pub fn default_value(&self) -> i64 {
        match self {
            RosettaCounter::SyncedBlocks => 0, // Will be set to actual block count during initialization
            RosettaCounter::CollectorBalancesFixed => 0, // Flag starts as false (0)
        }
    }

    /// Returns whether this counter represents a boolean flag (0/1 values only).
    pub fn is_flag(&self) -> bool {
        match self {
            RosettaCounter::SyncedBlocks => false,
            RosettaCounter::CollectorBalancesFixed => true,
        }
    }
}

impl std::fmt::Display for RosettaCounter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct RosettaBlock {
    pub index: u64,
    pub block: IcrcBlock,
}

impl RosettaBlock {
    // Converts a generic block to a RosettaBlock
    // Use this method for blocks that come directly from an ICRC-1 Ledger, because only then can be guarenteed that the block hash is correct
    pub fn from_generic_block(generic_block: GenericBlock, block_idx: u64) -> anyhow::Result<Self> {
        Ok(Self {
            block: IcrcBlock::try_from(generic_block)?,
            index: block_idx,
        })
    }

    pub fn from_icrc_ledger_block(block: IcrcBlock, block_idx: u64) -> Self {
        Self {
            block,
            index: block_idx,
        }
    }

    pub fn from_encoded_block(eb: &EncodedBlock, block_idx: u64) -> anyhow::Result<Self> {
        Ok(Self {
            block: IcrcBlock::try_from(encoded_block_to_generic_block(eb))?,
            index: block_idx,
        })
    }

    pub fn get_generic_block(&self) -> GenericBlock {
        self.block.clone().into()
    }

    pub fn get_block_hash(self) -> ByteBuf {
        ByteBuf::from(self.block.hash())
    }

    pub fn get_effective_fee(&self) -> Option<Nat> {
        self.block.effective_fee.clone()
    }

    pub fn get_transaction_hash(self) -> ByteBuf {
        ByteBuf::from(self.block.transaction.hash())
    }

    pub fn get_timestamp(&self) -> u64 {
        self.block.timestamp
    }

    pub fn get_parent_hash(&self) -> Option<ByteBuf> {
        self.block.parent_hash.map(ByteBuf::from)
    }

    pub fn get_fee_paid(&self) -> anyhow::Result<Option<Nat>> {
        Ok(self
            .get_effective_fee()
            .or(match self.get_transaction().operation {
                IcrcOperation::Mint { fee, .. } => fee,
                IcrcOperation::Transfer { fee, .. } => fee,
                IcrcOperation::Approve { fee, .. } => fee,
                IcrcOperation::Burn { fee, .. } => fee,
            }))
    }

    pub fn get_transaction(&self) -> IcrcTransaction {
        self.block.transaction.clone()
    }

    pub fn get_fee_collector(&self) -> Option<Account> {
        self.block.fee_collector
    }

    pub fn get_fee_collector_block_index(&self) -> Option<u64> {
        self.block.fee_collector_block_index
    }

    pub fn get_icrc1_block(&self) -> IcrcBlock {
        self.block.clone()
    }

    pub fn get_parent_block_identifier(&self) -> BlockIdentifier {
        self.get_parent_hash()
            .as_ref()
            .map(|ph| BlockIdentifier::from_bytes(self.index.saturating_sub(1), ph))
            .unwrap_or_else(|| {
                BlockIdentifier::from_bytes(self.index, &self.clone().get_block_hash())
            })
    }

    pub fn get_transaction_identifier(self) -> rosetta_core::identifiers::TransactionIdentifier {
        rosetta_core::identifiers::TransactionIdentifier::from_bytes(&self.get_transaction_hash())
    }

    pub fn get_block_identifier(self) -> rosetta_core::identifiers::BlockIdentifier {
        BlockIdentifier::from_bytes(self.index, &self.get_block_hash())
    }
}
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct IcrcBlock {
    pub parent_hash: Option<[u8; 32]>,
    pub transaction: IcrcTransaction,
    pub effective_fee: Option<Nat>,
    pub timestamp: u64,
    pub fee_collector: Option<Account>,
    pub fee_collector_block_index: Option<u64>,
}

impl IcrcBlock {
    pub fn hash(self) -> [u8; 32] {
        Value::from(self).hash()
    }
}

impl From<RosettaBlock> for BlockIdentifier {
    fn from(block: RosettaBlock) -> Self {
        Self {
            index: block.index,
            hash: hex::encode(block.block.hash()),
        }
    }
}

impl TryFrom<Value> for IcrcBlock {
    type Error = anyhow::Error;

    fn try_from(value: Value) -> anyhow::Result<Self> {
        // The base of all fields is a BTreeMap that holds all the other fields from the ICRC-3 standard
        let map = value
            .as_map()
            .map_err(|err| anyhow!("The block top level element should be map: {:?}", err))?;

        // Now we can try to extract every field that corresponds to a Block object from the map
        let parent_hash = get_opt_field::<Vec<u8>>(&map, &[], "phash")?
            .map(|bs| {
                bs.try_into()
                    .map_err(|_| anyhow!("phash should be 32 bytes"))
            })
            .transpose()?;
        let timestamp = get_field::<u64>(&map, &[], "ts")?;
        let effective_fee = get_opt_field::<Nat>(&map, &[], "fee")?;
        let fee_collector = get_opt_field::<Account>(&map, &[], "fee_col")?;
        let fee_collector_block_index = get_opt_field::<u64>(&map, &[], "fee_col_block")?;
        let transaction = map.get("tx").ok_or(anyhow!("Missing field 'tx'"))?.clone();
        let transaction = IcrcTransaction::try_from(transaction)?;

        Ok(Self {
            parent_hash,
            transaction,
            effective_fee,
            timestamp,
            fee_collector,
            fee_collector_block_index,
        })
    }
}

impl From<IcrcBlock> for Value {
    fn from(block: IcrcBlock) -> Self {
        // To convert a Block object into a GenericValue we create a Map at the root of the object and store every field of the Block object as an entry in the map
        let mut map = BTreeMap::new();
        if let Some(parent_hash) = block.parent_hash {
            let parent_hash = ByteBuf::from(parent_hash);
            map.insert("phash".to_string(), Value::Blob(parent_hash));
        }
        map.insert("tx".to_string(), Value::from(block.transaction));
        if let Some(effective_fee) = block.effective_fee {
            map.insert("fee".to_string(), Value::Nat(effective_fee));
        }
        map.insert("ts".to_string(), Value::Nat(Nat::from(block.timestamp)));
        if let Some(fee_col) = block.fee_collector {
            map.insert("fee_col".to_string(), Value::from(fee_col));
        }
        if let Some(fee_col_block) = block.fee_collector_block_index {
            map.insert(
                "fee_col_block".to_string(),
                Value::Nat(Nat::from(fee_col_block)),
            );
        }
        Self::Map(map)
    }
}

impl ToSql for IcrcBlock {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        Ok(Encode!(self)
            .map_err(|_| rusqlite::Error::from(FromSqlError::InvalidType))?
            .into())
    }
}

impl FromSql for IcrcBlock {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> FromSqlResult<Self> {
        let s = match value {
            rusqlite::types::ValueRef::Text(text) => text.to_vec(),
            rusqlite::types::ValueRef::Blob(blob) => blob.to_vec(),
            _ => Vec::new(),
        };

        match Decode!(&s, IcrcBlock) {
            Ok(t) => Ok(t),
            Err(err) => {
                let err: Box<dyn StdError + Send + Sync + 'static> = err.into();
                Err(FromSqlError::Other(err))
            }
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct IcrcTransaction {
    pub operation: IcrcOperation,
    pub created_at_time: Option<u64>,
    pub memo: Option<Memo>,
}

impl IcrcTransaction {
    pub fn hash(self) -> [u8; 32] {
        Value::from(self).hash()
    }
}

impl TryFrom<Value> for IcrcTransaction {
    type Error = anyhow::Error;

    fn try_from(value: Value) -> anyhow::Result<Self> {
        const FIELD_PREFIX: &[&str] = &["tx"];
        let map = value.as_map().map_err(|err| anyhow!("{:?}", err))?;

        let created_at_time = get_opt_field::<u64>(&map, FIELD_PREFIX, "ts")?;
        let memo = get_opt_field::<ByteBuf>(&map, FIELD_PREFIX, "memo")?.map(Memo);
        let operation = IcrcOperation::try_from(map)?;
        Ok(Self {
            operation,
            created_at_time,
            memo,
        })
    }
}

impl From<IcrcTransaction> for Value {
    fn from(
        IcrcTransaction {
            operation,
            created_at_time,
            memo,
        }: IcrcTransaction,
    ) -> Self {
        let mut map = BTreeMap::from(operation);
        if let Some(created_at_time) = created_at_time {
            map.insert("ts".to_string(), Value::Nat(Nat::from(created_at_time)));
        }
        if let Some(memo) = memo {
            map.insert("memo".to_string(), Value::Blob(memo.0));
        }
        Self::Map(map)
    }
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub enum IcrcOperation {
    Mint {
        to: Account,
        amount: Nat,
        fee: Option<Nat>,
    },
    Transfer {
        from: Account,
        to: Account,
        spender: Option<Account>,
        amount: Nat,
        fee: Option<Nat>,
    },
    Burn {
        from: Account,
        spender: Option<Account>,
        amount: Nat,
        fee: Option<Nat>,
    },
    Approve {
        from: Account,
        spender: Account,
        amount: Nat,
        expected_allowance: Option<Nat>,
        expires_at: Option<u64>,
        fee: Option<Nat>,
    },
}

impl TryFrom<BTreeMap<String, Value>> for IcrcOperation {
    type Error = anyhow::Error;

    fn try_from(map: BTreeMap<String, Value>) -> anyhow::Result<Self> {
        const FIELD_PREFIX: &[&str] = &["tx"];
        let amount: Nat = get_field(&map, FIELD_PREFIX, "amt")?;
        let fee: Option<Nat> = get_opt_field(&map, FIELD_PREFIX, "fee")?;
        match get_field::<String>(&map, FIELD_PREFIX, "op")?.as_str() {
            "burn" => {
                let from: Account = get_field(&map, FIELD_PREFIX, "from")?;
                let spender: Option<Account> = get_opt_field(&map, FIELD_PREFIX, "spender")?;
                Ok(Self::Burn {
                    from,
                    spender,
                    amount,
                    fee,
                })
            }
            "mint" => {
                let to: Account = get_field(&map, FIELD_PREFIX, "to")?;
                Ok(Self::Mint { to, amount, fee })
            }
            "xfer" => {
                let from: Account = get_field(&map, FIELD_PREFIX, "from")?;
                let to: Account = get_field(&map, FIELD_PREFIX, "to")?;
                let spender: Option<Account> = get_opt_field(&map, FIELD_PREFIX, "spender")?;
                Ok(Self::Transfer {
                    from,
                    to,
                    spender,
                    amount,
                    fee,
                })
            }
            "approve" => {
                let from: Account = get_field(&map, FIELD_PREFIX, "from")?;
                let spender: Account = get_field(&map, FIELD_PREFIX, "spender")?;
                let expected_allowance: Option<Nat> =
                    get_opt_field(&map, FIELD_PREFIX, "expected_allowance")?;
                let expires_at = get_opt_field::<u64>(&map, FIELD_PREFIX, "expires_at")?;
                Ok(Self::Approve {
                    from,
                    spender,
                    amount,
                    fee,
                    expected_allowance,
                    expires_at,
                })
            }
            found => {
                bail!(
                    "Expected field 'op' to be 'burn', 'mint', 'xfer' or 'approve' but found {found}"
                )
            }
        }
    }
}

impl From<IcrcOperation> for BTreeMap<String, Value> {
    fn from(op: IcrcOperation) -> Self {
        use IcrcOperation as Op;
        let mut map = BTreeMap::new();
        match op {
            Op::Approve {
                from,
                spender,
                amount,
                fee,
                expected_allowance,
                expires_at,
            } => {
                map.insert("op".to_string(), Value::text("approve"));
                map.insert("from".to_string(), Value::from(from));
                map.insert("spender".to_string(), Value::from(spender));
                map.insert("amt".to_string(), Value::Nat(amount));
                if let Some(fee) = fee {
                    map.insert("fee".to_string(), Value::Nat(fee));
                }
                if let Some(expected_allowance) = expected_allowance {
                    map.insert(
                        "expected_allowance".to_string(),
                        Value::Nat(expected_allowance),
                    );
                }
                if let Some(expires_at) = expires_at {
                    map.insert("expires_at".to_string(), Value::Nat(Nat::from(expires_at)));
                }
            }
            Op::Burn {
                from,
                spender,
                amount,
                fee,
            } => {
                map.insert("op".to_string(), Value::text("burn"));
                map.insert("from".to_string(), Value::from(from));
                if let Some(spender) = spender {
                    map.insert("spender".to_string(), Value::from(spender));
                }
                map.insert("amt".to_string(), Value::Nat(amount));
                if let Some(fee) = fee {
                    map.insert("fee".to_string(), Value::Nat(fee));
                }
            }
            Op::Mint { to, amount, fee } => {
                map.insert("op".to_string(), Value::text("mint"));
                map.insert("to".to_string(), Value::from(to));
                map.insert("amt".to_string(), Value::Nat(amount));
                if let Some(fee) = fee {
                    map.insert("fee".to_string(), Value::Nat(fee));
                }
            }
            Op::Transfer {
                from,
                to,
                spender,
                amount,
                fee,
            } => {
                map.insert("op".to_string(), Value::text("xfer"));
                map.insert("from".to_string(), Value::from(from));
                map.insert("to".to_string(), Value::from(to));
                if let Some(spender) = spender {
                    map.insert("spender".to_string(), Value::from(spender));
                }
                map.insert("amt".to_string(), Value::Nat(amount));
                if let Some(fee) = fee {
                    map.insert("fee".to_string(), Value::Nat(fee));
                }
            }
        }
        map
    }
}

fn make_field_full_path(field_prefix: &[&str], field_name: &str) -> String {
    format!("{}.{}", field_prefix.join("."), field_name)
}

fn get_field<'a, T>(
    map: &'a BTreeMap<String, Value>,
    field_prefix: &[&'a str],
    field_name: &str,
) -> anyhow::Result<T>
where
    T: TryFrom<Value, Error = String>,
{
    get_opt_field(map, field_prefix, field_name)?.ok_or_else(|| {
        let field_path = make_field_full_path(field_prefix, field_name);
        anyhow!("Missing field '{field_path}'")
    })
}

fn get_opt_field<'a, T>(
    map: &'a BTreeMap<String, Value>,
    field_prefix: &[&'a str],
    field_name: &str,
) -> anyhow::Result<Option<T>>
where
    T: TryFrom<Value, Error = String>,
{
    map.get(field_name)
        .map(|field| {
            T::try_from(field.to_owned()).map_err(|err| {
                let field_path = make_field_full_path(field_prefix, field_name);
                anyhow!("Error decoding field '{field_path}': {err}")
            })
        })
        .transpose()
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct MetadataEntry {
    pub key: String,
    pub value: Vec<u8>,
}

impl MetadataEntry {
    pub fn from_metadata_value(key: &str, value: &MetadataValue) -> anyhow::Result<Self> {
        let value = candid::encode_one(value)?;

        Ok(Self {
            key: key.to_string(),
            value,
        })
    }

    pub fn value(&self) -> anyhow::Result<MetadataValue> {
        Ok(candid::decode_one(&self.value)?)
    }
}

impl<T> From<ic_icrc1::Operation<T>> for IcrcOperation
where
    T: TokensType,
{
    fn from(op: ic_icrc1::Operation<T>) -> Self {
        use ic_icrc1::Operation as Op;
        match op {
            Op::Approve {
                from,
                spender,
                amount,
                expected_allowance,
                expires_at,
                fee,
            } => Self::Approve {
                from,
                spender,
                amount: amount.into(),
                expected_allowance: expected_allowance.map(Into::into),
                expires_at,
                fee: fee.map(Into::into),
            },
            Op::Burn {
                from,
                spender,
                amount,
                fee,
            } => Self::Burn {
                from,
                spender,
                amount: amount.into(),
                fee: fee.map(Into::into),
            },
            Op::Mint { to, amount, fee } => Self::Mint {
                to,
                amount: amount.into(),
                fee: fee.map(Into::into),
            },
            Op::Transfer {
                from,
                to,
                spender,
                amount,
                fee,
            } => Self::Transfer {
                from,
                to,
                spender,
                amount: amount.into(),
                fee: fee.map(Into::into),
            },
            Op::FeeCollector { .. } => {
                panic!("FeeCollector107 not implemented")
            }
        }
    }
}

impl<T> From<ic_icrc1::Transaction<T>> for IcrcTransaction
where
    T: TokensType,
{
    fn from(tx: ic_icrc1::Transaction<T>) -> Self {
        Self {
            operation: tx.operation.into(),
            created_at_time: tx.created_at_time,
            memo: tx.memo,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use candid::{Nat, Principal};
    use ic_icrc1::blocks::{
        encoded_block_to_generic_block, generic_block_to_encoded_block,
        generic_transaction_from_generic_block,
    };
    use ic_icrc1_test_utils::blocks_strategy;
    use ic_icrc1_tokens_u64::U64;
    use ic_icrc1_tokens_u256::U256;
    use ic_ledger_canister_core::ledger::LedgerTransaction;
    use ic_ledger_core::block::BlockType;
    use ic_ledger_core::tokens::TokensType;
    use icrc_ledger_types::icrc::generic_value::Value;
    use icrc_ledger_types::icrc1::account::Account;
    use icrc_ledger_types::icrc1::transfer::Memo;
    use num_bigint::BigUint;
    use proptest::collection::vec;
    use proptest::prelude::any;
    use proptest::prop_assert_eq;
    use proptest::{option, prop_oneof, proptest, strategy::Strategy};
    use serde_bytes::ByteBuf;
    use std::collections::BTreeMap;

    fn arb_account() -> impl Strategy<Value = Account> {
        (vec(any::<u8>(), 0..30), option::of(vec(any::<u8>(), 32))).prop_map(
            |(owner, subaccount)| {
                let owner = Principal::from_slice(owner.as_slice());
                let subaccount = subaccount.map(|v| v.try_into().unwrap());
                Account { owner, subaccount }
            },
        )
    }

    fn arb_nat() -> impl Strategy<Value = Nat> {
        (vec(any::<u32>(), 0..64)).prop_map(|digits| Nat::from(BigUint::new(digits)))
    }

    fn arb_approve() -> impl Strategy<Value = IcrcOperation> {
        (
            arb_account(),            // from
            arb_account(),            // spender
            arb_nat(),                // amount
            option::of(arb_nat()),    // expected_allowance
            option::of(any::<u64>()), // expires_at
            option::of(arb_nat()),    // fee
        )
            .prop_map(
                |(from, spender, amount, expected_allowance, expires_at, fee)| {
                    IcrcOperation::Approve {
                        from,
                        spender,
                        amount,
                        expected_allowance,
                        expires_at,
                        fee,
                    }
                },
            )
    }

    fn arb_burn() -> impl Strategy<Value = IcrcOperation> {
        (
            arb_account(),             // from
            option::of(arb_account()), // spender
            arb_nat(),                 // amount
            option::of(arb_nat()),     // fee
        )
            .prop_map(|(from, spender, amount, fee)| IcrcOperation::Burn {
                from,
                spender,
                amount,
                fee,
            })
    }

    fn arb_mint() -> impl Strategy<Value = IcrcOperation> {
        (
            arb_account(),         // to
            arb_nat(),             // amount
            option::of(arb_nat()), // fee
        )
            .prop_map(|(to, amount, fee)| IcrcOperation::Mint { to, amount, fee })
    }

    fn arb_transfer() -> impl Strategy<Value = IcrcOperation> {
        (
            arb_account(),             // from
            arb_account(),             // to
            option::of(arb_account()), // spender
            arb_nat(),                 // amount
            option::of(arb_nat()),     // fee
        )
            .prop_map(|(from, to, spender, amount, fee)| IcrcOperation::Transfer {
                from,
                to,
                spender,
                amount,
                fee,
            })
    }

    fn arb_op() -> impl Strategy<Value = IcrcOperation> {
        prop_oneof![arb_approve(), arb_burn(), arb_mint(), arb_transfer(),]
    }

    fn arb_memo() -> impl Strategy<Value = Memo> {
        vec(any::<u8>(), 0..200).prop_map(|bytes| Memo(ByteBuf::from(bytes)))
    }

    fn arb_transaction() -> impl Strategy<Value = IcrcTransaction> {
        (arb_op(), option::of(any::<u64>()), option::of(arb_memo())).prop_map(
            |(operation, created_at_time, memo)| IcrcTransaction {
                operation,
                created_at_time,
                memo,
            },
        )
    }

    fn arb_block() -> impl Strategy<Value = IcrcBlock> {
        (
            option::of(vec(any::<u8>(), 32).prop_map(|b| b.try_into().unwrap())), // phash
            arb_transaction(),                                                    // tx
            option::of(arb_nat()),                                                // effective_fee
            any::<u64>(),                                                         // timestamp
            option::of(arb_account()),                                            // fee_col
            option::of(any::<u64>()), // fee_col_block_index
        )
            .prop_map(
                |(
                    parent_hash,
                    transaction,
                    effective_fee,
                    timestamp,
                    fee_collector,
                    fee_collector_block_index,
                )| IcrcBlock {
                    parent_hash,
                    transaction,
                    effective_fee,
                    timestamp,
                    fee_collector,
                    fee_collector_block_index,
                },
            )
    }

    #[test]
    fn test_operation_value_codec() {
        proptest!(|(op in arb_op().no_shrink())| {
            let actual_op = match IcrcOperation::try_from(BTreeMap::from(op.clone())) {
                Ok(actual_op) => actual_op,
                Err(err) => panic!("{err:?}"),
            };
            prop_assert_eq!(op, actual_op)
        })
    }

    #[test]
    fn test_transaction_value_codec() {
        proptest!(|(tx in arb_transaction().no_shrink())| {
            let actual_tx = match IcrcTransaction::try_from(Value::from(tx.clone())) {
                Ok(actual_tx) => actual_tx,
                Err(err) => panic!("{err:?}"),
            };
            prop_assert_eq!(tx, actual_tx)
        })
    }

    #[test]
    fn test_block_value_codec() {
        proptest!(|(block in arb_block().no_shrink())| {
            let actual_block = match IcrcBlock::try_from(Value::from(block.clone())) {
                Ok(actual_block) => actual_block,
                Err(err) => panic!("{err:?}"),
            };
            prop_assert_eq!(block, actual_block)
        })
    }

    #[track_caller]
    fn compare_blocks<T>(block: ic_icrc1::Block<T>, rosetta_block: IcrcBlock)
    where
        T: TokensType,
    {
        // 1. compare the block hash
        assert_eq!(
            ic_icrc1::Block::<T>::block_hash(&block.clone().encode()).as_slice(),
            rosetta_block.clone().hash(),
            "block hash",
        );

        // 2. compare the transaction hash
        assert_eq!(
            block.transaction.hash().as_slice(),
            rosetta_block.transaction.clone().hash(),
            "transaction hash",
        );

        // 3. compare generic values
        let generic_block_expected = encoded_block_to_generic_block(&block.clone().encode());
        let generic_block_actual = Value::from(rosetta_block.clone());
        // Compare generic block hashes
        assert_eq!(generic_block_expected.hash(), generic_block_actual.hash());
        // Compare conversion to encoded block
        assert_eq!(
            generic_block_to_encoded_block(generic_block_expected.clone()).unwrap(),
            generic_block_to_encoded_block(generic_block_actual.clone()).unwrap(),
            "Generic block to encoded block comparison failed."
        );
        // Compare hashes of generic transactions
        assert_eq!(
            generic_transaction_from_generic_block(generic_block_expected.clone())
                .unwrap()
                .hash(),
            generic_transaction_from_generic_block(generic_block_actual.clone())
                .unwrap()
                .hash(),
            "Generic transaction hash comparison failed."
        );

        // 4. compare the fields
        let hash = block.parent_hash.map(|h| h.into_bytes());
        assert_eq!(hash, rosetta_block.parent_hash, "parent_hash");
        assert_eq!(
            block.effective_fee.map(|fee| fee.into()),
            rosetta_block.effective_fee,
            "effective_fee",
        );
        assert_eq!(block.timestamp, rosetta_block.timestamp, "timestamp",);
        assert_eq!(
            block.fee_collector, rosetta_block.fee_collector,
            "fee_collector",
        );
        assert_eq!(
            block.fee_collector_block_index, rosetta_block.fee_collector_block_index,
            "fee_collector_block_index",
        );
        compare_transactions(block.transaction, rosetta_block.transaction);
    }

    #[track_caller]
    fn compare_transactions<T>(tx: ic_icrc1::Transaction<T>, rosetta_tx: IcrcTransaction)
    where
        T: TokensType,
    {
        assert_eq!(
            tx.created_at_time, rosetta_tx.created_at_time,
            "created_at_time",
        );
        assert_eq!(tx.memo, rosetta_tx.memo, "memo");
        compare_operations(tx.operation, rosetta_tx.operation);
    }

    #[track_caller]
    fn compare_operations<T>(op: ic_icrc1::Operation<T>, rosetta_op: IcrcOperation)
    where
        T: TokensType,
    {
        match (op, rosetta_op) {
            (
                ic_icrc1::Operation::Approve {
                    from,
                    spender,
                    amount,
                    expected_allowance,
                    expires_at,
                    fee,
                },
                IcrcOperation::Approve {
                    from: rosetta_from,
                    spender: rosetta_spender,
                    amount: rosetta_amount,
                    expected_allowance: rosetta_expected_allowance,
                    expires_at: rosetta_expires_at,
                    fee: rosetta_fee,
                },
            ) => {
                assert_eq!(from, rosetta_from, "from");
                assert_eq!(spender, rosetta_spender, "spender");
                assert_eq!(amount.into(), rosetta_amount, "amount");
                assert_eq!(
                    expected_allowance.map(|t| t.into()),
                    rosetta_expected_allowance,
                    "allowance",
                );
                assert_eq!(expires_at, rosetta_expires_at, "expires_at");
                assert_eq!(fee.map(|t| t.into()), rosetta_fee, "fee");
            }
            (
                ic_icrc1::Operation::Burn {
                    from,
                    spender,
                    amount,
                    fee,
                },
                IcrcOperation::Burn {
                    from: rosetta_from,
                    spender: rosetta_spender,
                    amount: rosetta_amount,
                    fee: rosetta_fee,
                },
            ) => {
                assert_eq!(from, rosetta_from, "from");
                assert_eq!(spender, rosetta_spender, "spender");
                assert_eq!(amount.into(), rosetta_amount, "amount");
                assert_eq!(fee.map(|t| t.into()), rosetta_fee, "fee");
            }
            (
                ic_icrc1::Operation::Mint { to, amount, fee },
                IcrcOperation::Mint {
                    to: rosetta_to,
                    amount: rosetta_amount,
                    fee: rosetta_fee,
                },
            ) => {
                assert_eq!(to, rosetta_to, "to");
                assert_eq!(amount.into(), rosetta_amount, "amount");
                assert_eq!(fee.map(|t| t.into()), rosetta_fee, "fee");
            }
            (
                ic_icrc1::Operation::Transfer {
                    from,
                    to,
                    spender,
                    amount,
                    fee,
                },
                IcrcOperation::Transfer {
                    from: rosetta_from,
                    to: rosetta_to,
                    spender: rosetta_spender,
                    amount: rosetta_amount,
                    fee: rosetta_fee,
                },
            ) => {
                assert_eq!(from, rosetta_from, "from");
                assert_eq!(to, rosetta_to, "to");
                assert_eq!(spender, rosetta_spender, "spender");
                assert_eq!(amount.into(), rosetta_amount, "amount");
                assert_eq!(fee.map(|t| t.into()), rosetta_fee, "fee");
            }
            (l, r) => panic!(
                "Found different type of operations. Operation:{l:?} rosetta's Operation:{r:?}"
            ),
        }
    }

    fn test_block_from_ledger_block<T, S>(arb_amount: S)
    where
        T: TokensType,
        S: Strategy<Value = T>,
    {
        let arb_block = blocks_strategy(arb_amount).no_shrink();
        proptest!(|(block in arb_block)| {
            let encoded_block = block.clone().encode();
            let generic_block = encoded_block_to_generic_block(&encoded_block);
            let rosetta_block = IcrcBlock::try_from(generic_block).unwrap();
            compare_blocks(block, rosetta_block);
        })
    }

    #[test]
    fn test_block_from_u64_block() {
        let arb_amount = any::<u64>().prop_map(U64::new);
        test_block_from_ledger_block(arb_amount);
    }

    #[test]
    fn test_block_from_u256_block() {
        let arb_amount =
            (any::<u128>(), any::<u128>()).prop_map(|(lo, hi)| U256::from_words(lo, hi));
        test_block_from_ledger_block(arb_amount);
    }
}
