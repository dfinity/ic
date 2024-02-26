use anyhow::{Context, Result};
use candid::Nat;
use ic_icrc1::blocks::{
    encoded_block_to_generic_block, generic_block_to_encoded_block,
    generic_transaction_from_generic_block,
};
use ic_icrc1::{Block, Transaction};
use ic_icrc1_tokens_u256::U256;
use ic_icrc1_tokens_u64::U64;
use ic_ledger_core::block::{BlockType, EncodedBlock};
use ic_ledger_core::tokens::{CheckedAdd, CheckedSub, TokensType, Zero};
use icrc_ledger_types::icrc::generic_metadata_value::MetadataValue;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc3::blocks::GenericBlock;
use num_bigint::BigUint;
use num_traits::Bounded;
use rosetta_core::identifiers::BlockIdentifier;
use rosetta_core::objects::Amount;
use rusqlite::types::{FromSql, FromSqlError, FromSqlResult};
use rusqlite::ToSql;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::error::Error as StdError;
use std::fmt;
use std::str::FromStr;

pub type Tokens = RosettaToken;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RosettaBlock {
    pub index: u64,
    pub parent_hash: Option<ByteBuf>,
    pub block_hash: ByteBuf,
    pub encoded_block: EncodedBlock,
    pub transaction_hash: ByteBuf,
    pub timestamp: u64,
}

impl RosettaBlock {
    // Converts a generic block to a RosettaBlock
    // Use this method for blocks that come directly from an ICRC-1 Ledger, because only then can be guarenteed that the block hash is correct
    pub fn from_generic_block(generic_block: GenericBlock, block_idx: u64) -> anyhow::Result<Self> {
        let block_hash = ByteBuf::from(generic_block.hash());
        let encoded_block = generic_block_to_encoded_block(generic_block.clone()).map_err(|e| {
            anyhow::Error::msg(format!(
                "Failed to encode block at index {}, cause: {}",
                block_idx, e
            ))
        })?;
        let block = Block::<Tokens>::decode(encoded_block.clone()).map_err(|e| {
            anyhow::Error::msg(format!(
                "Failed to decode block at index {}, cause: {}",
                block_idx, e
            ))
        })?;
        let transaction_hash = ByteBuf::from(
            generic_transaction_from_generic_block(generic_block)
                .map_err(|e| {
                    anyhow::Error::msg(format!(
                        "Failed to decode transaction from block at index {}, cause: {}",
                        block_idx, e
                    ))
                })?
                .hash(),
        );
        let timestamp = block.timestamp;

        Ok(Self {
            index: block_idx,
            parent_hash: Block::parent_hash(&block).map(|eb| ByteBuf::from(eb.as_slice().to_vec())),
            block_hash,
            timestamp,
            encoded_block,
            transaction_hash,
        })
    }

    pub fn from_icrc_ledger_block<T>(block: Block<T>, block_idx: u64) -> anyhow::Result<Self>
    where
        T: TokensType,
    {
        Self::from_encoded_block(block.encode(), block_idx)
    }

    pub fn from_encoded_block(eb: EncodedBlock, block_idx: u64) -> anyhow::Result<Self> {
        Self::from_generic_block(encoded_block_to_generic_block(&eb), block_idx)
    }

    pub fn get_effective_fee(&self) -> anyhow::Result<Option<Tokens>> {
        Block::decode(self.encoded_block.clone())
            .map(|b| b.effective_fee)
            .map_err(anyhow::Error::msg)
    }

    pub fn get_fee_payed(&self) -> anyhow::Result<Option<Tokens>> {
        Ok(self
            .get_effective_fee()?
            .or(match self.get_transaction()?.operation {
                ic_icrc1::Operation::Mint { .. } => None,
                ic_icrc1::Operation::Transfer { fee, .. } => fee,
                ic_icrc1::Operation::Approve { fee, .. } => fee,
                ic_icrc1::Operation::Burn { .. } => None,
            }))
    }

    pub fn get_transaction(&self) -> anyhow::Result<Transaction<Tokens>> {
        Ok(Block::<Tokens>::decode(self.encoded_block.clone())
            .map_err(anyhow::Error::msg)?
            .transaction)
    }

    pub fn get_fee_collector(&self) -> anyhow::Result<Option<Account>> {
        Ok(Block::<Tokens>::decode(self.encoded_block.clone())
            .map_err(anyhow::Error::msg)?
            .fee_collector)
    }

    pub fn get_icrc1_block(&self) -> anyhow::Result<Block<Tokens>> {
        Block::<Tokens>::decode(self.encoded_block.clone()).map_err(anyhow::Error::msg)
    }

    pub fn get_parent_block_identifier(&self) -> BlockIdentifier {
        self.parent_hash
            .as_ref()
            .map(|ph| BlockIdentifier::from_bytes(self.index.saturating_sub(1), ph))
            .unwrap_or_else(|| BlockIdentifier::from_bytes(self.index, &self.block_hash))
    }

    pub fn get_transaction_identifier(&self) -> rosetta_core::identifiers::TransactionIdentifier {
        rosetta_core::identifiers::TransactionIdentifier::from_bytes(&self.transaction_hash)
    }

    pub fn get_block_identifier(&self) -> rosetta_core::identifiers::BlockIdentifier {
        BlockIdentifier::from_bytes(self.index, &self.block_hash)
    }
}

impl From<&RosettaBlock> for BlockIdentifier {
    fn from(block: &RosettaBlock) -> Self {
        Self {
            index: block.index,
            hash: hex::encode(&block.block_hash),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
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

#[derive(Default, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Hash, Deserialize)]
#[serde(transparent)]
pub struct RosettaToken(Nat);

impl FromStr for RosettaToken {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<RosettaToken, Self::Err> {
        Ok(Self(
            Nat::from_str(s).context("Cannot parse Nat from String")?,
        ))
    }
}

impl CheckedAdd for RosettaToken {
    fn checked_add(&self, other: &Self) -> Option<Self> {
        self.0
             .0
            .checked_add(&other.0 .0)
            .map(|biguint| Self(Nat(biguint)))
    }
}

impl CheckedSub for RosettaToken {
    fn checked_sub(&self, other: &Self) -> Option<Self> {
        self.0
             .0
            .checked_sub(&other.0 .0)
            .map(|biguint| Self(Nat(biguint)))
    }
}

impl From<U64> for RosettaToken {
    fn from(value: U64) -> Self {
        Self(value.into())
    }
}

impl TryFrom<Amount> for RosettaToken {
    type Error = anyhow::Error;
    fn try_from(value: Amount) -> std::prelude::v1::Result<Self, Self::Error> {
        RosettaToken::from_str(&value.value)
            .with_context(|| format!("Could not convert amount: {:?} to RosettaToken", value))
    }
}

impl TryFrom<RosettaToken> for U64 {
    type Error = String;
    fn try_from(value: RosettaToken) -> Result<Self, Self::Error> {
        value.0.try_into()
    }
}

impl From<U256> for RosettaToken {
    fn from(value: U256) -> Self {
        Self(value.into())
    }
}

impl TryFrom<RosettaToken> for U256 {
    type Error = String;
    fn try_from(value: RosettaToken) -> Result<Self, Self::Error> {
        value.0.try_into()
    }
}

impl Bounded for RosettaToken {
    fn min_value() -> Self {
        RosettaToken(Nat(BigUint::zero()))
    }

    fn max_value() -> Self {
        // The max value of BigUnit is only limited by how much memory is available
        // For now u256::MAX is the biggest number that RosettaToken will ever have to represent
        U256::MAX.into()
    }
}

impl Zero for RosettaToken {
    fn zero() -> Self {
        RosettaToken(Nat(BigUint::zero()))
    }

    fn is_zero(&self) -> bool {
        self.0 .0.is_zero()
    }
}

impl From<RosettaToken> for Nat {
    fn from(value: RosettaToken) -> Self {
        value.0
    }
}

impl TryFrom<Nat> for RosettaToken {
    type Error = String;

    fn try_from(n: Nat) -> Result<Self, Self::Error> {
        Ok(RosettaToken(n))
    }
}

impl std::fmt::Display for RosettaToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0 .0.fmt(f)
    }
}

impl ToSql for RosettaToken {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        Ok(self.to_string().into())
    }
}

impl FromSql for RosettaToken {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> FromSqlResult<Self> {
        let s = value.as_str()?;
        match Self::from_str(s) {
            Ok(t) => Ok(t),
            Err(err) => {
                let err: Box<dyn StdError + Send + Sync + 'static> = err.into();
                Err(FromSqlError::Other(err))
            }
        }
    }
}

#[cfg(test)]
mod test {
    use candid::Nat;
    use ic_icrc1_tokens_u256::U256;
    use ic_icrc1_tokens_u64::U64;
    use num_bigint::BigUint;
    use proptest::{
        prelude::any, prop_assert_eq, proptest, strategy::Strategy, test_runner::TestCaseError,
    };
    use rusqlite::{
        types::{FromSql, ValueRef},
        ToSql,
    };
    use std::{fmt::Debug, str::FromStr};

    use super::RosettaToken;

    fn arb_rosetta_token() -> impl Strategy<Value = RosettaToken> {
        proptest::collection::vec(any::<u32>(), 1..10)
            .prop_map(|digits| RosettaToken(Nat(BigUint::new(digits))))
    }

    #[test]
    fn test_display_from_str_roundtrip() {
        proptest!(|(tokens in arb_rosetta_token())| {
            prop_assert_eq!(Some(tokens.clone()), RosettaToken::from_str(&tokens.to_string()).ok())
        })
    }

    fn test_from_sql_to_sql_roundtrip_helper<T>(tokens: T) -> Result<(), TestCaseError>
    where
        T: Clone + Debug + Into<RosettaToken> + PartialEq + TryFrom<RosettaToken>,
        <T as TryFrom<RosettaToken>>::Error: Debug,
    {
        let rosetta_tokens: RosettaToken = tokens.clone().into();
        let to_sql_output = rosetta_tokens
            .to_sql()
            .expect("Unable to convert token to sql");
        let result = match to_sql_output {
            rusqlite::types::ToSqlOutput::Borrowed(value_ref) => {
                RosettaToken::column_result(value_ref)
            }
            rusqlite::types::ToSqlOutput::Owned(value) => {
                RosettaToken::column_result(ValueRef::from(&value))
            }
            v => panic!("Unexpected to_sql output {:?}!", v),
        };
        prop_assert_eq!(
            Ok(tokens),
            result.map(|r| T::try_from(r).expect("Unable to convert to RosettaToken"))
        );
        Ok(())
    }

    #[test]
    fn test_from_sql_to_sql_roundtrip() {
        proptest!(|(tokens in arb_rosetta_token())| {
            test_from_sql_to_sql_roundtrip_helper(tokens)?;
        });
    }

    #[test]
    fn test_from_sql_to_sql_roundtrip_64() {
        proptest!(|(tokens in any::<u64>().prop_map(U64::new))| {
            test_from_sql_to_sql_roundtrip_helper(tokens)?;
        });
    }

    #[test]
    fn test_from_sql_to_sql_roundtrip_256() {
        let strategy = any::<(u128, u128)>().prop_map(|(hi, lo)| U256::from_words(hi, lo));
        proptest!(|(tokens in strategy)| {
            test_from_sql_to_sql_roundtrip_helper(tokens)?;
        });
    }
}
