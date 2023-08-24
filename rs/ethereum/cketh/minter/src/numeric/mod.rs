//! Numeric types for Ethereum.

#[cfg(test)]
mod tests;

use crate::eth_rpc::Quantity;
use phantom_newtype::Id;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Wei is the smallest denomination of ether.
/// 1 wei == 10^(-18) ether
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct Wei(ethnum::u256);

impl Wei {
    pub const TWO: Wei = Wei::new(2);

    pub const fn new(value: u128) -> Self {
        Self(ethnum::u256::new(value))
    }

    pub fn checked_add(self, other: Self) -> Option<Self> {
        self.0.checked_add(other.0).map(Self)
    }

    pub fn checked_sub(self, other: Self) -> Option<Self> {
        self.0.checked_sub(other.0).map(Self)
    }

    pub fn checked_mul<T: Into<Wei>>(self, other: T) -> Option<Self> {
        self.0.checked_mul(other.into().0).map(Self)
    }
}

impl From<u64> for Wei {
    fn from(value: u64) -> Self {
        Wei(ethnum::u256::from(value))
    }
}

impl From<u128> for Wei {
    fn from(value: u128) -> Self {
        Wei(ethnum::u256::from(value))
    }
}

impl From<Quantity> for Wei {
    fn from(value: Quantity) -> Self {
        Wei(value)
    }
}

impl From<Wei> for ethnum::u256 {
    fn from(value: Wei) -> Self {
        value.0
    }
}

impl From<Wei> for candid::Nat {
    fn from(value: Wei) -> Self {
        use num_bigint::BigUint;
        candid::Nat::from(BigUint::from_bytes_be(&value.0.to_be_bytes()))
    }
}

impl fmt::Display for Wei {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Number of transactions sent by the sender.
/// Ethereum expects nonce to increase by 1 for each transaction.
/// If that's not the case, the transaction is rejected
/// (if the nonce was already seen in another transaction from the same sender)
/// or kept in the node's transaction pool while waiting for the missing nonce.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct TransactionNonce(ethnum::u256);

impl TransactionNonce {
    pub const ZERO: Self = TransactionNonce(ethnum::u256::ZERO);

    pub fn checked_increment(&self) -> Option<Self> {
        self.0.checked_add(ethnum::u256::ONE).map(Self)
    }
}

impl From<u64> for TransactionNonce {
    fn from(value: u64) -> Self {
        TransactionNonce(ethnum::u256::from(value))
    }
}

impl TryFrom<candid::Nat> for TransactionNonce {
    type Error = String;

    fn try_from(value: candid::Nat) -> Result<Self, Self::Error> {
        let bytes = value.0.to_bytes_be();
        if bytes.len() > 32 {
            return Err(format!("Nat does not fit in a U256: {}", value));
        }
        let mut u256_bytes = [0u8; 32];
        u256_bytes[32 - bytes.len()..].copy_from_slice(&bytes);
        Ok(Self(ethnum::u256::from_be_bytes(u256_bytes)))
    }
}

impl From<TransactionNonce> for ethnum::u256 {
    fn from(value: TransactionNonce) -> Self {
        value.0
    }
}

impl From<TransactionNonce> for candid::Nat {
    fn from(value: TransactionNonce) -> Self {
        use num_bigint::BigUint;
        candid::Nat::from(BigUint::from_bytes_be(&value.0.to_be_bytes()))
    }
}

pub enum BurnIndexTag {}
pub type LedgerBurnIndex = Id<BurnIndexTag, u64>;

pub enum MintIndexTag {}
pub type LedgerMintIndex = Id<MintIndexTag, u64>;
