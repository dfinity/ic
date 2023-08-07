//! Numeric types for Ethereum.

#[cfg(test)]
mod tests;

use crate::eth_rpc::Quantity;
use serde::{Deserialize, Serialize};

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

/// Number of transactions sent by the sender.
/// Ethereum expects nonce to increase by 1 for each transaction.
/// If that's not the case, the transaction is rejected
/// (if the nonce was already seen in another transaction from the same sender)
/// or kept in the node's transaction pool while waiting for the missing nonce.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct TransactionNonce(ethnum::u256);

impl TransactionNonce {
    pub fn checked_increment(&self) -> Option<Self> {
        self.0.checked_add(ethnum::u256::ONE).map(Self)
    }
}

impl From<u64> for TransactionNonce {
    fn from(value: u64) -> Self {
        TransactionNonce(ethnum::u256::from(value))
    }
}

impl From<TransactionNonce> for ethnum::u256 {
    fn from(value: TransactionNonce) -> Self {
        value.0
    }
}

#[derive(Clone, Copy, Serialize, Deserialize, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LedgerBurnIndex(pub u64);

impl From<LedgerBurnIndex> for candid::Nat {
    fn from(value: LedgerBurnIndex) -> Self {
        candid::Nat::from(value.0)
    }
}
