//! Numeric types for Ethereum.

#[cfg(test)]
mod tests;

use crate::checked_amount::CheckedAmountOf;
use phantom_newtype::Id;

pub enum WeiTag {}
pub type Wei = CheckedAmountOf<WeiTag>;

pub fn wei_from_milli_ether(value: u128) -> Wei {
    const MILLI_ETHER: u64 = 1_000_000_000_000_000_000;
    Wei::new(value)
        .checked_mul(MILLI_ETHER)
        .expect("any u128 multiplied by 10^15 always fits in a u256")
}

pub enum TransactionNonceTag {}
/// Number of transactions sent by the sender.
/// Ethereum expects nonce to increase by 1 for each transaction.
/// If that's not the case, the transaction is rejected
/// (if the nonce was already seen in another transaction from the same sender)
/// or kept in the node's transaction pool while waiting for the missing nonce.
pub type TransactionNonce = CheckedAmountOf<TransactionNonceTag>;

pub enum TransactionCountTag {}

/// Number of transactions emitted by an address at a given block height (`finalized`, `safe` or `latest`).
/// This should closely follow [`TransactionNonce`] in case the address is the minter's one,
/// but depending on the block height the two may differ.
pub type TransactionCount = CheckedAmountOf<TransactionCountTag>;

pub enum BlockNumberTag {}
pub type BlockNumber = CheckedAmountOf<BlockNumberTag>;

pub enum EthLogIndexTag {}
pub type LogIndex = CheckedAmountOf<EthLogIndexTag>;
pub enum BurnIndexTag {}
pub type LedgerBurnIndex = Id<BurnIndexTag, u64>;

pub enum MintIndexTag {}
pub type LedgerMintIndex = Id<MintIndexTag, u64>;
