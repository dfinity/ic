//! Numeric types for Ethereum.

#[cfg(test)]
mod tests;

use crate::rpc_client::amount::Amount;

pub enum WeiTag {}
pub type Wei = Amount<WeiTag>;

pub enum WeiPerGasUnit {}
pub type WeiPerGas = Amount<WeiPerGasUnit>;

pub enum TransactionCountTag {}
/// Number of transactions emitted by an address at a given block height (`finalized`, `safe` or `latest`).
/// This should closely follow [`TransactionNonce`] in case the address is the same,
/// but depending on the block height the two may differ.
pub type TransactionCount = Amount<TransactionCountTag>;

pub enum TransactionNonceTag {}
pub type TransactionNonce = Amount<TransactionNonceTag>;

pub enum TransactionIndexTag {}
pub type TransactionIndex = Amount<TransactionIndexTag>;

pub enum BlockNumberTag {}
pub type BlockNumber = Amount<BlockNumberTag>;

pub enum GasUnit {}
/// The number of gas units attached to a transaction for execution.
pub type GasAmount = Amount<GasUnit>;

pub enum EthLogIndexTag {}
pub type LogIndex = Amount<EthLogIndexTag>;

pub enum DifficultyTag {}
pub type Difficulty = Amount<DifficultyTag>;

pub enum BlockNonceTag {}
pub type BlockNonce = Amount<BlockNonceTag>;

pub enum NumBlocksTag {}
pub type NumBlocks = Amount<NumBlocksTag>;

pub enum NumBytesTag {}
pub type NumBytes = Amount<NumBytesTag>;

pub enum TimestampTag {}
pub type Timestamp = Amount<TimestampTag>;

pub enum ChainIdTag {}
pub type ChainId = Amount<ChainIdTag>;
