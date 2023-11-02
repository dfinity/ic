//! Module dealing with the lifecycle methods of the ckETH Minter.
use crate::lifecycle::init::InitArg;
use crate::lifecycle::upgrade::UpgradeArg;
use candid::{CandidType, Deserialize};
use minicbor::{Decode, Encode};
use serde::Serialize;
use std::fmt::{Display, Formatter};

#[cfg(test)]
mod tests;

pub mod init;
pub mod upgrade;
pub use upgrade::post_upgrade;

#[derive(CandidType, Deserialize, Clone, Debug)]
pub enum MinterArg {
    InitArg(InitArg),
    UpgradeArg(UpgradeArg),
}

#[derive(
    CandidType,
    Clone,
    Copy,
    Default,
    Serialize,
    Deserialize,
    Debug,
    Eq,
    PartialEq,
    Hash,
    Encode,
    Decode,
)]
#[cbor(index_only)]
pub enum EthereumNetwork {
    #[n(1)]
    Mainnet,
    #[n(11155111)]
    #[default]
    Sepolia,
}

impl EthereumNetwork {
    pub fn chain_id(&self) -> u64 {
        match self {
            EthereumNetwork::Mainnet => 1,
            EthereumNetwork::Sepolia => 11155111,
        }
    }
}

impl Display for EthereumNetwork {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            EthereumNetwork::Mainnet => write!(f, "Ethereum Mainnet"),
            EthereumNetwork::Sepolia => write!(f, "Ethereum Testnet Sepolia"),
        }
    }
}
