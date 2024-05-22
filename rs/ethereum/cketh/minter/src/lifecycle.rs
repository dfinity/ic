//! Module dealing with the lifecycle methods of the ckETH Minter.
use crate::lifecycle::init::InitArg;
use crate::lifecycle::upgrade::UpgradeArg;
use candid::{CandidType, Deserialize};
use minicbor::{Decode, Encode};
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
    CandidType, Clone, Copy, Default, Deserialize, Debug, Eq, PartialEq, Hash, Encode, Decode,
)]
#[serde(transparent)]
#[cbor(transparent)]
pub struct EthereumNetwork(#[n(0)] pub u64);

impl EthereumNetwork {
    pub const MAINNET: EthereumNetwork = EthereumNetwork(1);
    pub const SEPOLIA: EthereumNetwork = EthereumNetwork(11155111);
    pub const ARBITRUM: EthereumNetwork = EthereumNetwork(42161);
    pub const BASE: EthereumNetwork = EthereumNetwork(8453);
    pub const OPTIMISM: EthereumNetwork = EthereumNetwork(10);

    pub fn chain_id(&self) -> u64 {
        self.0
    }
}

impl Display for EthereumNetwork {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            &Self::MAINNET => write!(f, "Ethereum Mainnet"),
            &Self::SEPOLIA => write!(f, "Ethereum Testnet Sepolia"),
            Self(chain_id) => write!(f, "Unknown Network ({})", chain_id),
        }
    }
}
