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

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum MinterArg {
    InitArg(InitArg),
    UpgradeArg(UpgradeArg),
}

#[derive(
    Copy, Clone, Eq, PartialEq, Hash, Debug, Default, CandidType, Decode, Deserialize, Encode,
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

impl TryFrom<u64> for EthereumNetwork {
    type Error = String;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(EthereumNetwork::Mainnet),
            11155111 => Ok(EthereumNetwork::Sepolia),
            _ => Err("Unknown Ethereum Network".to_string()),
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
