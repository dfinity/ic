//! Types used to support the candid API.
use bitcoin::Network as BitcoinNetwork;
use candid::{CandidType, Deserialize};

/// The payload used to initialize the canister.
#[derive(CandidType, Deserialize)]
pub struct InitPayload {
    pub delta: u64,
    pub network: Network,
}

/// The supported Bitcoin networks.
///
/// Note that this is identical to `Network` that's defined in the Bitcoin
/// crate, with the only difference being that it derives a `CandidType`.
#[derive(CandidType, Deserialize, Copy, Clone)]
pub enum Network {
    Bitcoin,
    Regtest,
    Testnet,
    Signet,
}

impl From<Network> for BitcoinNetwork {
    fn from(network: Network) -> Self {
        match network {
            Network::Bitcoin => Self::Bitcoin,
            Network::Testnet => Self::Testnet,
            Network::Signet => Self::Signet,
            Network::Regtest => Self::Regtest,
        }
    }
}
