use crate::canister_common::BitcoinCanister;
use crate::utxo_management;
use async_trait::async_trait;
use bitcoin::{Address, Network};
use ic_btc_library_types::{GetUtxosError, Utxo};

/// The real Bitcoin canister is used to provide actual interaction with Bitcoin.
#[derive(Clone)]
pub struct BitcoinCanisterImpl {
    network: Network,
}

#[async_trait]
impl BitcoinCanister for BitcoinCanisterImpl {
    /// Creates a new instance of the real Bitcoin canister.
    fn new(network: ic_btc_library_types::Network) -> Self {
        Self {
            network: Network::from(network),
        }
    }

    /// Returns the network the Bitcoin canister interacts with.
    fn get_network(&self) -> Network {
        self.network
    }

    /// Returns the UTXOs of the given Bitcoin `address` according to `min_confirmations`.
    /// This getter always return the same value until a block, with transactions concerning the address, is mined.
    async fn get_utxos(
        &self,
        address: &Address,
        min_confirmations: u32,
    ) -> Result<Vec<Utxo>, GetUtxosError> {
        utxo_management::get_utxos(address, min_confirmations).await
    }
}
