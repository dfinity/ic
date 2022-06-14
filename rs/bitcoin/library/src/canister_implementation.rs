use crate::{
    canister_common::BitcoinCanister, types::from_types_network_to_bitcoin_network,
    utxo_management, MinConfirmationsTooHigh, Utxo,
};
use async_trait::async_trait;
use bitcoin::{Address, Network};

/// The real Bitcoin canister is used to provide actual interaction with Bitcoin.
#[derive(Clone)]
pub struct BitcoinCanisterImpl {
    network: Network,
}

#[async_trait]
impl BitcoinCanister for BitcoinCanisterImpl {
    /// Creates a new instance of the real Bitcoin canister.
    fn new(network: crate::Network) -> Self {
        Self {
            network: from_types_network_to_bitcoin_network(network),
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
    ) -> Result<Vec<Utxo>, MinConfirmationsTooHigh> {
        utxo_management::get_utxos(self, address, min_confirmations).await
    }
}
