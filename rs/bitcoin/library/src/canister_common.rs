use crate::{MinConfirmationsTooHigh, Utxo};
use async_trait::async_trait;
use bitcoin::{Address, Network};

#[async_trait]
pub trait BitcoinCanister {
    /// Creates a new instance of the Bitcoin canister.
    fn new(network: crate::Network) -> Self;

    /// Returns the network the Bitcoin canister interacts with.
    fn get_network(&self) -> Network;

    /// Returns the UTXOs of the given Bitcoin `address` according to `min_confirmations`.
    async fn get_utxos(
        &self,
        address: &Address,
        min_confirmations: u32,
    ) -> Result<Vec<Utxo>, MinConfirmationsTooHigh>;
}
