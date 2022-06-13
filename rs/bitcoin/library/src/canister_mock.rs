use crate::canister_common::BitcoinCanister;
use async_trait::async_trait;
use bitcoin::{Address, Network};
use ic_btc_library_types::{BalanceUpdate, GetUtxosError, OutPoint, Utxo, UtxosUpdate};

/// The Bitcoin canister mock is used to perform unit tests against the library.
pub(crate) struct BitcoinCanisterMock {
    pub(crate) utxos: Vec<Utxo>,
    network: Network,
}

#[async_trait]
impl BitcoinCanister for BitcoinCanisterMock {
    /// Creates a new instance of the Bitcoin canister mock.
    fn new(network: ic_btc_library_types::Network) -> Self {
        Self {
            utxos: get_init_utxos(),
            network: Network::from(network),
        }
    }

    /// Returns the network the Bitcoin canister interacts with.
    fn get_network(&self) -> Network {
        self.network
    }

    /// Returns the mock UTXOs of the canister address according to `min_confirmations`.
    /// Note: `address` is ignored for simplicity purpose.
    async fn get_utxos(
        &self,
        _address: &Address,
        min_confirmations: u32,
    ) -> Result<Vec<Utxo>, GetUtxosError> {
        Ok(self
            .utxos
            .clone()
            .into_iter()
            .filter(|utxo| utxo.confirmations >= min_confirmations)
            .collect())
    }
}

/// Gets some hard-coded UTXOs to be used by the mock.
pub(crate) fn get_init_utxos() -> Vec<Utxo> {
    vec![Utxo {
        outpoint: OutPoint {
            tx_id: vec![0; 32],
            vout: 0,
        },
        value: 250_000,
        height: 0,
        confirmations: 1,
    }]
}

/// Gets the initial UTXOs update to be used by the mock.
pub(crate) fn get_init_utxos_update() -> UtxosUpdate {
    UtxosUpdate {
        added_utxos: get_init_utxos(),
        removed_utxos: vec![],
    }
}

/// Gets the initial balance update to be used by the mock.
pub(crate) fn get_init_balance_update() -> BalanceUpdate {
    BalanceUpdate::from(get_init_utxos_update())
}
