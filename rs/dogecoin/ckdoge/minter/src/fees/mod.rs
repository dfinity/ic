#[cfg(test)]
mod tests;

use crate::lifecycle::init::Network;
use crate::tx::UnsignedTransaction;
use ic_ckbtc_minter::{MillisatoshiPerByte, Satoshi, fees::FeeEstimator};
use std::cmp::max;

// TODO DEFI-2458: have proper domain design for handling units:
// * fee rate (millistatoshis/vbyte or millikoinus/byte)
// * base unit (satoshi or koinu)
// * millis base unit (millisatoshis or millikoinus)
pub struct DogecoinFeeEstimator {
    network: Network,
    retrieve_doge_min_amount: u64,
}

impl DogecoinFeeEstimator {
    pub fn new(network: Network, retrieve_doge_min_amount: u64) -> Self {
        Self {
            network,
            retrieve_doge_min_amount,
        }
    }

    pub fn from_state(state: &ic_ckbtc_minter::state::CkBtcMinterState) -> Self {
        Self::new(
            Network::from(state.btc_network),
            state.retrieve_btc_min_amount,
        )
    }
}

impl FeeEstimator for DogecoinFeeEstimator {
    fn estimate_median_fee(&self, fee_percentiles: &[u64]) -> Option<u64> {
        const DEFAULT_REGTEST_FEE: MillisatoshiPerByte = 5_000;

        match &self.network {
            Network::Mainnet | Network::Testnet => {
                if fee_percentiles.len() < 100 {
                    return None;
                }
                Some(fee_percentiles[50])
            }
            Network::Regtest => Some(DEFAULT_REGTEST_FEE),
        }
    }

    /// Minter cycles consumption to sign and send a transaction with `num_inputs` inputs and `num_outputs` outputs is evaluated
    /// ```text
    /// 29.14B * num_inputs +0.7B * num_outputs + 5.2B,
    /// ```
    /// where `B` denotes one billion cycles.
    ///
    /// Assuming that `1B <= 0.05 DOGE == 5_000_000 Koinu`, we have
    /// ```text
    /// 1.46 DOGE * num_inputs + 0.04 DOGE * num_outputs + 0.26 DOGE,
    /// ```
    fn evaluate_minter_fee(&self, num_inputs: u64, num_outputs: u64) -> Satoshi {
        //in Koinu
        const MINTER_FEE_PER_INPUT: u64 = 146_000_000;
        //in Koinu
        const MINTER_FEE_PER_OUTPUT: u64 = 4_000_000;
        //in Koinu
        const MINTER_FEE_CONSTANT: u64 = 26_000_000;
        // Dogecoin has a dust limit of 0.01 DOGE.
        // in Koinu
        const MINTER_ADDRESS_DUST_LIMIT: u64 = 1_000_000;

        max(
            MINTER_FEE_PER_INPUT * num_inputs
                + MINTER_FEE_PER_OUTPUT * num_outputs
                + MINTER_FEE_CONSTANT,
            MINTER_ADDRESS_DUST_LIMIT,
        )
    }

    fn fee_based_minimum_withrawal_amount(&self, median_fee: u64) -> u64 {
        match self.network {
            Network::Mainnet | Network::Testnet => {
                //in Koinu
                const PER_REQUEST_RBF_BOUND: u64 = 374_000;
                //in Bytes
                const PER_REQUEST_SIZE_BOUND: u64 = 374;
                //in Koinu
                const PER_REQUEST_MINTER_FEE_BOUND: u64 = 326_000;

                let min_withdrawal_amount_increment = self.retrieve_doge_min_amount >> 1;
                let median_fee_rate = median_fee / 1_000;
                ((PER_REQUEST_RBF_BOUND
                    + PER_REQUEST_SIZE_BOUND * median_fee_rate
                    + PER_REQUEST_MINTER_FEE_BOUND)
                    / min_withdrawal_amount_increment)
                    * min_withdrawal_amount_increment
                    + self.retrieve_doge_min_amount
            }
            Network::Regtest => self.retrieve_doge_min_amount,
        }
    }

    fn evaluate_transaction_fee(
        &self,
        unsigned_tx: &UnsignedTransaction,
        fee_per_byte: u64,
    ) -> u64 {
        let tx_size = ic_ckbtc_minter::fake_sign(unsigned_tx).serialized_len();
        (tx_size as u64 * fee_per_byte) / 1000
    }
}
