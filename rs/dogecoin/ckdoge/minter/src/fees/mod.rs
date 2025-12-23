#[cfg(test)]
mod tests;

use crate::candid_api::WithdrawalFee;
use crate::lifecycle::init::Network;
use crate::tx::UnsignedTransaction;
use ic_ckbtc_minter::{
    BuildTxError, MillisatoshiPerByte, Satoshi, address::BitcoinAddress, fees::FeeEstimator,
    state::utxos::UtxoSet,
};
use std::cmp::max;

// TODO DEFI-2458: have proper domain design for handling units:
// * fee rate (millisatoshis/vbyte or millikoinus/byte)
// * base unit (satoshi or koinu)
// * millis base unit (millisatoshis or millikoinus)
pub struct DogecoinFeeEstimator {
    network: Network,
    retrieve_doge_min_amount: u64,
}

impl DogecoinFeeEstimator {
    /// Cost in koinu of 1B cycles.
    ///
    /// Use a lower bound on the price of Doge of 50 DOGE = 1 XDR, so that 5M koinus correspond to 1B cycles.
    pub const COST_OF_ONE_BILLION_CYCLES: u64 = 5_000_000;

    pub fn new(network: Network, retrieve_doge_min_amount: u64) -> Self {
        Self {
            network,
            retrieve_doge_min_amount,
        }
    }

    pub fn from_state(state: &ic_ckbtc_minter::state::CkBtcMinterState) -> Self {
        Self::new(
            Network::try_from(state.btc_network).expect("BUG: unsupported network"),
            state.retrieve_btc_min_amount,
        )
    }
}

impl FeeEstimator for DogecoinFeeEstimator {
    // Dogecoin has a dust limit of 0.01 DOGE.
    // in Koinu
    const DUST_LIMIT: u64 = 1_000_000;

    // Incremental fee rate for resubmission is 10 koinu/byte,
    // corresponding to 10k millikoinus/byte
    const MIN_RELAY_FEE_RATE_INCREASE: u64 = 10_000;

    fn estimate_median_fee(&self, fee_percentiles: &[u64]) -> Option<u64> {
        const DEFAULT_REGTEST_FEE: MillisatoshiPerByte = DogecoinFeeEstimator::DUST_LIMIT * 1_000;

        match &self.network {
            Network::Mainnet => {
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

        max(
            MINTER_FEE_PER_INPUT * num_inputs
                + MINTER_FEE_PER_OUTPUT * num_outputs
                + MINTER_FEE_CONSTANT,
            Self::DUST_LIMIT,
        )
    }

    fn fee_based_minimum_withdrawal_amount(&self, median_fee: u64) -> u64 {
        match self.network {
            Network::Mainnet => {
                //in Koinu
                const PER_REQUEST_RBF_BOUND: u64 = 374_000;
                // in Bytes
                // Size of a typical transaction made by the minter,
                // which is a P2PKH transaction with 2 inputs and 2 outputs
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

    fn reimbursement_fee_for_pending_withdrawal_requests(&self, num_requests: u64) -> u64 {
        // Heuristic:
        // * charge 1B cycles for each request (a burn on the ledger on the fiduciary subnet is probably around 50M cycles).
        num_requests.saturating_mul(Self::COST_OF_ONE_BILLION_CYCLES)
    }
}

pub fn estimate_retrieve_doge_fee<F: FeeEstimator>(
    available_utxos: &mut UtxoSet,
    withdrawal_amount: u64,
    median_fee_millikoinu_per_byte: u64,
    max_num_inputs_in_transaction: usize,
    fee_estimator: &F,
) -> Result<WithdrawalFee, BuildTxError> {
    // We simulate the algorithm that selects UTXOs for the specified amount.
    // Only the address type matters for the amount of bytes, not the actual bytes in the address.
    let dummy_minter_address = BitcoinAddress::P2pkh([u8::MAX; 20]);
    let dummy_recipient_address = BitcoinAddress::P2pkh([42_u8; 20]);

    ic_ckbtc_minter::queries::estimate_withdrawal_fee(
        available_utxos,
        withdrawal_amount,
        median_fee_millikoinu_per_byte,
        dummy_minter_address,
        dummy_recipient_address,
        max_num_inputs_in_transaction,
        fee_estimator,
    )
    .map(WithdrawalFee::from)
}
