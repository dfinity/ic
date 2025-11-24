use crate::state::CkBtcMinterState;
use crate::tx::UnsignedTransaction;
use crate::{Network, fake_sign};
use ic_btc_interface::{MillisatoshiPerByte, Satoshi};
use std::cmp::max;

pub trait FeeEstimator {
    const DUST_LIMIT: u64;

    /// Estimate the median fees based on the given fee percentiles (slice of fee rates in milli base unit per vbyte/byte).
    fn estimate_median_fee(
        &self,
        fee_percentiles: &[MillisatoshiPerByte],
    ) -> Option<MillisatoshiPerByte>;

    /// Evaluate the fee necessary to cover the minter's cycles consumption.
    fn evaluate_minter_fee(&self, num_inputs: u64, num_outputs: u64) -> Satoshi;

    /// Evaluate transaction fee with the given fee rate (in milli base unit per vbyte/byte)
    fn evaluate_transaction_fee(&self, tx: &UnsignedTransaction, fee_rate: u64) -> u64;

    /// Compute a new minimum withdrawal amount based on the current fee rate
    fn fee_based_minimum_withdrawal_amount(&self, median_fee: MillisatoshiPerByte) -> Satoshi;
}

pub struct BitcoinFeeEstimator {
    /// The Bitcoin network that the minter will connect to
    network: Network,
    /// Minimum amount of bitcoin that can be retrieved
    retrieve_btc_min_amount: u64,
    /// The fee for a single Bitcoin check request.
    check_fee: u64,
}

impl BitcoinFeeEstimator {
    /// The minter's address is of type P2WPKH which means it has a dust limit of 294 sats.
    /// For additional safety, we round that value up.
    pub const MINTER_ADDRESS_P2PWPKH_DUST_LIMIT: Satoshi = 300;

    pub fn new(network: Network, retrieve_btc_min_amount: u64, check_fee: u64) -> Self {
        Self {
            network,
            retrieve_btc_min_amount,
            check_fee,
        }
    }

    pub fn from_state(state: &CkBtcMinterState) -> Self {
        Self::new(
            state.btc_network,
            state.retrieve_btc_min_amount,
            state.check_fee,
        )
    }

    /// An estimated fee per vbyte of 142 millisatoshis per vbyte was selected around 2025.06.21 01:09:50 UTC
    /// for Bitcoin Mainnet, whereas the median fee around that time should have been 2_000.
    /// Until we know the root cause, we ensure that the estimated fee has a meaningful minimum value.
    const fn minimum_fee_per_vbyte(&self) -> MillisatoshiPerByte {
        match &self.network {
            Network::Mainnet => 1_500,
            Network::Testnet => 1_000,
            Network::Regtest => 0,
        }
    }
}

impl FeeEstimator for BitcoinFeeEstimator {
    // The default dustRelayFee is 3 sat/vB,
    // which translates to a dust threshold of 546 satoshi for P2PKH outputs.
    // The threshold for other types is lower,
    // so we simply use 546 satoshi as the minimum amount per output.
    const DUST_LIMIT: u64 = 546;

    fn estimate_median_fee(
        &self,
        fee_percentiles: &[MillisatoshiPerByte],
    ) -> Option<MillisatoshiPerByte> {
        /// The default fee we use on regtest networks.
        const DEFAULT_REGTEST_FEE: MillisatoshiPerByte = 5_000;

        let median_fee = match &self.network {
            Network::Mainnet | Network::Testnet => {
                if fee_percentiles.len() < 100 {
                    return None;
                }
                Some(fee_percentiles[50])
            }
            Network::Regtest => Some(DEFAULT_REGTEST_FEE),
        };
        median_fee.map(|f| f.max(self.minimum_fee_per_vbyte()))
    }

    fn evaluate_minter_fee(&self, num_inputs: u64, num_outputs: u64) -> u64 {
        const MINTER_FEE_PER_INPUT: u64 = 146;
        const MINTER_FEE_PER_OUTPUT: u64 = 4;
        const MINTER_FEE_CONSTANT: u64 = 26;

        max(
            MINTER_FEE_PER_INPUT * num_inputs
                + MINTER_FEE_PER_OUTPUT * num_outputs
                + MINTER_FEE_CONSTANT,
            Self::MINTER_ADDRESS_P2PWPKH_DUST_LIMIT,
        )
    }

    /// Returns the minimum withdrawal amount based on the current median fee rate (in millisatoshi per byte).
    /// The returned amount is in satoshi.
    fn fee_based_minimum_withdrawal_amount(&self, median_fee: MillisatoshiPerByte) -> Satoshi {
        match self.network {
            Network::Mainnet | Network::Testnet => {
                const PER_REQUEST_RBF_BOUND: u64 = 22_100;
                const PER_REQUEST_VSIZE_BOUND: u64 = 221;
                const PER_REQUEST_MINTER_FEE_BOUND: u64 = 305;

                let median_fee_rate = median_fee / 1_000;
                ((PER_REQUEST_RBF_BOUND
                    + PER_REQUEST_VSIZE_BOUND * median_fee_rate
                    + PER_REQUEST_MINTER_FEE_BOUND
                    + self.check_fee)
                    / 50_000) //TODO DEFI-2187: adjust increment of minimum withdrawal amount to be a multiple of retrieve_btc_min_amount/2
                    * 50_000
                    + self.retrieve_btc_min_amount
            }
            Network::Regtest => self.retrieve_btc_min_amount,
        }
    }

    fn evaluate_transaction_fee(
        &self,
        unsigned_tx: &UnsignedTransaction,
        fee_per_vbyte: u64,
    ) -> u64 {
        let tx_vsize = fake_sign(unsigned_tx).vsize();
        (tx_vsize as u64 * fee_per_vbyte) / 1000
    }
}
