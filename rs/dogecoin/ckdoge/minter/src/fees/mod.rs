use crate::lifecycle::init::Network;
use ic_ckbtc_minter::MillisatoshiPerByte;
use ic_ckbtc_minter::fees::FeeEstimator;

pub struct DogecoinFeeEstimator {
    network: Network,
    retrieve_doge_min_amount: u64,
}

impl DogecoinFeeEstimator {
    pub fn from_state(state: &ic_ckbtc_minter::state::CkBtcMinterState) -> Self {
        Self {
            network: Network::from(state.btc_network),
            retrieve_doge_min_amount: state.retrieve_btc_min_amount,
        }
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

    fn minimum_withrawal_amount(&self, median_fee: u64) -> u64 {
        match self.network {
            Network::Mainnet | Network::Testnet => {
                const PER_REQUEST_RBF_BOUND: u64 = 22_100;
                const PER_REQUEST_VSIZE_BOUND: u64 = 221;
                const PER_REQUEST_MINTER_FEE_BOUND: u64 = 305;

                let median_fee_rate = median_fee / 1_000;
                ((PER_REQUEST_RBF_BOUND
                    + PER_REQUEST_VSIZE_BOUND * median_fee_rate
                    + PER_REQUEST_MINTER_FEE_BOUND)
                    / 50_000)
                    * 50_000
                    + self.retrieve_doge_min_amount
            }
            Network::Regtest => self.retrieve_doge_min_amount,
        }
    }
}
