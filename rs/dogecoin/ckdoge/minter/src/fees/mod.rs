use crate::lifecycle::init::Network;
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
    fn estimate_median_fee(&self, _: &[u64]) -> Option<u64> {
        todo!()
    }

    fn minimum_withrawal_amount(&self, _: u64) -> u64 {
        todo!()
    }
}
