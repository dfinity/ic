#[cfg(test)]
mod tests;

use crate::fees::DogecoinFeeEstimator;
use crate::lifecycle::init::Network;

pub mod arbitrary;

pub fn dogecoin_fee_estimator() -> DogecoinFeeEstimator {
    const RETRIEVE_DOGE_MIN_AMOUNT: u64 = 50 * 100_000_000;
    DogecoinFeeEstimator::new(Network::Mainnet, RETRIEVE_DOGE_MIN_AMOUNT)
}
