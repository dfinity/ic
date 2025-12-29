#[cfg(test)]
mod tests;

use crate::address::DogecoinAddress;
use crate::fees::DogecoinFeeEstimator;
use crate::lifecycle::init::Network;

pub mod arbitrary;
pub mod mock;

pub fn dogecoin_fee_estimator() -> DogecoinFeeEstimator {
    const RETRIEVE_DOGE_MIN_AMOUNT: u64 = 50 * 100_000_000;
    DogecoinFeeEstimator::new(Network::Mainnet, RETRIEVE_DOGE_MIN_AMOUNT)
}

pub fn dogecoin_address_to_bitcoin(
    address: DogecoinAddress,
) -> ic_ckbtc_minter::address::BitcoinAddress {
    match address {
        DogecoinAddress::P2pkh(hash) => ic_ckbtc_minter::address::BitcoinAddress::P2pkh(hash),
        DogecoinAddress::P2sh(hash) => ic_ckbtc_minter::address::BitcoinAddress::P2sh(hash),
    }
}
