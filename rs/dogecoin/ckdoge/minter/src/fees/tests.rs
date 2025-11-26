use crate::fees::DogecoinFeeEstimator;
use crate::lifecycle::init::Network;
use ic_ckbtc_minter::fees::FeeEstimator;

pub const DOGE: u64 = 100_000_000;

#[test]
fn should_increase_minimum_withdrawal_amount_by_half() {
    let initial_min_amount = 50 * DOGE;
    let increment = 25 * DOGE;
    let estimator = DogecoinFeeEstimator::new(Network::Mainnet, initial_min_amount);

    for fee_rate_in_millikoinus_per_byte in
        [0, 1, 100, 1_000, 10_000, 100_000, 1_000_000].map(|f| f * 1_000)
    {
        assert_eq!(
            estimator.fee_based_minimum_withdrawal_amount(fee_rate_in_millikoinus_per_byte),
            initial_min_amount,
            "BUG: unexpected fee for fee rate {fee_rate_in_millikoinus_per_byte}"
        );
    }

    assert_eq!(
        estimator.fee_based_minimum_withdrawal_amount(10_000_000 * 1_000),
        initial_min_amount + increment,
    );
}
