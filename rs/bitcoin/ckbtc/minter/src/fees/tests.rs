use super::*;
use crate::test_fixtures::bitcoin_fee_estimator;
use crate::tx::FeeRate;

#[test]
fn test_fee_based_minimum_withdrawal_amount_rounds_to_half_of_min_amount() {
    let estimator = BitcoinFeeEstimator::new(Network::Mainnet, 10_000, 0);
    let low_fee_rate = FeeRate::from_millis_per_byte(1_500);

    let result = estimator.fee_based_minimum_withdrawal_amount(low_fee_rate);

    assert_eq!(result, 30_000);
}

#[test]
fn test_fee_based_minimum_withdrawal_amount_mainnet_behavior_unchanged() {
    let estimator = BitcoinFeeEstimator::new(Network::Mainnet, 100_000, 0);
    let low_fee_rate = FeeRate::from_millis_per_byte(1_500);

    let result = estimator.fee_based_minimum_withdrawal_amount(low_fee_rate);

    assert_eq!(result, 100_000);
}

#[test]
fn test_fee_based_minimum_withdrawal_amount_no_division_by_zero_when_min_amount_is_zero() {
    let estimator = BitcoinFeeEstimator::new(Network::Mainnet, 0, 0);
    let low_fee_rate = FeeRate::from_millis_per_byte(1_500);

    let result = estimator.fee_based_minimum_withdrawal_amount(low_fee_rate);

    assert_eq!(result, 22_737);
}

#[test]
fn test_estimate_nth_fee() {
    let estimator = bitcoin_fee_estimator();
    let min_fee = estimator.minimum_fee_per_vbyte();
    assert_eq!(estimator.estimate_nth_fee(&[], 10), None);
    let percentiles = (1..=100)
        .map(|i| FeeRate::from_millis_per_byte(i * 150))
        .collect::<Vec<_>>();
    for i in 0..100 {
        assert_eq!(
            estimator.estimate_nth_fee(&percentiles, i),
            Some(percentiles[i].max(min_fee))
        );
    }
    assert_eq!(estimator.estimate_nth_fee(&percentiles, 100), None);
}
