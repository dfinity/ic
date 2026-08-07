use super::*;
use crate::test_fixtures::bitcoin_fee_estimator;
use crate::tx::FeeRate;

#[test]
fn test_fee_based_minimum_withdrawal_amount_rounds_to_half_of_min_amount() {
    // Step 1: Prepare the world.
    // Use a small retrieve_btc_min_amount so the increment (min/2 = 5_000)
    // differs clearly from the old hardcoded 50_000.
    let estimator = BitcoinFeeEstimator::new(Network::Mainnet, 10_000, 0);
    let low_fee_rate = FeeRate::from_millis_per_byte(1_500);

    // Step 2: Run the code under test.
    let result = estimator.fee_based_minimum_withdrawal_amount(low_fee_rate);

    // Step 3: Verify result.
    // increment = 10_000 / 2 = 5_000.
    // fee_sum = 22_100 + ceil(221 * 1.5) + 305 + 0 = 22_100 + 332 + 305 = 22_737.
    // rounded = (22_737 / 5_000) * 5_000 = 4 * 5_000 = 20_000.
    // total = 20_000 + 10_000 = 30_000.
    assert_eq!(result, 30_000);
}

#[test]
fn test_fee_based_minimum_withdrawal_amount_mainnet_behavior_unchanged() {
    // Step 1: Prepare the world.
    // On mainnet retrieve_btc_min_amount = 100_000, so increment = 50_000 —
    // identical to the old hardcoded value, so mainnet behavior is unchanged.
    let estimator = BitcoinFeeEstimator::new(Network::Mainnet, 100_000, 0);
    let low_fee_rate = FeeRate::from_millis_per_byte(1_500);

    // Step 2: Run the code under test.
    let result = estimator.fee_based_minimum_withdrawal_amount(low_fee_rate);

    // Step 3: Verify result.
    // increment = 100_000 / 2 = 50_000 (same as old hardcoded 50_000).
    // fee_sum = 22_100 + 332 + 305 + 0 = 22_737.
    // rounded = (22_737 / 50_000) * 50_000 = 0 * 50_000 = 0.
    // total = 0 + 100_000 = 100_000.
    assert_eq!(result, 100_000);
}

#[test]
fn test_fee_based_minimum_withdrawal_amount_no_division_by_zero_when_min_amount_is_zero() {
    // Step 1: Prepare the world.
    // Edge case: retrieve_btc_min_amount = 0 → increment = max(0/2, 1) = 1.
    let estimator = BitcoinFeeEstimator::new(Network::Mainnet, 0, 0);
    let low_fee_rate = FeeRate::from_millis_per_byte(1_500);

    // Step 2: Run the code under test.
    let result = estimator.fee_based_minimum_withdrawal_amount(low_fee_rate);

    // Step 3: Verify result — no panic, increment of 1 means no rounding at all.
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
