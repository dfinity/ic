use crate::Utxo;
use crate::fees::{DogecoinFeeEstimator, estimate_retrieve_doge_fee};
use crate::lifecycle::init::Network;
use crate::test_fixtures::{arbitrary, dogecoin_fee_estimator};
use ic_ckbtc_minter::fees::FeeEstimator;
use proptest::{collection::btree_set, prop_assert};
use std::collections::BTreeSet;
use test_strategy::proptest;

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

#[proptest]
fn test_fee_range(
    #[strategy(btree_set(arbitrary::utxo(5_000u64..1_000_000_000), 20..40))] utxos: BTreeSet<Utxo>,
    #[strategy(0_u64..15_000)] amount: u64,
    #[strategy(2000..10000u64)] fee_rate_in_millikoinus_per_byte: u64,
) {
    const SMALLEST_TX_SIZE_BYTES: u64 = 225; // one input, two outputs
    const MIN_MINTER_FEE: u64 = DogecoinFeeEstimator::DUST_LIMIT;

    let fee_estimator = dogecoin_fee_estimator();
    let amount = std::cmp::max(
        amount,
        fee_estimator.fee_based_minimum_withdrawal_amount(fee_rate_in_millikoinus_per_byte),
    );
    let estimate = estimate_retrieve_doge_fee(
        &utxos,
        amount,
        fee_rate_in_millikoinus_per_byte,
        &fee_estimator,
    )
    .unwrap();
    let lower_bound =
        MIN_MINTER_FEE + SMALLEST_TX_SIZE_BYTES * fee_rate_in_millikoinus_per_byte / 1000;
    let estimate_fee_amount = estimate.minter_fee + estimate.dogecoin_fee;

    prop_assert!(
        estimate_fee_amount >= lower_bound,
        "The fee estimate {} is below the lower bound {}",
        estimate_fee_amount,
        lower_bound
    );
}
