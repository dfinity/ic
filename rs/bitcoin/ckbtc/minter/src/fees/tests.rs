use super::*;
use crate::test_fixtures::bitcoin_fee_estimator;

#[test]
fn test_estimate_nth_fee() {
    let estimator = bitcoin_fee_estimator();
    let min_fee = estimator.minimum_fee_per_vbyte();
    assert_eq!(estimator.estimate_nth_fee(&[], 10), None);
    let percentiles = (1..=100).map(|i| i * 150).collect::<Vec<_>>();
    for i in 0..100 {
        assert_eq!(
            estimator.estimate_nth_fee(&percentiles, i),
            Some(percentiles[i].max(min_fee))
        );
    }
    assert_eq!(estimator.estimate_nth_fee(&percentiles, 100), None);
}
