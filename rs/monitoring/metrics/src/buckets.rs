//! Various bucketing schemes to use when defining histograms.

use std::cmp::Ordering;

/// Create buckets using divisors of 10 multiplied by powers of 10, e.g.,
/// ```text
/// […, 0.1, 0.2, 0.5, 1, 2, 5, 10, 20, 50, …]
/// ```
///
/// The buckets go from `10^min_power` to `5 × 10^max_power`, inclusively.
/// The total number of buckets is `3 * (max_power - min_power + 1)`.
///
/// # Examples
///
/// ```
/// use ic_metrics::buckets::decimal_buckets;
///
/// assert_eq!(vec![0.1, 0.2, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 50.0], decimal_buckets(-1, 1));
/// assert_eq!(vec![1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0, 200.0, 500.0], decimal_buckets(0, 2));
/// assert_eq!(3 * 21, decimal_buckets(-10, 10).len());
/// ```
///
/// # Panics
///
/// * Panics if min_power > max_power.
pub fn decimal_buckets(min_power: i32, max_power: i32) -> Vec<f64> {
    assert!(
        min_power <= max_power,
        "min_power must be <= max_power, given {} and {}",
        min_power,
        max_power
    );
    let mut buckets = Vec::with_capacity(3 * (max_power - min_power + 1) as usize);
    for n in min_power..=max_power {
        for m in &[1f64, 2f64, 5f64] {
            buckets.push(m * 10f64.powi(n))
        }
    }
    buckets
}

/// Create decimal buckets with `0` as the first bucket
pub fn decimal_buckets_with_zero(min_power: i32, max_power: i32) -> Vec<f64> {
    let mut buckets = decimal_buckets(min_power, max_power);
    buckets.insert(0, 0f64);
    buckets
}

/// Create `count` buckets forming an arithmetic progression, i.e.
/// ```text
/// [start, start + width, start + 2 × width, …, start + (count - 1) × width]
/// ```
///
/// # Examples
///
/// ```
/// use ic_metrics::buckets::linear_buckets;
/// assert_eq!(vec![0.0, 1.0, 2.0, 3.0, 4.0, 5.0], linear_buckets(0.0, 1.0, 6));
/// ```
///
/// # Panics
///
/// * Panics if `count == 0`.
/// * Panics if `width <= 0`.
pub fn linear_buckets(start: f64, width: f64, count: usize) -> Vec<f64> {
    prometheus::linear_buckets(start, width, count).unwrap()
}

/// Create `count` buckets forming a geometric progression, i.e.
/// ```text
/// [start, start × factor, start × factor^2, …, start × factor^(count - 1)]
/// ```
///
/// # Examples
///
/// ```
/// use ic_metrics::buckets::exponential_buckets;
/// assert_eq!(vec![1.0, 2.0, 4.0, 8.0, 16.0], exponential_buckets(1.0, 2.0, 5));
/// ```
///
/// # Panics
///
/// * Panics if `count == 0`.
/// * Panics if `start <= 0`.
/// * Panics if `factor <= 1`.
pub fn exponential_buckets(start: f64, factor: f64, count: usize) -> Vec<f64> {
    prometheus::exponential_buckets(start, factor, count).unwrap()
}

/// Insert a bucket in the existing vector of buckets.
///
/// The bucket will be added in the correct order in the vector. The method
/// assumes that the elements of the bucket are already sorted.
///
/// # Examples
///
/// ```
/// use ic_metrics::buckets::{add_bucket, decimal_buckets};
/// assert_eq!(vec![1.0, 2.0, 4.5, 5.0], add_bucket(4.5, decimal_buckets(0, 0)));
/// ```
pub fn add_bucket(new_bound: f64, mut buckets: Vec<f64>) -> Vec<f64> {
    // core::cmp::Ord is not implemented for f64, so we rely on the partial
    // ordering. Total ordering has to deal with NaNs, +/-Infs, which we don't
    // have do to here, simply because such values will cause Prometheus to
    // throw errors.
    match buckets.binary_search_by(|probe| probe.partial_cmp(&new_bound).unwrap_or(Ordering::Less))
    {
        Ok(_) => {} // element already in vector @ `pos`
        Err(pos) => buckets.insert(pos, new_bound),
    }
    buckets
}
