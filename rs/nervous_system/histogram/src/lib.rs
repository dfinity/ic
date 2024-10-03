use ic_metrics_encoder::LabeledHistogramBuilder;
use itertools::Itertools;
use lazy_static::lazy_static;
use std::collections::BTreeMap;

#[cfg(test)]
mod tests;

lazy_static! {
    /// As the name suggests, this is useful when constructing a Histogram.
    ///
    /// The value of this is vec![1,2,3, ... 10, 20, 30, ... 100, 125, 150, 175,
    /// 200, 225, 250, 275, ...] and goes as high as i64 allows.
    pub static ref STANDARD_POSITIVE_BIN_INCLUSIVE_UPPER_BOUNDS: Vec<i64> = {
        let units = (1..=9).collect::<Vec<i64>>();

        let max_e = i64::MAX.ilog10();
        let powers_of_ten = (0..=max_e).map(|e| 10_i64.pow(e)).collect::<Vec<i64>>();

        let mut result = powers_of_ten
            .iter()
            .cartesian_product(units.iter())
            .filter_map(|(power_of_ten, unit)| power_of_ten.checked_mul(*unit))
            .unique()
            .collect::<Vec<i64>>();

        // result now looks like [1, 2, 3, ... 10, 20, 30, ... 100, 200, 300, ...]
        // Next, we further "subdivide" elements >= 100 into quarters. So for,
        // example 200 expands to 200, 225, 250, 275.

        let tail = result.split_off(18);
        debug_assert_eq!(result[result.len() - 1], 90);
        debug_assert_eq!(tail[0], 100);

        let minors = [0, 25, 50, 75];
        let mut tail = tail
            .iter()
            .cartesian_product(minors.iter())
            .filter_map(|(major, minor)| {
                let e = major.ilog10();

                10_i64.pow(e.saturating_sub(2))
                    .saturating_mul(*minor)
                    .checked_add(*major)
            })
            .collect::<Vec<i64>>();

        // Concatenate tail back onto result.
        result.append(&mut tail);

        // A sanity check. Looks like we generated 634 upper bounds.
        debug_assert!(result.len() < 1000, "{:#?}", result);

        result
    };
}

/// An "event" has some real number associated with it. For example, a request takes 123 ms to
/// process.
///
/// This does two things:
///
/// 1. Groups events based on
///     a) the real number associated with the event
///     b) bucketing scheme (more on this later)
/// 2. Counts how many events there are in each group.
///
/// This is designed to plug into ic_metrics_encoder::MetricsEncoder::histogram_vec.
///
/// A limitation of this is that instead of being able to use f64 for the real
/// value associated with an event, you must use i64. You can usually work with
/// this by picking a sufficiently small unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Histogram {
    bin_inclusive_upper_bound_to_count: BTreeMap<i64, u64>,

    // Counts events that do not fall into one of the finite bins.
    infinity_bin_count: u64,

    // This can be used to find the mean of observed real values associated with events.
    sum: i64,
}

impl Histogram {
    pub fn new(bin_inclusive_upper_bounds: Vec<i64>) -> Self {
        let bin_inclusive_upper_bound_to_count = bin_inclusive_upper_bounds
            .into_iter()
            .map(|bin_inclusive_upper_bound| (bin_inclusive_upper_bound, 0))
            .collect();

        Self {
            infinity_bin_count: 0,
            bin_inclusive_upper_bound_to_count,
            sum: 0,
        }
    }

    pub fn add_event(&mut self, value: i64) {
        self.sum += value;

        let count: &mut u64 = self
            .bin_inclusive_upper_bound_to_count
            .range_mut(value..)
            .next()
            .map(|(_, count)| count)
            .unwrap_or(&mut self.infinity_bin_count);

        *count += 1;
    }

    pub fn encode_metrics<'a, MyWrite: std::io::Write>(
        &self,
        metric_labels: &BTreeMap<String, String>,
        out: LabeledHistogramBuilder<'a, MyWrite>,
    ) -> std::io::Result<LabeledHistogramBuilder<'a, MyWrite>> {
        // Convert String to &str.
        let metric_labels = metric_labels
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect::<Vec<_>>();

        // Convert from integers to floats.
        let bin_inclusive_upper_bound_to_count = self
            .bin_inclusive_upper_bound_to_count
            .iter()
            .map(|(bin_inclusive_upper_bound, count)| {
                (*bin_inclusive_upper_bound as f64, *count as f64)
            })
            .chain([(f64::INFINITY, self.infinity_bin_count as f64)]);

        out.histogram(
            &metric_labels,
            bin_inclusive_upper_bound_to_count,
            self.sum as f64,
        )
    }
}
