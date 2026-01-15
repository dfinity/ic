//! An "event" has some real number associated with it. For example, a request
//! takes 123 ms to process.
//!
//! The Histogram struct in this crate does two things:
//!
//! 1. Groups events based on
//!    a) the real number associated with the event
//!    b) binning scheme
//! 2. Counts how many events there are in each group.
//!
//! This is designed to plug into ic_metrics_encoder::MetricsEncoder::histogram_vec.
//!
//! A limitation of this is that instead of being able to use f64 for the real
//! value associated with an event, you must use i64. You can usually work with
//! this by picking a sufficiently small unit.

use ic_metrics_encoder::LabeledHistogramBuilder;
use std::collections::BTreeMap;

#[cfg(test)]
mod tests;

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
