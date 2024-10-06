//! Important limitation: This only only works on update methods, not query.
//! This is because canisters (in particular, their heap) are not changed by
//! queries. This is a fundamental platform limitation, not just a limitation in
//! the implementation of this library.
//!
//! Basic usage:
//!
//! 1. At the beginning of a canister method implementation, add one line:
//!    let _on_drop = UpdateInstructionStatsOnDrop::new(method_name, additional_labels);
//!
//! 2. Call encode_instruction_metrics. This writes a data for a metric named
//!    `candid_call_instructions`.

use ic_metrics_encoder::MetricsEncoder;
use ic_nervous_system_histogram::{Histogram, STANDARD_POSITIVE_BIN_INCLUSIVE_UPPER_BOUNDS};
use lazy_static::lazy_static;
use std::{cell::RefCell, collections::BTreeMap};

#[cfg(test)]
use crate::tests::call_context_instruction_counter;
#[cfg(not(test))]
use ic_cdk::api::call_context_instruction_counter;

#[cfg(test)]
mod tests;

lazy_static! {
    // Covers a wide range, yet is still fairly fine grained.
    static ref INSTRUCTIONS_BIN_INCLUSIVE_UPPER_BOUNDS: Vec<i64> = {
        // Drop values that are too small and too big.
        STANDARD_POSITIVE_BIN_INCLUSIVE_UPPER_BOUNDS
            .clone()
            .into_iter()
            // For instructions consumed, only values in this range make sense.
            // For the upper bound, 40 billion was obtained from this page:
            // https://internetcomputer.org/docs/current/developer-docs/smart-contracts/maintain/resource-limits
            .filter(|b| 100_000 <= *b && *b <= 40_000_000_000)
            .collect()
    };
}

type LabelSet = BTreeMap<String, String>;
thread_local! {
    static STATS: RefCell<BTreeMap<LabelSet, Histogram>> = Default::default();
}

/// Adds statistics related to instructions used to service canister calls to `out`.
///
/// Despite the name being plural ("metrics"), currently, this only adds one
/// metric: candid_call_instructions.
///
/// It is broken out by method_name (and possibly other custom labels, according
/// to Request::request_labels).
pub fn encode_instruction_metrics<MyWrite: std::io::Write>(
    out: &mut MetricsEncoder<MyWrite>,
) -> std::io::Result<()> {
    STATS.with(|stats| {
        let mut out = out.histogram_vec(
            "candid_call_instructions",
            "How many instructions were directly consumed to service requests. Useful numbers: https://internetcomputer.org/docs/current/developer-docs/smart-contracts/maintain/resource-limits",
        )?;

        for (metric_labels, histogram) in stats.borrow().iter() {
            out = histogram.encode_metrics(metric_labels, out)?;
        }

        Ok(())
    })
}

/// Does what the name says.
///
/// For now (and possibly forever), "update" just consists of incrementing the
/// right counter (by 1), based on the amount of instructions.
///
/// As statistics accumulate, they can be seen by calling
/// encode_instruction_metrics.
pub struct UpdateInstructionStatsOnDrop {
    metric_labels: BTreeMap<String, String>,
}

impl UpdateInstructionStatsOnDrop {
    /// What is a label: https://prometheus.io/docs/concepts/data_model/
    ///
    /// (In cases where there is no desire to break out stats, pass an empty vec to the
    /// additional_labels parameter.)
    ///
    /// The resulting full set of labels includes "method_name" => method_name.
    /// (If "method_name" is one of the keys in additional_labels, it gets
    /// ignored.)
    pub fn new(method_name: &str, additional_labels: BTreeMap<String, String>) -> Self {
        let mut metric_labels = additional_labels;
        metric_labels.insert("method_name".to_string(), method_name.to_string());
        Self { metric_labels }
    }
}

impl Drop for UpdateInstructionStatsOnDrop {
    fn drop(&mut self) {
        let instruction_count = call_context_instruction_counter().min(i64::MAX as u64) as i64;

        STATS.with(|stats| {
            stats
                .borrow_mut()
                .entry(self.metric_labels.clone())
                .or_insert_with(|| Histogram::new(INSTRUCTIONS_BIN_INCLUSIVE_UPPER_BOUNDS.clone()))
                .add_event(instruction_count);
        });
    }
}
