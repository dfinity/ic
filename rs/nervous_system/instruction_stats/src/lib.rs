use ic_metrics_encoder::MetricsEncoder;
use ic_nervous_system_histogram::{Histogram, STANDARD_POSITIVE_BIN_INCLUSIVE_UPPER_BOUNDS};
use itertools::Itertools;
use lazy_static::lazy_static;
use std::{
    cell::RefCell,
    collections::HashMap,
    marker::PhantomData,
};

#[cfg(not(test))]
use ic_cdk::api::call_context_instruction_counter;

#[cfg(test)]
use crate::tests::call_context_instruction_counter;

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

thread_local! {
    static STATS: RefCell<HashMap<Vec<(String, String)>, Histogram>> = Default::default();
}

pub fn encode_instruction_metrics<MyWrite: std::io::Write>(out: &mut MetricsEncoder<MyWrite>) -> std::io::Result<()> {
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

/// (The design of this assumes that each request type is associated with a
/// unique Candid method. If you follow the very good convention where a method
/// named foo takes FooRequest and returns FooResponse, then you are golden.)
pub trait Request {
    const METHOD_NAME: &'static str;

    /// If you do not want to further break out requests, just return an empty map.
    fn metric_labels(&self) -> HashMap<String, String>;
}

pub struct UpdateInstructionStatsOnDrop<MyRequest: Request> {
    metric_labels: Vec<(String, String)>,

    _phantom_data_my_metric_labels: PhantomData<MyRequest>
}

impl<MyRequest: Request> UpdateInstructionStatsOnDrop<MyRequest> {
    pub fn new(metric_labels: &MyRequest) -> Self {
        let mut metric_labels = metric_labels.metric_labels();

        metric_labels.insert("method_name".to_string(), MyRequest::METHOD_NAME.to_string());

        let metric_labels = metric_labels
            .into_iter()
            .sorted()
            .collect();

        Self {
            metric_labels,
            _phantom_data_my_metric_labels: Default::default(),
        }
    }
}

impl<MyRequest: Request> Drop for UpdateInstructionStatsOnDrop<MyRequest> {
    fn drop(&mut self) {
        let instruction_count = call_context_instruction_counter().min(i64::MAX as u64) as i64;

        STATS.with(|stats| {
            stats.borrow_mut()
                .entry(self.metric_labels.clone())
                .or_insert_with(|| Histogram::new(INSTRUCTIONS_BIN_INCLUSIVE_UPPER_BOUNDS.clone()))
                .add_event(instruction_count);
        });
    }
}
