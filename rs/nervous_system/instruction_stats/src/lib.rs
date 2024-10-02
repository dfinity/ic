//! Important limitation: This only only works on update methods, not query.
//! This is because canisters (in particular, their heap) are not changed by
//! queries. This is a fundamental platform limitation, not just a limitation in
//! the implementation of this library.
//!
//! Basic usage:
//!
//! 0. Optional. If you want to break out the request stream to a method using
//!    labels (see https://prometheus.io/docs/concepts/data_model/) implement
//!    the Request trait. Otherwise, just use BasicRequest.
//!
//! 1. At the beginning of a method implementation, add one line:
//!    let _on_drop = UpdateInstructionStatsOnDrop::new(&request);
//!    If you did not do step 0, pass
//!    &BasicRequest { method_name: "your_method_name" }
//!    instead of &request.
//!
//! 2. Call encode_instruction_metrics. This writes a data for a metric named
//!    `candid_call_instructions`.

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

/// Adds statistics related to instructions used to service canister calls to `out`.
///
/// Despite the name being plural ("metrics"), currently, this only adds one
/// metric: candid_call_instructions.
///
/// It is broken out by method_name (and possibly other custom labels, according
/// to Request::request_labels).
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

/// The basic characteristics of a request (for the purposes of instruction
/// stats gathering).
///
/// The resulting time series will have as its labels
///
/// { "method_name" => method_name } + request_labels.
///
/// If you do not need to break stats out beyond method_name, see BasicRequest.
pub trait Request {
    /// In general, the body of this would look like
    /// "make_sandwhich".to_string(). This method could have instead been a
    /// constant, but we wanted BasicRequest to be able to cover the common case
    /// where people do not wish to further break out instruction stats for a
    /// method.
    fn method_name(&self) -> String;

    /// If you do not want to further break out requests, just return an empty map.
    fn request_labels(&self) -> HashMap<String, String>;
}

/// An implementation of Request for people who do not want/need custom request
/// labels.
pub struct BasicRequest {
    method_name: &'static str,
}

impl Request for BasicRequest {
    fn method_name(&self) -> String {
        self.method_name.to_string()
    }

    fn request_labels(&self) -> HashMap<String, String> {
        Default::default()
    }
}

/// Does what the name says.
///
/// For now (and possibly forever), "update" just consists of incrementing the right counter.
///
/// As statistics accumulate, they can be seen by calling encode_instruction_metrics.
pub struct UpdateInstructionStatsOnDrop<MyRequest: Request> {
    metric_labels: Vec<(String, String)>,

    _phantom_data_my_metric_labels: PhantomData<MyRequest>
}

impl<MyRequest: Request> UpdateInstructionStatsOnDrop<MyRequest> {
    pub fn new(request: &MyRequest) -> Self {
        let mut metric_labels = request.request_labels();

        metric_labels.insert("method_name".to_string(), request.method_name());

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
