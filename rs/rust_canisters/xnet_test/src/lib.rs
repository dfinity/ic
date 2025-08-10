use candid::{CandidType, Deserialize};
use ic_management_canister_types::CanisterId;
use serde::Serialize;
use std::time::Duration;

/// Configuration of the network: the outer vector enumerates canisters
/// installed on the same subnet.
///
/// This message is used as request payload for "start" call.
pub type NetworkTopology = Vec<Vec<CanisterId>>;

/// Arguments for the "start" call of this canister.
#[derive(Default, Clone, CandidType, Deserialize, Debug)]
pub struct StartArgs {
    pub network_topology: NetworkTopology,
    pub canister_to_subnet_rate: u64,
    pub request_payload_size_bytes: u64,
    pub call_timeouts_seconds: Vec<Option<u32>>,
    pub response_payload_size_bytes: u64,
}

/// Metrics observed by this canister.
///
/// This message is used as reply payload for "metrics" query.
#[derive(Default, Clone, CandidType, Serialize, Deserialize, Debug)]
pub struct Metrics {
    /// Number of calls attempted (whether successful or not).
    pub calls_attempted: usize,

    /// Number of times a call failed synchronously (e.g. due to a full canister
    /// output queue or running out of cycles).
    pub call_errors: usize,

    /// Number of requests rejected by the remote subnet (e,g, due to a full
    /// canister input queue).
    pub reject_responses: usize,

    /// Number of sequence number errors.
    pub seq_errors: usize,

    /// Observed message roundtrip latencies.
    pub latency_distribution: LatencyDistribution,

    /// Rotating buffer collecting log messages.
    pub log: String,
}

impl Metrics {
    /// Adds the observations of `other` to `self`.
    pub fn merge(&mut self, other: &Metrics) {
        self.calls_attempted += other.calls_attempted;
        self.call_errors += other.call_errors;
        self.reject_responses += other.reject_responses;
        self.seq_errors += other.seq_errors;
        self.latency_distribution.merge(&other.latency_distribution);
        self.log.push_str("-----\n");
        self.log.push_str(&other.log);
    }

    /// Returns the number of requests sent successfully.
    pub fn requests_sent(&self) -> usize {
        self.calls_attempted - self.call_errors
    }
}

/// Latency distribution implements a cumulative histogram used to record
/// message roundtrip latencies.
///
/// The latency is measured using IC time, which is not guaranteed to be
/// particularly accurate.
#[derive(CandidType, Clone, Serialize, Deserialize, Debug)]
pub struct LatencyDistribution {
    buckets: Vec<(i64, usize)>,
    sum_millis: usize,
}

impl Default for LatencyDistribution {
    fn default() -> Self {
        const MUL: [i64; 3] = [1, 2, 5];
        // constructs buckets
        // [10ms, 20ms, 50ms, 100ms, 200ms, 500ms, 1s, 2s, 5s, ..., 5000s, i64::MAX]
        Self {
            buckets: (1..6)
                .flat_map(|p| MUL.iter().map(move |n| n * 10i64.pow(p)))
                .chain(std::iter::once(i64::MAX))
                .map(|n| (n, 0))
                .collect(),
            sum_millis: 0,
        }
    }
}

impl LatencyDistribution {
    /// Updates this histogram with a new observed latency.
    pub fn observe(&mut self, latency: Duration) {
        let ms = latency.as_millis() as i64;
        self.sum_millis += ms as usize;

        // The number of cells in the histogram is fixed, so this is really O(1).
        for (bucket, counter) in self.buckets.iter_mut().rev() {
            if *bucket < ms {
                break;
            }
            *counter += 1;
        }
    }

    /// Returns an iterator over buckets of the histogram.
    pub fn buckets(&self) -> impl Iterator<Item = &(i64, usize)> {
        self.buckets.iter()
    }

    /// Returns the sum of all observed latencies.
    pub fn sum_millis(&self) -> usize {
        self.sum_millis
    }

    /// Adds the observations of `other` to `self`.
    pub fn merge(&mut self, other: &LatencyDistribution) {
        assert_eq!(self.buckets.len(), other.buckets.len());
        self.buckets.iter_mut().zip(other.buckets.iter()).for_each(
            |(self_bucket, other_bucket)| {
                assert_eq!(self_bucket.0, other_bucket.0);
                self_bucket.1 += other_bucket.1;
            },
        );
        self.sum_millis += other.sum_millis;
    }
}
