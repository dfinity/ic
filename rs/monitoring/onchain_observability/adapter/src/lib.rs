//! This module is for collecting replica stats and sending to a reporting canister

/// This module contains the basic configuration struct used to start up an adapter instance.
mod config;
/// Error handling
mod error_types;
/// Config settings from command line
mod flags;
/// Separate location for misc helper functions
mod helpers;
/// Metrics for the adapter
mod metrics;
/// Temporary helpers for node id
mod non_sampled_metrics_collector;
/// Provides a sampling API to fetch single instance of metric and aggregate
mod sampled_metrics_collector;

pub use config::Config;
pub use error_types::{CanisterPublishError, MetricsCollectError};
pub use flags::Flags;
pub use helpers::poll_until_reporting_enabled;
pub use metrics::OnchainObservabilityAdapterMetrics;
pub use non_sampled_metrics_collector::{
    collect_metrics_for_peers, derive_peer_counters_for_current_report_interval, NonSampledMetrics,
    PeerCounterMetrics,
};
pub use sampled_metrics_collector::SampledMetricsCollector;
