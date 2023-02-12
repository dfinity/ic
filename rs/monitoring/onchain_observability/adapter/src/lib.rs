//! This module is for collecting replica stats and sending to a reporting canister

/// This module contains the basic configuration struct used to start up an adapter instance.
mod config;
/// Config settings from command line
mod flags;
/// Error handling
mod metrics_parse_error;
/// Provides a sampling API to fetch single instance of metric and aggregate
mod sampled_metrics_collector;
/// Temporary helpers for node id
mod static_metric_collector;

pub use config::Config;
pub use flags::Flags;
pub use metrics_parse_error::MetricsParseError;
pub use sampled_metrics_collector::SampledMetricsCollector;
pub use static_metric_collector::get_peer_ids;
