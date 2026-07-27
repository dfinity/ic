mod dark_launch;
mod legacy;
mod metrics;
mod payg;

use std::time::Duration;

use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_types::{
    NumBytes, NumInstructions,
    canister_http::{CanisterHttpPaymentReceipt, CanisterHttpRequestContext, PricingVersion},
};
pub use ic_types_cycles::CanisterCyclesCostSchedule;

use dark_launch::DarkLaunchTracker;
use legacy::LegacyTracker;
use metrics::PricingMetrics;
use payg::PayAsYouGoTracker;

pub trait BudgetTracker: Send {
    /// Returns the maximum network resources the Adapter is allowed to consume.
    fn get_adapter_limits(&self) -> AdapterLimits;
    /// Deducts the cost of the network resources consumed by the request.
    ///
    /// # Invariants
    ///  - This method returns `Ok(())` if `network_usage <= get_adapter_limits()`.
    ///  - This method returns `Err(PricingError)` if `network_usage > get_adapter_limits()`.
    ///
    /// Note that "<=" is used here to mean field-wise less than or equal to.
    fn subtract_network_usage(&mut self, network_usage: NetworkUsage) -> Result<(), PricingError>;
    /// Returns the maximum instructions allowed for the transformation function.
    fn get_transform_limit(&self) -> NumInstructions;
    /// Deducts the cost of the instructions consumed by the transformation.
    ///
    /// # Invariants
    ///  - This method returns `Ok(())` if and only if `usage <= get_transform_limit()`.
    fn subtract_transform_usage(&mut self, usage: NumInstructions) -> Result<(), PricingError>;
    /// Deducts the cost of the final (post-transform) response that this replica
    /// produced and that will be gossiped to peers. This cost does not apply to fully-replicated
    /// requests, which doesn't gossip responses.
    ///
    /// This is the last accounting step and is invoked once the size of the
    /// response is known.
    fn subtract_gossip_usage(
        &mut self,
        transformed_response_size: NumBytes,
    ) -> Result<(), PricingError>;
    /// Produces the per-replica payment receipt that summarizes the cycles
    /// accounting outcome of the outcall, given the resources consumed so
    /// far via the `subtract_*` methods.
    fn create_payment_receipt(&self) -> CanisterHttpPaymentReceipt;
}

/// The maximum duration the adapter is allowed to take to fully receive a
/// response, as measured by the client. The server already enforces a 30s
/// timeout (see `DEFAULT_HTTP_REQUEST_TIMEOUT_SECS`), so this is a safety margin
/// above it.
pub(crate) const MAX_RESPONSE_TIME: Duration = Duration::from_secs(60);

pub struct AdapterLimits {
    /// The maximum size of the HTTP response, including the headers and the body.
    pub max_response_size: NumBytes,
    /// The maximumm duration allowed from sending the HTTP request to fully receiving the response, as measured by the client.
    pub max_response_time: Duration,
}

#[derive(Clone, Copy)]
pub struct NetworkUsage {
    /// The size of the HTTP response, including the headers and the body.
    pub response_size: NumBytes,
    /// The total time elapsed between sending the HTTP request and fully receiving the response, as measured by the client.
    pub response_time: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PricingError {
    InsufficientCycles,
}

#[derive(Clone)]
pub struct PricingFactory {
    metrics: PricingMetrics,
    log: ReplicaLogger,
}

impl PricingFactory {
    pub fn new(metrics_registry: &MetricsRegistry, log: ReplicaLogger) -> Self {
        Self {
            metrics: PricingMetrics::new(metrics_registry),
            log,
        }
    }

    pub fn new_tracker(&self, context: &CanisterHttpRequestContext) -> Box<dyn BudgetTracker> {
        match context.pricing_version {
            PricingVersion::Legacy => Box::new(DarkLaunchTracker::new(
                Box::new(LegacyTracker::new(context)),
                Box::new(PayAsYouGoTracker::new(context)),
                context,
                self.metrics.clone(),
                self.log.clone(),
            )),
            PricingVersion::PayAsYouGo => Box::new(PayAsYouGoTracker::new(context)),
        }
    }
}
