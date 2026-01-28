mod legacy;

use std::time::Duration;

use ic_types::{NumBytes, canister_http::CanisterHttpRequestContext};
use legacy::LegacyTracker;

pub trait BudgetTracker: Send {
    fn get_adapter_limits(&self) -> AdapterLimits;
    fn subtract_network_usage(&mut self, network_usage: NetworkUsage) -> Result<(), PricingError>;
}

pub struct AdapterLimits {
    /// The maximum size of the HTTP response, including the headers and the body.
    pub max_response_size: NumBytes,
    /// The maximumm duration allowed from sending the HTTP request to fully receiving the response, as measured by the client.
    pub max_response_time: Duration,
}

pub struct NetworkUsage {
    /// The size of the HTTP response, including the headers and the body.
    pub response_size: NumBytes,
    /// The total time elapsed between sending the HTTP request and fully receiving the response, as measured by the client.
    pub response_time: Duration,
}

pub enum PricingError {
    InsufficientCycles,
}

pub struct PricingFactory;

impl PricingFactory {
    pub fn new_tracker(context: &CanisterHttpRequestContext) -> Box<dyn BudgetTracker> {
        // TODO(IC-1937): This should take into account context.pricing_version and a replica config.
        // Currently, we only support the legacy pricing version.
        Box::new(LegacyTracker::new(context.max_response_bytes))
    }
}
