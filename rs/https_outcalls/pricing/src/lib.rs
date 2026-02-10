mod legacy;

use std::time::Duration;

use ic_types::{
    Cycles, NumBytes, NumInstructions,
    canister_http::{CanisterHttpPaymentReceipt, CanisterHttpRequestContext},
};
use legacy::LegacyTracker;

pub trait BudgetTracker: Send {
    /// Returns the maximum network resources the Adapter is allowed to consume.
    fn get_adapter_limits(&self) -> AdapterLimits;
    /// Deducts the actual network resources consumed.
    ///
    /// # Invariants
    ///  - This method returns `Ok(())` if `network_usage <= get_adapter_limits()`.
    ///  - This method returns `Err(PricingError)` if `network_usage > get_adapter_limits()`.
    ///
    /// Note that "<=" is used here to mean field-wise less than or equal to.
    fn subtract_network_usage(&mut self, network_usage: NetworkUsage) -> Result<(), PricingError>;
    /// Returns the maximum instructions allowed for the transformation function.
    fn get_transform_limit(&self) -> NumInstructions;
    /// Deducts the actual instructions consumed by the transformation.
    ///
    /// # Invariants
    ///  - This method returns `Ok(())` if and only if `usage <= get_transform_limit()`.
    fn subtract_transform_usage(&mut self, usage: NumInstructions) -> Result<(), PricingError>;

    /// Creates a payment receipt for the payment metadata.
    fn create_payment_receipt(&self) -> CanisterHttpPaymentReceipt;
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
