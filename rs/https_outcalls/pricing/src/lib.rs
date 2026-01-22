mod legacy;

use std::time::Duration;

use ic_types::{NumBytes, canister_http::CanisterHttpRequestContext};
use legacy::LegacyTracker;

// TODO(next): continue here: define pricing strategy trait etc
// TODO(urgent): sync is probably not needed. 
pub trait BudgetTracker : Send {
    //TODO(urgent): this should be called duringexecution.
    fn charge_base_fee(&mut self) -> Result<(), PricingError>;
    fn get_adapter_limits(&self) -> AdapterLimits;
}

pub struct AdapterLimits {
    pub max_response_size: NumBytes,
    pub max_response_duration: Duration,
}

pub enum PricingError {
    //TODO(urgent): add more error types?
    InsufficientCycles,
}

pub struct PricingFactory;

impl PricingFactory {
    pub fn new_tracker(context: &CanisterHttpRequestContext) -> Box<dyn BudgetTracker> {
        //TODO(urgent): this can be pay_as_you_go too.
        Box::new(LegacyTracker::new(context.max_response_bytes))
    }
}
