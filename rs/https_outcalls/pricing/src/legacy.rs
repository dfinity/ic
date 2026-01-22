use std::time::Duration;

use ic_types::{NumBytes, canister_http::MAX_CANISTER_HTTP_RESPONSE_BYTES};

use crate::{AdapterLimits, BudgetTracker, PricingError};

pub struct LegacyTracker {
    max_response_size: NumBytes,
}

impl LegacyTracker {
    pub fn new(max_response_bytes: Option<NumBytes>) -> Self {
        Self {
            max_response_size: max_response_bytes.unwrap_or(NumBytes::from(MAX_CANISTER_HTTP_RESPONSE_BYTES)),
        }
    }
}

impl BudgetTracker for LegacyTracker {
    fn charge_base_fee(&mut self) -> Result<(), PricingError> {
        Ok(())
    }

    fn get_adapter_limits(&self) -> AdapterLimits {
        AdapterLimits {
            max_response_size: self.max_response_size,
            //TODO: urgent: take this from config. 
            max_response_duration: Duration::from_secs(30),
        }
    }
}
