use std::time::Duration;

use ic_types::{NumBytes, canister_http::MAX_CANISTER_HTTP_RESPONSE_BYTES};

use crate::{AdapterLimits, BudgetTracker, NetworkUsage, PricingError};

pub struct LegacyTracker {
    max_response_size: NumBytes,
}

impl LegacyTracker {
    pub fn new(max_response_bytes: Option<NumBytes>) -> Self {
        Self {
            max_response_size: max_response_bytes
                .unwrap_or(NumBytes::from(MAX_CANISTER_HTTP_RESPONSE_BYTES)),
        }
    }
}

impl BudgetTracker for LegacyTracker {
    fn get_adapter_limits(&self) -> AdapterLimits {
        AdapterLimits {
            max_response_size: self.max_response_size,
            // Note: there is already a timeout limit on the server itself (30 seconds).
            // Setting higher than that just to be safe.
            max_response_duration: Duration::from_secs(60),
        }
    }

    fn subtract_network_usage(&mut self, _network_usage: NetworkUsage) -> Result<(), PricingError> {
        // Note: currently the client enforces the timeout limit, while the adapter enforces the response size limit.
        // So there is no need to do anything here.
        Ok(())
    }
}
