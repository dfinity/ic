use std::time::Duration;

use ic_config::subnet_config::MAX_INSTRUCTIONS_PER_QUERY_MESSAGE;
use ic_types::{
    NumBytes, NumInstructions,
    canister_http::{
        CanisterHttpPaymentReceipt, CanisterHttpRequestContext, CanisterHttpResponse,
        MAX_CANISTER_HTTP_RESPONSE_BYTES,
    },
};
use ic_types_cycles::Cycles;

use crate::{AdapterLimits, BudgetTracker, NetworkUsage, PricingCalculator, PricingError};

pub struct LegacyCalculator;

impl PricingCalculator for LegacyCalculator {
    fn consensus_cost(&self, _response: &CanisterHttpResponse, _subnet_size: u32) -> Cycles {
        // Note: the legacy pricing calculator does not calculate the cost of the response.
        Cycles::zero()
    }

    fn base_cost(&self, _context: &CanisterHttpRequestContext, _subnet_size: u32) -> Cycles {
        // Note: the legacy pricing calculator does not calculate the cost of the request.
        Cycles::zero()
    }
}

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
            // Note: there is already a timeout limit on the server itself (30 seconds, see DEFAULT_HTTP_REQUEST_TIMEOUT_SECS).
            // Setting higher than that just to be safe.
            max_response_time: Duration::from_secs(60),
        }
    }

    fn subtract_network_usage(&mut self, _network_usage: NetworkUsage) -> Result<(), PricingError> {
        // Note: currently the client enforces the timeout limit, while the adapter enforces the response size limit.
        // So there is no need to do anything here.
        Ok(())
    }

    fn get_transform_limit(&self) -> NumInstructions {
        MAX_INSTRUCTIONS_PER_QUERY_MESSAGE
    }

    fn subtract_transform_usage(&mut self, _usage: NumInstructions) -> Result<(), PricingError> {
        Ok(())
    }

    fn get_gossip_limit(&self) -> NumBytes {
        self.max_response_size
    }

    fn subtract_gossip_usage(&mut self, _response_size: usize) -> Result<(), PricingError> {
        Ok(())
    }

    fn create_payment_receipt(&self) -> CanisterHttpPaymentReceipt {
        // Legacy pricing does not perform cycles accounting, so no cycles
        // are ever refunded.
        CanisterHttpPaymentReceipt::default()
    }
}
