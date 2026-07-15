use ic_config::subnet_config::MAX_INSTRUCTIONS_PER_QUERY_MESSAGE;
use ic_types::{
    NumBytes, NumInstructions,
    canister_http::{CanisterHttpPaymentReceipt, MAX_CANISTER_HTTP_RESPONSE_BYTES},
};

use crate::{AdapterLimits, BudgetTracker, MAX_RESPONSE_TIME, NetworkUsage, PricingError};

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
            max_response_time: MAX_RESPONSE_TIME,
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

    fn subtract_gossip_usage(
        &mut self,
        _transformed_response_size: NumBytes,
    ) -> Result<(), PricingError> {
        Ok(())
    }

    fn create_payment_receipt(&self) -> CanisterHttpPaymentReceipt {
        // Legacy pricing does not perform cycles accounting, so no cycles
        // are ever spent.
        CanisterHttpPaymentReceipt::default()
    }
}
