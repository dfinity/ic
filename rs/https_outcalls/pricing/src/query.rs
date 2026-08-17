//! Pricing for HTTP outcalls made from a query.
//!
//! A query has no cycle budget -- its state changes, cycle balance included, are
//! discarded -- so an outcall is charged against its instruction budget, at the
//! pay-as-you-go fees converted one instruction per cycle. The caller reserves
//! before suspending and is refunded what went unspent.
//!
//! Only what the node itself does is priced: the request it uploads and the
//! response it downloads. Nothing is gossiped, agreed or settled.

use std::time::Duration;

use ic_types::{NumBytes, NumInstructions, canister_http::CanisterHttpPaymentReceipt};
use ic_types_cycles::Cycles;

use crate::fees::{max_downloaded_bytes, max_response_time, network_usage_fee, request_fee};
use crate::{AdapterLimits, BudgetTracker, NetworkUsage, PricingError};

/// Paid outright, not reserved: the request is uploaded whatever comes back.
pub fn request_cost(request_size: NumBytes) -> Cycles {
    request_fee(request_size)
}

/// The worst case for the response, which is what a caller reserves.
pub fn max_network_cost(max_response_bytes: NumBytes, max_response_time: Duration) -> Cycles {
    network_usage_fee(max_response_bytes, max_response_time)
}

/// Fixed rate, not the subnet's instruction fee: that fee is zero on subnets
/// which charge nothing, leaving outcalls there unbounded.
pub fn instructions_for(cost: Cycles) -> NumInstructions {
    NumInstructions::from(u64::try_from(cost.get()).unwrap_or(u64::MAX))
}

/// The inverse of [`instructions_for`].
pub fn cycles_for(instructions: NumInstructions) -> Cycles {
    Cycles::from(instructions.get())
}

/// Charges an HTTP outcall made from a query against an allowance reserved out
/// of the query's instruction budget.
pub struct QueryOutcallBudget {
    allowance: Cycles,
    spent: Cycles,
    /// What the caller asked for, an upper bound on what the allowance may buy.
    max_response_size: NumBytes,
    max_response_time: Duration,
}

impl QueryOutcallBudget {
    pub fn new(
        allowance: Cycles,
        max_response_size: NumBytes,
        max_response_time: Duration,
    ) -> Self {
        Self {
            allowance,
            spent: Cycles::zero(),
            max_response_size,
            max_response_time,
        }
    }

    pub fn spent(&self) -> Cycles {
        self.spent
    }

    fn remaining(&self) -> Cycles {
        self.allowance - self.spent
    }

    fn charge(&mut self, amount: Cycles) -> Result<(), PricingError> {
        self.spent += amount;
        if self.spent > self.allowance {
            Err(PricingError::InsufficientCycles)
        } else {
            Ok(())
        }
    }
}

impl BudgetTracker for QueryOutcallBudget {
    /// Bounds the request by what the allowance buys, so an outcall that cannot
    /// be paid for is never made.
    fn get_adapter_limits(&self) -> AdapterLimits {
        // Each dimension gets the whole remainder, as on the replicated path:
        // splitting would spend half of every allowance on latency the response
        // will not use. Maxing out both then costs about twice the allowance,
        // which `subtract_network_usage` refuses.
        let remaining = self.remaining();

        AdapterLimits {
            max_response_size: max_downloaded_bytes(remaining).min(self.max_response_size),
            max_response_time: max_response_time(remaining).min(self.max_response_time),
        }
    }

    /// The query's remaining walltime, always below the protocol maximum:
    /// without this every outcall that ran out of time would be reported as
    /// having run out of cycles.
    fn max_response_time_ceiling(&self) -> Duration {
        self.max_response_time
    }

    fn subtract_network_usage(&mut self, network_usage: NetworkUsage) -> Result<(), PricingError> {
        let NetworkUsage {
            response_size,
            response_time,
        } = network_usage;
        self.charge(network_usage_fee(response_size, response_time))
    }

    /// Unused: the transform runs in the query context, not in the client.
    fn get_transform_limit(&self) -> NumInstructions {
        NumInstructions::from(0)
    }

    /// No-op: `execute_query` already debits the transform's instructions.
    fn subtract_transform_usage(&mut self, _usage: NumInstructions) -> Result<(), PricingError> {
        Ok(())
    }

    /// No-op: nothing is gossiped.
    fn subtract_gossip_usage(
        &mut self,
        _transformed_response_size: NumBytes,
    ) -> Result<(), PricingError> {
        Ok(())
    }

    /// Nothing settles: there is no canister balance to refund to.
    fn create_payment_receipt(&self) -> CanisterHttpPaymentReceipt {
        CanisterHttpPaymentReceipt {
            spent: Cycles::zero(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget(allowance: u128) -> QueryOutcallBudget {
        QueryOutcallBudget::new(
            Cycles::new(allowance),
            NumBytes::from(2_000_000),
            Duration::from_secs(10),
        )
    }

    #[test]
    fn limits_are_capped_by_what_the_caller_asked_for() {
        // A generous allowance cannot buy more than the request allows.
        let limits = budget(u128::MAX / 2).get_adapter_limits();
        assert_eq!(limits.max_response_size, NumBytes::from(2_000_000));
        assert_eq!(limits.max_response_time, Duration::from_secs(10));
    }

    #[test]
    fn limits_shrink_with_the_allowance() {
        // 100_000 cycles buys either 2_000 bytes at 50/byte or 333ms at 300/ms.
        // Both are offered in full, so both are below what the request asked for.
        let limits = budget(100_000).get_adapter_limits();
        assert_eq!(limits.max_response_size, NumBytes::from(2_000));
        assert_eq!(limits.max_response_time, Duration::from_millis(333));
    }

    /// The two limits are individually affordable but not jointly, and it is the
    /// charge that catches the difference.
    ///
    /// Worth pinning because it is the accepted cost of offering each dimension
    /// the whole allowance: an outcall that maxes out both is refused after the
    /// adapter has already done the work.
    #[test]
    fn maxing_out_both_dimensions_costs_more_than_the_allowance() {
        let mut budget = budget(100_000);
        let limits = budget.get_adapter_limits();

        assert_eq!(
            budget.subtract_network_usage(NetworkUsage {
                response_size: limits.max_response_size,
                response_time: limits.max_response_time,
            }),
            Err(PricingError::InsufficientCycles),
            "using both limits in full must cost more than the allowance"
        );
        // About twice the allowance, which bounds how far over it can go.
        assert!(budget.spent() <= Cycles::new(200_000));
    }

    #[test]
    fn an_empty_allowance_buys_nothing() {
        let limits = budget(0).get_adapter_limits();
        assert_eq!(limits.max_response_size, NumBytes::from(0));
        assert_eq!(limits.max_response_time, Duration::ZERO);
    }

    #[test]
    fn charges_bytes_and_time() {
        let mut budget = budget(1_000_000);
        budget
            .subtract_network_usage(NetworkUsage {
                response_size: NumBytes::from(1_000),
                response_time: Duration::from_millis(100),
            })
            .unwrap();
        // 50 * 1000 + 300 * 100
        assert_eq!(budget.spent(), Cycles::new(80_000));
    }

    #[test]
    fn spending_past_the_allowance_fails() {
        let mut budget = budget(10_000);
        assert_eq!(
            budget.subtract_network_usage(NetworkUsage {
                response_size: NumBytes::from(1_000_000),
                response_time: Duration::ZERO,
            }),
            Err(PricingError::InsufficientCycles)
        );
    }

    /// A subnet that charges nothing for outcalls does not make them free to a
    /// query: the instruction budget still bounds them.
    ///
    /// Otherwise the cost bound would vanish on exactly the subnets where it is
    /// the only bound there is.
    #[test]
    fn the_budget_binds_regardless_of_what_the_subnet_charges() {
        let mut budget = budget(100_000);

        assert_eq!(
            budget.subtract_network_usage(NetworkUsage {
                response_size: NumBytes::from(2_000_000),
                response_time: Duration::from_secs(10),
            }),
            Err(PricingError::InsufficientCycles),
            "a full-size response must not be affordable on a 100_000 allowance"
        );
    }

    #[test]
    fn the_transform_is_not_charged_here() {
        let mut budget = budget(1_000);
        budget
            .subtract_transform_usage(NumInstructions::from(u64::MAX))
            .unwrap();
        budget
            .subtract_gossip_usage(NumBytes::from(u64::MAX))
            .unwrap();
        assert_eq!(budget.spent(), Cycles::zero());
    }

    #[test]
    fn max_network_cost_covers_both_dimensions() {
        let cost = max_network_cost(NumBytes::from(1_000), Duration::from_millis(100));
        assert_eq!(cost, Cycles::new(50 * 1_000 + 300 * 100));
    }
}
