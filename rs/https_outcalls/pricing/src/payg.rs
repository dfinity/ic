use std::time::Duration;

use ic_config::subnet_config::MAX_INSTRUCTIONS_PER_QUERY_MESSAGE;
use ic_types::{
    NumBytes, NumInstructions,
    canister_http::{
        CanisterHttpPaymentReceipt, CanisterHttpRequestContext, MAX_CANISTER_HTTP_RESPONSE_BYTES,
        Replication,
    },
};
use ic_types_cycles::Cycles;

use crate::{AdapterLimits, BudgetTracker, NetworkUsage, PricingError};

// Per-replica fee constants.
//
// A request's cost is split into three parts:
//   1. the base cost, subtracted up-front when the request context is created
//      (and therefore reflected in `per_replica_allowance`);
//   2. the per-replica cost, accounted for here as-you-go;
//   3. the consensus cost, computed from the aggregated response in the block
//      payload (ignored for now).
//
// This tracker only implements the per-replica part. The formula differs
// between fully/non-replicated and flexible outcalls:
//
// Fully/non-replicated per replica:
//   50 * downloaded_bytes_i + 300 * request_ms_i + transform_instructions_i / 13
//
// Flexible per replica:
//   50 * downloaded_bytes_i + 300 * request_ms_i
//     + 50 * transformed_response_bytes_i * N + transform_instructions_i / 13
const PER_DOWNLOADED_BYTE_FEE: u128 = 50;
const PER_RESPONSE_MS_FEE: u128 = 300;
const TRANSFORM_INSTRUCTION_DIVISOR: u128 = 13;
const FLEXIBLE_PER_TRANSFORMED_BYTE_NODE_FEE: u128 = 50;

pub struct PayAsYouGoTracker {
    /// Number of nodes (`N`) on the subnet.
    n: u64,
    /// Whether this is a flexible outcall (different per-replica formula).
    is_flexible: bool,
    /// The cycles budget available to this replica (already net of the base
    /// cost, which was subtracted when the context was created).
    allowance: u128,
    /// The maximum size of the HTTP response, including headers and body.
    max_response_size: NumBytes,
    /// The cycles charged so far against `allowance`.
    spent: u128,
}

impl PayAsYouGoTracker {
    pub fn new(context: &CanisterHttpRequestContext) -> Self {
        Self {
            n: 13,
            is_flexible: matches!(context.replication, Replication::Flexible { .. }),
            allowance: context.refund_status.per_replica_allowance.get(),
            max_response_size: context
                .max_response_bytes
                .unwrap_or(NumBytes::from(MAX_CANISTER_HTTP_RESPONSE_BYTES)),
            spent: 0,
        }
    }

    /// Charges `amount` against the budget. Returns an error if the total spent
    /// now exceeds the available allowance.
    fn charge(&mut self, amount: u128) -> Result<(), PricingError> {
        self.spent = self.spent.saturating_add(amount);
        if self.spent > self.allowance {
            Err(PricingError::InsufficientCycles)
        } else {
            Ok(())
        }
    }
}

impl BudgetTracker for PayAsYouGoTracker {
    fn get_adapter_limits(&self) -> AdapterLimits {
        AdapterLimits {
            max_response_size: self.max_response_size,
            // Mirror the legacy limit: the server enforces a 30s timeout, so 60s
            // here is just a safety margin.
            max_response_time: Duration::from_secs(60),
        }
    }

    fn subtract_network_usage(&mut self, network_usage: NetworkUsage) -> Result<(), PricingError> {
        let NetworkUsage {
            response_size,
            response_time,
        } = network_usage;
        let cost = PER_DOWNLOADED_BYTE_FEE
            .saturating_mul(response_size.get() as u128)
            .saturating_add(PER_RESPONSE_MS_FEE.saturating_mul(response_time.as_millis()));
        self.charge(cost)
    }

    fn get_transform_limit(&self) -> NumInstructions {
        MAX_INSTRUCTIONS_PER_QUERY_MESSAGE
    }

    fn subtract_transform_usage(&mut self, usage: NumInstructions) -> Result<(), PricingError> {
        let cost = (usage.get() as u128) / TRANSFORM_INSTRUCTION_DIVISOR;
        self.charge(cost)
    }

    fn subtract_gossip_usage(
        &mut self,
        transformed_response_size: NumBytes,
    ) -> Result<(), PricingError> {
        // For fully replicated outcalls the gossip term is a
        // consensus cost (ignored here for now). For flexible outcalls each
        // replica is charged 50 * transformed_response_bytes_i * N.
        if !self.is_flexible {
            return Ok(());
        }
        let cost = FLEXIBLE_PER_TRANSFORMED_BYTE_NODE_FEE
            .saturating_mul(transformed_response_size.get() as u128)
            .saturating_mul(self.n as u128);
        self.charge(cost)
    }

    fn create_payment_receipt(&self) -> CanisterHttpPaymentReceipt {
        CanisterHttpPaymentReceipt {
            refund: Cycles::new(self.allowance.saturating_sub(self.spent)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_types::{
        CanisterId, NodeId, PrincipalId, RegistryVersion,
        canister_http::{CanisterHttpMethod, PricingVersion, RefundStatus},
        messages::{CallbackId, NO_DEADLINE, Request},
        time::UNIX_EPOCH,
    };
    use std::collections::BTreeSet;

    fn context(
        replication: Replication,
        per_replica_allowance: u128,
    ) -> CanisterHttpRequestContext {
        CanisterHttpRequestContext {
            request: Request {
                receiver: CanisterId::from_u64(1),
                sender: CanisterId::from_u64(1),
                sender_reply_callback: CallbackId::from(1),
                payment: Cycles::zero(),
                method_name: String::new(),
                method_payload: Vec::new(),
                metadata: Default::default(),
                deadline: NO_DEADLINE,
            },
            url: String::new(),
            max_response_bytes: None,
            headers: vec![],
            body: None,
            http_method: CanisterHttpMethod::GET,
            transform: None,
            time: UNIX_EPOCH,
            replication,
            pricing_version: PricingVersion::Legacy,
            refund_status: RefundStatus {
                refundable_cycles: Cycles::new(per_replica_allowance),
                per_replica_allowance: Cycles::new(per_replica_allowance),
                refunded_cycles: Cycles::zero(),
                refunding_nodes: BTreeSet::new(),
            },
            registry_version: RegistryVersion::from(1),
        }
    }

    fn flexible(n: usize) -> Replication {
        let committee: BTreeSet<NodeId> = (0..n as u64)
            .map(|i| NodeId::from(PrincipalId::new_node_test_id(i)))
            .collect();
        Replication::Flexible {
            committee,
            min_responses: 1,
            max_responses: n as u32,
        }
    }

    #[test]
    fn does_not_charge_base_cost() {
        // The base cost is handled at context creation, so a freshly created
        // tracker has spent nothing and a zero-usage request refunds everything.
        let ctx = context(Replication::FullyReplicated, 1_000_000);
        let tracker = PayAsYouGoTracker::new(&ctx);
        assert_eq!(tracker.spent, 0);
        assert_eq!(
            tracker.create_payment_receipt().refund,
            Cycles::new(1_000_000)
        );
    }

    #[test]
    fn charges_per_replica_cost_fully_replicated() {
        let allowance = 1_000_000_000_u128;
        let ctx = context(Replication::FullyReplicated, allowance);
        let mut tracker = PayAsYouGoTracker::new(&ctx);

        let response_size = 1_000_u64;
        let response_ms = 2_000_u128;
        assert_eq!(
            tracker.subtract_network_usage(NetworkUsage {
                response_size: NumBytes::from(response_size),
                response_time: Duration::from_millis(response_ms as u64),
            }),
            Ok(())
        );
        let network =
            PER_DOWNLOADED_BYTE_FEE * response_size as u128 + PER_RESPONSE_MS_FEE * response_ms;

        let instructions = 13_000_u64;
        assert_eq!(
            tracker.subtract_transform_usage(NumInstructions::from(instructions)),
            Ok(())
        );
        let transform = instructions as u128 / TRANSFORM_INSTRUCTION_DIVISOR;

        // For fully-replicated requests the gossip term is a
        // consensus cost and must not be charged here.
        assert_eq!(tracker.subtract_gossip_usage(NumBytes::from(5_000)), Ok(()));

        assert_eq!(tracker.spent, network + transform);
        assert_eq!(
            tracker.create_payment_receipt().refund,
            Cycles::new(allowance - network - transform)
        );
    }

    #[test]
    fn charges_transformed_response_for_flexible() {
        let allowance = 1_000_000_000_u128;
        let n = 13;
        let ctx = context(flexible(n), allowance);
        let mut tracker = PayAsYouGoTracker::new(&ctx);

        let transformed_size = 500_u64;
        assert_eq!(
            tracker.subtract_gossip_usage(NumBytes::from(transformed_size)),
            Ok(())
        );
        let expected =
            FLEXIBLE_PER_TRANSFORMED_BYTE_NODE_FEE * transformed_size as u128 * n as u128;
        assert_eq!(tracker.spent, expected);
    }

    #[test]
    fn returns_pricing_error_when_budget_is_exceeded() {
        let ctx = context(Replication::FullyReplicated, 100);
        let mut tracker = PayAsYouGoTracker::new(&ctx);
        assert_eq!(
            tracker.subtract_network_usage(NetworkUsage {
                response_size: NumBytes::from(1_000),
                response_time: Duration::ZERO,
            }),
            Err(PricingError::InsufficientCycles)
        );
        assert_eq!(tracker.create_payment_receipt().refund, Cycles::zero());
    }
}
