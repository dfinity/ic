use ic_config::subnet_config::MAX_INSTRUCTIONS_PER_QUERY_MESSAGE;
use ic_types::{
    NumBytes, NumInstructions, NumberOfNodes,
    canister_http::{
        CanisterHttpPaymentReceipt, CanisterHttpRequestContext, MAX_CANISTER_HTTP_RESPONSE_BYTES,
        MAX_HTTP_OUTCALL_SPEND_FREE_SUBNET, Replication,
    },
};
use ic_types_cycles::{CanisterCyclesCostSchedule, Cycles};

use crate::{AdapterLimits, BudgetTracker, MAX_RESPONSE_TIME, NetworkUsage, PricingError};

// Per-replica fee constants.
//
// A request's cost is split into three parts:
//   1. the base cost, subtracted up-front when the request context is created
//      (and therefore reflected in `per_replica_allowance`);
//   2. the per-replica cost, accounted for here as-you-go;
//   3. the consensus cost, computed from the aggregated response in the block
//      payload.
//
// This tracker implements the per-replica part. The formula differs
// between fully-replicated and non-replicated/flexible outcalls:
//
// Fully-replicated per replica:
//   50 * downloaded_bytes_i + 300 * request_ms_i + transform_instructions_i / 13
//
// Non-replicated/Flexible per replica:
//   50 * downloaded_bytes_i + 300 * request_ms_i
//     + 50 * transformed_response_bytes_i * N + transform_instructions_i / 13
const PER_DOWNLOADED_BYTE_FEE: u128 = 50;
const PER_RESPONSE_MS_FEE: u128 = 300;
/// HTTP outcalls are priced consistently against a reference subnet size of 13.
const TRANSFORM_INSTRUCTION_DIVISOR: u128 = 13;
const FLEXIBLE_PER_TRANSFORMED_BYTE_NODE_FEE: u128 = 50;

pub struct PayAsYouGoTracker {
    /// Number of nodes (`N`) on the subnet.
    subnet_size: NumberOfNodes,
    /// Whether responses to this outcalls are gossiped (only flexible and non-replicated).
    is_gossiping: bool,
    /// Whether the subnet uses a free cost schedule. When `true` the tracker
    /// still accumulates the spend (so free subnets report accurate cost
    /// metrics) but never returns an out-of-cycles error.
    is_free: bool,
    /// The cycles budget available to this replica (already net of the base
    /// cost, which was subtracted when the context was created).
    allowance: u128,
    /// The maximum size of the HTTP response, including headers and body.
    max_response_size: NumBytes,
    /// The cycles charged so far against `allowance`.
    spent: u128,
}

impl PayAsYouGoTracker {
    pub fn new(
        context: &CanisterHttpRequestContext,
        subnet_size: NumberOfNodes,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> Self {
        Self {
            subnet_size,
            is_gossiping: match context.replication {
                // Non-replicated outcalls gossip the response, so they are charged
                // the same way as flexible outcalls.
                Replication::Flexible { .. } | Replication::NonReplicated(_) => true,
                Replication::FullyReplicated => false,
            },
            is_free: match cost_schedule {
                CanisterCyclesCostSchedule::Free => true,
                CanisterCyclesCostSchedule::Normal => false,
            },
            allowance: context.refund_status.per_replica_allowance.get(),
            max_response_size: context
                .max_response_bytes
                .unwrap_or(NumBytes::from(MAX_CANISTER_HTTP_RESPONSE_BYTES)),
            spent: 0,
        }
    }

    /// Charges `amount` against the budget. Returns an error if the total spent
    /// now exceeds the available allowance (never on a free cost schedule).
    fn charge(&mut self, amount: u128) -> Result<(), PricingError> {
        // Always accumulate the spend, including on a free cost schedule, so
        // free subnets can report the real per-replica cost for canister cost
        // accounting.
        self.spent = self.spent.saturating_add(amount);
        // A free cost schedule charges nothing for resources, so it never runs
        // out of cycles.
        if self.is_free {
            return Ok(());
        }
        if self.spent > self.allowance {
            Err(PricingError::InsufficientCycles)
        } else {
            Ok(())
        }
    }
}

impl BudgetTracker for PayAsYouGoTracker {
    fn get_adapter_limits(&self) -> AdapterLimits {
        // TODO: Adjust limits based on remaining budget.
        AdapterLimits {
            max_response_size: self.max_response_size,
            max_response_time: MAX_RESPONSE_TIME,
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
        // TODO: Adjust limits based on remaining budget.
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
        // consensus cost (ignored here). For flexible outcalls each
        // replica is charged 50 * transformed_response_bytes_i * N.
        if !self.is_gossiping {
            return Ok(());
        }
        let cost = FLEXIBLE_PER_TRANSFORMED_BYTE_NODE_FEE
            .saturating_mul(transformed_response_size.get() as u128)
            .saturating_mul(self.subnet_size.get() as u128);
        self.charge(cost)
    }

    fn create_payment_receipt(&self) -> CanisterHttpPaymentReceipt {
        // Cap the reported spend at the maximum this replica may report having
        // spent. On a charging subnet that is the allowance. On a free cost
        // schedule nothing is actually charged, but the real spend is still
        // reported (so canister cost metrics reflect the actual work), bounded
        // by `MAX_HTTP_OUTCALL_SPEND_FREE_SUBNET`.
        let cap = if self.is_free {
            MAX_HTTP_OUTCALL_SPEND_FREE_SUBNET.get()
        } else {
            self.allowance
        };
        CanisterHttpPaymentReceipt {
            spent: Cycles::new(self.spent.min(cap)),
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
    use std::time::Duration;

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
            subnet_size: NumberOfNodes::from(13),
            cost_schedule: None,
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

    /// Builds a tracker on a `Normal` cost schedule with the given subnet size.
    fn make_tracker(ctx: &CanisterHttpRequestContext, subnet_size: u32) -> PayAsYouGoTracker {
        PayAsYouGoTracker::new(
            ctx,
            NumberOfNodes::from(subnet_size),
            CanisterCyclesCostSchedule::Normal,
        )
    }

    /// Asserts that a gossiping outcall (flexible or non-replicated) charges the
    /// gossip term over the full subnet size.
    fn assert_gossip_charged_over_subnet_size(replication: Replication) {
        let subnet_size = 13_u32;
        let ctx = context(replication, 1_000_000_000);
        let mut tracker = make_tracker(&ctx, subnet_size);

        let transformed_size = 500_u64;
        assert_eq!(
            tracker.subtract_gossip_usage(NumBytes::from(transformed_size)),
            Ok(())
        );
        let expected =
            FLEXIBLE_PER_TRANSFORMED_BYTE_NODE_FEE * transformed_size as u128 * subnet_size as u128;
        assert_eq!(tracker.spent, expected);
    }

    #[test]
    fn does_not_charge_base_cost() {
        // The base cost is handled at context creation, so a freshly created
        // tracker has spent nothing and a zero-usage request records no spend
        // (the full allowance is refunded downstream).
        let ctx = context(Replication::FullyReplicated, 1_000_000);
        let tracker = make_tracker(&ctx, 13);
        assert_eq!(tracker.spent, 0);
        assert_eq!(tracker.create_payment_receipt().spent, Cycles::zero());
    }

    #[test]
    fn charges_per_replica_cost_fully_replicated() {
        let allowance = 1_000_000_000_u128;
        let ctx = context(Replication::FullyReplicated, allowance);
        let mut tracker = make_tracker(&ctx, 13);

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
            tracker.create_payment_receipt().spent,
            Cycles::new(network + transform)
        );
    }

    #[test]
    fn charges_gossip_usage_for_flexible() {
        assert_gossip_charged_over_subnet_size(flexible(13));
    }

    #[test]
    fn charges_gossip_usage_for_non_replicated() {
        // Non-replicated outcalls use the same (flexible) pricing as flexible
        // outcalls, so the gossip term is charged over the full subnet size.
        let node = NodeId::from(PrincipalId::new_node_test_id(0));
        assert_gossip_charged_over_subnet_size(Replication::NonReplicated(node));
    }

    #[test]
    fn returns_pricing_error_when_budget_is_exceeded() {
        let allowance = 100;
        let ctx = context(Replication::FullyReplicated, allowance);
        let mut tracker = make_tracker(&ctx, 13);
        assert_eq!(
            tracker.subtract_network_usage(NetworkUsage {
                response_size: NumBytes::from(1_000),
                response_time: Duration::ZERO,
            }),
            Err(PricingError::InsufficientCycles)
        );
        // The reported spend is capped at the allowance, so an over-budget
        // outcall reports consuming exactly its allowance (the refund derived
        // downstream is zero) rather than the larger raw amount.
        assert_eq!(
            tracker.create_payment_receipt().spent,
            Cycles::new(allowance)
        );
    }

    #[test]
    fn free_cost_schedule_reports_real_spend_without_rejecting() {
        // On a free subnet the tracker charges nothing (it never returns an
        // error), but it still accumulates the real per-replica spend and
        // reports it — even though it exceeds the zero allowance — so canister
        // cost metrics on free subnets stay accurate. The reported spend here is
        // well below `MAX_HTTP_OUTCALL_SPEND_FREE_SUBNET`, so the cap is a no-op.
        // A flexible request is used so the gossip term (not charged for
        // fully-replicated requests) is also exercised.
        let subnet_size = 13_u64;
        let ctx = context(flexible(subnet_size as usize), 0);
        let mut tracker = PayAsYouGoTracker::new(
            &ctx,
            NumberOfNodes::from(subnet_size as u32),
            CanisterCyclesCostSchedule::Free,
        );

        let response_size = 1_000_000_u64;
        let response_ms = 30_000_u128;
        assert_eq!(
            tracker.subtract_network_usage(NetworkUsage {
                response_size: NumBytes::from(response_size),
                response_time: Duration::from_millis(response_ms as u64),
            }),
            Ok(())
        );
        let network =
            PER_DOWNLOADED_BYTE_FEE * response_size as u128 + PER_RESPONSE_MS_FEE * response_ms;

        let instructions = 1_000_000_000_u64;
        assert_eq!(
            tracker.subtract_transform_usage(NumInstructions::from(instructions)),
            Ok(())
        );
        let transform = instructions as u128 / TRANSFORM_INSTRUCTION_DIVISOR;

        let transformed_size = 1_000_000_u64;
        assert_eq!(
            tracker.subtract_gossip_usage(NumBytes::from(transformed_size)),
            Ok(())
        );
        let gossip =
            FLEXIBLE_PER_TRANSFORMED_BYTE_NODE_FEE * transformed_size as u128 * subnet_size as u128;

        let expected = network + transform + gossip;
        // Nothing is charged (no error), yet the full spend is tracked and
        // reported, exceeding the zero allowance.
        assert!(expected > 0);
        assert!(expected < MAX_HTTP_OUTCALL_SPEND_FREE_SUBNET.get());
        assert_eq!(tracker.spent, expected);
        assert_eq!(
            tracker.create_payment_receipt().spent,
            Cycles::new(expected)
        );
    }

    #[test]
    fn free_cost_schedule_caps_reported_spend_at_maximum() {
        // Even though a free subnet may report a spend exceeding its (zero)
        // allowance, the reported spend is never unbounded: it is capped at
        // `MAX_HTTP_OUTCALL_SPEND_FREE_SUBNET`.
        let subnet_size = 13_u64;
        let ctx = context(flexible(subnet_size as usize), 0);
        let mut tracker = PayAsYouGoTracker::new(
            &ctx,
            NumberOfNodes::from(subnet_size as u32),
            CanisterCyclesCostSchedule::Free,
        );

        // A gossip term large enough to push the raw spend past the cap.
        assert_eq!(
            tracker.subtract_gossip_usage(NumBytes::from(u64::MAX)),
            Ok(())
        );
        assert!(tracker.spent > MAX_HTTP_OUTCALL_SPEND_FREE_SUBNET.get());
        assert_eq!(
            tracker.create_payment_receipt().spent,
            MAX_HTTP_OUTCALL_SPEND_FREE_SUBNET
        );
    }
}
