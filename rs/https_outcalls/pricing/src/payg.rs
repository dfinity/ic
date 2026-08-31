use ic_config::subnet_config::MAX_INSTRUCTIONS_PER_QUERY_MESSAGE;
use ic_types::{
    NumBytes, NumInstructions, NumberOfNodes,
    canister_http::{
        CanisterHttpPaymentReceipt, CanisterHttpRequestContext, MAX_CANISTER_HTTP_RESPONSE_BYTES,
        MAX_HTTP_OUTCALL_SPEND_FREE_SUBNET, Replication,
    },
};
use ic_types_cycles::{CanisterCyclesCostSchedule, Cycles};

use crate::fees::{
    gossip_usage_fee, max_downloaded_bytes, max_response_time, max_transform_instructions,
    network_usage_fee, transform_usage_fee,
};
use crate::{AdapterLimits, BudgetTracker, MAX_RESPONSE_TIME, NetworkUsage, PricingError};

/// This tracker implements the per-replica part of pay-as-you-go pricing. The formula
/// differs between fully-replicated and non-replicated/flexible outcalls:
///
/// Fully-replicated per replica:
///   50 * downloaded_bytes_i + 300 * request_ms_i + transform_instructions_i / 13
///
/// Non-replicated/Flexible per replica:
///   50 * downloaded_bytes_i + 300 * request_ms_i
///      + 50 * transformed_response_bytes_i * N + transform_instructions_i / 13
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
    allowance: Cycles,
    /// The maximum size of the HTTP response, including headers and body.
    max_response_size: NumBytes,
    /// The cycles charged so far against `allowance`.
    spent: Cycles,
}

impl PayAsYouGoTracker {
    pub fn new(context: &CanisterHttpRequestContext) -> Self {
        Self {
            subnet_size: context.subnet_size,
            is_gossiping: match context.replication {
                // Non-replicated outcalls gossip the response, so they are charged
                // the same way as flexible outcalls.
                Replication::Flexible { .. } | Replication::NonReplicated(_) => true,
                Replication::FullyReplicated => false,
            },
            is_free: match context.cost_schedule {
                CanisterCyclesCostSchedule::Free => true,
                CanisterCyclesCostSchedule::Normal => false,
            },
            allowance: context.refund_status.per_replica_allowance,
            max_response_size: context
                .max_response_bytes
                .unwrap_or(NumBytes::from(MAX_CANISTER_HTTP_RESPONSE_BYTES)),
            spent: Cycles::zero(),
        }
    }

    /// What is left of the allowance, i.e. the largest cost the next accounting
    /// step can incur without running out of cycles.
    ///
    /// Meaningless on a free cost schedule, where nothing is ever charged and the
    /// allowance is zero.
    fn remaining(&self) -> Cycles {
        self.allowance - self.spent
    }

    /// Charges `amount` against the budget. Returns an error if the total spent
    /// now exceeds the available allowance (never on a free cost schedule).
    fn charge(&mut self, amount: Cycles) -> Result<(), PricingError> {
        // Always accumulate the spend, including on a free cost schedule, so
        // free subnets can report the real per-replica cost for canister cost
        // accounting.
        self.spent += amount;
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
        // A free cost schedule never charges, so the budget never constrains the
        // outcall; only the caller's own limit and the protocol maximum apply.
        if self.is_free {
            return AdapterLimits {
                max_response_size: self.max_response_size,
                max_response_time: MAX_RESPONSE_TIME,
            };
        }
        let remaining = self.remaining();
        AdapterLimits {
            // Never above what the caller asked for, even when it could afford more.
            max_response_size: self.max_response_size.min(max_downloaded_bytes(remaining)),
            max_response_time: MAX_RESPONSE_TIME.min(max_response_time(remaining)),
        }
    }

    fn subtract_network_usage(&mut self, network_usage: NetworkUsage) -> Result<(), PricingError> {
        let NetworkUsage {
            response_size,
            response_time,
        } = network_usage;
        self.charge(network_usage_fee(response_size, response_time))
    }

    fn get_transform_limit(&self) -> NumInstructions {
        // A free cost schedule never charges, so the transform runs on the full
        // query limit regardless of the (zero) allowance.
        if self.is_free {
            return MAX_INSTRUCTIONS_PER_QUERY_MESSAGE;
        }
        MAX_INSTRUCTIONS_PER_QUERY_MESSAGE.min(max_transform_instructions(self.remaining()))
    }

    fn subtract_transform_usage(&mut self, usage: NumInstructions) -> Result<(), PricingError> {
        self.charge(transform_usage_fee(usage))
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
        self.charge(gossip_usage_fee(
            transformed_response_size,
            self.subnet_size,
        ))
    }

    fn create_payment_receipt(&self) -> CanisterHttpPaymentReceipt {
        // Cap the reported spend at the maximum this replica may report having
        // spent. On a charging subnet that is the allowance. On a free cost
        // schedule nothing is actually charged, but the real spend is still
        // reported (so canister cost metrics reflect the actual work), bounded
        // by `MAX_HTTP_OUTCALL_SPEND_FREE_SUBNET`.
        let cap = if self.is_free {
            MAX_HTTP_OUTCALL_SPEND_FREE_SUBNET
        } else {
            self.allowance
        };
        CanisterHttpPaymentReceipt {
            spent: self.spent.min(cap),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fees::{
        FLEXIBLE_PER_TRANSFORMED_BYTE_NODE_FEE, PER_DOWNLOADED_BYTE_FEE, PER_RESPONSE_MS_FEE,
        TRANSFORM_INSTRUCTION_DIVISOR, max_consensus_fee, max_usage_fee,
    };
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
            cost_schedule: CanisterCyclesCostSchedule::Normal,
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

    /// Asserts that a gossiping outcall (flexible or non-replicated) charges the
    /// gossip term over the full subnet size.
    fn assert_gossip_charged_over_subnet_size(replication: Replication) {
        let ctx = context(replication, 1_000_000_000);
        let mut tracker = PayAsYouGoTracker::new(&ctx);

        let transformed_size = 500_u64;
        assert_eq!(
            tracker.subtract_gossip_usage(NumBytes::from(transformed_size)),
            Ok(())
        );
        let expected = FLEXIBLE_PER_TRANSFORMED_BYTE_NODE_FEE
            * transformed_size as u128
            * ctx.subnet_size.get() as u128;
        assert_eq!(tracker.spent, expected);
    }

    #[test]
    fn does_not_charge_base_cost() {
        // The base cost is handled at context creation, so a freshly created
        // tracker has spent nothing and a zero-usage request records no spend
        // (the full allowance is refunded downstream).
        let ctx = context(Replication::FullyReplicated, 1_000_000);
        let tracker = PayAsYouGoTracker::new(&ctx);
        assert_eq!(tracker.spent, Cycles::zero());
        assert_eq!(tracker.create_payment_receipt().spent, Cycles::zero());
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
        let transform = Cycles::new(instructions as u128 / TRANSFORM_INSTRUCTION_DIVISOR);

        // For fully-replicated requests the gossip term is a
        // consensus cost and must not be charged here.
        assert_eq!(tracker.subtract_gossip_usage(NumBytes::from(5_000)), Ok(()));

        assert_eq!(tracker.spent, network + transform);
        assert_eq!(tracker.create_payment_receipt().spent, network + transform);
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
        let mut tracker = PayAsYouGoTracker::new(&ctx);
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
        let ctx = CanisterHttpRequestContext {
            cost_schedule: CanisterCyclesCostSchedule::Free,
            ..context(flexible(subnet_size as usize), 0)
        };
        let mut tracker = PayAsYouGoTracker::new(&ctx);

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
        let transform = Cycles::new(instructions as u128 / TRANSFORM_INSTRUCTION_DIVISOR);

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
        assert!(expected > Cycles::zero());
        assert!(expected < MAX_HTTP_OUTCALL_SPEND_FREE_SUBNET);
        assert_eq!(tracker.spent, expected);
        assert_eq!(tracker.create_payment_receipt().spent, expected);
    }

    /// A non-replicated request, whose single replica also gossips its response.
    fn non_replicated() -> Replication {
        Replication::NonReplicated(NodeId::from(PrincipalId::new_node_test_id(0)))
    }

    #[test]
    fn usage_at_the_rationed_limits_is_always_affordable() {
        for replication in [Replication::FullyReplicated, non_replicated(), flexible(13)] {
            // Allowances spanning nothing, less than a single byte, and more than
            // every limit needs.
            for allowance in [0, 1, 1_000, 18_000_000, 1_000_000_000, u64::MAX as u128] {
                let ctx = context(replication.clone(), allowance);
                let mut tracker = PayAsYouGoTracker::new(&ctx);
                let case = format!("{replication:?} at allowance {allowance}");

                let limits = tracker.get_adapter_limits();
                assert_eq!(
                    tracker.subtract_network_usage(NetworkUsage {
                        response_size: limits.max_response_size,
                        response_time: Duration::ZERO,
                    }),
                    Ok(()),
                    "{case}: a download at the size limit"
                );

                let transform_limit = tracker.get_transform_limit();
                assert_eq!(
                    tracker.subtract_transform_usage(transform_limit),
                    Ok(()),
                    "{case}: a transform at the instruction limit"
                );

                // The time limit draws on the same allowance as the size limit, so
                // it is affordable on its own rather than on top of the download
                // above.
                let mut tracker = PayAsYouGoTracker::new(&ctx);
                let response_time = tracker.get_adapter_limits().max_response_time;
                assert_eq!(
                    tracker.subtract_network_usage(NetworkUsage {
                        response_size: NumBytes::from(0),
                        response_time,
                    }),
                    Ok(()),
                    "{case}: a download at the time limit"
                );
            }
        }
    }

    #[test]
    fn free_cost_schedule_keeps_the_default_limits() {
        // A free subnet is never charged, so its zero allowance must not be read as
        // a budget of zero: the limits stay at the defaults a request would get if
        // cycles were no object.
        let ctx = CanisterHttpRequestContext {
            cost_schedule: CanisterCyclesCostSchedule::Free,
            ..context(flexible(13), 0)
        };
        let tracker = PayAsYouGoTracker::new(&ctx);

        let limits = tracker.get_adapter_limits();
        assert_eq!(
            limits.max_response_size,
            NumBytes::from(MAX_CANISTER_HTTP_RESPONSE_BYTES)
        );
        assert_eq!(limits.max_response_time, MAX_RESPONSE_TIME);
        assert_eq!(
            tracker.get_transform_limit(),
            MAX_INSTRUCTIONS_PER_QUERY_MESSAGE
        );
    }

    #[test]
    fn zero_allowance_on_a_charging_subnet_buys_nothing_that_costs_a_cycle() {
        let ctx = context(flexible(13), 0);
        let tracker = PayAsYouGoTracker::new(&ctx);

        let limits = tracker.get_adapter_limits();
        assert_eq!(limits.max_response_size, NumBytes::from(0));
        assert_eq!(limits.max_response_time, Duration::ZERO);
        // Not zero, but everything a zero budget can pay for: the transform fee
        // rounds down, so the first `TRANSFORM_INSTRUCTION_DIVISOR` instructions
        // are free.
        assert_eq!(
            tracker.get_transform_limit(),
            NumInstructions::from(TRANSFORM_INSTRUCTION_DIVISOR as u64 - 1)
        );
    }

    #[test]
    fn adapter_limit_never_exceeds_the_requested_max_response_bytes() {
        // An allowance that could afford the full 2 MB does not entitle the request
        // to more than it asked for.
        let ctx = CanisterHttpRequestContext {
            max_response_bytes: Some(NumBytes::from(1_000)),
            ..context(Replication::FullyReplicated, 1_000_000_000)
        };
        let tracker = PayAsYouGoTracker::new(&ctx);
        assert_eq!(
            tracker.get_adapter_limits().max_response_size,
            NumBytes::from(1_000)
        );
    }

    #[test]
    fn bytes_and_latency_are_each_offered_the_whole_allowance() {
        // Neither term reserves anything for the other: the download may use all
        // 1_000 cycles on bytes, or all 1_000 on latency. Partitioning them would
        // spend part of every allowance up front on latency the response will
        // probably not use.
        let ctx = context(Replication::FullyReplicated, 1_000);
        let mut tracker = PayAsYouGoTracker::new(&ctx);

        let limits = tracker.get_adapter_limits();
        // 1_000 / 50 bytes, or 1_000 / 300 ms.
        assert_eq!(limits.max_response_size, NumBytes::from(20));
        assert_eq!(limits.max_response_time, Duration::from_millis(3));

        // A response that uses both to the full is charged for both,
        // and is rejected after the fact rather than prevented
        // up front. 50 * 20 + 300 * 3 = 1_900 > 1_000.
        assert_eq!(
            tracker.subtract_network_usage(NetworkUsage {
                response_size: limits.max_response_size,
                response_time: limits.max_response_time,
            }),
            Err(PricingError::InsufficientCycles)
        );
    }

    #[test]
    fn the_time_limit_forbids_exactly_the_unaffordable_responses() {
        for allowance in [0, 1, 1_000, 300_000, 18_000_000, 1_000_000_000] {
            let ctx = context(Replication::FullyReplicated, allowance);
            let limit = PayAsYouGoTracker::new(&ctx)
                .get_adapter_limits()
                .max_response_time;
            for millis in [0, 1, 2, 10, 1_000, 59_999, 60_000] {
                let response_time = Duration::from_millis(millis);
                let mut tracker = PayAsYouGoTracker::new(&ctx);
                let affordable = tracker
                    .subtract_network_usage(NetworkUsage {
                        response_size: NumBytes::from(0),
                        response_time,
                    })
                    .is_ok();
                assert_eq!(
                    affordable,
                    response_time <= limit,
                    "allowance {allowance}: a {millis} ms response is affordable: \
                     {affordable}, but the limit is {limit:?}"
                );
            }
        }
    }

    #[test]
    fn transform_limit_is_tight() {
        // The limit is not merely safe but exact: an allowance of 1_000 buys
        // 1_000 * 13 instructions plus the 12 the last cycle already paid for,
        // and a single instruction more costs one cycle more than the allowance.
        let ctx = context(Replication::FullyReplicated, 1_000);
        let mut tracker = PayAsYouGoTracker::new(&ctx);

        let limit = tracker.get_transform_limit();
        assert_eq!(limit, NumInstructions::from(13_012));
        assert_eq!(
            tracker.subtract_transform_usage(NumInstructions::from(limit.get() + 1)),
            Err(PricingError::InsufficientCycles)
        );
    }

    #[test]
    fn limits_shrink_as_the_allowance_is_spent() {
        // An allowance small enough that every limit is set by the budget rather
        // than by the constant it is capped at.
        let ctx = context(flexible(13), 3_000_000);
        let mut tracker = PayAsYouGoTracker::new(&ctx);
        assert!(tracker.get_transform_limit() < MAX_INSTRUCTIONS_PER_QUERY_MESSAGE);

        let transform_limit_before = tracker.get_transform_limit();
        let limits_before = tracker.get_adapter_limits();
        assert!(limits_before.max_response_time < MAX_RESPONSE_TIME);

        assert_eq!(
            tracker.subtract_network_usage(NetworkUsage {
                response_size: NumBytes::from(1_000),
                response_time: Duration::from_millis(1_000),
            }),
            Ok(())
        );

        assert!(
            tracker.get_transform_limit() < transform_limit_before,
            "the transform limit should reflect the spent network usage"
        );
        let limits_after = tracker.get_adapter_limits();
        assert!(
            limits_after.max_response_size < limits_before.max_response_size
                && limits_after.max_response_time < limits_before.max_response_time,
            "the adapter limits should reflect the spent network usage"
        );
    }

    #[test]
    fn free_cost_schedule_caps_reported_spend_at_maximum() {
        // Even though a free subnet may report a spend exceeding its (zero)
        // allowance, the reported spend is never unbounded: it is capped at
        // `MAX_HTTP_OUTCALL_SPEND_FREE_SUBNET`.
        let subnet_size = 13_u64;
        let ctx = CanisterHttpRequestContext {
            cost_schedule: CanisterCyclesCostSchedule::Free,
            ..context(flexible(subnet_size as usize), 0)
        };
        let mut tracker = PayAsYouGoTracker::new(&ctx);

        // A gossip term large enough to push the raw spend past the cap.
        assert_eq!(
            tracker.subtract_gossip_usage(NumBytes::from(u64::MAX)),
            Ok(())
        );
        assert!(tracker.spent > MAX_HTTP_OUTCALL_SPEND_FREE_SUBNET);
        assert_eq!(
            tracker.create_payment_receipt().spent,
            MAX_HTTP_OUTCALL_SPEND_FREE_SUBNET
        );
    }

    #[test]
    fn allowance_derived_from_max_usage_fee_covers_the_largest_possible_spend() {
        // `max_usage_fee` bounds how much of a request's payment is withheld as
        // per-replica allowances, so it has to cover everything this tracker can
        // charge a replica: the largest response the adapter may return, taking the
        // longest it may take, transformed with the whole instruction limit into the
        // largest response that may be delivered. On top of that, what the allowances
        // of all replicas together leave unspent has to cover the consensus fee of
        // delivering the response(s). If it didn't, a request paying for the worst
        // case could still run out of cycles.
        let node = NodeId::from(PrincipalId::new_node_test_id(0));
        for replication in [
            Replication::FullyReplicated,
            Replication::NonReplicated(node),
            flexible(4),
            // A committee of 11 on a 13-node subnet, whose worst case is not a whole
            // number of allowances, so that the rounding below actually happens.
            flexible(11),
        ] {
            for max_response_bytes in [None, Some(NumBytes::from(0)), Some(NumBytes::from(1_000))] {
                let subnet_size = NumberOfNodes::from(13);
                let node_count = replication.node_count(subnet_size);
                let allowance =
                    max_usage_fee(&replication, max_response_bytes, subnet_size) / node_count;
                let ctx = CanisterHttpRequestContext {
                    max_response_bytes,
                    ..context(replication.clone(), allowance.get())
                };
                assert_eq!(ctx.subnet_size, subnet_size);
                // The largest response of either kind the validators would accept,
                // which is what the worst case has to be funded for.
                let delivered = NumBytes::from(
                    ctx.max_http_outcall_content_size(/* is_reject = */ false)
                        .max(ctx.max_http_outcall_content_size(/* is_reject = */ true)),
                );
                let mut tracker = PayAsYouGoTracker::new(&ctx);

                let limits = tracker.get_adapter_limits();
                assert_eq!(
                    tracker.subtract_network_usage(NetworkUsage {
                        response_size: limits.max_response_size,
                        response_time: limits.max_response_time,
                    }),
                    Ok(()),
                    "{replication:?}, {max_response_bytes:?}"
                );
                let transform_limit = tracker.get_transform_limit();
                assert_eq!(
                    tracker.subtract_transform_usage(transform_limit),
                    Ok(()),
                    "{replication:?}, {max_response_bytes:?}"
                );
                assert_eq!(
                    tracker.subtract_gossip_usage(delivered),
                    Ok(()),
                    "{replication:?}, {max_response_bytes:?}"
                );
                // What every replica leaves unspent adds up to at least the consensus
                // fee of delivering the largest response from each of them.
                let consensus_fee = max_consensus_fee(replication.kind(), delivered, subnet_size);
                let worst_case = tracker.spent * node_count + consensus_fee;
                let allowances = allowance * node_count;
                assert!(
                    allowances >= worst_case,
                    "{replication:?}, {max_response_bytes:?}"
                );
                // And they cover no more than that: the only slack is what [`usage_fee`]
                // added by rounding the worst case up to a whole number of allowances,
                // i.e. fewer cycles than there are allowances.
                assert!(
                    allowances - worst_case < Cycles::from(node_count as u64),
                    "{replication:?}, {max_response_bytes:?}"
                );
                // Every replica leaves its own share of the consensus fee unspent, not
                // just the collective allowance above.
                assert!(
                    allowance - tracker.spent >= consensus_fee.div_ceil(node_count as u128),
                    "{replication:?}, {max_response_bytes:?}: a replica that spent \
                     {} of its {allowance} allowance does not hold its share of the \
                     {consensus_fee} consensus fee",
                    tracker.spent
                );
            }
        }
    }
}
