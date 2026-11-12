//! Pay-as-you-go pricing for HTTP outcalls.
//!
//! A request's cost is split into three parts, all defined here so that they
//! share a single set of constants and formulas:
//!   1. the base fee ([`base_fee`]), subtracted up-front when the request context
//!      is created (and therefore reflected in `per_replica_allowance`);
//!   2. the per-replica fees ([`network_usage_fee`], [`transform_usage_fee`],
//!      [`gossip_usage_fee`]), accounted for as-you-go by the
//!      `PayAsYouGoTracker` (see `payg.rs`);
//!   3. the consensus fee ([`non_flexible_initial_spent`] /
//!      [`flexible_initial_spent`]), computed from the aggregated response in the
//!      block payload.
//!
//! [`total_fee`] adds those three parts up for a hypothetical outcall, which is the
//! price reported to canisters; its second and third part — everything the
//! per-replica allowances have to cover — is [`usage_fee`], whose worst case
//! ([`max_usage_fee`]) in turn bounds how much of a request's payment is withheld as
//! allowances.

use std::time::Duration;

use ic_config::subnet_config::MAX_INSTRUCTIONS_PER_QUERY_MESSAGE;
use ic_types::{
    NumBytes, NumInstructions, NumberOfNodes,
    canister_http::{
        CanisterHttpResponseMetadata, CanisterHttpResponseProof, CanisterHttpResponseShare,
        MAX_CANISTER_HTTP_REJECT_BYTES, MAX_CANISTER_HTTP_RESPONSE_BYTES, Replication,
        ReplicationKind, canister_http_threshold, max_http_outcall_response_size,
    },
};
use ic_types_cycles::{CompoundCycles, Cycles, CyclesAccountManagerSubnetConfig, HTTPOutcalls};
use std::collections::BTreeMap;

use crate::MAX_RESPONSE_TIME;

// ============================ Base-fee constants ============================
// Charged up-front for every request by [`base_fee`].

const HTTP_REQUEST_BASE_FEE: Cycles = Cycles::new(1_000_000);
const HTTP_REQUEST_PER_BYTE_FEE: Cycles = Cycles::new(50);
const HTTP_REQUEST_FULLY_REPLICATED_PER_NODE_FEE: Cycles = Cycles::new(140_000);
const HTTP_REQUEST_FULLY_REPLICATED_QUADRATIC_NODE_FEE: Cycles = Cycles::new(800);
const HTTP_REQUEST_FLEXIBLE_PER_NODE_FEE: Cycles = Cycles::new(90_000);
const HTTP_REQUEST_FLEXIBLE_PER_NODE_RESPONSE_CONSENSUS_FEE: Cycles = Cycles::new(2_000);
const HTTP_REQUEST_FLEXIBLE_PER_RESPONSE_CONSENSUS_FEE: Cycles = Cycles::new(100_000);

// ========================= Per-replica-fee constants =========================
// Charged as-you-go by the `PayAsYouGoTracker` in `payg.rs`, through the
// per-replica fee functions below.

pub(crate) const PER_DOWNLOADED_BYTE_FEE: Cycles = Cycles::new(50);
pub(crate) const PER_RESPONSE_MS_FEE: Cycles = Cycles::new(300);
/// HTTP outcalls are priced consistently against a reference subnet size of 13.
pub(crate) const TRANSFORM_INSTRUCTION_DIVISOR: u128 = 13;
pub(crate) const FLEXIBLE_PER_TRANSFORMED_BYTE_NODE_FEE: Cycles = Cycles::new(50);

// ========================== Consensus-fee constants ==========================
// Charged for including the aggregated response in a block, via
// [`non_flexible_initial_spent`] / [`flexible_initial_spent`].

const CONSENSUS_PER_NODE_BYTE_FEE: Cycles = Cycles::new(10);
const CONSENSUS_BYTE_FEE: Cycles = Cycles::new(600);
const FLEXIBLE_RESPONSE_SIZE_OVERHEAD: u128 = 181;

/// The number of nodes of the subnet described by `subnet_cycles_config`.
fn subnet_size_of(subnet_cycles_config: CyclesAccountManagerSubnetConfig) -> NumberOfNodes {
    NumberOfNodes::from(subnet_cycles_config.subnet_size as u32)
}

// ================================= Base fee =================================

/// Computes the up-front base fee for an HTTP outcall request of size
/// `request_size` with the given `replication`, on the subnet described by
/// `subnet_cycles_config`.
pub fn base_fee(
    request_size: NumBytes,
    replication: &Replication,
    subnet_cycles_config: CyclesAccountManagerSubnetConfig,
) -> CompoundCycles<HTTPOutcalls> {
    CompoundCycles::new(
        base_fee_amount(
            request_size,
            replication.kind(),
            subnet_size_of(subnet_cycles_config),
        ),
        subnet_cycles_config.cost_schedule,
    )
}

/// The [`base_fee`], on a subnet of `subnet_size` nodes.
fn base_fee_amount(
    request_size: NumBytes,
    replication_kind: ReplicationKind,
    subnet_size: NumberOfNodes,
) -> Cycles {
    let n = subnet_size.get() as u64;
    let request_bytes = request_size.get();
    match replication_kind {
        ReplicationKind::FullyReplicated => {
            (HTTP_REQUEST_BASE_FEE
                + HTTP_REQUEST_PER_BYTE_FEE * request_bytes
                + HTTP_REQUEST_FULLY_REPLICATED_PER_NODE_FEE * n
                + HTTP_REQUEST_FULLY_REPLICATED_QUADRATIC_NODE_FEE * n * n)
                * n
        }
        // Non-replicated is equivalent to flexible replication with min_responses = 1.
        ReplicationKind::NonReplicated => gossipping_base_fee(request_bytes, subnet_size, 1),
        ReplicationKind::Flexible { min_responses, .. } => {
            gossipping_base_fee(request_bytes, subnet_size, min_responses)
        }
    }
}

/// The base fee of a gossiping (flexible or non-replicated) outcall of
/// `request_bytes` bytes that requires `min_responses` responses, on a subnet of
/// `subnet_size` nodes.
fn gossipping_base_fee(
    request_bytes: u64,
    subnet_size: NumberOfNodes,
    min_responses: u32,
) -> Cycles {
    let n = subnet_size.get() as u64;
    let min_responses = min_responses as u64;
    (HTTP_REQUEST_BASE_FEE
        + HTTP_REQUEST_PER_BYTE_FEE * request_bytes
        + HTTP_REQUEST_FLEXIBLE_PER_NODE_FEE * n
        + HTTP_REQUEST_FLEXIBLE_PER_NODE_RESPONSE_CONSENSUS_FEE * n * min_responses
        + HTTP_REQUEST_FLEXIBLE_PER_RESPONSE_CONSENSUS_FEE * min_responses)
        * n
}

// ============================= Per-replica fees =============================
// The individual fees the `PayAsYouGoTracker` (see `payg.rs`) charges a replica
// as it performs the outcall.

/// The fee for downloading a response of `response_size` in `response_time`.
pub(crate) fn network_usage_fee(response_size: NumBytes, response_time: Duration) -> Cycles {
    PER_DOWNLOADED_BYTE_FEE * response_size.get() + PER_RESPONSE_MS_FEE * response_time.as_millis()
}

/// The largest response [`network_usage_fee`] prices within `budget`, i.e. the
/// inverse of its per-byte term.
pub(crate) fn max_downloaded_bytes(budget: Cycles) -> NumBytes {
    NumBytes::from(u64::try_from(budget.get() / PER_DOWNLOADED_BYTE_FEE.get()).unwrap_or(u64::MAX))
}

/// The longest response time [`network_usage_fee`] prices within `budget`, i.e.
/// the inverse of its per-millisecond term.
pub(crate) fn max_response_time(budget: Cycles) -> Duration {
    Duration::from_millis(
        u64::try_from(budget.get() / PER_RESPONSE_MS_FEE.get()).unwrap_or(u64::MAX),
    )
}

/// The fee for running the transform function for `instructions`.
pub(crate) fn transform_usage_fee(instructions: NumInstructions) -> Cycles {
    Cycles::from((instructions.get() as u128) / TRANSFORM_INSTRUCTION_DIVISOR)
}

/// The most instructions [`transform_usage_fee`] prices within `budget`, i.e. the
/// largest transform the budget affords.
pub(crate) fn max_transform_instructions(budget: Cycles) -> NumInstructions {
    // The fee rounds the instruction count down to a whole number of cycles, so
    // the budget also affords the divisor's worth of instructions that costs
    // nothing on top of it.
    let instructions = (budget * TRANSFORM_INSTRUCTION_DIVISOR)
        .get()
        .saturating_add(TRANSFORM_INSTRUCTION_DIVISOR - 1);
    NumInstructions::from(u64::try_from(instructions).unwrap_or(u64::MAX))
}

/// The fee for gossiping a transformed response of `transformed_response_size` to
/// all `subnet_size` nodes of the subnet. Only gossiping (flexible and
/// non-replicated) outcalls are charged this; for fully-replicated ones,
/// disseminating the response is a consensus cost instead.
pub fn gossip_usage_fee(transformed_response_size: NumBytes, subnet_size: NumberOfNodes) -> Cycles {
    FLEXIBLE_PER_TRANSFORMED_BYTE_NODE_FEE
        * transformed_response_size.get()
        * (subnet_size.get() as u64)
}

// =============================== Consensus fee ===============================

/// The consensus fee for putting `response_bytes` many response bytes into a
/// block on a subnet of size `subnet_size`, i.e. `N * (10 * N + 600) * response_bytes`.
pub fn consensus_fee(response_bytes: u128, subnet_size: NumberOfNodes) -> Cycles {
    let n = subnet_size.get() as u64;
    (CONSENSUS_PER_NODE_BYTE_FEE * n + CONSENSUS_BYTE_FEE) * n * response_bytes
}

/// The additional consensus fee charged for `extra_responses` flexible responses
/// beyond the `min_responses` required to reach consensus.
fn flexible_extra_response_fee(extra_responses: u32, subnet_size: NumberOfNodes) -> Cycles {
    let n = subnet_size.get() as u64;
    (HTTP_REQUEST_FLEXIBLE_PER_NODE_RESPONSE_CONSENSUS_FEE * n
        + HTTP_REQUEST_FLEXIBLE_PER_RESPONSE_CONSENSUS_FEE)
        * n
        * (extra_responses as u64)
}

// ================================= Total fee =================================

/// The total fee for an HTTP outcall of the given `replication_kind` where every
/// participating replica consumed the given resources, i.e. the sum of all three
/// parts of its price: the up-front [`base_fee`], the per-replica fees of every
/// replica attempting it, and the consensus fee of putting the responses that are
/// delivered into a block. Used by canisters to estimate the cost of an outcall.
///
/// Since neither how many replicas will respond nor which result they will produce is
/// known ahead of time, this is what an outcall has to *pay up front* rather than what
/// it ends up costing: every replica of the (flexible) committee is assumed to attempt
/// the call. The consensus fee is reserved for the result that is most expensive to
/// fund — which is more than any result actually charges (see [`max_consensus_fee`]).
/// Whatever of that is not spent is refunded once the request is settled.
pub fn total_fee(
    request_size: NumBytes,
    http_roundtrip_time: Duration,
    raw_response_size: NumBytes,
    transform_instructions: NumInstructions,
    transformed_response_size: NumBytes,
    replication_kind: ReplicationKind,
    subnet_cycles_config: CyclesAccountManagerSubnetConfig,
) -> CompoundCycles<HTTPOutcalls> {
    let subnet_size = subnet_size_of(subnet_cycles_config);
    let amount = base_fee_amount(request_size, replication_kind, subnet_size)
        + usage_fee(
            replication_kind,
            http_roundtrip_time,
            raw_response_size,
            transform_instructions,
            transformed_response_size,
            subnet_size,
        );

    CompoundCycles::new(amount, subnet_cycles_config.cost_schedule)
}

/// Everything an HTTP outcall of the given `replication_kind` with the given
/// resource usage costs beyond its up-front [`base_fee`]: the per-replica fee of
/// every replica attempting it, plus the consensus fee of delivering the responses.
///
/// This is the part of the price that the per-replica allowances have to cover, and
/// hence the amount a caller pays that is split into those allowances. The returned
/// value is therefore rounded up to a whole number of the committee size.
fn usage_fee(
    replication_kind: ReplicationKind,
    http_roundtrip_time: Duration,
    raw_response_size: NumBytes,
    transform_instructions: NumInstructions,
    transformed_response_size: NumBytes,
    subnet_size: NumberOfNodes,
) -> Cycles {
    let gossip_fee = match replication_kind {
        ReplicationKind::FullyReplicated => Cycles::zero(),
        ReplicationKind::NonReplicated | ReplicationKind::Flexible { .. } => {
            // A replica that rejects gossips its reject body rather than the response
            // that was asked for, so the term is priced for at least a maximally large
            // reject (see [`max_consensus_fee`]).
            gossip_usage_fee(
                transformed_response_size.max(NumBytes::from(MAX_CANISTER_HTTP_REJECT_BYTES)),
                subnet_size,
            )
        }
    };
    let consensus_fee = max_consensus_fee(replication_kind, transformed_response_size, subnet_size);

    let per_replica_fee = network_usage_fee(raw_response_size, http_roundtrip_time)
        + transform_usage_fee(transform_instructions)
        + gossip_fee;
    let replicas = replication_kind.node_count(subnet_size);

    (per_replica_fee + consensus_fee.div_ceil(replicas as u128)) * replicas
}

/// The consensus fee an outcall of the given `replication_kind` reserves for delivering
/// its response(s), each `transformed_response_size` bytes large.
///
/// The fee has to be paid out of the replica's unspent allowances. Therefore, the
/// returned fee is priced such that every deliverable result is self-funding. Specifically,
/// the fully replicated consensus fee is scaled up by a factor of `subnet_size / threshold`,
/// to account for the fact that only `threshold` many replicas contribute to the result, but
/// the allowance is split across the whole subnet.
///
/// For the same reason, the flexible consensus fee is priced for `total_requests` responses
/// rather than for the `max_responses` that are delivered.
pub(crate) fn max_consensus_fee(
    replication_kind: ReplicationKind,
    transformed_response_size: NumBytes,
    subnet_size: NumberOfNodes,
) -> Cycles {
    // Whatever was asked for, a reject of this size may be delivered in its place.
    let response_bytes =
        (transformed_response_size.get() as u128).max(MAX_CANISTER_HTTP_REJECT_BYTES as u128);
    match replication_kind {
        ReplicationKind::NonReplicated => consensus_fee(response_bytes, subnet_size),
        ReplicationKind::FullyReplicated => {
            // The replicas the reserve is split across, i.e. the whole subnet, and the
            // quorum of them a response proof needs.
            let n = replication_kind.node_count(subnet_size);
            let threshold = canister_http_threshold(n) as u128;
            // The fee delivering the response will cost, cut into the share each of the
            // `threshold` contributors has to cover, times the `n` replicas the reserve is
            // split across.
            consensus_fee(response_bytes, subnet_size).div_ceil(threshold) * n
        }
        // Fire-and-forget: no response is ever delivered, so consensus never puts one in a block.
        ReplicationKind::Flexible {
            max_responses: 0, ..
        } => Cycles::zero(),
        ReplicationKind::Flexible {
            total_requests,
            min_responses,
            ..
        } => {
            consensus_fee(
                // `total_requests` (instead of `max_responses`) such that each replica's
                // allowance can cover the cost of delivering its own response.
                (total_requests as u128)
                    .saturating_mul(FLEXIBLE_RESPONSE_SIZE_OVERHEAD.saturating_add(response_bytes)),
                subnet_size,
            ) + flexible_extra_response_fee(
                // With `T = total_requests` and `m = min_responses`: each allowance holds
                // `(T - m) / T` of one response's surcharge, while a result of `K` responses
                // charges its `K` contributors `(K - m) / K` each. That is covered for every
                // `K <= T`, which is why we choose `total_requests` to quote the maximum cost.
                total_requests.saturating_sub(min_responses),
                subnet_size,
            )
        }
    }
}

// ============================= Maximum usage fee =============================

/// The largest [`usage_fee`] an HTTP outcall with the given `replication` and
/// `max_response_bytes` can have, i.e. its worst case: a response of the largest
/// permitted size, downloaded over the full `MAX_RESPONSE_TIME`, transformed with the
/// full query instruction limit and delivered as a maximally large transformed response.
///
/// This is what bounds how much of a request's payment is withheld as allowances;
/// anything beyond it could never be spent, so withholding it would only lock up the
/// caller's cycles until the request is settled.
///
/// This is an upper bound on what an outcall can be *charged*, not the charge itself: the
/// consensus fee it reserves exceeds what delivering any single result costs (see
/// [`max_consensus_fee`]), and the excess is refunded.
///
/// Being a [`usage_fee`], it is a whole multiple of the number of participating replicas,
/// so splitting it evenly among them loses nothing.
pub fn max_usage_fee(
    replication: &Replication,
    max_response_bytes: Option<NumBytes>,
    subnet_size: NumberOfNodes,
) -> Cycles {
    let replication_kind = replication.kind();
    let raw_response_size =
        max_response_bytes.unwrap_or(NumBytes::from(MAX_CANISTER_HTTP_RESPONSE_BYTES));
    usage_fee(
        replication_kind,
        MAX_RESPONSE_TIME,
        raw_response_size,
        MAX_INSTRUCTIONS_PER_QUERY_MESSAGE,
        NumBytes::from(max_http_outcall_response_size(max_response_bytes)),
        subnet_size,
    )
}

// =============================== Initial spent ===============================

/// Computes the collective initial spent cycles for a fully-replicated (or
/// non-replicated) HTTP outcall response.
///
/// The spend is the sum of the per-replica spends claimed in the proof's payment
/// receipts, plus the consensus cost `N * (10 * N + 600) * <response_size>` of
/// including the aggregated response in a block.
pub fn non_flexible_initial_spent(
    proof: &CanisterHttpResponseProof,
    subnet_size: NumberOfNodes,
) -> Cycles {
    let spent_sum: Cycles = proof
        .signatures
        .values()
        .map(|sig| sig.payment_receipt.spent)
        .sum();
    spent_sum + consensus_fee(proof.metadata.content_size as u128, subnet_size)
}

/// Computes the collective initial spent cycles for a group of flexible HTTP
/// outcall responses (used both for successful responses and `TooManyRejects`
/// errors).
///
/// The spend is the sum of the per-replica spends claimed in the shares' payment
/// receipts, plus the consensus cost
/// `N * (10 * N + 600) * sum over K replicas (181 + <transformed_response_size_i>)`,
/// plus an additional per-extra-response cost
/// `N * (HTTP_REQUEST_FLEXIBLE_PER_NODE_RESPONSE_CONSENSUS_FEE * N * (K - min_responses)`
/// `   + HTTP_REQUEST_FLEXIBLE_PER_RESPONSE_CONSENSUS_FEE * (K - min_responses))`
/// charged for every response beyond the `min_responses` required to reach
/// consensus, where `K` is the number of shares in `shares`.
///
/// `extra_shares` are shares whose responses are not delivered (see
/// [`FlexibleCanisterHttpResponses::extra_shares`]). They only add their claimed
/// per-replica spend: since they carry no response, they neither incur a
/// consensus cost nor count towards `K`.
///
/// [`FlexibleCanisterHttpResponses::extra_shares`]: ic_types::batch::FlexibleCanisterHttpResponses::extra_shares
pub fn flexible_initial_spent<'a>(
    shares: impl Iterator<Item = &'a CanisterHttpResponseShare>,
    extra_shares: impl Iterator<Item = &'a CanisterHttpResponseShare>,
    subnet_size: NumberOfNodes,
    min_responses: u32,
) -> Cycles {
    let mut spent_sum = Cycles::zero();
    let mut size_term: u128 = 0;
    let mut count: u32 = 0;
    for share in shares {
        spent_sum += share.content.payment_receipt.spent;
        size_term += FLEXIBLE_RESPONSE_SIZE_OVERHEAD + share.content.content_size() as u128;
        count += 1;
    }
    for share in extra_shares {
        spent_sum += share.content.payment_receipt.spent;
    }
    let extra_responses = count.saturating_sub(min_responses);
    spent_sum
        + consensus_fee(size_term, subnet_size)
        + flexible_extra_response_fee(extra_responses, subnet_size)
}

/// A lower bound on the consensus cost of delivering a flexible response, given
/// the currently `seen_shares`.
///
/// The cheapest response delivers as few bodies as it may: every committee member
/// that has not been seen yet may still produce an empty body, so only the bodies
/// that must come out of `seen_shares` are counted at their actual size.
pub fn min_flexible_consensus_cost<'a>(
    seen_shares: impl Iterator<Item = &'a CanisterHttpResponseShare>,
    subnet_size: NumberOfNodes,
    committee_size: usize,
    min_responses: u32,
) -> Option<Cycles> {
    let mut ok_sizes = Vec::new();
    let mut reject_sizes = Vec::new();
    for share in seen_shares {
        if share.content.is_reject() {
            reject_sizes.push(share.content.content_size());
        } else {
            ok_sizes.push(share.content.content_size());
        }
    }
    // Smallest first: those are the bodies a cheapest result would pick.
    ok_sizes.sort_unstable();
    reject_sizes.sort_unstable();
    let unseen = committee_size.saturating_sub(ok_sizes.len() + reject_sizes.len());

    let min_ok = min_responses as usize;
    let min_rejects = committee_size.saturating_sub(min_ok) + 1;
    // A result is still reachable only while enough replicas can contribute to it.
    let ok_cost = (ok_sizes.len() + unseen >= min_ok)
        .then(|| min_delivery_cost(&ok_sizes, unseen, min_ok, subnet_size, min_responses));
    let reject_cost = (reject_sizes.len() + unseen >= min_rejects).then(|| {
        min_delivery_cost(
            &reject_sizes,
            unseen,
            min_rejects,
            subnet_size,
            min_responses,
        )
    });

    ok_cost.into_iter().chain(reject_cost).min()
}

/// The least it can cost to deliver the `required_responses` that a result cannot
/// deliver fewer than: of those, at most `unseen` may still turn out to have an empty
/// body and the rest have to have the smallest of the already known `seen_sizes`.
fn min_delivery_cost(
    seen_sizes: &[u32],
    unseen: usize,
    required_responses: usize,
    subnet_size: NumberOfNodes,
    min_responses: u32,
) -> Cycles {
    // Every replica not seen yet may still produce an empty body, so only the
    // responses beyond those have to take a body from the seen sizes.
    let from_seen = required_responses
        .saturating_sub(unseen)
        .min(seen_sizes.len());
    let assumed_empty = required_responses - from_seen;
    let size_term: u128 = seen_sizes[..from_seen]
        .iter()
        .map(|size| FLEXIBLE_RESPONSE_SIZE_OVERHEAD + *size as u128)
        .sum::<u128>()
        + FLEXIBLE_RESPONSE_SIZE_OVERHEAD * assumed_empty as u128;
    // `required_responses` is bounded by the committee size, so it always fits a `u32`
    let extra_responses = u32::try_from(required_responses.saturating_sub(min_responses as usize))
        .unwrap_or(u32::MAX);
    consensus_fee(size_term, subnet_size)
        + flexible_extra_response_fee(extra_responses, subnet_size)
}

/// A lower bound on the consensus cost of delivering a fully- or non-replicated
/// response, given the `seen_shares` produced so far (at most one per replica).
pub fn min_non_flexible_consensus_cost<'a>(
    seen_shares: impl Iterator<Item = &'a CanisterHttpResponseShare>,
    subnet_size: NumberOfNodes,
    committee_size: usize,
    threshold: usize,
) -> Option<Cycles> {
    // Shares agreeing on the same metadata are votes for the same response.
    let mut votes: BTreeMap<&CanisterHttpResponseMetadata, usize> = BTreeMap::new();
    let mut seen = 0;
    for share in seen_shares {
        *votes.entry(&share.content.metadata).or_default() += 1;
        seen += 1;
    }
    let unseen = committee_size.saturating_sub(seen);

    votes
        .into_iter()
        .map(|(metadata, votes)| (votes, metadata.content_size))
        // A response nobody has voted for yet would have to come from the replicas that
        // have not been seen, and may have an empty body.
        .chain(std::iter::once((0, 0)))
        .filter(|(votes, _)| votes + unseen >= threshold)
        .map(|(_, content_size)| consensus_fee(content_size as u128, subnet_size))
        .min()
}

#[cfg(test)]
mod tests {
    //! The expected values in these tests are computed by hand rather than by
    //! calling the functions under test, so that a wrong constant or dropped
    //! term is actually caught. (The consensus payload builder/validator tests
    //! only compare these functions against themselves and would not.)
    use super::*;
    use ic_types::{
        NodeId, PrincipalId,
        canister_http::{
            CanisterHttpPaymentReceipt, CanisterHttpResponseMetadata, CanisterHttpResponseProof,
            CanisterHttpResponseReceipt, CanisterHttpResponseShare, CanisterHttpResponseSignature,
        },
        crypto::{BasicSig, BasicSigOf, CryptoHash, CryptoHashOf, Signed},
        messages::CallbackId,
        signature::BasicSignature,
    };
    use ic_types_cycles::CanisterCyclesCostSchedule;
    use ic_types_test_utils::ids::test_replica_version;
    use std::collections::BTreeMap;

    fn node(i: u64) -> NodeId {
        NodeId::from(PrincipalId::new_node_test_id(i))
    }

    /// A flexible replication delegated to a committee of `total_requests` nodes.
    fn flexible(total_requests: u64, min_responses: u32, max_responses: u32) -> Replication {
        Replication::Flexible {
            committee: (0..total_requests).map(node).collect(),
            min_responses,
            max_responses,
        }
    }

    fn metadata(content_size: u32) -> CanisterHttpResponseMetadata {
        CanisterHttpResponseMetadata {
            id: CallbackId::from(1),
            content_hash: CryptoHashOf::new(CryptoHash(vec![])),
            content_size,
            is_reject: false,
            replica_version: test_replica_version(),
        }
    }

    /// A fully-replicated proof over a response of `content_size` bytes, with one
    /// signer per entry in `spends` claiming that many spent cycles.
    fn proof(content_size: u32, spends: &[u128]) -> CanisterHttpResponseProof {
        let signatures: BTreeMap<_, _> = spends
            .iter()
            .enumerate()
            .map(|(i, spent)| {
                (
                    node(i as u64),
                    CanisterHttpResponseSignature {
                        payment_receipt: CanisterHttpPaymentReceipt {
                            spent: Cycles::new(*spent),
                        },
                        signature: BasicSigOf::new(BasicSig(vec![])),
                    },
                )
            })
            .collect();
        CanisterHttpResponseProof {
            metadata: metadata(content_size),
            signatures,
        }
    }

    /// A flexible share signed by `signer`, spending `spent` cycles over a
    /// response of `content_size` bytes.
    fn share(signer: u64, content_size: u32, spent: u128) -> CanisterHttpResponseShare {
        Signed {
            content: CanisterHttpResponseReceipt {
                metadata: metadata(content_size),
                payment_receipt: CanisterHttpPaymentReceipt {
                    spent: Cycles::new(spent),
                },
            },
            signature: BasicSignature {
                signature: BasicSigOf::new(BasicSig(vec![])),
                signer: node(signer),
            },
        }
    }

    /// Same as [`share`], but for a reject response.
    fn reject_share(signer: u64, content_size: u32, spent: u128) -> CanisterHttpResponseShare {
        let mut share = share(signer, content_size, spent);
        share.content.metadata.is_reject = true;
        share
    }

    #[test]
    fn non_flexible_initial_spent_sums_receipts_plus_consensus_cost() {
        // Two signers spending distinct amounts (so a dropped or double-counted
        // receipt changes the result), over a 100-byte response at N = 13.
        //   spent_sum      = 1_000 + 2_000                 = 3_000
        //   consensus_cost = 9_490 * 100                   = 949_000
        let spent =
            non_flexible_initial_spent(&proof(100, &[1_000, 2_000]), NumberOfNodes::from(13));
        assert_eq!(spent, Cycles::new(3_000 + 949_000));
    }

    #[test]
    fn non_flexible_initial_spent_with_zero_content_is_just_the_spends() {
        // A zero-size response contributes no consensus cost; only the receipts
        // remain.
        let spent = non_flexible_initial_spent(&proof(0, &[7, 11]), NumberOfNodes::from(13));
        assert_eq!(spent, Cycles::new(18));
    }

    #[test]
    fn flexible_initial_spent_sums_receipts_consensus_and_extra_cost() {
        // K = 3 shares, min_responses = 1 (so extra_responses = 2), at N = 13.
        //   spent_sum      = 100 + 200 + 300                                = 600
        //   size_term      = (181+10) + (181+20) + (181+30)                 = 603
        //   consensus_cost = 9_490 * 603                                    = 5_722_470
        //   extra_cost     = 13 * (2_000 * 13 * 2 + 100_000 * 2)            = 3_276_000
        let shares = [share(0, 10, 100), share(1, 20, 200), share(2, 30, 300)];
        let spent = flexible_initial_spent(
            shares.iter(),
            std::iter::empty(),
            NumberOfNodes::from(13),
            1,
        );
        assert_eq!(spent, Cycles::new(600 + 5_722_470 + 3_276_000));
    }

    #[test]
    fn flexible_initial_spent_adds_only_the_spends_of_extra_shares() {
        // Same K = 3 shares and min_responses = 1 as above, plus two extra
        // shares. Their responses are not delivered, so despite their sizes they
        // add neither consensus cost nor extra-response cost — only their
        // spends:
        //   extra_spent_sum = 1_000 + 2_000 = 3_000
        let shares = [share(0, 10, 100), share(1, 20, 200), share(2, 30, 300)];
        let extra_shares = [share(3, 40, 1_000), share(4, 50, 2_000)];
        let spent = flexible_initial_spent(
            shares.iter(),
            extra_shares.iter(),
            NumberOfNodes::from(13),
            1,
        );
        assert_eq!(spent, Cycles::new(600 + 5_722_470 + 3_276_000 + 3_000));
    }

    #[test]
    fn flexible_initial_spent_at_min_responses_has_no_extra_cost() {
        // K == min_responses == 2, so extra_responses = 0 and extra_cost = 0.
        //   spent_sum      = 100 + 200                     = 300
        //   size_term      = (181+10) + (181+20)           = 392
        //   consensus_cost = 9_490 * 392                   = 3_720_080
        let shares = [share(0, 10, 100), share(1, 20, 200)];
        let spent = flexible_initial_spent(
            shares.iter(),
            std::iter::empty(),
            NumberOfNodes::from(13),
            2,
        );
        assert_eq!(spent, Cycles::new(300 + 3_720_080));
    }

    #[test]
    fn flexible_initial_spent_does_not_count_extra_shares_as_extra_responses() {
        // K == min_responses == 2 as above, plus an extra share: the extra share
        // must not push `K` beyond `min_responses`, so extra_cost stays 0 and
        // only the extra share's spend of 500 is added.
        let shares = [share(0, 10, 100), share(1, 20, 200)];
        let extra_shares = [share(2, 30, 500)];
        let spent = flexible_initial_spent(
            shares.iter(),
            extra_shares.iter(),
            NumberOfNodes::from(13),
            2,
        );
        assert_eq!(spent, Cycles::new(300 + 3_720_080 + 500));
    }

    #[test]
    fn flexible_initial_spent_below_min_responses_does_not_underflow() {
        // K = 1 < min_responses = 3: extra_responses saturates to 0 (no panic),
        // so only the single receipt and its consensus cost are charged.
        //   consensus_cost = 9_490 * (181 + 30) = 9_490 * 211 = 2_002_390
        let shares = [share(0, 30, 500)];
        let spent = flexible_initial_spent(
            shares.iter(),
            std::iter::empty(),
            NumberOfNodes::from(13),
            3,
        );
        assert_eq!(spent, Cycles::new(500 + 2_002_390));
    }

    #[test]
    fn min_flexible_consensus_cost_assumes_empty_bodies_for_unseen_replicas() {
        // Nothing seen yet, so every body a result might deliver is assumed empty
        // and costs only the 9_490 * 181 = 1_717_690 per-response overhead.
        const PER_RESPONSE: u128 = 1_717_690;
        let n = NumberOfNodes::from(13);
        let seen = || std::iter::empty();
        // A committee of 13 needing 7 responses delivers 7 bodies either way
        // (7 successes, or the 13 - 7 + 1 = 7 rejects of a `TooManyRejects`), and
        // neither is charged a fee for exceeding the 7 it needs.
        assert_eq!(
            min_flexible_consensus_cost(seen(), n, 13, 7),
            Some(Cycles::new(7 * PER_RESPONSE))
        );
        // Needing just one response, a single successful body is the cheapest of
        // the two; the 4 rejects proving the error would cost far more.
        assert_eq!(
            min_flexible_consensus_cost(seen(), n, 4, 1),
            Some(Cycles::new(PER_RESPONSE))
        );
        // Needing all four, a single reject already makes the outcall fail, so one
        // body suffices here too — and it is not an "extra" response, so no fee.
        assert_eq!(
            min_flexible_consensus_cost(seen(), n, 4, 4),
            Some(Cycles::new(PER_RESPONSE))
        );
        // A (degenerate) `min_responses` of zero is delivered by an empty group,
        // which genuinely costs nothing.
        assert_eq!(
            min_flexible_consensus_cost(seen(), n, 4, 0),
            Some(Cycles::zero())
        );
    }

    #[test]
    fn min_flexible_consensus_cost_counts_the_smallest_bodies_it_must_deliver() {
        // A committee of 4 needing 2 responses, of which 3 have been seen, so one
        // replica is still unseen and may yet produce an empty body. The group
        // therefore has to take just one body out of those seen — the smallest:
        //   size_term = (181 + 1_000) + 181  = 1_362
        //   cost      = 9_490 * 1_362        = 12_925_380
        // The `TooManyRejects` branch needs 4 - 2 + 1 = 3 rejects, which the one
        // unseen replica can no longer supply, so it is out of reach and ignored.
        let n = NumberOfNodes::from(13);
        // Deliberately not in ascending order, so that taking the smallest is not the
        // same as taking the first.
        let seen = [share(0, 3_000, 0), share(1, 1_000, 0), share(2, 2_000, 0)];
        assert_eq!(
            min_flexible_consensus_cost(seen.iter(), n, 4, 2),
            Some(Cycles::new(12_925_380))
        );
    }

    #[test]
    fn min_flexible_consensus_cost_includes_the_fee_of_the_rejects_proving_an_error() {
        // The mirror image: 3 of a committee of 4 have rejected and 2 responses are
        // needed, so a group of successful responses is out of reach and only the
        // `TooManyRejects` error remains. It delivers 4 - 2 + 1 = 3 rejects, two of
        // which have to come from those seen — the two smallest — and pays the fee for
        // the one response it delivers beyond `min_responses`:
        //   size_term = (181 + 50) + (181 + 100) + 181 = 693
        //   cost      = 9_490 * 693                    = 6_576_570
        //   fee       = 13 * (2_000 * 13 + 100_000)    = 1_638_000
        let n = NumberOfNodes::from(13);
        // Distinct sizes, and not in ascending order, so that taking the two smallest
        // is not the same as taking the first two.
        let seen = [
            reject_share(0, 5_000, 0),
            reject_share(1, 50, 0),
            reject_share(2, 100, 0),
        ];
        assert_eq!(
            min_flexible_consensus_cost(seen.iter(), n, 4, 2),
            Some(Cycles::new(6_576_570 + 1_638_000))
        );
    }

    #[test]
    fn min_flexible_consensus_cost_is_none_when_no_result_can_be_delivered() {
        // A committee of 4 that has all responded successfully, but needs 10
        // responses: neither the 10 successes nor a reject can still turn up, so
        // there is no body left whose cost there would be to bound.
        let n = NumberOfNodes::from(13);
        let seen = [
            share(0, 10, 0),
            share(1, 10, 0),
            share(2, 10, 0),
            share(3, 10, 0),
        ];
        assert_eq!(min_flexible_consensus_cost(seen.iter(), n, 4, 10), None);
    }

    #[test]
    fn min_flexible_consensus_cost_is_tight_once_the_whole_committee_is_seen() {
        // With nothing left unseen the bound is no longer an estimate: it is exactly
        // what the cheapest deliverable group costs, namely the two smallest of the
        // four responses.
        let n = NumberOfNodes::from(13);
        let seen = [
            share(0, 1_000, 7),
            share(1, 2_000, 11),
            share(2, 3_000, 13),
            share(3, 4_000, 17),
        ];
        let bound = min_flexible_consensus_cost(seen.iter(), n, 4, 2).expect("a bound exists");
        // The spends are not part of the bound, so they are subtracted from the
        // group's collective spend before comparing.
        let cheapest = flexible_initial_spent(seen[..2].iter(), std::iter::empty(), n, 2)
            - Cycles::new(7 + 11);
        assert_eq!(bound, cheapest);
        // And it stays a bound for the groups that deliver more, or larger, bodies.
        for delivered in 2..=4 {
            let spends: u128 = seen[..delivered]
                .iter()
                .map(|s| s.content.spent().get())
                .sum();
            let spend = flexible_initial_spent(seen[..delivered].iter(), std::iter::empty(), n, 2)
                - Cycles::new(spends);
            assert!(
                bound <= spend,
                "bound exceeds the cost of {delivered} responses"
            );
        }
    }

    #[test]
    fn min_non_flexible_consensus_cost_is_zero_while_another_response_can_still_win() {
        // A committee of 13 tolerating 4 faults, so 9 have to agree.
        let n = NumberOfNodes::from(13);
        let (committee, threshold) = (13, 9);
        let votes: Vec<_> = (0..13).map(|i| share(i, 1_000, 0)).collect();

        // With 4 shares for a response of non-zero size (thus cost), the remaining 9 unseen
        // shares may all be for a response of size 0, so the cheapest deliverable response is still free.
        assert_eq!(
            min_non_flexible_consensus_cost(votes[..4].iter(), n, committee, threshold),
            Some(Cycles::zero())
        );
        // One more share for the non-zero size response, and a zero size response may no longer
        // reach majority: the cheapest deliverable response is now the one with non-zero size.
        assert_eq!(
            min_non_flexible_consensus_cost(votes[..5].iter(), n, committee, threshold),
            Some(Cycles::new(9_490_000))
        );
    }

    #[test]
    fn min_non_flexible_consensus_cost_pins_a_non_replicated_response_at_once() {
        let n = NumberOfNodes::from(13);
        // Nothing seen: the designated replica may still return an empty body.
        assert_eq!(
            min_non_flexible_consensus_cost(std::iter::empty(), n, 1, 1),
            Some(Cycles::zero())
        );
        assert_eq!(
            min_non_flexible_consensus_cost(std::iter::once(&share(0, 1_000, 0)), n, 1, 1),
            Some(Cycles::new(9_490_000))
        );
    }

    #[test]
    fn min_non_flexible_consensus_cost_is_none_when_no_response_can_reach_the_threshold() {
        let n = NumberOfNodes::from(13);
        // Two camps of 5 out of 13, with 3 unseen: neither camp can reach 9, and the 3
        // unseen cannot carry a third response there either.
        let split: Vec<_> = (0..5)
            .map(|i| share(i, 1_000, 0))
            .chain((5..10).map(|i| share(i, 2_000, 0)))
            .collect();
        assert_eq!(
            min_non_flexible_consensus_cost(split.iter(), n, 13, 9),
            None
        );
    }

    #[test]
    fn flexible_initial_spent_empty_is_zero() {
        let spent = flexible_initial_spent(
            std::iter::empty(),
            std::iter::empty(),
            NumberOfNodes::from(13),
            0,
        );
        assert_eq!(spent, Cycles::zero());
    }

    #[test]
    fn max_downloaded_bytes_recovers_the_size_the_network_fee_priced() {
        for size in [0, 1, 49, 50, 51, 1_000, 2_000_000, u64::MAX] {
            let size = NumBytes::from(size);
            assert_eq!(
                max_downloaded_bytes(network_usage_fee(size, Duration::ZERO)),
                size,
                "a response of {size} does not survive the round trip"
            );
        }
    }

    #[test]
    fn max_downloaded_bytes_is_the_largest_size_a_budget_affords() {
        for budget in [0, 1, 49, 50, 51, 1_000, 100_000_000].map(Cycles::new) {
            let size = max_downloaded_bytes(budget);
            assert!(
                network_usage_fee(size, Duration::ZERO) <= budget,
                "a response of {size} costs more than the budget {budget}"
            );
            assert!(
                network_usage_fee(NumBytes::from(size.get() + 1), Duration::ZERO) > budget,
                "budget {budget}: {size} is not the largest affordable response"
            );
        }
        // Except past what `NumBytes` can hold, where the size is bounded by the
        // type rather than by the budget: a larger response would still be
        // affordable, there just isn't one.
        assert_eq!(
            max_downloaded_bytes(Cycles::new(u128::MAX)),
            NumBytes::from(u64::MAX)
        );
        // Exact whenever the budget is a whole number of bytes.
        assert_eq!(
            network_usage_fee(max_downloaded_bytes(Cycles::new(1_000)), Duration::ZERO),
            Cycles::new(1_000)
        );
    }

    #[test]
    fn max_transform_instructions_is_the_largest_transform_a_budget_affords() {
        for budget in [0, 1, 12, 13, 14, 1_000, 5_000_000_000].map(Cycles::new) {
            let instructions = max_transform_instructions(budget);
            assert_eq!(
                transform_usage_fee(instructions),
                budget,
                "budget {budget} is not spent exactly by {instructions} instructions"
            );
            assert!(
                transform_usage_fee(NumInstructions::from(instructions.get() + 1)) > budget,
                "budget {budget}: {instructions} is not the largest affordable transform"
            );
        }
        // Except once the instruction count saturates: past what `NumInstructions`
        // can hold the budget is no longer spent exactly, only never exceeded.
        let saturated = max_transform_instructions(Cycles::new(u128::MAX));
        assert_eq!(saturated, NumInstructions::from(u64::MAX));
        assert!(transform_usage_fee(saturated) < Cycles::new(u128::MAX));
    }

    #[test]
    fn max_response_time_is_the_longest_response_a_budget_affords() {
        for budget in [0, 1, 299, 300, 301, 18_000_000, 100_000_000].map(Cycles::new) {
            let time = max_response_time(budget);
            assert!(
                network_usage_fee(NumBytes::from(0), time) <= budget,
                "a response taking {time:?} costs more than the budget {budget}"
            );
            assert!(
                network_usage_fee(NumBytes::from(0), time + Duration::from_millis(1)) > budget,
                "budget {budget}: {time:?} is not the longest affordable response"
            );
        }
        // 18_000_000 is the latency term every worst case is priced with, and it
        // buys exactly the 60 s cap — so an allowance covering the worst case is
        // never rationed below the full response time.
        assert_eq!(
            max_response_time(Cycles::new(18_000_000)),
            MAX_RESPONSE_TIME
        );
        // Past what a `Duration` of whole milliseconds can hold, the time is bounded
        // by that conversion rather than by the budget.
        assert_eq!(
            max_response_time(Cycles::new(u128::MAX)),
            Duration::from_millis(u64::MAX)
        );
    }

    /// The terms shared by every worst case at N = 13: the 60 s latency cap and the
    /// full 5 B-instruction query limit.
    const MAX_LATENCY_FEE: u128 = 300 * 60_000; // 18_000_000
    const MAX_TRANSFORM_FEE: u128 = 5_000_000_000 / 13; // 384_615_384
    /// The consensus fee at N = 13 of delivering the largest response a *fully*
    /// replicated outcall without a response limit may have, i.e.
    /// `MAX_CANISTER_HTTP_RESPONSE_BYTES + CANDID_OVERHEAD_RESERVE_BYTES`. Its
    /// allowance is split across all 13 replicas while only the `threshold` of 9 that
    /// agree on the response contribute their share of the fee, so the plain
    /// `9_490 * 2_001_024 = 18_989_717_760` is scaled to
    /// `ceil(9_490 * 2_001_024 / 9) * 13`.
    const MAX_FULLY_REPLICATED_CONSENSUS_FEE: u128 = 27_429_592_320;
    /// A 1 KB response limit is delivered as at most `1_000 + 1_024` bytes, which at
    /// N = 13 costs `50 * 2_024 * 13` to gossip and `9_490 * 2_024` to put in a block.
    const KB_LIMIT_GOSSIP_FEE: u128 = 1_315_600;
    const KB_LIMIT_CONSENSUS_FEE: u128 = 19_207_760;

    /// The resource usage the `total_fee` tests below price, and the config they price
    /// it on: a 100-byte request whose 1_000-byte response arrived in 2_000 ms, was
    /// transformed with 26 instructions and ended up `transformed_bytes` bytes, at
    /// N = 13.
    fn total_fee_with_transformed(
        replication_kind: ReplicationKind,
        transformed_bytes: u64,
    ) -> CompoundCycles<HTTPOutcalls> {
        total_fee(
            NumBytes::from(100),
            Duration::from_millis(2_000),
            NumBytes::from(1_000),
            NumInstructions::from(26),
            NumBytes::from(transformed_bytes),
            replication_kind,
            CyclesAccountManagerSubnetConfig::new(13, CanisterCyclesCostSchedule::Normal, 13),
        )
    }

    /// [`total_fee_with_transformed`] of a 2_000-byte transformed response.
    fn total_fee_of(replication_kind: ReplicationKind) -> CompoundCycles<HTTPOutcalls> {
        total_fee_with_transformed(replication_kind, 2_000)
    }

    /// `50 * 1_000 + 300 * 2_000 + 26 / 13`, the network and transform fees of a
    /// single replica for the usage priced by [`total_fee_of`].
    const USAGE_FEE: u128 = 650_002;

    #[test]
    fn total_fee_fully_replicated_charges_no_gossip() {
        // All 13 replicas produce the same response, whose dissemination is charged
        // as a consensus fee rather than a per-replica gossip fee.
        //   base fee    = 13 * (1_000_000 + 50*100 + 140_000*13 + 800*13*13)
        //                                                          = 38_482_600
        //   per replica = 13 * 650_002                              =  8_450_026
        //   consensus   = ceil(9_490 * 2_000 / 9) * 13              = 27_415_557
        let fee = total_fee_of(ReplicationKind::FullyReplicated);
        assert_eq!(
            fee.real(),
            Cycles::new(38_482_600 + 13 * USAGE_FEE + 27_415_557)
        );

        // The parts add up to the formula reported by `ic0.cost_http_request_v2`, with
        // `(10 * N + 600) * N` as the consensus fee's per-transformed-byte coefficient,
        // cut into the share each of the `threshold` contributors must cover and
        // multiplied back up by the `N` replicas the reserve is split across.
        let n = 13_u128;
        let threshold = 9_u128; // canister_http_threshold(13)
        assert_eq!(
            fee.real(),
            Cycles::new(
                n * (1_000_000
                    + 50 * 100
                    + 140_000 * n
                    + 800 * n * n
                    + 50 * 1_000
                    + 300 * 2_000
                    + 26 / 13)
                    + ((10 * n + 600) * n * 2_000).div_ceil(threshold) * n
            )
        );
    }

    #[test]
    fn total_fee_non_replicated_charges_one_replica_that_gossips() {
        // A single replica performs the outcall and gossips its response to all 13
        // nodes; the base fee is the flexible one with `min_responses = 1`.
        //   base fee    = 13 * (1_000_000 + 50*100 + 90_000*13 + 2_000*13 + 100_000)
        //                                                          = 29_913_000
        //   per replica = 1 * (650_002 + 50*2_000*13)              =  1_950_002
        //   consensus   = 9_490 * 2_000                            = 18_980_000
        let fee = total_fee_of(ReplicationKind::NonReplicated);
        assert_eq!(
            fee.real(),
            Cycles::new(29_913_000 + (USAGE_FEE + 50 * 2_000 * 13) + 18_980_000)
        );
    }

    #[test]
    fn total_fee_flexible_charges_every_delegated_replica_and_response() {
        // 3 delegated replicas, 2 of whose responses suffice, so all 3 perform the
        // outcall and gossip their own response, and up to 3 responses are delivered
        // — one of them beyond `min_responses`. The consensus term is priced for a
        // response from every one of the 3, which is also what a `TooManyRejects`
        // delivers here, so the same fee funds either result.
        //   base fee    = 13 * (1_000_000 + 50*100 + 90_000*13 + 2_000*13*2 + 100_000*2)
        //                                                          = 31_551_000
        //   per replica = 3 * (650_002 + 50*2_000*13)              =  5_850_006
        //   consensus   = 9_490 * 3 * (181 + 2_000)                = 62_093_070
        //   extra resp. = (3 - 2) * 13 * (2_000*13 + 100_000)      =  1_638_000
        let fee = total_fee_of(ReplicationKind::Flexible {
            total_requests: 3,
            min_responses: 2,
            max_responses: 3,
        });
        assert_eq!(
            fee.real(),
            Cycles::new(31_551_000 + 3 * (USAGE_FEE + 50 * 2_000 * 13) + 62_093_070 + 1_638_000)
        );

        // Asking for fewer responses than there are delegated replicas does not lower
        // the price: every one of them is still priced for delivering a response, since
        // each holds only a third of the fee.
        assert_eq!(
            total_fee_of(ReplicationKind::Flexible {
                total_requests: 3,
                min_responses: 2,
                max_responses: 2,
            })
            .real(),
            fee.real()
        );
    }

    #[test]
    fn total_fee_prices_every_response_for_at_least_a_maximally_large_reject() {
        // Whatever response size is asked for, a reject of up to 1_025 bytes may be
        // delivered in its place, so both the gossip and the consensus term are priced
        // for at least that many bytes.
        assert_eq!(MAX_CANISTER_HTTP_REJECT_BYTES, 1_025);
        for replication_kind in [
            ReplicationKind::FullyReplicated,
            ReplicationKind::NonReplicated,
            ReplicationKind::Flexible {
                total_requests: 3,
                min_responses: 2,
                max_responses: 3,
            },
        ] {
            let at_the_floor =
                total_fee_with_transformed(replication_kind, MAX_CANISTER_HTTP_REJECT_BYTES);
            // Anything below the reject size is priced like the reject size ...
            for transformed_bytes in [0, 1, 500, MAX_CANISTER_HTTP_REJECT_BYTES - 1] {
                assert_eq!(
                    total_fee_with_transformed(replication_kind, transformed_bytes).real(),
                    at_the_floor.real(),
                    "{replication_kind:?} at {transformed_bytes} transformed bytes"
                );
            }
            // ... and anything above it for its own size.
            assert!(
                total_fee_with_transformed(replication_kind, MAX_CANISTER_HTTP_REJECT_BYTES + 1)
                    .real()
                    > at_the_floor.real(),
                "{replication_kind:?}"
            );
        }

        // The floor in the concrete: a fully-replicated outcall whose transformed
        // response is 100 bytes is charged the consensus fee of 1_025 bytes.
        //   base fee    = 38_482_600
        //   per replica = 13 * 650_002                             =  8_450_026
        //   consensus   = ceil(9_490 * 1_025 / 9) * 13             = 14_050_478
        assert_eq!(
            total_fee_with_transformed(ReplicationKind::FullyReplicated, 100).real(),
            Cycles::new(38_482_600 + 13 * USAGE_FEE + 14_050_478)
        );
    }

    #[test]
    fn max_consensus_fee_flexible_prices_a_response_from_every_delegated_replica() {
        // A committee of 13 of which a single response suffices. Only one response is
        // delivered, but each replica holds just a thirteenth of the fee, so the fee is
        // priced for all 13 of them — which is also what a `TooManyRejects` delivers,
        // 12 responses more than the one that was asked for.
        let n = NumberOfNodes::from(13);
        let kind = ReplicationKind::Flexible {
            total_requests: 13,
            min_responses: 1,
            max_responses: 1,
        };
        //   13 responses of 2 MB = 9_490 * 13 * (181 + 2_000_000)  = 246_762_329_970
        //   extra responses      = (13 - 1) * 13 * (2_000*13 + 100_000)
        //                                                          =      19_656_000
        assert_eq!(
            max_consensus_fee(kind, NumBytes::from(MAX_CANISTER_HTTP_RESPONSE_BYTES), n),
            Cycles::new(246_762_329_970 + 19_656_000)
        );
        // For a small response the floor applies, so the 13 are reject-sized:
        //   13 rejects of 1_025  = 9_490 * 13 * (181 + 1_025)       =    148_784_220
        //   extra responses                                         =     19_656_000
        assert_eq!(
            max_consensus_fee(kind, NumBytes::from(1_000), n),
            Cycles::new(148_784_220 + 19_656_000)
        );
        // If `total_requests` is 1, the fee consists of a single
        // response of at least the max reject size.
        assert_eq!(
            max_consensus_fee(
                ReplicationKind::Flexible {
                    total_requests: 1,
                    min_responses: 1,
                    max_responses: 1,
                },
                NumBytes::from(1_000),
                n
            ),
            Cycles::new(9_490 * (181 + 1_025))
        );
    }

    #[test]
    fn max_consensus_fee_flexible_is_free_for_fire_and_forget() {
        // A fire-and-forget outcall asks for no responses at all, so consensus never puts
        // one in a block and there is nothing to reserve a consensus fee for.
        let n = NumberOfNodes::from(13);
        let fire_and_forget = |total_requests| ReplicationKind::Flexible {
            total_requests,
            min_responses: 0,
            max_responses: 0,
        };
        for total_requests in [1, 5, 13] {
            assert_eq!(
                max_consensus_fee(
                    fire_and_forget(total_requests),
                    NumBytes::from(MAX_CANISTER_HTTP_RESPONSE_BYTES),
                    n
                ),
                Cycles::zero(),
                "{total_requests} delegated replicas"
            );
        }
        // Asking for even a single response is not free, though ...
        assert!(
            max_consensus_fee(
                ReplicationKind::Flexible {
                    total_requests: 13,
                    min_responses: 0,
                    max_responses: 1,
                },
                NumBytes::from(MAX_CANISTER_HTTP_RESPONSE_BYTES),
                n
            ) > Cycles::zero()
        );
        // ... and neither is the outcall itself: its replicas still perform the request
        // and gossip their shares, they just never have a response delivered.
        assert!(
            usage_fee(
                fire_and_forget(13),
                MAX_RESPONSE_TIME,
                NumBytes::from(1_000),
                NumInstructions::from(26),
                NumBytes::from(2_000),
                n,
            ) > Cycles::zero()
        );
    }

    /// Asserts that for every result an outcall with the given `replication_kind` and
    /// transformed response size could deliver, the replicas that produced *that result*
    /// hold enough of the priced consensus fee — [`max_consensus_fee`] — to pay what
    /// delivering it charges, as [`flexible_initial_spent`] /
    /// [`non_flexible_initial_spent`] compute it.
    ///
    /// This is the property that makes a result deliverable as soon as it exists, rather
    /// than only once replicas that contributed nothing to it have reported their
    /// allowances as well.
    fn assert_contributors_cover_every_result(
        replication_kind: ReplicationKind,
        transformed_bytes: u64,
        subnet_size: NumberOfNodes,
    ) {
        let priced = max_consensus_fee(
            replication_kind,
            NumBytes::from(transformed_bytes),
            subnet_size,
        );
        let nodes = replication_kind.node_count(subnet_size) as u128;
        let share_of_fee = priced.get().div_ceil(nodes);
        let assert_covers = |contributors: usize, charged: Cycles, what: &str| {
            let held = Cycles::new(share_of_fee.saturating_mul(contributors as u128));
            assert!(
                held >= charged,
                "{replication_kind:?} at {transformed_bytes} transformed bytes, N = {subnet_size}: \
                 the {contributors} replicas behind {what} hold {held} of the {priced} priced, \
                 which does not cover the {charged} charged"
            );
        };

        match replication_kind {
            ReplicationKind::FullyReplicated | ReplicationKind::NonReplicated => {
                let min_contributors = match replication_kind {
                    ReplicationKind::NonReplicated => 1,
                    // The threshold of agreeing signers a response proof needs, i.e. the
                    // fewest replicas a delivered response can come from.
                    ReplicationKind::FullyReplicated => {
                        canister_http_threshold(replication_kind.node_count(subnet_size))
                    }
                    ReplicationKind::Flexible { .. } => unreachable!(),
                };
                for content_size in [transformed_bytes, MAX_CANISTER_HTTP_REJECT_BYTES] {
                    let proof = proof(content_size as u32, &vec![0; min_contributors]);
                    assert_covers(
                        min_contributors,
                        non_flexible_initial_spent(&proof, subnet_size),
                        &format!("a response of {content_size} bytes"),
                    );
                }
            }
            ReplicationKind::Flexible {
                total_requests,
                min_responses,
                max_responses,
            } => {
                // The responses asked for: all `max_responses` of them ...
                let asked_for_max: Vec<_> = (0..max_responses)
                    .map(|i| share(i as u64, transformed_bytes as u32, 0))
                    .collect();
                assert_covers(
                    max_responses as usize,
                    flexible_initial_spent(
                        asked_for_max.iter(),
                        std::iter::empty(),
                        subnet_size,
                        min_responses,
                    ),
                    &format!("{max_responses} responses of {transformed_bytes} bytes"),
                );
                // ... But allows also only `min_responses` of them ...
                let asked_for_min: Vec<_> = (0..min_responses)
                    .map(|i| share(i as u64, transformed_bytes as u32, 0))
                    .collect();
                assert_covers(
                    min_responses as usize,
                    flexible_initial_spent(
                        asked_for_min.iter(),
                        std::iter::empty(),
                        subnet_size,
                        min_responses,
                    ),
                    &format!("{min_responses} responses of {transformed_bytes} bytes"),
                );
                // ... or a `TooManyRejects` in which every committee member rejected,
                // each with a maximally large reject. Unreachable when no responses are
                // required at all: rejecting can never keep an outcall from reaching
                // `min_responses` of them if that is zero.
                if min_responses > 0 {
                    let rejects: Vec<_> = (0..total_requests)
                        .map(|i| reject_share(i as u64, MAX_CANISTER_HTTP_REJECT_BYTES as u32, 0))
                        .collect();
                    assert_covers(
                        total_requests as usize,
                        flexible_initial_spent(
                            rejects.iter(),
                            std::iter::empty(),
                            subnet_size,
                            min_responses,
                        ),
                        &format!("a TooManyRejects of {total_requests} rejects"),
                    );
                }
            }
        }
    }

    #[test]
    fn the_replicas_behind_a_result_cover_its_consensus_fee() {
        const SIZES: [u64; 5] = [
            0,
            1_000,
            MAX_CANISTER_HTTP_REJECT_BYTES,
            100_000,
            MAX_CANISTER_HTTP_RESPONSE_BYTES,
        ];
        for subnet_size in [1, 4, 7, 13, 34, 40].map(NumberOfNodes::from) {
            for transformed_bytes in SIZES {
                for replication_kind in [
                    ReplicationKind::FullyReplicated,
                    ReplicationKind::NonReplicated,
                ] {
                    assert_contributors_cover_every_result(
                        replication_kind,
                        transformed_bytes,
                        subnet_size,
                    );
                }
                for total_requests in 1..=subnet_size.get() {
                    for min_responses in 0..=total_requests {
                        for max_responses in min_responses..=total_requests {
                            assert_contributors_cover_every_result(
                                ReplicationKind::Flexible {
                                    total_requests,
                                    min_responses,
                                    max_responses,
                                },
                                transformed_bytes,
                                subnet_size,
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn usage_fee_is_a_whole_number_of_allowances() {
        // The usage fee is split into the allowances, so it should be a whole number of them.
        for subnet_size in [1, 4, 7, 13, 34, 40].map(NumberOfNodes::from) {
            for transformed_bytes in [
                0,
                MAX_CANISTER_HTTP_REJECT_BYTES,
                max_http_outcall_response_size(None),
            ] {
                let assert_whole = |replication_kind: ReplicationKind| {
                    let priced = usage_fee(
                        replication_kind,
                        Duration::from_millis(2_000),
                        NumBytes::from(1_000),
                        NumInstructions::from(26),
                        NumBytes::from(transformed_bytes),
                        subnet_size,
                    );
                    let nodes = replication_kind.node_count(subnet_size) as u128;
                    assert_eq!(
                        priced.get() % nodes,
                        0,
                        "{replication_kind:?} at {transformed_bytes} transformed bytes, \
                         N = {subnet_size}: the priced {priced} is not a whole number of \
                         the {nodes} allowances it is split into"
                    );
                };
                assert_whole(ReplicationKind::FullyReplicated);
                assert_whole(ReplicationKind::NonReplicated);
                for total_requests in 1..=subnet_size.get() {
                    for min_responses in 0..=total_requests {
                        for max_responses in [min_responses, total_requests] {
                            assert_whole(ReplicationKind::Flexible {
                                total_requests,
                                min_responses,
                                max_responses,
                            });
                        }
                    }
                }
            }
        }
    }

    /// [`total_fee`] of the largest outcall a canister can ask the price of, with the
    /// given `replication_kind`: every byte and instruction count at `u64::MAX`, and
    /// (where the kind has them) every response count at `u32::MAX`.
    fn total_fee_of_maximal_params(
        replication_kind: ReplicationKind,
        subnet_size: usize,
    ) -> Cycles {
        total_fee(
            NumBytes::from(u64::MAX),
            Duration::from_millis(u64::MAX),
            NumBytes::from(u64::MAX),
            NumInstructions::from(u64::MAX),
            NumBytes::from(u64::MAX),
            replication_kind,
            CyclesAccountManagerSubnetConfig::new(
                subnet_size,
                CanisterCyclesCostSchedule::Normal,
                13,
            ),
        )
        .real()
    }

    #[test]
    fn total_fee_of_maximal_params_saturates_instead_of_overflowing() {
        for replication_kind in [
            ReplicationKind::FullyReplicated,
            ReplicationKind::NonReplicated,
            ReplicationKind::Flexible {
                total_requests: u32::MAX,
                min_responses: u32::MAX,
                max_responses: u32::MAX,
            },
        ] {
            // The cost doesn't overflow on realistic subnet sizes
            for subnet_size in [0, 1, 13, 40, 1_000] {
                let fee = total_fee_of_maximal_params(replication_kind, subnet_size);
                assert!(
                    fee < Cycles::new(u128::MAX),
                    "{replication_kind:?} at subnet size {subnet_size}: price saturated at {fee}"
                );
            }
            // The cost saturates at the maximum value
            assert_eq!(
                total_fee_of_maximal_params(replication_kind, u32::MAX as usize),
                Cycles::new(u128::MAX),
                "{replication_kind:?}"
            );
        }
    }

    #[test]
    fn total_fee_is_zero_on_a_free_subnet() {
        let fee = total_fee(
            NumBytes::from(100),
            Duration::from_millis(2_000),
            NumBytes::from(1_000),
            NumInstructions::from(26),
            NumBytes::from(500),
            ReplicationKind::FullyReplicated,
            CyclesAccountManagerSubnetConfig::new(13, CanisterCyclesCostSchedule::Free, 13),
        );
        assert_eq!(fee.real(), Cycles::zero());
        // The nominal cost is still reported.
        assert!(!fee.nominal().is_zero());
    }

    #[test]
    fn max_usage_fee_fully_replicated() {
        // A fully-replicated outcall at N = 13 without a response limit, so the
        // download term uses the full 2 MB and the response is delivered with the
        // Candid reserve on top of it. All 13 replicas perform it, and their single
        // agreed-on response is disseminated by consensus rather than gossiped.
        //   per replica = 50 * 2_000_000                      =    100_000_000
        //               + latency                             =     18_000_000
        //               + transform                           =    384_615_384
        //   consensus   = ceil(9_490 * 2_001_024 / 9) * 13    = 27_429_592_320
        let per_replica = 100_000_000 + MAX_LATENCY_FEE + MAX_TRANSFORM_FEE;
        assert_eq!(
            max_usage_fee(&Replication::FullyReplicated, None, NumberOfNodes::from(13)),
            Cycles::new(13 * per_replica + MAX_FULLY_REPLICATED_CONSENSUS_FEE)
        );
    }

    #[test]
    fn max_usage_fee_non_replicated_charges_one_replica_that_gossips() {
        // A non-replicated outcall with a 1 KB response limit at N = 13: a single
        // replica performs it and gossips the response it delivers — at most the 1 KB
        // asked for plus the Candid reserve — to the whole subnet.
        //   per replica = 50 * 1_000                     =         50_000
        //               + latency                        =     18_000_000
        //               + transform                      =    384_615_384
        //               + gossip 50 * 2_024 * 13         =      1_315_600
        //   consensus   = 9_490 * 2_024                  =     19_207_760
        let per_replica = 50_000 + MAX_LATENCY_FEE + MAX_TRANSFORM_FEE + KB_LIMIT_GOSSIP_FEE;
        assert_eq!(
            max_usage_fee(
                &Replication::NonReplicated(node(0)),
                Some(NumBytes::from(1_000)),
                NumberOfNodes::from(13)
            ),
            Cycles::new(per_replica + KB_LIMIT_CONSENSUS_FEE)
        );
    }

    #[test]
    fn max_usage_fee_flexible_covers_all_delegated_replicas_and_responses() {
        // A flexible outcall with a committee of 3 (2 of which suffice) and a 1 KB
        // response limit at N = 13: all 3 replicas perform it and gossip their own
        // response, and all 3 are delivered, one of them beyond `min_responses`.
        //   per replica    = 50_000 + latency + transform + gossip(1_315_600)
        //   consensus      = 9_490 * 3 * (181 + 2_024)                 = 62_776_350
        //   extra response = (3 - 2) * 13 * (2_000 * 13 + 100_000)     =  1_638_000
        let per_replica = 50_000 + MAX_LATENCY_FEE + MAX_TRANSFORM_FEE + KB_LIMIT_GOSSIP_FEE;
        let consensus = 9_490 * 3 * (181 + 2_024) + 13 * (2_000 * 13 + 100_000);
        let replication = Replication::Flexible {
            committee: (0..3).map(node).collect(),
            min_responses: 2,
            max_responses: 3,
        };
        assert_eq!(
            max_usage_fee(
                &replication,
                Some(NumBytes::from(1_000)),
                NumberOfNodes::from(13)
            ),
            Cycles::new(3 * per_replica + consensus)
        );
    }

    #[test]
    fn max_usage_fee_flexible_does_not_depend_on_max_responses() {
        // The consensus reserve is priced for a response from every delegated replica
        // rather than for the `max_responses` that are delivered, so that each replica's
        // allowance can cover its own response (see [`max_consensus_fee`]). Asking for
        // fewer responses back therefore does not make the outcall any cheaper.
        let subnet_size = NumberOfNodes::from(13);
        let reference = max_usage_fee(&flexible(7, 2, 7), None, subnet_size);
        for max_responses in 2..=7 {
            assert_eq!(
                max_usage_fee(&flexible(7, 2, max_responses), None, subnet_size),
                reference,
                "max_responses = {max_responses}"
            );
        }
    }

    #[test]
    fn max_usage_fee_is_a_whole_number_of_allowances_and_bounds_every_usage() {
        // The reported maximum is a multiple of the number of participating replicas, so
        // that splitting it into allowances loses nothing. It is [`usage_fee`] that rounds
        // up to one (see [`usage_fee_is_a_whole_number_of_allowances`]), so the maximum
        // adds nothing of its own on top of the worst case it reports.
        for subnet_size in [1_u32, 4, 13, 34, 40].map(NumberOfNodes::from) {
            let flexible_replications = (1..=u64::from(subnet_size.get())).flat_map(|total| {
                (0..=total as u32).flat_map(move |min| {
                    (min..=total as u32).map(move |max| flexible(total, min, max))
                })
            });
            for replication in [
                Replication::FullyReplicated,
                Replication::NonReplicated(node(0)),
            ]
            .into_iter()
            .chain(flexible_replications)
            {
                let replication_kind = replication.kind();
                let node_count = replication_kind.node_count(subnet_size) as u128;
                let reported = max_usage_fee(&replication, None, subnet_size);

                assert_eq!(
                    reported.get() % node_count,
                    0,
                    "{replication:?} on {subnet_size} nodes"
                );
                // The worst case reaches the reported maximum exactly, so it is not just an
                // upper bound but the one an outcall without a response limit can hit ...
                assert_eq!(
                    usage_fee(
                        replication_kind,
                        MAX_RESPONSE_TIME,
                        NumBytes::from(MAX_CANISTER_HTTP_RESPONSE_BYTES),
                        MAX_INSTRUCTIONS_PER_QUERY_MESSAGE,
                        NumBytes::from(max_http_outcall_response_size(None)),
                        subnet_size,
                    ),
                    reported,
                    "{replication:?} on {subnet_size} nodes"
                );
                // ... and nothing short of it is priced above it.
                for (roundtrip, raw_bytes, instructions, transformed_bytes) in [
                    (Duration::ZERO, 0, 0, 0),
                    (Duration::from_millis(1), 1, 1, 1),
                    (Duration::from_secs(30), 1_000_000, 2_500_000_000, 1_000_000),
                    (
                        MAX_RESPONSE_TIME,
                        MAX_CANISTER_HTTP_RESPONSE_BYTES,
                        MAX_INSTRUCTIONS_PER_QUERY_MESSAGE.get(),
                        max_http_outcall_response_size(None) - 1,
                    ),
                ] {
                    let usage = usage_fee(
                        replication_kind,
                        roundtrip,
                        NumBytes::from(raw_bytes),
                        NumInstructions::from(instructions),
                        NumBytes::from(transformed_bytes),
                        subnet_size,
                    );
                    assert!(
                        usage <= reported,
                        "{replication:?} on {subnet_size} nodes: the usage fee {usage} of a \
                     {raw_bytes}-byte response transformed into {transformed_bytes} bytes \
                     exceeds the reported maximum {reported}"
                    );
                }
            }
        }
    }
}
