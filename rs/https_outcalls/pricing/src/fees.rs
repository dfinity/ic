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
        CanisterHttpResponseProof, CanisterHttpResponseShare, MAX_CANISTER_HTTP_RESPONSE_BYTES,
        Replication, ReplicationKind,
    },
};
use ic_types_cycles::{CompoundCycles, Cycles, CyclesAccountManagerSubnetConfig, HTTPOutcalls};

use crate::MAX_RESPONSE_TIME;

// ============================ Base-fee constants ============================
// Charged up-front for every request by [`base_fee`].

const HTTP_REQUEST_BASE_FEE: u128 = 1_000_000;
const HTTP_REQUEST_PER_BYTE_FEE: u128 = 50;
const HTTP_REQUEST_FULLY_REPLICATED_PER_NODE_FEE: u128 = 140_000;
const HTTP_REQUEST_FULLY_REPLICATED_QUADRATIC_NODE_FEE: u128 = 800;
const HTTP_REQUEST_FLEXIBLE_PER_NODE_FEE: u128 = 90_000;
const HTTP_REQUEST_FLEXIBLE_PER_NODE_RESPONSE_CONSENSUS_FEE: u128 = 2_000;
const HTTP_REQUEST_FLEXIBLE_PER_RESPONSE_CONSENSUS_FEE: u128 = 100_000;

// ========================= Per-replica-fee constants =========================
// Charged as-you-go by the `PayAsYouGoTracker` in `payg.rs`, through the
// per-replica fee functions below.

pub(crate) const PER_DOWNLOADED_BYTE_FEE: u128 = 50;
pub(crate) const PER_RESPONSE_MS_FEE: u128 = 300;
/// HTTP outcalls are priced consistently against a reference subnet size of 13.
pub(crate) const TRANSFORM_INSTRUCTION_DIVISOR: u128 = 13;
pub(crate) const FLEXIBLE_PER_TRANSFORMED_BYTE_NODE_FEE: u128 = 50;

// ========================== Consensus-fee constants ==========================
// Charged for including the aggregated response in a block, via
// [`non_flexible_initial_spent`] / [`flexible_initial_spent`].

const CONSENSUS_PER_NODE_BYTE_FEE: u128 = 10;
const CONSENSUS_BYTE_FEE: u128 = 600;
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
        Cycles::new(base_fee_amount(
            request_size,
            replication.kind(),
            subnet_size_of(subnet_cycles_config),
        )),
        subnet_cycles_config.cost_schedule,
    )
}

/// The [`base_fee`], on a subnet of `subnet_size` nodes.
fn base_fee_amount(
    request_size: NumBytes,
    replication_kind: ReplicationKind,
    subnet_size: NumberOfNodes,
) -> u128 {
    let n = subnet_size.get() as u128;
    let request_bytes = request_size.get() as u128;
    let per_replica = match replication_kind {
        ReplicationKind::FullyReplicated => {
            HTTP_REQUEST_BASE_FEE
                + HTTP_REQUEST_PER_BYTE_FEE * request_bytes
                + HTTP_REQUEST_FULLY_REPLICATED_PER_NODE_FEE * n
                + HTTP_REQUEST_FULLY_REPLICATED_QUADRATIC_NODE_FEE * n * n
        }
        // Non-replicated is equivalent to flexible replication with min_responses = 1.
        ReplicationKind::NonReplicated => flexible_base_fee_per_replica(request_bytes, n, 1),
        ReplicationKind::Flexible { min_responses, .. } => {
            flexible_base_fee_per_replica(request_bytes, n, min_responses as u128)
        }
    };

    n * per_replica
}

/// The per-replica part of the base fee of a gossiping (flexible or
/// non-replicated) outcall of `request_bytes` bytes that requires
/// `min_responses` responses, on a subnet of `n` nodes.
fn flexible_base_fee_per_replica(request_bytes: u128, n: u128, min_responses: u128) -> u128 {
    HTTP_REQUEST_BASE_FEE
        + HTTP_REQUEST_PER_BYTE_FEE * request_bytes
        + HTTP_REQUEST_FLEXIBLE_PER_NODE_FEE * n
        + HTTP_REQUEST_FLEXIBLE_PER_NODE_RESPONSE_CONSENSUS_FEE * n * min_responses
        + HTTP_REQUEST_FLEXIBLE_PER_RESPONSE_CONSENSUS_FEE * min_responses
}

// ============================= Per-replica fees =============================
// The individual fees the `PayAsYouGoTracker` (see `payg.rs`) charges a replica
// as it performs the outcall.

/// The fee for downloading a response of `response_size` in `response_time`.
pub(crate) fn network_usage_fee(response_size: NumBytes, response_time: Duration) -> u128 {
    PER_DOWNLOADED_BYTE_FEE
        .saturating_mul(response_size.get() as u128)
        .saturating_add(PER_RESPONSE_MS_FEE.saturating_mul(response_time.as_millis()))
}

/// The fee for running the transform function for `instructions`.
pub(crate) fn transform_usage_fee(instructions: NumInstructions) -> u128 {
    (instructions.get() as u128) / TRANSFORM_INSTRUCTION_DIVISOR
}

/// The fee for gossiping a transformed response of `transformed_response_size` to
/// all `subnet_size` nodes of the subnet. Only gossiping (flexible and
/// non-replicated) outcalls are charged this; for fully-replicated ones,
/// disseminating the response is a consensus cost instead.
pub(crate) fn gossip_usage_fee(
    transformed_response_size: NumBytes,
    subnet_size: NumberOfNodes,
) -> u128 {
    FLEXIBLE_PER_TRANSFORMED_BYTE_NODE_FEE
        .saturating_mul(transformed_response_size.get() as u128)
        .saturating_mul(subnet_size.get() as u128)
}

// =============================== Consensus fee ===============================

/// The consensus fee for putting `response_bytes` many response bytes into a
/// block on a subnet of size `subnet_size`.
fn consensus_fee(response_bytes: u128, subnet_size: NumberOfNodes) -> Cycles {
    let n = subnet_size.get() as u128;
    Cycles::from(
        (CONSENSUS_PER_NODE_BYTE_FEE * n + CONSENSUS_BYTE_FEE)
            .saturating_mul(n)
            .saturating_mul(response_bytes),
    )
}

/// The additional consensus fee charged for `extra_responses` flexible responses
/// beyond the `min_responses` required to reach consensus.
fn flexible_extra_response_fee(extra_responses: u128, subnet_size: NumberOfNodes) -> Cycles {
    let n = subnet_size.get() as u128;
    Cycles::from(
        (HTTP_REQUEST_FLEXIBLE_PER_NODE_RESPONSE_CONSENSUS_FEE * n
            + HTTP_REQUEST_FLEXIBLE_PER_RESPONSE_CONSENSUS_FEE)
            .saturating_mul(n)
            .saturating_mul(extra_responses),
    )
}

// ================================= Total fee =================================

/// The total fee for an HTTP outcall of the given `replication_kind` that consumed
/// the given resources, i.e. the sum of all three parts of its price: the up-front
/// [`base_fee`], the per-replica fees of every replica attempting it, and the
/// consensus fee of putting the responses that are delivered into a block.
/// Used by canisters to estimate the cost of an outcall.
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
    let amount = Cycles::new(base_fee_amount(request_size, replication_kind, subnet_size))
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
///
/// This is the part of the price that the per-replica allowances have to cover.
fn usage_fee(
    replication_kind: ReplicationKind,
    http_roundtrip_time: Duration,
    raw_response_size: NumBytes,
    transform_instructions: NumInstructions,
    transformed_response_size: NumBytes,
    subnet_size: NumberOfNodes,
) -> Cycles {
    let transformed_bytes = transformed_response_size.get() as u128;
    // How the responses reach the rest of the subnet, and which of them consensus
    // delivers, is all the replication kind decides here.
    let (gossip_fee, consensus_fee) = match replication_kind {
        // Every replica produces the same response, so it doesn't need to be gossiped
        // and consensus is reached on that single response.
        ReplicationKind::FullyReplicated => (0, consensus_fee(transformed_bytes, subnet_size)),
        // The single replica gossips its own response, which is then delivered.
        ReplicationKind::NonReplicated => (
            gossip_usage_fee(transformed_response_size, subnet_size),
            consensus_fee(transformed_bytes, subnet_size),
        ),
        // Every replica gossips its own response, and up to `max_responses` of them
        // are delivered — those beyond `min_responses` at an extra fee.
        ReplicationKind::Flexible {
            min_responses,
            max_responses,
            ..
        } => {
            let responses = max_responses as u128;
            (
                gossip_usage_fee(transformed_response_size, subnet_size),
                consensus_fee(
                    responses.saturating_mul(
                        FLEXIBLE_RESPONSE_SIZE_OVERHEAD.saturating_add(transformed_bytes),
                    ),
                    subnet_size,
                ) + flexible_extra_response_fee(
                    responses.saturating_sub(min_responses as u128),
                    subnet_size,
                ),
            )
        }
    };

    let per_replica_fee = network_usage_fee(raw_response_size, http_roundtrip_time)
        .saturating_add(transform_usage_fee(transform_instructions))
        .saturating_add(gossip_fee);
    let replicas = replication_kind.node_count(subnet_size) as u128;

    Cycles::new(replicas.saturating_mul(per_replica_fee)) + consensus_fee
}

// ============================= Maximum usage fee =============================

/// The most an HTTP outcall with the given `replication` and `max_response_bytes`
/// can ever spend, i.e. its [`usage_fee`] in the worst case: a response of the
/// largest permitted size, downloaded over the full `MAX_RESPONSE_TIME`,
/// transformed with the full query instruction limit and delivered as a maximally
/// large transformed response.
///
/// This is everything the per-replica allowances of a request have to cover, so
/// withholding more of its payment than this cannot buy the caller anything.
///
/// The result is rounded up to a multiple of the number of participating replicas,
/// so that splitting it evenly among them always yields allowances that add up to at
/// least the worst case.
pub fn max_usage_fee(
    replication: &Replication,
    max_response_bytes: Option<NumBytes>,
    subnet_size: NumberOfNodes,
) -> Cycles {
    let replication_kind = replication.kind();
    let worst_case = usage_fee(
        replication_kind,
        MAX_RESPONSE_TIME,
        max_response_bytes.unwrap_or(NumBytes::from(MAX_CANISTER_HTTP_RESPONSE_BYTES)),
        MAX_INSTRUCTIONS_PER_QUERY_MESSAGE,
        NumBytes::from(MAX_CANISTER_HTTP_RESPONSE_BYTES),
        subnet_size,
    );
    let node_count = replication_kind.node_count(subnet_size) as u128;
    Cycles::new(
        worst_case
            .get()
            .div_ceil(node_count)
            .saturating_mul(node_count),
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
/// consensus, where `K` is the number of shares.
pub fn flexible_initial_spent<'a>(
    shares: impl Iterator<Item = &'a CanisterHttpResponseShare>,
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
    let extra_responses = count.saturating_sub(min_responses) as u128;
    spent_sum
        + consensus_fee(size_term, subnet_size)
        + flexible_extra_response_fee(extra_responses, subnet_size)
}

#[cfg(test)]
mod tests {
    //! The expected values in these tests are computed by hand rather than by
    //! calling the functions under test, so that a wrong constant or dropped
    //! term is actually caught. (The consensus payload builder/validator tests
    //! only compare these functions against themselves and would not.)
    use super::*;
    use ic_types::{
        NodeId, PrincipalId, ReplicaVersion,
        canister_http::{
            CanisterHttpPaymentReceipt, CanisterHttpResponseMetadata, CanisterHttpResponseProof,
            CanisterHttpResponseReceipt, CanisterHttpResponseShare, CanisterHttpResponseSignature,
        },
        crypto::{BasicSig, BasicSigOf, CryptoHash, CryptoHashOf, Signed},
        messages::CallbackId,
        signature::BasicSignature,
    };
    use ic_types_cycles::CanisterCyclesCostSchedule;
    use std::collections::BTreeMap;

    fn node(i: u64) -> NodeId {
        NodeId::from(PrincipalId::new_node_test_id(i))
    }

    fn metadata(content_size: u32) -> CanisterHttpResponseMetadata {
        CanisterHttpResponseMetadata {
            id: CallbackId::from(1),
            content_hash: CryptoHashOf::new(CryptoHash(vec![])),
            content_size,
            is_reject: false,
            replica_version: ReplicaVersion::default(),
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
        let spent = flexible_initial_spent(shares.iter(), NumberOfNodes::from(13), 1);
        assert_eq!(spent, Cycles::new(600 + 5_722_470 + 3_276_000));
    }

    #[test]
    fn flexible_initial_spent_at_min_responses_has_no_extra_cost() {
        // K == min_responses == 2, so extra_responses = 0 and extra_cost = 0.
        //   spent_sum      = 100 + 200                     = 300
        //   size_term      = (181+10) + (181+20)           = 392
        //   consensus_cost = 9_490 * 392                   = 3_720_080
        let shares = [share(0, 10, 100), share(1, 20, 200)];
        let spent = flexible_initial_spent(shares.iter(), NumberOfNodes::from(13), 2);
        assert_eq!(spent, Cycles::new(300 + 3_720_080));
    }

    #[test]
    fn flexible_initial_spent_below_min_responses_does_not_underflow() {
        // K = 1 < min_responses = 3: extra_responses saturates to 0 (no panic),
        // so only the single receipt and its consensus cost are charged.
        //   consensus_cost = 9_490 * (181 + 30) = 9_490 * 211 = 2_002_390
        let shares = [share(0, 30, 500)];
        let spent = flexible_initial_spent(shares.iter(), NumberOfNodes::from(13), 3);
        assert_eq!(spent, Cycles::new(500 + 2_002_390));
    }

    #[test]
    fn flexible_initial_spent_empty_is_zero() {
        let spent = flexible_initial_spent(std::iter::empty(), NumberOfNodes::from(13), 0);
        assert_eq!(spent, Cycles::zero());
    }

    /// The terms shared by every worst case at N = 13: the 60 s latency cap and the
    /// full 5 B-instruction query limit.
    const MAX_LATENCY_FEE: u128 = 300 * 60_000; // 18_000_000
    const MAX_TRANSFORM_FEE: u128 = 5_000_000_000 / 13; // 384_615_384
    /// `50 * 2_000_000 * 13`, the gossip fee for a maximally large transformed
    /// response at N = 13.
    const MAX_GOSSIP_FEE: u128 = 1_300_000_000;
    /// `9_490 * 2_000_000`, the consensus fee for a maximally large response at
    /// N = 13.
    const MAX_NON_FLEXIBLE_CONSENSUS_FEE: u128 = 18_980_000_000;

    /// The resource usage the `total_fee` tests below price, and the config they
    /// price it on: a 100-byte request whose 1_000-byte response arrived in 2_000 ms,
    /// was transformed with 26 instructions and ended up 500 bytes, at N = 13.
    fn total_fee_of(replication_kind: ReplicationKind) -> CompoundCycles<HTTPOutcalls> {
        total_fee(
            NumBytes::from(100),
            Duration::from_millis(2_000),
            NumBytes::from(1_000),
            NumInstructions::from(26),
            NumBytes::from(500),
            replication_kind,
            CyclesAccountManagerSubnetConfig::new(13, CanisterCyclesCostSchedule::Normal, 13),
        )
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
        //   consensus   = 9_490 * 500                               =  4_745_000
        let fee = total_fee_of(ReplicationKind::FullyReplicated);
        assert_eq!(
            fee.real(),
            Cycles::new(38_482_600 + 13 * USAGE_FEE + 4_745_000)
        );

        // The parts add up to the single-expression formula of
        // `ic0.cost_http_request_v2`, with the consensus fee's `10 * N + 600` as the
        // per-transformed-byte coefficient. (The formula was originally specified
        // with `10 * N + 650`, charging every replica another 50 per transformed
        // byte; that is not what `PayAsYouGoTracker` charges a fully-replicated
        // replica, so it is not reported either.)
        let n = 13_u128;
        assert_eq!(
            fee.real(),
            Cycles::new(
                n * (1_000_000
                    + 50 * 100
                    + 140_000 * n
                    + 800 * n * n
                    + 50 * 1_000
                    + 300 * 2_000
                    + 26 / 13
                    + (10 * n + 600) * 500)
            )
        );
    }

    #[test]
    fn total_fee_non_replicated_charges_one_replica_that_gossips() {
        // A single replica performs the outcall and gossips its response to all 13
        // nodes; the base fee is the flexible one with `min_responses = 1`.
        //   base fee    = 13 * (1_000_000 + 50*100 + 90_000*13 + 2_000*13 + 100_000)
        //                                                          = 29_913_000
        //   per replica = 1 * (650_002 + 50*500*13)                =    975_002
        //   consensus   = 9_490 * 500                              =  4_745_000
        let fee = total_fee_of(ReplicationKind::NonReplicated);
        assert_eq!(
            fee.real(),
            Cycles::new(29_913_000 + (USAGE_FEE + 50 * 500 * 13) + 4_745_000)
        );
    }

    #[test]
    fn total_fee_flexible_charges_every_delegated_replica_and_response() {
        // 3 delegated replicas, 2 of whose responses suffice, so all 3 perform the
        // outcall and gossip their own response, and up to 3 responses are delivered
        // — one of them beyond `min_responses`.
        //   base fee    = 13 * (1_000_000 + 50*100 + 90_000*13 + 2_000*13*2 + 100_000*2)
        //                                                          = 31_551_000
        //   per replica = 3 * (650_002 + 50*500*13)                =  2_925_006
        //   consensus   = 9_490 * 3 * (181 + 500)                  = 19_388_070
        //   extra resp. = 13 * (2_000*13 + 100_000)                =  1_638_000
        let fee = total_fee_of(ReplicationKind::Flexible {
            total_requests: 3,
            min_responses: 2,
            max_responses: 3,
        });
        assert_eq!(
            fee.real(),
            Cycles::new(31_551_000 + 3 * (USAGE_FEE + 50 * 500 * 13) + 19_388_070 + 1_638_000)
        );
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
        // download term uses the full 2 MB. All 13 replicas perform it, and their
        // single agreed-on response is disseminated by consensus rather than
        // gossiped.
        //   per replica = 50 * 2_000_000                 =    100_000_000
        //               + latency                        =     18_000_000
        //               + transform                      =    384_615_384
        //   consensus   = 9_490 * 2_000_000              = 18_980_000_000
        let per_replica = 100_000_000 + MAX_LATENCY_FEE + MAX_TRANSFORM_FEE;
        assert_eq!(
            max_usage_fee(&Replication::FullyReplicated, None, NumberOfNodes::from(13)),
            Cycles::new(13 * per_replica + MAX_NON_FLEXIBLE_CONSENSUS_FEE)
        );
    }

    #[test]
    fn max_usage_fee_non_replicated_charges_one_replica_that_gossips() {
        // A non-replicated outcall with a 1 KB response limit at N = 13: a single
        // replica performs it and gossips a maximally large transformed response to
        // the whole subnet.
        //   per replica = 50 * 1_000                     =         50_000
        //               + latency                        =     18_000_000
        //               + transform                      =    384_615_384
        //               + gossip                         =  1_300_000_000
        //   consensus   = 9_490 * 2_000_000              = 18_980_000_000
        let per_replica = 50_000 + MAX_LATENCY_FEE + MAX_TRANSFORM_FEE + MAX_GOSSIP_FEE;
        assert_eq!(
            max_usage_fee(
                &Replication::NonReplicated(node(0)),
                Some(NumBytes::from(1_000)),
                NumberOfNodes::from(13)
            ),
            Cycles::new(per_replica + MAX_NON_FLEXIBLE_CONSENSUS_FEE)
        );
    }

    #[test]
    fn max_usage_fee_flexible_covers_all_delegated_replicas_and_responses() {
        // A flexible outcall with a committee of 3 (2 of which suffice) and a 1 KB
        // response limit at N = 13: all 3 replicas perform it and gossip their own
        // maximally large response, and all 3 responses are delivered, one of them
        // beyond `min_responses`.
        //   per replica    = 50_000 + latency + transform + gossip
        //   consensus      = 9_490 * 3 * (181 + 2_000_000)   = 56_945_153_070
        //   extra response = 13 * (2_000 * 13 + 100_000)     =      1_638_000
        let per_replica = 50_000 + MAX_LATENCY_FEE + MAX_TRANSFORM_FEE + MAX_GOSSIP_FEE;
        let consensus = 9_490 * 3 * (181 + 2_000_000) + 13 * (2_000 * 13 + 100_000);
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
    fn max_usage_fee_is_rounded_up_to_whole_allowances() {
        // Whatever the worst case, the reported maximum is a multiple of the number of
        // participating replicas and at most `node_count - 1` cycles above the actual
        // worst case, so that splitting it evenly always covers that worst case.
        for replication in [
            Replication::FullyReplicated,
            Replication::NonReplicated(node(0)),
            // A committee of 4, whose worst case is not a multiple of 4.
            Replication::Flexible {
                committee: (0..4).map(node).collect(),
                min_responses: 2,
                max_responses: 3,
            },
        ] {
            let subnet_size = NumberOfNodes::from(13);
            let replication_kind = replication.kind();
            let node_count = replication_kind.node_count(subnet_size) as u128;
            let worst_case = usage_fee(
                replication_kind,
                MAX_RESPONSE_TIME,
                NumBytes::from(MAX_CANISTER_HTTP_RESPONSE_BYTES),
                MAX_INSTRUCTIONS_PER_QUERY_MESSAGE,
                NumBytes::from(MAX_CANISTER_HTTP_RESPONSE_BYTES),
                subnet_size,
            );
            let rounded = max_usage_fee(&replication, None, subnet_size);

            assert_eq!(rounded.get() % node_count, 0, "{replication:?}");
            assert!(
                rounded >= worst_case && rounded.get() - worst_case.get() < node_count,
                "{replication:?}: {rounded} not within a rounding step of {worst_case}"
            );
            // Splitting it evenly covers the worst case, which is the point.
            assert!(
                rounded / node_count * node_count >= worst_case,
                "{replication:?}"
            );
        }
    }
}
