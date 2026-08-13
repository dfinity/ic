//! Pay-as-you-go pricing for HTTP outcalls.
//!
//! A request's cost is split into three parts, all defined here so that they
//! share a single set of constants:
//!   1. the base fee ([`base_fee`]), subtracted up-front when the request context
//!      is created (and therefore reflected in `per_replica_allowance`);
//!   2. the per-replica fee, accounted for as-you-go by the `PayAsYouGoTracker`
//!      (see `payg.rs`), which uses the per-replica constants below;
//!   3. the consensus fee ([`non_flexible_initial_spent`] /
//!      [`flexible_initial_spent`]), computed from the aggregated response in the
//!      block payload.

use ic_types::{
    NumBytes, NumberOfNodes,
    canister_http::{
        CanisterHttpResponseMetadata, CanisterHttpResponseProof, CanisterHttpResponseShare,
        Replication,
    },
};
use ic_types_cycles::{CompoundCycles, Cycles, CyclesAccountManagerSubnetConfig, HTTPOutcalls};
use std::collections::BTreeMap;

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
// Charged as-you-go by the `PayAsYouGoTracker` in `payg.rs`.

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

// ================================= Base fee =================================

/// Computes the up-front base fee for an HTTP outcall request of size
/// `request_size` with the given `replication`, on the subnet described by
/// `subnet_cycles_config`.
pub fn base_fee(
    request_size: NumBytes,
    replication: &Replication,
    subnet_cycles_config: CyclesAccountManagerSubnetConfig,
) -> CompoundCycles<HTTPOutcalls> {
    let n = subnet_cycles_config.subnet_size as u128;
    let request_bytes = request_size.get() as u128;
    let per_replica = match replication {
        Replication::FullyReplicated => {
            HTTP_REQUEST_BASE_FEE
                + HTTP_REQUEST_PER_BYTE_FEE * request_bytes
                + HTTP_REQUEST_FULLY_REPLICATED_PER_NODE_FEE * n
                + HTTP_REQUEST_FULLY_REPLICATED_QUADRATIC_NODE_FEE * n * n
        }
        Replication::Flexible {
            min_responses: min, ..
        } => {
            let min = *min as u128;
            HTTP_REQUEST_BASE_FEE
                + HTTP_REQUEST_PER_BYTE_FEE * request_bytes
                + HTTP_REQUEST_FLEXIBLE_PER_NODE_FEE * n
                + HTTP_REQUEST_FLEXIBLE_PER_NODE_RESPONSE_CONSENSUS_FEE * n * min
                + HTTP_REQUEST_FLEXIBLE_PER_RESPONSE_CONSENSUS_FEE * min
        }
        Replication::NonReplicated(_) => {
            // Non-replicated is equivalent to flexible replication with min_responses = 1.
            HTTP_REQUEST_BASE_FEE
                + HTTP_REQUEST_PER_BYTE_FEE * request_bytes
                + HTTP_REQUEST_FLEXIBLE_PER_NODE_FEE * n
                + HTTP_REQUEST_FLEXIBLE_PER_NODE_RESPONSE_CONSENSUS_FEE * n
                + HTTP_REQUEST_FLEXIBLE_PER_RESPONSE_CONSENSUS_FEE
        }
    };

    CompoundCycles::new(
        Cycles::new(n * per_replica),
        subnet_cycles_config.cost_schedule,
    )
}

// =============================== Consensus fee ===============================

/// Per-response-byte consensus cost coefficient `N * (10 * N + 600)`, where `N`
/// is the subnet size.
pub fn consensus_cost_coefficient(subnet_size: NumberOfNodes) -> u128 {
    let n = subnet_size.get() as u128;
    n * (CONSENSUS_PER_NODE_BYTE_FEE * n + CONSENSUS_BYTE_FEE)
}

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
    let consensus_cost =
        Cycles::from(consensus_cost_coefficient(subnet_size) * proof.metadata.content_size as u128);
    spent_sum + consensus_cost
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
    let consensus_cost = Cycles::from(consensus_cost_coefficient(subnet_size) * size_term);
    let extra_cost = extra_response_fee(subnet_size, count.saturating_sub(min_responses) as u128);
    spent_sum + consensus_cost + extra_cost
}

/// The fee charged for `extra_responses` many responses delivered beyond the
/// `min_responses` the caller already paid for up front.
fn extra_response_fee(subnet_size: NumberOfNodes, extra_responses: u128) -> Cycles {
    let n = subnet_size.get() as u128;
    Cycles::from(
        n * (HTTP_REQUEST_FLEXIBLE_PER_NODE_RESPONSE_CONSENSUS_FEE * n * extra_responses
            + HTTP_REQUEST_FLEXIBLE_PER_RESPONSE_CONSENSUS_FEE * extra_responses),
    )
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
    Cycles::from(consensus_cost_coefficient(subnet_size) * size_term)
        + extra_response_fee(
            subnet_size,
            (required_responses as u128).saturating_sub(min_responses as u128),
        )
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
        .map(|(_, content_size)| {
            Cycles::from(consensus_cost_coefficient(subnet_size) * content_size as u128)
        })
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
        NodeId, PrincipalId, ReplicaVersion,
        canister_http::{
            CanisterHttpPaymentReceipt, CanisterHttpResponseMetadata, CanisterHttpResponseProof,
            CanisterHttpResponseReceipt, CanisterHttpResponseShare, CanisterHttpResponseSignature,
        },
        crypto::{BasicSig, BasicSigOf, CryptoHash, CryptoHashOf, Signed},
        messages::CallbackId,
        signature::BasicSignature,
    };
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

    /// Same as [`share`], but for a reject response.
    fn reject_share(signer: u64, content_size: u32, spent: u128) -> CanisterHttpResponseShare {
        let mut share = share(signer, content_size, spent);
        share.content.metadata.is_reject = true;
        share
    }

    #[test]
    fn consensus_cost_coefficient_matches_formula() {
        // N * (10 * N + 600).
        assert_eq!(consensus_cost_coefficient(NumberOfNodes::from(1)), 610);
        assert_eq!(consensus_cost_coefficient(NumberOfNodes::from(13)), 9_490);
        assert_eq!(consensus_cost_coefficient(NumberOfNodes::from(40)), 40_000);
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
}
