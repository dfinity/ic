//! Pay-as-you-go pricing for HTTP outcalls.
//!
//! A request's cost is split into three parts, all defined here so that they
//! share a single set of constants:
//!   1. the base fee ([`base_fee`]), subtracted up-front when the request context
//!      is created (and therefore reflected in `per_replica_allowance`);
//!   2. the per-replica fee, accounted for as-you-go by the `PayAsYouGoTracker`
//!      (see `payg.rs`), which uses the per-replica constants below;
//!   3. the consensus fee ([`fully_replicated_initial_spent`] /
//!      [`flexible_initial_spent`]), computed from the aggregated response in the
//!      block payload.

use ic_types::{
    NumBytes, NumberOfNodes,
    canister_http::{CanisterHttpResponseProof, CanisterHttpResponseShare, Replication},
};
use ic_types_cycles::{CompoundCycles, Cycles, CyclesAccountManagerSubnetConfig, HTTPOutcalls};

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
// [`fully_replicated_initial_spent`] / [`flexible_initial_spent`].

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
pub fn fully_replicated_initial_spent(
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
    let n = subnet_size.get() as u128;
    let consensus_cost = Cycles::from(consensus_cost_coefficient(subnet_size) * size_term);
    let extra_responses = count.saturating_sub(min_responses) as u128;
    let extra_cost = Cycles::from(
        n * (HTTP_REQUEST_FLEXIBLE_PER_NODE_RESPONSE_CONSENSUS_FEE * n * extra_responses
            + HTTP_REQUEST_FLEXIBLE_PER_RESPONSE_CONSENSUS_FEE * extra_responses),
    );
    spent_sum + consensus_cost + extra_cost
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

    #[test]
    fn consensus_cost_coefficient_matches_formula() {
        // N * (10 * N + 600).
        assert_eq!(consensus_cost_coefficient(NumberOfNodes::from(1)), 610);
        assert_eq!(consensus_cost_coefficient(NumberOfNodes::from(13)), 9_490);
        assert_eq!(consensus_cost_coefficient(NumberOfNodes::from(40)), 40_000);
    }

    #[test]
    fn fully_replicated_initial_spent_sums_receipts_plus_consensus_cost() {
        // Two signers spending distinct amounts (so a dropped or double-counted
        // receipt changes the result), over a 100-byte response at N = 13.
        //   spent_sum      = 1_000 + 2_000                 = 3_000
        //   consensus_cost = 9_490 * 100                   = 949_000
        let spent =
            fully_replicated_initial_spent(&proof(100, &[1_000, 2_000]), NumberOfNodes::from(13));
        assert_eq!(spent, Cycles::new(3_000 + 949_000));
    }

    #[test]
    fn fully_replicated_initial_spent_with_zero_content_is_just_the_spends() {
        // A zero-size response contributes no consensus cost; only the receipts
        // remain.
        let spent = fully_replicated_initial_spent(&proof(0, &[7, 11]), NumberOfNodes::from(13));
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
}
