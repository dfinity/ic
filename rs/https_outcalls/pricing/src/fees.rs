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

pub const HTTP_REQUEST_BASE_FEE: u128 = 1_000_000;
pub const HTTP_REQUEST_PER_BYTE_FEE: u128 = 50;
pub const HTTP_REQUEST_FULLY_REPLICATED_PER_NODE_FEE: u128 = 140_000;
pub const HTTP_REQUEST_FULLY_REPLICATED_QUADRATIC_NODE_FEE: u128 = 800;
pub const HTTP_REQUEST_FLEXIBLE_PER_NODE_FEE: u128 = 90_000;
pub const HTTP_REQUEST_FLEXIBLE_PER_NODE_RESPONSE_CONSENSUS_FEE: u128 = 2_000;
pub const HTTP_REQUEST_FLEXIBLE_PER_RESPONSE_CONSENSUS_FEE: u128 = 100_000;

// ========================= Per-replica-fee constants =========================
// Charged as-you-go by the `PayAsYouGoTracker` in `payg.rs`.

pub const PER_DOWNLOADED_BYTE_FEE: u128 = 50;
pub const PER_RESPONSE_MS_FEE: u128 = 300;
/// HTTP outcalls are priced consistently against a reference subnet size of 13.
pub const TRANSFORM_INSTRUCTION_DIVISOR: u128 = 13;
pub const FLEXIBLE_PER_TRANSFORMED_BYTE_NODE_FEE: u128 = 50;

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
