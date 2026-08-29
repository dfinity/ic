use ic_https_outcalls_pricing::fees::{
    flexible_initial_spent, min_flexible_consensus_cost, min_non_flexible_consensus_cost,
    non_flexible_initial_spent,
};
use ic_interfaces::canister_http::{CanisterHttpPool, InvalidCanisterHttpPayloadReason};
use ic_logger::{ReplicaLogger, warn};
use ic_types::{
    CountBytes, NodeId, NumBytes, RegistryVersion,
    batch::{
        CanisterHttpOutOfCycles, FlexibleCanisterHttpError, FlexibleCanisterHttpResponseWithProof,
        FlexibleCanisterHttpResponses, MAX_CANISTER_HTTP_PAYLOAD_SIZE,
    },
    canister_http::{
        CanisterHttpPaymentReceipt, CanisterHttpRequestContext, CanisterHttpResponse,
        CanisterHttpResponseMetadata, CanisterHttpResponseProof, CanisterHttpResponseReceipt,
        CanisterHttpResponseShare, CanisterHttpResponseSignature,
        CanisterHttpResponseWithConsensus, PricingVersion,
    },
    crypto::{Signed, crypto_hash},
    messages::CallbackId,
    signature::{BasicSigBatchEntry, BasicSignature},
};
use ic_types_cycles::{CanisterCyclesCostSchedule, Cycles};
use std::collections::{BTreeMap, BTreeSet, HashSet};

use crate::metrics::CanisterHttpPayloadBuilderMetrics;

/// Checks whether the response is consistent
///
/// Consistency means:
/// - The signed metadata is the same as the metadata of the response
/// - The content_hash is the same as the hash of the content
/// - The content_size is the same as the size of the content
/// - The is_reject flag matches whether the content is a Reject
///
/// **NOTE**: The signature is not checked
pub(crate) fn check_response_consistency(
    response: &CanisterHttpResponseWithConsensus,
) -> Result<(), InvalidCanisterHttpPayloadReason> {
    let content = &response.content;
    let metadata = &response.proof.metadata;

    // Check metadata field consistency
    if metadata.id != content.id {
        return Err(InvalidCanisterHttpPayloadReason::InvalidMetadata {
            metadata_id: metadata.id,
            content_id: content.id,
        });
    }

    // Check the calculated hash matches the metadata hash
    let calculated_hash = crypto_hash(content);
    if calculated_hash != metadata.content_hash {
        return Err(InvalidCanisterHttpPayloadReason::ContentHashMismatch {
            metadata_hash: metadata.content_hash.clone(),
            calculated_hash,
        });
    }

    // Check the calculated size matches the metadata size
    let calculated_size = content.content.count_bytes() as u32;
    if calculated_size != metadata.content_size {
        return Err(InvalidCanisterHttpPayloadReason::ContentSizeMismatch {
            metadata_size: metadata.content_size,
            calculated_size,
        });
    }

    // Check the is_reject flag matches the response content type
    let calculated_is_reject = content.content.is_reject();
    if calculated_is_reject != metadata.is_reject {
        return Err(InvalidCanisterHttpPayloadReason::IsRejectMismatch {
            metadata_is_reject: metadata.is_reject,
            calculated_is_reject,
        });
    }

    Ok(())
}

/// Enforces the per-replica spend limit from the request context: the amount
/// the replica claims to have `spent` in the payment receipt must never exceed
/// the maximum returned by [`CanisterHttpRequestContext::max_http_outcall_spend`].
///
/// On charging subnets this is the `per_replica_allowance`. Free subnets charge
/// nothing, so their spend (used only for cost accounting) may exceed the (zero)
/// allowance, but may never exceed [`MAX_HTTP_OUTCALL_SPEND_FREE_SUBNET`].
pub(crate) fn check_spent_within_limit(
    receipt: &CanisterHttpPaymentReceipt,
    context: &CanisterHttpRequestContext,
) -> Result<(), InvalidCanisterHttpPayloadReason> {
    let limit = context.max_http_outcall_spend();
    if receipt.spent > limit {
        return Err(InvalidCanisterHttpPayloadReason::SpentExceedsLimit {
            spent: receipt.spent,
            limit,
        });
    }
    Ok(())
}

/// Enforces the response size limit from the request context: the `content_size`
/// the signed metadata claims must never exceed the maximum returned by
/// [`CanisterHttpRequestContext::max_http_outcall_content_size`].
pub(crate) fn check_content_size_within_limit(
    metadata: &CanisterHttpResponseMetadata,
    callback_id: CallbackId,
    context: &CanisterHttpRequestContext,
) -> Result<(), InvalidCanisterHttpPayloadReason> {
    let limit = context.max_http_outcall_content_size(metadata.is_reject);
    if metadata.content_size as u64 > limit {
        return Err(InvalidCanisterHttpPayloadReason::ContentSizeExceedsLimit {
            callback_id,
            content_size: metadata.content_size,
            limit,
        });
    }
    Ok(())
}

enum ConsensusCostAllowance {
    Legacy(Cycles),
    PayAsYouGo(Cycles),
    Free,
}

/// The per-replica allowance that will be used to cover the consensus cost of
/// delivering a response.
///
/// The consensus cost of legacy and free requests does not need to be covered
/// by the replicas' allowances.
fn per_replica_consensus_allowance(context: &CanisterHttpRequestContext) -> ConsensusCostAllowance {
    let allowance = context.refund_status.per_replica_allowance;
    match context.cost_schedule {
        CanisterCyclesCostSchedule::Free => ConsensusCostAllowance::Free,
        CanisterCyclesCostSchedule::Normal => match context.pricing_version {
            PricingVersion::Legacy => ConsensusCostAllowance::Legacy(allowance),
            PricingVersion::PayAsYouGo => ConsensusCostAllowance::PayAsYouGo(allowance),
        },
    }
}

/// Enforces that `initial_spent`, the collective spend of the `num_replicas`
/// replicas contributing to a response, stays within their collective allowance,
/// i.e. the sum of their [per-replica allowances](per_replica_consensus_allowance).
///
/// Unlike the per-replica spends, which are bounded individually by
/// [`check_spent_within_limit`], the collective spend also contains the consensus
/// cost of putting the response into a block. That cost is only covered if the
/// contributing replicas left enough of their allowances unspent, which is what
/// this check ensures.
pub(crate) fn check_initial_spent_within_limit(
    initial_spent: Cycles,
    num_replicas: usize,
    callback_id: CallbackId,
    context: &CanisterHttpRequestContext,
    obs: Option<(&ReplicaLogger, &CanisterHttpPayloadBuilderMetrics)>,
) -> Result<(), InvalidCanisterHttpPayloadReason> {
    match per_replica_consensus_allowance(context) {
        // Pay-as-you-go enforces that the collective spend must be covered
        // by the collective allowance of contributing replicas.
        ConsensusCostAllowance::PayAsYouGo(allowance)
            if initial_spent > allowance * num_replicas =>
        {
            Err(InvalidCanisterHttpPayloadReason::InitialSpentExceedsLimit {
                callback_id,
                initial_spent,
                per_replica_allowance: allowance,
                num_replicas,
            })
        }
        // Legacy requests do not enforce the collective spend limit, but we
        // log a warning if it is exceeded, to observe canister compatibility
        // with the new pricing.
        ConsensusCostAllowance::Legacy(allowance) if initial_spent > allowance * num_replicas => {
            if let Some((log, metrics)) = obs {
                metrics.initial_spent_exceeds_limit.inc();
                warn!(
                    log,
                    "Initial HTTP spent {} of {} replicas exceeds collective allowance {} \
                     for {} request {} of canister {}",
                    initial_spent,
                    num_replicas,
                    allowance * num_replicas,
                    context.replication.kind().as_str(),
                    callback_id,
                    context.request.sender,
                );
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// An outcall is out of cycles if its committee's unspent allowance
/// is smaller than the minimum cost required to deliver a response.
pub(crate) struct OutOfCyclesProof {
    /// The least it can cost to deliver a response.
    pub min_cost: Cycles,
    /// What is left of the committee's collective allowance.
    pub unspent_allowance: Cycles,
}

/// What is left of the committee's collective allowance, given the shares it has
/// produced so far.
///
/// `None` if the consensus cost of this outcall is not enforced against its per-replica
/// allowance (see [`per_replica_consensus_allowance`]).
fn unspent_committee_allowance<'a>(
    seen_shares: impl Iterator<Item = &'a CanisterHttpResponseShare>,
    committee_size: usize,
    context: &CanisterHttpRequestContext,
) -> Option<Cycles> {
    let ConsensusCostAllowance::PayAsYouGo(allowance) = per_replica_consensus_allowance(context)
    else {
        return None;
    };
    let spent: Cycles = seen_shares.map(|share| share.content.spent()).sum();
    Some(allowance * committee_size - spent)
}

/// An out of cycles error is produced once what is left of the allowance falls short
/// of the least a delivery can cost.
fn out_of_cycles_verdict(
    min_cost: Option<Cycles>,
    unspent_allowance: Option<Cycles>,
    callback_id: CallbackId,
) -> Result<OutOfCyclesProof, InvalidCanisterHttpPayloadReason> {
    match (min_cost, unspent_allowance) {
        (Some(min_cost), Some(unspent_allowance)) if unspent_allowance < min_cost => {
            Ok(OutOfCyclesProof {
                min_cost,
                unspent_allowance,
            })
        }
        _ => {
            debug_assert!(
                unspent_allowance
                    .map(|allowance| allowance >= min_cost.unwrap_or_default())
                    .unwrap_or(true),
                "expect unspent allowance {:?} >= min cost {:?}",
                unspent_allowance,
                min_cost
            );
            Err(InvalidCanisterHttpPayloadReason::NotOutOfCycles {
                callback_id,
                unspent_allowance,
                min_cost,
            })
        }
    }
}

/// Checks that a flexible outcall has run out of cycles, i.e. that its
/// committee's remaining allowances can no longer cover the consensus cost of
/// delivering any response.
pub(crate) fn check_flexible_out_of_cycles<'a>(
    seen_shares: impl Iterator<Item = &'a CanisterHttpResponseShare> + Clone,
    committee_size: usize,
    min_responses: u32,
    callback_id: CallbackId,
    context: &CanisterHttpRequestContext,
) -> Result<OutOfCyclesProof, InvalidCanisterHttpPayloadReason> {
    out_of_cycles_verdict(
        min_flexible_consensus_cost(
            seen_shares.clone(),
            context.subnet_size,
            committee_size,
            min_responses,
        ),
        unspent_committee_allowance(seen_shares, committee_size, context),
        callback_id,
    )
}

/// Checks that a fully- or non-replicated outcall has run out of cycles, i.e. that
/// its committee's remaining allowances can no longer cover the consensus cost of
/// delivering any response.
pub(crate) fn check_non_flexible_out_of_cycles<'a>(
    seen_shares: impl Iterator<Item = &'a CanisterHttpResponseShare> + Clone,
    committee_size: usize,
    threshold: usize,
    callback_id: CallbackId,
    context: &CanisterHttpRequestContext,
) -> Result<OutOfCyclesProof, InvalidCanisterHttpPayloadReason> {
    out_of_cycles_verdict(
        min_non_flexible_consensus_cost(
            seen_shares.clone(),
            context.subnet_size,
            committee_size,
            threshold,
        ),
        unspent_committee_allowance(seen_shares, committee_size, context),
        callback_id,
    )
}

/// Collects at most one share per committee member.
fn one_share_per_committee_member<'a>(
    grouped_shares: &BTreeMap<CanisterHttpResponseMetadata, Vec<&'a CanisterHttpResponseShare>>,
    committee: &BTreeSet<NodeId>,
) -> Vec<&'a CanisterHttpResponseShare> {
    let mut seen_signers = BTreeSet::new();
    grouped_shares
        .values()
        .flatten()
        .filter(|share| {
            let signer = share.signature.signer;
            committee.contains(&signer) && seen_signers.insert(signer)
        })
        .copied()
        .collect()
}

/// Reports a fully- or non-replicated outcall whose committee can no longer pay for
/// delivering a response, or `None` while it still can.
pub(crate) fn find_non_flexible_out_of_cycles(
    callback_id: CallbackId,
    grouped_shares: &BTreeMap<CanisterHttpResponseMetadata, Vec<&CanisterHttpResponseShare>>,
    committee: &BTreeSet<NodeId>,
    threshold: usize,
    context: &CanisterHttpRequestContext,
) -> Option<CanisterHttpOutOfCycles> {
    let shares = one_share_per_committee_member(grouped_shares, committee);
    let proof = check_non_flexible_out_of_cycles(
        shares.iter().copied(),
        committee.len(),
        threshold,
        callback_id,
        context,
    )
    .ok()?;
    Some(CanisterHttpOutOfCycles {
        callback_id,
        shares: shares.into_iter().cloned().collect(),
        min_cost: proof.min_cost,
        unspent_allowance: proof.unspent_allowance,
    })
}

/// The replicas of an already responded to outcall whose spend has been accounted
/// for, and that must therefore not be refunded a second time.
pub(crate) struct RefundedNodes<'a> {
    by_context: &'a BTreeSet<NodeId>,
    by_past_payload: Option<&'a HashSet<NodeId>>,
}

impl<'a> RefundedNodes<'a> {
    pub(crate) fn new(
        callback_id: CallbackId,
        context: &'a CanisterHttpRequestContext,
        past_payload_refunds: &'a BTreeMap<CallbackId, HashSet<NodeId>>,
    ) -> Self {
        Self {
            by_context: &context.refund_status.refunding_nodes,
            by_past_payload: past_payload_refunds.get(&callback_id),
        }
    }

    pub(crate) fn contains(&self, node_id: &NodeId) -> bool {
        self.by_context.contains(node_id)
            || self
                .by_past_payload
                .is_some_and(|nodes| nodes.contains(node_id))
    }
}

/// The receipts of the replicas that have contributed to an already responded to
/// outcall but have not been refunded yet, at most one per replica.
pub(crate) fn find_async_receipts<'a>(
    grouped_shares: &BTreeMap<CanisterHttpResponseMetadata, Vec<&'a CanisterHttpResponseShare>>,
    committee: &BTreeSet<NodeId>,
    already_refunded: &RefundedNodes,
) -> Vec<&'a CanisterHttpResponseShare> {
    one_share_per_committee_member(grouped_shares, committee)
        .into_iter()
        .filter(|share| !already_refunded.contains(&share.signature.signer))
        .collect()
}

/// Reconstructs, for every signer of an aggregated proof, the
/// [`CanisterHttpResponseShare`] that signer actually signed: the shared
/// [`CanisterHttpResponseMetadata`] combined with that signer's own
/// [`CanisterHttpPaymentReceipt`], paired with that signer's basic signature.
pub(crate) fn reconstruct_individual_shares(
    proof: &CanisterHttpResponseProof,
) -> impl Iterator<Item = CanisterHttpResponseShare> + '_ {
    proof.signatures.iter().map(|(signer, sig)| Signed {
        content: CanisterHttpResponseReceipt {
            metadata: proof.metadata.clone(),
            payment_receipt: sig.payment_receipt.clone(),
        },
        signature: BasicSignature {
            signature: sig.signature.clone(),
            signer: *signer,
        },
    })
}

/// Assembles a [`CanisterHttpResponseProof`] from a slice of contributing
/// shares: the shared `metadata` together with, for each signer, the
/// basic signature and payment receipt taken directly from that signer's
/// share.
pub(crate) fn aggregate_shares(
    metadata: CanisterHttpResponseMetadata,
    shares: &[&CanisterHttpResponseShare],
) -> CanisterHttpResponseProof {
    let signatures = shares
        .iter()
        .map(|share| {
            (
                share.signature.signer,
                CanisterHttpResponseSignature {
                    payment_receipt: share.content.payment_receipt.clone(),
                    signature: share.signature.signature.clone(),
                },
            )
        })
        .collect();
    CanisterHttpResponseProof {
        metadata,
        signatures,
    }
}

/// Validates a single [`FlexibleCanisterHttpResponseWithProof`].
///
/// Checks callback-id consistency, share validity (using
/// [`validate_response_share`]), content hash, and content size.
///
/// **NOTE**: The signature on the share is not verified. Callers are expected
/// to batch-verify the signatures of all shares in the surrounding group via
/// [`BasicSigVerifier::verify_basic_sig_batch_multi_msg`].
pub(crate) fn validate_flexible_response_with_proof(
    response_with_proof: &FlexibleCanisterHttpResponseWithProof,
    callback_id: CallbackId,
    flex_committee: &BTreeSet<NodeId>,
    seen_signers: &mut HashSet<NodeId>,
    context: &CanisterHttpRequestContext,
) -> Result<(), InvalidCanisterHttpPayloadReason> {
    if response_with_proof.response.id != callback_id {
        return Err(InvalidCanisterHttpPayloadReason::ShareCallbackIdMismatch {
            callback_id,
            mismatched_id: response_with_proof.response.id,
        });
    }

    validate_response_share(
        &response_with_proof.proof,
        callback_id,
        flex_committee,
        seen_signers,
        context,
    )?;

    let calculated_hash = crypto_hash(&response_with_proof.response);
    if &calculated_hash != response_with_proof.proof.content.content_hash() {
        return Err(InvalidCanisterHttpPayloadReason::ContentHashMismatch {
            metadata_hash: response_with_proof.proof.content.content_hash().clone(),
            calculated_hash,
        });
    }

    let calculated_size = response_with_proof.response.content.count_bytes() as u32;
    if calculated_size != response_with_proof.proof.content.content_size() {
        return Err(InvalidCanisterHttpPayloadReason::ContentSizeMismatch {
            metadata_size: response_with_proof.proof.content.content_size(),
            calculated_size,
        });
    }

    let calculated_is_reject = response_with_proof.response.content.is_reject();
    if calculated_is_reject != response_with_proof.proof.content.is_reject() {
        return Err(InvalidCanisterHttpPayloadReason::IsRejectMismatch {
            metadata_is_reject: response_with_proof.proof.content.is_reject(),
            calculated_is_reject,
        });
    }

    Ok(())
}

/// Validates a single [`CanisterHttpResponseShare`]'s metadata against the
/// `committee` the request was assigned to.
///
/// Checks callback-id consistency, duplicate signers, committee membership, the
/// per-replica spend limit, and the response size limit.
///
/// **NOTE**: The signature is not verified. Callers are expected to
/// batch-verify the signatures of all shares in the surrounding group via
/// [`BasicSigVerifier::verify_basic_sig_batch_multi_msg`].
pub(crate) fn validate_response_share(
    share: &CanisterHttpResponseShare,
    callback_id: CallbackId,
    committee: &BTreeSet<NodeId>,
    seen_signers: &mut HashSet<NodeId>,
    context: &CanisterHttpRequestContext,
) -> Result<(), InvalidCanisterHttpPayloadReason> {
    if share.content.id() != callback_id {
        return Err(InvalidCanisterHttpPayloadReason::ShareCallbackIdMismatch {
            callback_id,
            mismatched_id: share.content.id(),
        });
    }

    check_spent_within_limit(&share.content.payment_receipt, context)?;
    check_content_size_within_limit(&share.content.metadata, callback_id, context)?;

    let signer = share.signature.signer;
    if !seen_signers.insert(signer) {
        return Err(InvalidCanisterHttpPayloadReason::DuplicateShareSigner {
            callback_id,
            signer,
        });
    }
    if !committee.contains(&signer) {
        return Err(
            InvalidCanisterHttpPayloadReason::ShareSignerNotInCommittee {
                callback_id,
                signer,
            },
        );
    }

    Ok(())
}

/// A single signature input as consumed by
/// [`BasicSigVerifier::verify_basic_sig_batch_multi_msg`].
pub(crate) type ResponseShareSigInput<'a> = BasicSigBatchEntry<'a, CanisterHttpResponseReceipt>;

/// Maps response shares to the signature inputs consumed by
/// [`BasicSigVerifier::verify_basic_sig_batch_multi_msg`]. All shares produced
/// here belong to the same request, so they share the `registry_version`.
pub(crate) fn response_share_sig_inputs<'a, I>(
    shares: I,
    registry_version: RegistryVersion,
) -> impl Iterator<Item = ResponseShareSigInput<'a>>
where
    I: IntoIterator<Item = &'a CanisterHttpResponseShare>,
{
    shares.into_iter().map(move |share| BasicSigBatchEntry {
        signer: share.signature.signer,
        signature: &share.signature.signature,
        message: &share.content,
        registry_version,
    })
}

/// This function takes a mapping of response metadata to supporting shares
/// and determines, whether the divergence criterium is met.
///
/// The divergence criterium is met, if enough nodes support different responses,
/// such that the support of nodes who are missing from the set
/// (since their shares have not been received yet) can not bring any response
/// above the required threshold.
///
/// Specifically, what is done is as follows:
/// - The sets of shares are sorted from largest to smallest, and then the
///   largest set is removed.
/// - A new set of "diverging signers" is created by collecting every node id
///   that has signed a share not in the largest group.
/// - Finally any signers appearing in the largest group are
///   removed from the diverging signers group.
/// - If the size of this group exceeds the number of faults tolerated, then the
///   divergence criteria is met.
pub(crate) fn grouped_shares_meet_divergence_criteria(
    grouped_shares: &BTreeMap<CanisterHttpResponseMetadata, Vec<&CanisterHttpResponseShare>>,
    faults_tolerated: usize,
) -> bool {
    let mut share_for_content_signers: Vec<BTreeSet<NodeId>> = grouped_shares
        .values()
        .map(|shares| shares.iter().map(|share| share.signature.signer).collect())
        .collect();
    share_for_content_signers.sort_by_key(|b| core::cmp::Reverse(b.len()));
    if let Some(largest_signers) = share_for_content_signers.first() {
        let mut non_largest_signers = BTreeSet::new();
        for signer_group in share_for_content_signers.iter().skip(1) {
            for signer in signer_group.iter() {
                non_largest_signers.insert(*signer);
            }
        }
        let otherwise_committed_signer_count =
            non_largest_signers.difference(largest_signers).count();
        otherwise_committed_signer_count > faults_tolerated
    } else {
        false
    }
}

/// Groups shares by callback id and then by their shared metadata.
///
/// Shares from different replicas for the same outcall agree on the
/// shared metadata but each carry their own payment receipt. We key the
/// inner `BTreeMap` on the metadata (taken from
/// `share.content.metadata`), so each group holds all shares that voted
/// for the same response and differ only in their per-replica receipt.
pub(crate) fn group_shares_by_callback_id<
    'a,
    Shares: Iterator<Item = &'a CanisterHttpResponseShare>,
>(
    shares: Shares,
) -> BTreeMap<CallbackId, BTreeMap<CanisterHttpResponseMetadata, Vec<&'a CanisterHttpResponseShare>>>
{
    let mut map: BTreeMap<
        CallbackId,
        BTreeMap<CanisterHttpResponseMetadata, Vec<&'a CanisterHttpResponseShare>>,
    > = BTreeMap::new();
    for share in shares {
        map.entry(share.content.id())
            .or_default()
            .entry(share.content.metadata.clone())
            .or_default()
            .push(share);
    }
    map
}

/// Finds a fully-replicated HTTP outcall response ready for consensus.
///
/// Iterates over response shares grouped by metadata, looking for one
/// where at least `threshold` distinct replicas produced the same
/// response hash. If found, returns the assembled
/// [`CanisterHttpResponseWithConsensus`].
///
/// A response is only returned once the signing replicas left enough of their
/// allowances unspent to cover the consensus cost of putting it into a block
/// (see [`check_initial_spent_within_limit`]); otherwise it is held back until
/// further shares have arrived, each of which contributes another allowance.
/// If no further shares can be received that would add enough allowance, we
/// will generate an out-of-cycles error instead (see [`check_flexible_out_of_cycles`]).
pub(crate) fn find_fully_replicated_response(
    grouped_shares: &BTreeMap<CanisterHttpResponseMetadata, Vec<&CanisterHttpResponseShare>>,
    threshold: usize,
    context: &CanisterHttpRequestContext,
    pool_access: &dyn CanisterHttpPool,
    log: &ReplicaLogger,
    metrics: &CanisterHttpPayloadBuilderMetrics,
) -> Option<CanisterHttpResponseWithConsensus> {
    grouped_shares.iter().find_map(|(metadata, shares)| {
        let signers: BTreeSet<_> = shares.iter().map(|share| share.signature.signer).collect();
        if signers.len() < threshold {
            return None;
        }
        let content = pool_access.get_response_content_by_hash(&metadata.content_hash)?;
        let proof = aggregate_shares(metadata.clone(), shares);
        assemble_non_flexible_response(content, proof, context, log, metrics)
    })
}

/// Finds a non-replicated HTTP outcall response from the designated node.
///
/// Looks through the grouped shares for one signed by `designated_node_id`.
/// If found, returns the assembled [`CanisterHttpResponseWithConsensus`].
///
/// As for fully-replicated responses, the response is held back while its
/// collective spend exceeds the designated replica's allowance. In that case,
/// we will generate an out-of-cycles error instead (see [`check_flexible_out_of_cycles`]).
pub(crate) fn find_non_replicated_response(
    grouped_shares: &BTreeMap<CanisterHttpResponseMetadata, Vec<&CanisterHttpResponseShare>>,
    designated_node_id: &NodeId,
    context: &CanisterHttpRequestContext,
    pool_access: &dyn CanisterHttpPool,
    log: &ReplicaLogger,
    metrics: &CanisterHttpPayloadBuilderMetrics,
) -> Option<CanisterHttpResponseWithConsensus> {
    grouped_shares.iter().find_map(|(metadata, shares)| {
        let correct_share = shares
            .iter()
            .find(|share| share.signature.signer == *designated_node_id)?;
        let content = pool_access.get_response_content_by_hash(&metadata.content_hash)?;
        let proof = aggregate_shares(metadata.clone(), &[correct_share]);
        assemble_non_flexible_response(content, proof, context, log, metrics)
    })
}

/// Assembles a [`CanisterHttpResponseWithConsensus`] from `content` and `proof`,
/// computing the collective initial spend of the proof's signers. Returns `None`
/// if that spend exceeds their collective allowance, in which case the response
/// must not be delivered yet.
fn assemble_non_flexible_response(
    content: CanisterHttpResponse,
    proof: CanisterHttpResponseProof,
    context: &CanisterHttpRequestContext,
    log: &ReplicaLogger,
    metrics: &CanisterHttpPayloadBuilderMetrics,
) -> Option<CanisterHttpResponseWithConsensus> {
    let initial_spent = non_flexible_initial_spent(&proof, context.subnet_size);
    check_initial_spent_within_limit(
        initial_spent,
        proof.signatures.len(),
        proof.metadata.id,
        context,
        Some((log, metrics)),
    )
    .ok()?;
    Some(CanisterHttpResponseWithConsensus {
        content,
        proof,
        initial_spent,
    })
}

/// Result of scanning flexible HTTP outcall shares for a single callback.
pub(crate) enum FlexibleFindResult {
    /// Collected enough OK responses for consensus.
    OkResponses(FlexibleCanisterHttpResponses, usize),
    /// Detected an error condition (too many rejects, responses too large, or out
    /// of cycles).
    Error(FlexibleCanisterHttpError, usize),
    /// Not enough data to decide yet; more shares may arrive.
    Pending,
}

/// A committee member's contribution to a flexible HTTP outcall: the response it
/// produced, its signed receipt, and the number of payload bytes that delivering
/// that response takes.
struct FlexibleCandidate<'a> {
    response: CanisterHttpResponse,
    share: &'a CanisterHttpResponseShare,
    size: usize,
}

/// Scans grouped shares for a flexible HTTP outcall and determines the result.
///
/// Collects one candidate response per committee member and, if enough of them
/// are OK responses, returns a [`FlexibleFindResult::OkResponses`] delivering
/// between `min_responses` and `max_responses` of them (see
/// [`select_flexible_responses`]).
///
/// Otherwise checks for error conditions:
/// - **TooManyRejects**: more nodes returned rejects than the slack
///   allows (`committee.len() - min_responses`).
/// - **ResponsesTooLarge**: even the smallest `min_responses` many OK responses
///   (approximated by `count_bytes()`) exceed [`MAX_CANISTER_HTTP_PAYLOAD_SIZE`].
/// - **OutOfCycles**: delivering a response can never be paid for again (see
///   [`check_flexible_out_of_cycles`]).
/// - **Pending**: not enough data to decide yet.
///
/// Both of the results that deliver response bodies — `OkResponses` and
/// `TooManyRejects` — are topped up with [extra
/// shares](FlexibleCanisterHttpResponses::extra_shares) as needed to cover their
/// consensus cost (see [`fund_flexible_selection`]).
///
/// The cloning of the share is only done when building the [`FlexibleCanisterHttpResponses`] result.
pub(crate) fn find_flexible_result(
    callback_id: CallbackId,
    grouped_shares: &BTreeMap<CanisterHttpResponseMetadata, Vec<&CanisterHttpResponseShare>>,
    committee: &BTreeSet<NodeId>,
    min_responses: u32,
    max_responses: u32,
    accumulated_size: usize,
    max_payload_size: NumBytes,
    context: &CanisterHttpRequestContext,
    pool_access: &dyn CanisterHttpPool,
) -> FlexibleFindResult {
    let mut all_shares: Vec<&CanisterHttpResponseShare> = Vec::new();
    let mut ok_candidates: Vec<FlexibleCandidate> = Vec::new();
    let mut reject_candidates: Vec<FlexibleCandidate> = Vec::new();
    // Tracks all signers processed (both OK and reject).
    let mut seen_signers = BTreeSet::new();
    // We don't care about the grouping by metadata, so flatten the shares in two loops.
    for (metadata, shares) in grouped_shares {
        for &share in shares {
            let signer = share.signature.signer;
            if !committee.contains(&signer) || !seen_signers.insert(signer) {
                continue;
            }
            let Some(response) = pool_access.get_response_content_by_hash(&metadata.content_hash)
            else {
                continue;
            };
            all_shares.push(share);
            let candidate = FlexibleCandidate {
                size: FlexibleCanisterHttpResponseWithProof::count_bytes(&response, share),
                response,
                share,
            };
            if candidate.response.content.is_reject() {
                reject_candidates.push(candidate);
            } else {
                ok_candidates.push(candidate);
            }
        }
    }
    // Order response candidates by size, so that smallest ones are selected first.
    let by_size = |candidate: &FlexibleCandidate| {
        (
            candidate.size,
            candidate.share.content.spent(),
            candidate.share.signature.signer,
        )
    };
    ok_candidates.sort_unstable_by_key(by_size);
    reject_candidates.sort_unstable_by_key(by_size);
    // Order all shares by the cycles they spent, so that the ones with the highest
    // unspent allowance are selected first, as extra shares for funding candidates.
    all_shares.sort_unstable_by_key(|share| (share.content.spent(), share.signature.signer));
    let min_responses = min_responses as usize;

    // 1. Enough OK responses collected?
    // A group that cannot be paid for or does not fit falls through to the checks below.
    if ok_candidates.len() >= min_responses {
        if let Some(selection) = select_flexible_responses(
            &ok_candidates,
            &all_shares,
            callback_id,
            /* min_to_select = */ min_responses,
            /* max_to_select = */ max_responses as usize,
            /* min_responses = */ min_responses as u32,
            accumulated_size,
            max_payload_size,
            context,
        ) {
            let group = FlexibleCanisterHttpResponses {
                callback_id,
                responses: into_responses_with_proof(ok_candidates, selection.count),
                extra_shares: selection.extra_shares.into_iter().cloned().collect(),
                initial_spent: selection.initial_spent,
            };
            let group_size = group.count_bytes();
            return FlexibleFindResult::OkResponses(group, group_size);
        }
    }
    // 2. Too many nodes returned rejects (so that we can never reach min_responses OK responses)?
    else if reject_candidates.len() > committee.len().saturating_sub(min_responses) {
        // Delivering the smallest `min_rejects` of them already proves the error;
        // the rest is included only if they fit and are covered.
        let min_rejects = committee.len().saturating_sub(min_responses) + 1;
        if let Some(selection) = select_flexible_responses(
            &reject_candidates,
            &all_shares,
            callback_id,
            /* min_to_select = */ min_rejects,
            /* max_to_select = */ reject_candidates.len(),
            /* min_responses = */ min_responses as u32,
            accumulated_size,
            max_payload_size,
            context,
        ) {
            let error = FlexibleCanisterHttpError::TooManyRejects {
                callback_id,
                reject_responses: into_responses_with_proof(reject_candidates, selection.count),
                extra_shares: selection.extra_shares.into_iter().cloned().collect(),
                initial_spent: selection.initial_spent,
            };
            let error_size = error.count_bytes();
            return FlexibleFindResult::Error(error, error_size);
        }
    }

    // 3. Even the smallest OK responses exceed the absolute payload limit?
    // Unseen responses could still submit small OK responses, so we account for them.
    let num_unseen = committee.len().saturating_sub(all_shares.len());
    let min_known_ok_needed = min_responses.saturating_sub(num_unseen);
    if ok_candidates.len() >= min_known_ok_needed {
        let smallest_content_sum: usize = ok_candidates
            .iter()
            .take(min_known_ok_needed)
            .map(|candidate| candidate.size)
            .sum();

        if smallest_content_sum > MAX_CANISTER_HTTP_PAYLOAD_SIZE {
            let all_seen_shares: Vec<_> = ok_candidates
                .iter()
                .chain(reject_candidates.iter())
                .map(|candidate| candidate.share.clone())
                .collect();
            let error = FlexibleCanisterHttpError::ResponsesTooLarge {
                callback_id,
                all_seen_shares,
                total_requests: committee.len() as u32,
                min_responses: min_responses as u32,
            };
            let error_size = error.count_bytes();
            return FlexibleFindResult::Error(error, error_size);
        }
    }

    // 4. Can delivering a response ever be paid for?
    if let Ok(proof) = check_flexible_out_of_cycles(
        all_shares.iter().copied(),
        committee.len(),
        min_responses as u32,
        callback_id,
        context,
    ) {
        let error = FlexibleCanisterHttpError::OutOfCycles {
            callback_id,
            all_seen_shares: all_shares.into_iter().cloned().collect(),
            min_cost: proof.min_cost,
            unspent_allowance: proof.unspent_allowance,
        };
        let error_size = error.count_bytes();
        return FlexibleFindResult::Error(error, error_size);
    }

    // 5. Not enough data yet
    FlexibleFindResult::Pending
}

/// Turns the first `selected` of `candidates` into the entries of a flexible
/// result, dropping the rest (whose shares may still be included as [extra
/// shares](FlexibleCanisterHttpResponses::extra_shares)).
fn into_responses_with_proof(
    candidates: Vec<FlexibleCandidate>,
    selected: usize,
) -> Vec<FlexibleCanisterHttpResponseWithProof> {
    candidates
        .into_iter()
        .take(selected)
        .map(|candidate| FlexibleCanisterHttpResponseWithProof {
            response: candidate.response,
            proof: candidate.share.clone(),
        })
        .collect()
}

struct FlexibleSelection<'a> {
    /// How many of the candidates were selected.
    count: usize,
    /// Any extra shares funding the selected candidates' consensus cost.
    extra_shares: Vec<&'a CanisterHttpResponseShare>,
    /// The collective cost of the selected candidates and any extra shares.
    initial_spent: Cycles,
}

/// Returns how many (up to `max_to_select`) of `candidates` to include in the payload, and
/// which extra shares of `all_shares` to fund them with. Returns `None` if even the smallest
/// `min_to_select` responses do not fit into what is left of the block, or if the committee's
/// unspent allowance can not cover their cost.
///
/// `candidates` must be ordered smallest-response-first and `all_shares` smallest-spend-first,
/// each holding at most one share per committee member.
fn select_flexible_responses<'a>(
    candidates: &[FlexibleCandidate<'a>],
    all_shares: &[&'a CanisterHttpResponseShare],
    callback_id: CallbackId,
    min_to_select: usize,
    max_to_select: usize,
    min_responses: u32,
    accumulated_size: usize,
    max_payload_size: NumBytes,
    context: &CanisterHttpRequestContext,
) -> Option<FlexibleSelection<'a>> {
    let max_to_select = max_to_select.min(candidates.len());

    // Start with as many candidates as possible (up to `max_to_select`). Check whether the
    // current selection is funded (potentially by adding extra shares) and fits into the
    // block. If not, give up the largest response and try again with one fewer.
    for selected in (min_to_select..=max_to_select).rev() {
        let selected = &candidates[..selected];
        // Compute the cost of the current selection without any extra shares.
        let selected_spend = flexible_initial_spent(
            selected.iter().map(|candidate| candidate.share),
            std::iter::empty(),
            context.subnet_size,
            min_responses,
        );
        let selected_signers: BTreeSet<_> = selected
            .iter()
            .map(|candidate| candidate.share.signature.signer)
            .collect();
        // If the current selection is not covered by unspent allowance, try to fund it
        // by adding extra shares.
        let Some((extra_shares, extra_spent)) = fund_flexible_selection(
            selected_spend,
            selected.len(),
            &selected_signers,
            all_shares,
            callback_id,
            context,
        ) else {
            continue;
        };
        let size = FlexibleCanisterHttpResponses::base_count_bytes()
            + selected
                .iter()
                .map(|candidate| candidate.size)
                .sum::<usize>()
            + extra_shares
                .iter()
                .map(|share| share.count_bytes())
                .sum::<usize>();
        // Return the selection if it also fits into the block.
        if NumBytes::new((accumulated_size + size) as u64) < max_payload_size {
            return Some(FlexibleSelection {
                count: selected.len(),
                extra_shares,
                initial_spent: selected_spend + extra_spent,
            });
        }
    }
    None
}

/// Picks the fewest of `all_shares` required to cover the collective spend of
/// `selected_count` many responses with unspent allowance.
/// Returns the chosen shares together with the spend they add, or `None` if
/// even all of them together cannot cover the `selected_spend`.
fn fund_flexible_selection<'a>(
    selected_spend: Cycles,
    selected_count: usize,
    selected_signers: &BTreeSet<NodeId>,
    all_shares: &[&'a CanisterHttpResponseShare],
    callback_id: CallbackId,
    context: &CanisterHttpRequestContext,
) -> Option<(Vec<&'a CanisterHttpResponseShare>, Cycles)> {
    // Replicas that deliver a response already contribute their allowance.
    let mut fundable = all_shares
        .iter()
        .filter(|share| !selected_signers.contains(&share.signature.signer));
    let mut extra_shares = Vec::new();
    let mut extra_spent = Cycles::zero();

    loop {
        if check_initial_spent_within_limit(
            selected_spend + extra_spent,
            selected_count + extra_shares.len(),
            callback_id,
            context,
            None,
        )
        .is_ok()
        {
            // Return the chosen extra shares and the spend they add, if the
            // candidates are now covered by unspent allowance.
            return Some((extra_shares, extra_spent));
        }
        // Else: Add another share if one exists.
        let share = fundable.next()?;
        extra_spent += share.content.spent();
        extra_shares.push(*share);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_error_types::RejectCode;
    use ic_test_utilities_types::ids::test_replica_version;
    use ic_types::{
        CanisterId, NumberOfNodes,
        canister_http::{
            CANDID_OVERHEAD_RESERVE_BYTES, CanisterHttpMethod, CanisterHttpReject,
            MAX_CANISTER_HTTP_RESPONSE_BYTES, MAX_HTTP_OUTCALL_SPEND_FREE_SUBNET,
            MAXIMUM_CANISTER_HTTP_ERROR_MESSAGE_BYTES, PricingVersion, RefundStatus, Replication,
        },
        crypto::{CryptoHash, CryptoHashOf},
        messages::{NO_DEADLINE, Request},
        time::UNIX_EPOCH,
    };
    use ic_types_cycles::{CanisterCyclesCostSchedule, Cycles};

    fn receipt(spent: u128) -> CanisterHttpPaymentReceipt {
        CanisterHttpPaymentReceipt {
            spent: Cycles::new(spent),
        }
    }

    /// Builds a minimal request context pinning the given cost schedule and
    /// per-replica allowance — the only fields [`check_spent_within_limit`] reads.
    fn context(
        cost_schedule: CanisterCyclesCostSchedule,
        per_replica_allowance: Cycles,
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
            replication: Replication::FullyReplicated,
            pricing_version: PricingVersion::Legacy,
            refund_status: RefundStatus {
                per_replica_allowance,
                ..RefundStatus::default()
            },
            registry_version: RegistryVersion::from(1),
            subnet_size: NumberOfNodes::from(13),
            cost_schedule,
        }
    }

    #[test]
    fn spent_within_allowance_is_accepted_when_charging() {
        assert!(
            check_spent_within_limit(
                &receipt(50),
                &context(CanisterCyclesCostSchedule::Normal, Cycles::new(100)),
            )
            .is_ok()
        );
    }

    #[test]
    fn spent_exceeding_allowance_is_rejected_when_charging() {
        assert!(matches!(
            check_spent_within_limit(
                &receipt(101),
                &context(CanisterCyclesCostSchedule::Normal, Cycles::new(100)),
            ),
            Err(InvalidCanisterHttpPayloadReason::SpentExceedsLimit { .. })
        ));
    }

    #[test]
    fn spent_exceeding_zero_allowance_is_rejected_on_normal_schedule() {
        // A zero allowance on a charging subnet (e.g. the caller paid exactly the
        // base fee) must still reject any nonzero spend.
        assert!(matches!(
            check_spent_within_limit(
                &receipt(1),
                &context(CanisterCyclesCostSchedule::Normal, Cycles::zero()),
            ),
            Err(InvalidCanisterHttpPayloadReason::SpentExceedsLimit { .. })
        ));
    }

    #[test]
    fn spent_exceeding_allowance_is_accepted_on_free_schedule() {
        // Free subnets may report a spend exceeding the (zero) allowance for cost
        // accounting; nothing is charged. It is bounded only by the free-subnet
        // maximum, which the spend here stays well below.
        assert!(
            check_spent_within_limit(
                &receipt(1_000_000),
                &context(CanisterCyclesCostSchedule::Free, Cycles::zero()),
            )
            .is_ok()
        );
    }

    #[test]
    fn spent_at_free_subnet_maximum_is_accepted() {
        // A spend exactly at the free-subnet maximum is still accepted.
        assert!(
            check_spent_within_limit(
                &receipt(MAX_HTTP_OUTCALL_SPEND_FREE_SUBNET.get()),
                &context(CanisterCyclesCostSchedule::Free, Cycles::zero()),
            )
            .is_ok()
        );
    }

    /// Checks `content_size` against the limit, for a response of the given kind.
    fn check_size(
        content_size: u32,
        is_reject: bool,
        context: &CanisterHttpRequestContext,
    ) -> Result<(), InvalidCanisterHttpPayloadReason> {
        let callback_id = CallbackId::from(1);
        let metadata = CanisterHttpResponseMetadata {
            id: callback_id,
            content_hash: CryptoHashOf::new(CryptoHash(vec![])),
            content_size,
            is_reject,
            replica_version: test_replica_version(),
        };
        check_content_size_within_limit(&metadata, callback_id, context)
    }

    #[test]
    fn content_size_of_a_successful_response_is_bounded_by_the_response_maximum() {
        let ctx = context(CanisterCyclesCostSchedule::Normal, Cycles::new(100));
        let limit = (MAX_CANISTER_HTTP_RESPONSE_BYTES + CANDID_OVERHEAD_RESERVE_BYTES) as u32;
        assert!(check_size(limit, /* is_reject = */ false, &ctx).is_ok());
        assert!(matches!(
            check_size(limit + 1, /* is_reject = */ false, &ctx),
            Err(InvalidCanisterHttpPayloadReason::ContentSizeExceedsLimit {
                content_size,
                limit: reported,
                ..
            }) if content_size == limit + 1 && reported == limit as u64
        ));
    }

    #[test]
    fn content_size_of_a_reject_is_bounded_by_the_message_maximum() {
        let ctx = context(CanisterCyclesCostSchedule::Normal, Cycles::new(100));
        let largest_reject = CanisterHttpReject {
            reject_code: RejectCode::SysTransient,
            message: "m".repeat(MAXIMUM_CANISTER_HTTP_ERROR_MESSAGE_BYTES),
        };
        let limit = largest_reject.count_bytes() as u32;
        // Far below what a successful response would be allowed.
        assert!((limit as u64) < MAX_CANISTER_HTTP_RESPONSE_BYTES);
        assert!(check_size(limit, /* is_reject = */ true, &ctx).is_ok());
        assert!(matches!(
            check_size(limit + 1, /* is_reject = */ true, &ctx),
            Err(InvalidCanisterHttpPayloadReason::ContentSizeExceedsLimit { .. })
        ));
    }

    #[test]
    fn content_size_is_bounded_by_the_requested_max_response_bytes() {
        let mut ctx = context(CanisterCyclesCostSchedule::Normal, Cycles::new(100));
        ctx.max_response_bytes = Some(NumBytes::from(1_000));
        let limit = (1_000 + CANDID_OVERHEAD_RESERVE_BYTES) as u32;
        assert!(check_size(limit, /* is_reject = */ false, &ctx).is_ok());
        assert!(matches!(
            check_size(limit + 1, /* is_reject = */ false, &ctx),
            Err(InvalidCanisterHttpPayloadReason::ContentSizeExceedsLimit { limit: reported, .. })
                if reported == limit as u64
        ));
    }

    #[test]
    fn spent_exceeding_free_subnet_maximum_is_rejected() {
        // Free subnets may exceed their (zero) allowance, but not the free-subnet
        // maximum: the spend is bounded rather than unbounded.
        assert!(matches!(
            check_spent_within_limit(
                &receipt(MAX_HTTP_OUTCALL_SPEND_FREE_SUBNET.get() + 1),
                &context(CanisterCyclesCostSchedule::Free, Cycles::zero()),
            ),
            Err(InvalidCanisterHttpPayloadReason::SpentExceedsLimit { .. })
        ));
    }
}
