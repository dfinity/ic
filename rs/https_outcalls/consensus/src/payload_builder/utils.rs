use CanisterHttpResponseContent::Reject;
use ic_interfaces::canister_http::{CanisterHttpPool, InvalidCanisterHttpPayloadReason};
use ic_types::{
    CountBytes, NodeId, NumBytes, RegistryVersion,
    batch::{
        FlexibleCanisterHttpError, FlexibleCanisterHttpResponseWithProof,
        FlexibleCanisterHttpResponses, MAX_CANISTER_HTTP_PAYLOAD_SIZE,
    },
    canister_http::{
        CanisterHttpPaymentReceipt, CanisterHttpRequestContext, CanisterHttpResponse,
        CanisterHttpResponseContent, CanisterHttpResponseMetadata, CanisterHttpResponseProof,
        CanisterHttpResponseReceipt, CanisterHttpResponseShare, CanisterHttpResponseSignature,
        CanisterHttpResponseWithConsensus,
    },
    crypto::{Signed, crypto_hash},
    messages::CallbackId,
    signature::{BasicSigBatchEntry, BasicSignature},
};
use ic_types_cycles::Cycles;
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    mem::size_of,
};

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

/// Per-replica consensus cost coefficient `N * (10 * N + 600)`, where `N` is the
/// subnet size recorded in the request context.
fn consensus_cost_coefficient(subnet_size: u32) -> u128 {
    let n = subnet_size as u128;
    n * (10 * n + 600)
}

/// Computes the collective initial spent cycles for a fully-replicated (or
/// non-replicated) HTTP outcall response.
///
/// The spend is the sum of the per-replica spends claimed in the proof's payment
/// receipts, plus the consensus cost `N * (10 * N + 600) * <response_size>` of
/// including the aggregated response in a block. The messaging layer derives the
/// caller's refund from this and the per-replica allowance, and reports it as the
/// consumed-cycles metric.
pub(crate) fn fully_replicated_initial_spent(
    proof: &CanisterHttpResponseProof,
    subnet_size: u32,
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
/// `N * (2000 * N * (K - min_responses) + 100_000 * (K - min_responses))` charged
/// for every response beyond the `min_responses` required to reach consensus,
/// where `K` is the number of shares.
pub(crate) fn flexible_initial_spent<'a>(
    shares: impl Iterator<Item = &'a CanisterHttpResponseShare>,
    subnet_size: u32,
    min_responses: u32,
) -> Cycles {
    let mut spent_sum = Cycles::zero();
    let mut size_term: u128 = 0;
    let mut count: u32 = 0;
    for share in shares {
        spent_sum += share.content.payment_receipt.spent;
        size_term += 181 + share.content.content_size() as u128;
        count += 1;
    }
    let n = subnet_size as u128;
    let consensus_cost = Cycles::from(consensus_cost_coefficient(subnet_size) * size_term);
    let extra_responses = count.saturating_sub(min_responses) as u128;
    let extra_cost = Cycles::from(n * (2000 * n * extra_responses + 100_000 * extra_responses));
    spent_sum + consensus_cost + extra_cost
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
        return Err(
            InvalidCanisterHttpPayloadReason::FlexibleCallbackIdMismatch {
                callback_id,
                mismatched_id: response_with_proof.response.id,
            },
        );
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

/// Validates a single [`CanisterHttpResponseShare`]'s metadata.
///
/// Checks callback-id consistency, duplicate signers, committee membership,
/// and the per-replica spend limit.
///
/// **NOTE**: The signature is not verified. Callers are expected to
/// batch-verify the signatures of all shares in the surrounding group via
/// [`BasicSigVerifier::verify_basic_sig_batch_multi_msg`].
pub(crate) fn validate_response_share(
    share: &CanisterHttpResponseShare,
    callback_id: CallbackId,
    flex_committee: &BTreeSet<NodeId>,
    seen_signers: &mut HashSet<NodeId>,
    context: &CanisterHttpRequestContext,
) -> Result<(), InvalidCanisterHttpPayloadReason> {
    check_spent_within_limit(&share.content.payment_receipt, context)?;

    if share.content.id() != callback_id {
        return Err(
            InvalidCanisterHttpPayloadReason::FlexibleCallbackIdMismatch {
                callback_id,
                mismatched_id: share.content.id(),
            },
        );
    }

    let signer = share.signature.signer;
    if !seen_signers.insert(signer) {
        return Err(InvalidCanisterHttpPayloadReason::FlexibleDuplicateSigner {
            callback_id,
            signer,
        });
    }
    if !flex_committee.contains(&signer) {
        return Err(
            InvalidCanisterHttpPayloadReason::FlexibleSignerNotInCommittee {
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
pub(crate) fn find_fully_replicated_response(
    grouped_shares: &BTreeMap<CanisterHttpResponseMetadata, Vec<&CanisterHttpResponseShare>>,
    threshold: usize,
    subnet_size: u32,
    pool_access: &dyn CanisterHttpPool,
) -> Option<CanisterHttpResponseWithConsensus> {
    grouped_shares.iter().find_map(|(metadata, shares)| {
        let signers: BTreeSet<_> = shares.iter().map(|share| share.signature.signer).collect();
        if signers.len() >= threshold {
            pool_access
                .get_response_content_by_hash(&metadata.content_hash)
                .map(|content| {
                    let proof = aggregate_shares(metadata.clone(), shares);
                    let initial_spent = fully_replicated_initial_spent(&proof, subnet_size);
                    CanisterHttpResponseWithConsensus {
                        content,
                        proof,
                        initial_spent,
                    }
                })
        } else {
            None
        }
    })
}

/// Finds a non-replicated HTTP outcall response from the designated node.
///
/// Looks through the grouped shares for one signed by `designated_node_id`.
/// If found, returns the assembled [`CanisterHttpResponseWithConsensus`].
pub(crate) fn find_non_replicated_response(
    grouped_shares: &BTreeMap<CanisterHttpResponseMetadata, Vec<&CanisterHttpResponseShare>>,
    designated_node_id: &NodeId,
    subnet_size: u32,
    pool_access: &dyn CanisterHttpPool,
) -> Option<CanisterHttpResponseWithConsensus> {
    grouped_shares.iter().find_map(|(metadata, shares)| {
        shares
            .iter()
            .find(|share| share.signature.signer == *designated_node_id)
            .and_then(|correct_share| {
                pool_access
                    .get_response_content_by_hash(&metadata.content_hash)
                    .map(|content| {
                        let proof = aggregate_shares(metadata.clone(), &[correct_share]);
                        let initial_spent = fully_replicated_initial_spent(&proof, subnet_size);
                        CanisterHttpResponseWithConsensus {
                            content,
                            proof,
                            initial_spent,
                        }
                    })
            })
    })
}

/// Result of scanning flexible HTTP outcall shares for a single callback.
pub(crate) enum FlexibleFindResult {
    /// Collected enough OK responses for consensus.
    OkResponses(FlexibleCanisterHttpResponses, usize),
    /// Detected an error condition (too many rejects or responses too large).
    Error(FlexibleCanisterHttpError, usize),
    /// Not enough data to decide yet; more shares may arrive.
    Pending,
}

/// Scans grouped shares for a flexible HTTP outcall and determines the result.
///
/// Iterates shares sorted by `content_size` ascending (preferring smaller
/// responses), collecting OK responses from distinct committee members.
///
/// If enough OK responses are gathered, returns [`FlexibleFindResult::OkResponses`].
///
/// Otherwise checks for error conditions:
/// - **TooManyRejects**: more nodes returned rejects than the slack
///   allows (`committee.len() - min_responses`).
/// - **ResponsesTooLarge**: even the smallest `min_responses` many OK responses
///   (approximated by `count_bytes()`) exceed [`MAX_CANISTER_HTTP_PAYLOAD_SIZE`].
/// - **Pending**: not enough data to decide yet.
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
    subnet_size: u32,
    pool_access: &dyn CanisterHttpPool,
) -> FlexibleFindResult {
    let mut entries_sorted_asc: Vec<_> = grouped_shares.iter().collect();
    entries_sorted_asc.sort_unstable_by_key(|(metadata, _)| metadata.content_size);

    let min_responses = min_responses as usize;
    let mut ok_responses: Vec<(CanisterHttpResponse, &CanisterHttpResponseShare)> = Vec::new();
    // Account for the serialized `initial_spent` field alongside the callback id.
    let mut ok_responses_size = size_of::<CallbackId>() + size_of::<Cycles>();
    // Tracks all signers processed (both OK and reject)
    let mut seen_signers = BTreeSet::new();
    let mut reject_responses: Vec<(CanisterHttpResponse, &CanisterHttpResponseShare)> = Vec::new();
    let mut all_ok_shares_sorted_asc: Vec<(&CanisterHttpResponseShare, usize)> = Vec::new();

    'outer: for (metadata, shares) in entries_sorted_asc {
        for &share in shares {
            if ok_responses.len() >= max_responses as usize {
                break 'outer;
            }
            let signer = share.signature.signer;
            if !committee.contains(&signer) || !seen_signers.insert(signer) {
                continue;
            }
            let Some(response) = pool_access.get_response_content_by_hash(&metadata.content_hash)
            else {
                continue;
            };

            if matches!(response.content, Reject(_)) {
                reject_responses.push((response, share));
                continue;
            }

            let response_with_proof_size =
                FlexibleCanisterHttpResponseWithProof::count_bytes(&response, share);
            all_ok_shares_sorted_asc.push((share, response_with_proof_size));

            let new_total = NumBytes::new(
                (accumulated_size + ok_responses_size + response_with_proof_size) as u64,
            );
            if new_total >= max_payload_size {
                // We `continue` rather than `break` here, to further populate
                // the Vec later used to detect ResponsesTooLarge errors.
                continue;
            }
            ok_responses_size += response_with_proof_size;
            ok_responses.push((response, share));
        }
    }

    // 1. Enough OK responses collected?
    if ok_responses.len() >= min_responses {
        let initial_spent = flexible_initial_spent(
            ok_responses.iter().map(|(_, share)| *share),
            subnet_size,
            min_responses as u32,
        );
        return FlexibleFindResult::OkResponses(
            FlexibleCanisterHttpResponses {
                callback_id,
                responses: ok_responses
                    .into_iter()
                    .map(|(response, share)| FlexibleCanisterHttpResponseWithProof {
                        response,
                        proof: share.clone(),
                    })
                    .collect(),
                initial_spent,
            },
            ok_responses_size,
        );
    }

    // 2. Too many nodes returned rejects (so that we can never reach min_responses OK responses)?
    if reject_responses.len() > committee.len().saturating_sub(min_responses) {
        let initial_spent = flexible_initial_spent(
            reject_responses.iter().map(|(_, share)| *share),
            subnet_size,
            min_responses as u32,
        );
        let error = FlexibleCanisterHttpError::TooManyRejects {
            callback_id,
            reject_responses: reject_responses
                .into_iter()
                .map(|(response, share)| FlexibleCanisterHttpResponseWithProof {
                    response,
                    proof: share.clone(),
                })
                .collect(),
            initial_spent,
        };
        let error_size = error.count_bytes();
        return FlexibleFindResult::Error(error, error_size);
    }

    // 3. Even the smallest OK responses exceed the absolute payload limit?
    // Unseen responses could still submit small OK responses, so we account for them.
    let num_unseen = committee.len().saturating_sub(seen_signers.len());
    let min_known_ok_needed = min_responses.saturating_sub(num_unseen);
    if all_ok_shares_sorted_asc.len() >= min_known_ok_needed {
        let smallest_content_sum: usize = all_ok_shares_sorted_asc
            .iter()
            .take(min_known_ok_needed)
            .map(|(_share, response_with_proof_size)| response_with_proof_size)
            .sum();

        if smallest_content_sum > MAX_CANISTER_HTTP_PAYLOAD_SIZE {
            let all_seen_shares: Vec<_> = all_ok_shares_sorted_asc
                .iter()
                .map(|(share, _)| (*share).clone())
                .chain(reject_responses.iter().map(|(_, share)| (*share).clone()))
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

    // 4. Not enough data yet
    FlexibleFindResult::Pending
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_types::{
        CanisterId, NumberOfNodes,
        canister_http::{
            CanisterHttpMethod, MAX_HTTP_OUTCALL_SPEND_FREE_SUBNET, PricingVersion, RefundStatus,
            Replication,
        },
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
