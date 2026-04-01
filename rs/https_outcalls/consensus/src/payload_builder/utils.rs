use ic_interfaces::canister_http::{CanisterHttpPool, InvalidCanisterHttpPayloadReason};
use ic_types::{
    CountBytes, NodeId, NumBytes, RegistryVersion,
    batch::{
        FlexibleCanisterHttpResponseWithProof, FlexibleCanisterHttpResponses, ValidationContext,
    },
    canister_http::{
        CanisterHttpResponse, CanisterHttpResponseContent, CanisterHttpResponseMetadata,
        CanisterHttpResponseShare, CanisterHttpResponseWithConsensus,
    },
    crypto::crypto_hash,
    messages::CallbackId,
    signature::BasicSignature,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    mem::size_of,
};

/// Checks whether the response is consistent
///
/// Consistency means:
/// - The signed metadata is the same as the metadata of the response
/// - The content_hash is the same as the hash of the content
/// - The content_size is the same as the size of the content
///
/// **NOTE**: The signature is not checked
pub(crate) fn check_response_consistency(
    response: &CanisterHttpResponseWithConsensus,
) -> Result<(), InvalidCanisterHttpPayloadReason> {
    let content = &response.content;
    let metadata = &response.proof.content;

    // Check metadata field consistency
    match (
        metadata.id == content.id,
        metadata.timeout == content.timeout,
    ) {
        (true, true) => (),
        _ => {
            return Err(InvalidCanisterHttpPayloadReason::InvalidMetadata {
                metadata_id: metadata.id,
                content_id: content.id,
                metadata_timeout: metadata.timeout,
                content_timeout: content.timeout,
            });
        }
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

    Ok(())
}

/// Checks whether the response is valid against the provided [`ValidationContext`]
pub(crate) fn check_response_against_context(
    registry_version: RegistryVersion,
    response: &CanisterHttpResponseWithConsensus,
    context: &ValidationContext,
) -> Result<(), InvalidCanisterHttpPayloadReason> {
    // Check that response has not timed out
    if response.content.timeout < context.time {
        return Err(InvalidCanisterHttpPayloadReason::Timeout {
            timed_out_at: response.content.timeout,
            validation_time: context.time,
        });
    }

    // Check that registry version matched
    if response.proof.content.registry_version != registry_version {
        return Err(InvalidCanisterHttpPayloadReason::RegistryVersionMismatch {
            expected: registry_version,
            received: response.proof.content.registry_version,
        });
    }

    Ok(())
}

/// Returns true if the [`CanisterHttpResponseShare`] is valid against the [`ValidationContext`]
pub(crate) fn check_share_against_context(
    registry_version: RegistryVersion,
    share: &CanisterHttpResponseShare,
    context: &ValidationContext,
) -> bool {
    share.content.timeout > context.time && share.content.registry_version == registry_version
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
        map.entry(share.content.id)
            .or_default()
            .entry(share.content.clone())
            .or_default()
            .push(share);
    }
    map
}

/// Finds a fully-replicated HTTP outcall response ready for consensus.
///
/// Iterates over response shares grouped by metadata, looking for one where
/// at least `threshold` distinct replicas produced the same response hash.
/// If found, returns the metadata, collected signatures, and response body.
pub(crate) fn find_fully_replicated_response(
    grouped_shares: &BTreeMap<CanisterHttpResponseMetadata, Vec<&CanisterHttpResponseShare>>,
    threshold: usize,
    pool_access: &dyn CanisterHttpPool,
) -> Option<(
    CanisterHttpResponseMetadata,
    BTreeSet<BasicSignature<CanisterHttpResponseMetadata>>,
    CanisterHttpResponse,
)> {
    grouped_shares.iter().find_map(|(metadata, shares)| {
        let signers: BTreeSet<_> = shares.iter().map(|share| share.signature.signer).collect();
        if signers.len() >= threshold {
            pool_access
                .get_response_content_by_hash(&metadata.content_hash)
                .map(|content| {
                    (
                        metadata.clone(),
                        shares.iter().map(|share| share.signature.clone()).collect(),
                        content,
                    )
                })
        } else {
            None
        }
    })
}

/// Finds a non-replicated HTTP outcall response from the designated node.
///
/// Looks through the grouped shares for one signed by `designated_node_id`.
/// If found, returns the metadata, the single signature, and response body.
pub(crate) fn find_non_replicated_response(
    grouped_shares: &BTreeMap<CanisterHttpResponseMetadata, Vec<&CanisterHttpResponseShare>>,
    designated_node_id: &NodeId,
    pool_access: &dyn CanisterHttpPool,
) -> Option<(
    CanisterHttpResponseMetadata,
    BTreeSet<BasicSignature<CanisterHttpResponseMetadata>>,
    CanisterHttpResponse,
)> {
    grouped_shares.iter().find_map(|(metadata, shares)| {
        shares
            .iter()
            .find(|share| share.signature.signer == *designated_node_id)
            .and_then(|correct_share| {
                pool_access
                    .get_response_content_by_hash(&metadata.content_hash)
                    .map(|content| {
                        (
                            metadata.clone(),
                            BTreeSet::from([correct_share.signature.clone()]),
                            content,
                        )
                    })
            })
    })
}

/// Estimates the byte size of a [`CanisterHttpResponseWithConsensus`] before
/// the proof has been aggregated.
///
/// This function mirrors the implementation of
/// `CanisterHttpResponseWithConsensus::count_bytes()`:
///   proof.count_bytes()  → metadata.count_bytes() + Σ share.count_bytes()
///   content.count_bytes() → content.count_bytes()
pub(crate) fn estimate_response_with_consensus_size(
    metadata: &CanisterHttpResponseMetadata,
    shares: &BTreeSet<BasicSignature<CanisterHttpResponseMetadata>>,
    content: &CanisterHttpResponse,
) -> usize {
    metadata.count_bytes()
        + shares.iter().map(|s| s.count_bytes()).sum::<usize>()
        + content.count_bytes()
}

/// Collects distinct HTTP outcall OK-responses from flexible committee members.
///
/// Gathers up to `max_responses` individually-signed `(ok-response, share)` pairs
/// from unique committee members while disregarding rejects, and skipping any
/// that would exceed `max_payload_size`.
/// Returns the group and its accumulated byte size if at least `min_responses`
/// were collected.
pub(crate) fn find_flexible_responses(
    callback_id: CallbackId,
    grouped_shares: &BTreeMap<CanisterHttpResponseMetadata, Vec<&CanisterHttpResponseShare>>,
    committee: &BTreeSet<NodeId>,
    min_responses: u32,
    max_responses: u32,
    accumulated_size: usize,
    max_payload_size: NumBytes,
    pool_access: &dyn CanisterHttpPool,
) -> Option<(FlexibleCanisterHttpResponses, usize)> {
    let mut flexible_responses = Vec::new();
    let mut flexible_responses_size = size_of::<CallbackId>();
    let mut signers = BTreeSet::new();

    'outer: for (metadata, shares) in grouped_shares {
        for share in shares {
            if flexible_responses.len() >= max_responses as usize {
                break 'outer;
            }
            if !committee.contains(&share.signature.signer)
                || !signers.insert(share.signature.signer)
            {
                continue;
            }
            if let Some(http_response) =
                pool_access.get_response_content_by_hash(&metadata.content_hash)
            {
                if matches!(
                    http_response.content,
                    CanisterHttpResponseContent::Reject(_)
                ) {
                    // Disregard rejects, as we are collecting ok-responses.
                    continue;
                }
                let response = FlexibleCanisterHttpResponseWithProof {
                    response: http_response,
                    proof: (*share).clone(),
                };
                let response_size = response.count_bytes();
                let new_total = NumBytes::new(
                    (accumulated_size + flexible_responses_size + response_size) as u64,
                );
                if new_total >= max_payload_size {
                    continue;
                }
                flexible_responses_size += response_size;
                flexible_responses.push(response);
            }
        }
    }

    if flexible_responses.len() >= min_responses as usize {
        Some((
            FlexibleCanisterHttpResponses {
                callback_id,
                responses: flexible_responses,
            },
            flexible_responses_size,
        ))
    } else {
        None
    }
}
