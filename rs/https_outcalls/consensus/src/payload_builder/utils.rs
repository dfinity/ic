use ic_interfaces::canister_http::InvalidCanisterHttpPayloadReason;
use ic_types::{
    NodeId, RegistryVersion,
    batch::ValidationContext,
    canister_http::{
        CanisterHttpResponseMetadata, CanisterHttpResponseShare, CanisterHttpResponseWithConsensus,
    },
    crypto::crypto_hash,
    messages::CallbackId,
};
use std::collections::{BTreeMap, BTreeSet};

/// Checks whether the response is consistent
///
/// Consistency means:
/// - The signed metadata is the same as the metadata of the response
/// - The content_hash is the same as the hash of the content
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
