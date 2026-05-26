use CanisterHttpResponseContent::Reject;
use ic_consensus_utils::crypto::ConsensusCrypto;
use ic_interfaces::canister_http::{CanisterHttpPool, InvalidCanisterHttpPayloadReason};
use ic_types::{
    CountBytes, NodeId, NumBytes, RegistryVersion,
    batch::{
        FlexibleCanisterHttpError, FlexibleCanisterHttpResponseWithProof,
        FlexibleCanisterHttpResponses, MAX_CANISTER_HTTP_PAYLOAD_SIZE,
    },
    canister_http::{
        CanisterHttpResponse, CanisterHttpResponseContent, CanisterHttpResponseMetadata,
        CanisterHttpResponseReceipt, CanisterHttpResponseReceiptShare, CanisterHttpResponseShare,
        CanisterHttpResponseWithConsensus,
    },
    crypto::{Signed, crypto_hash},
    messages::CallbackId,
    signature::{BasicSignature, BasicSignatureBatch},
};
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
    let metadata = &response.proof.content.metadata;

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

/// Verifies every per-signer basic signature in the aggregated proof.
///
/// Each signer is expected to have signed a
/// [`CanisterHttpResponseReceiptShare`] consisting of the shared
/// [`CanisterHttpResponseMetadata`] and that signer's own
/// [`CanisterHttpPaymentReceipt`] (see
/// [`CanisterHttpResponseReceipt::receipt_share_of`]). The proof is
/// considered valid only if **all** of the following hold:
///   - `payment_receipts` and the signature batch have the same number
///     of entries.
///   - Every signer in the batch has a corresponding entry in
///     `payment_receipts` (enforced by `receipt_share_of` returning
///     `None`). Combined with the equal-size check, this implies the
///     two key sets are identical, so no "phantom" receipts can sneak
///     in without an authorizing signature.
///   - Each individual basic signature verifies against the reconstructed
///     per-signer message.
pub(crate) fn verify_aggregate_proof(
    proof: &Signed<
        CanisterHttpResponseReceipt,
        BasicSignatureBatch<CanisterHttpResponseReceiptShare>,
    >,
    consensus_registry_version: RegistryVersion,
    crypto: &dyn ConsensusCrypto,
) -> Result<(), InvalidCanisterHttpPayloadReason> {
    let receipt = &proof.content;
    let signatures = &proof.signature.signatures_map;
    if signatures.len() != receipt.payment_receipts.len() {
        return Err(malformed_signature(
            "payment_receipts and signatures map must have the same number of entries",
        ));
    }
    for (signer, sig) in signatures {
        let content = receipt.receipt_share_of(*signer).ok_or_else(|| {
            malformed_signature(
                "signature in aggregated proof has no corresponding payment receipt",
            )
        })?;
        let signed_share = Signed {
            content,
            signature: BasicSignature {
                signature: sig.clone(),
                signer: *signer,
            },
        };
        crypto
            .verify(&signed_share, consensus_registry_version)
            .map_err(|err| InvalidCanisterHttpPayloadReason::SignatureError(Box::new(err)))?;
    }
    Ok(())
}

fn malformed_signature(message: &str) -> InvalidCanisterHttpPayloadReason {
    InvalidCanisterHttpPayloadReason::SignatureError(Box::new(
        ic_types::crypto::CryptoError::MalformedSignature {
            algorithm: ic_types::crypto::AlgorithmId::Ed25519,
            sig_bytes: vec![],
            internal_error: message.to_string(),
        },
    ))
}

/// Validates a single [`FlexibleCanisterHttpResponseWithProof`].
///
/// Checks callback-id consistency, share validity (using
/// [`validate_response_share`]), content hash, and content size.
pub(crate) fn validate_flexible_response_with_proof(
    response_with_proof: &FlexibleCanisterHttpResponseWithProof,
    callback_id: CallbackId,
    flex_committee: &BTreeSet<NodeId>,
    seen_signers: &mut HashSet<NodeId>,
    consensus_registry_version: RegistryVersion,
    crypto: &dyn ConsensusCrypto,
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
        consensus_registry_version,
        crypto,
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

/// Validates a single [`CanisterHttpResponseShare`] (metadata + signature).
///
/// Checks callback-id consistency, duplicate signers, committee membership,
/// registry version, and performs signature verification.
pub(crate) fn validate_response_share(
    share: &CanisterHttpResponseShare,
    callback_id: CallbackId,
    flex_committee: &BTreeSet<NodeId>,
    seen_signers: &mut HashSet<NodeId>,
    consensus_registry_version: RegistryVersion,
    crypto: &dyn ConsensusCrypto,
) -> Result<(), InvalidCanisterHttpPayloadReason> {
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

    if share.content.registry_version() != consensus_registry_version {
        return Err(InvalidCanisterHttpPayloadReason::RegistryVersionMismatch {
            expected: consensus_registry_version,
            received: share.content.registry_version(),
        });
    }

    crypto
        .verify(share, consensus_registry_version)
        .map_err(|err| InvalidCanisterHttpPayloadReason::SignatureError(Box::new(err)))?;

    Ok(())
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
/// response hash. If found, returns a [`CanisterHttpResponseReceipt`]
/// (the shared metadata with the per-signer `payment_receipts` map
/// populated from the contributing shares), the collected signatures,
/// and the response body.
pub(crate) fn find_fully_replicated_response(
    grouped_shares: &BTreeMap<CanisterHttpResponseMetadata, Vec<&CanisterHttpResponseShare>>,
    threshold: usize,
    pool_access: &dyn CanisterHttpPool,
) -> Option<(
    CanisterHttpResponseReceipt,
    BTreeSet<BasicSignature<CanisterHttpResponseReceiptShare>>,
    CanisterHttpResponse,
)> {
    grouped_shares.iter().find_map(|(metadata, shares)| {
        let signers: BTreeSet<_> = shares.iter().map(|share| share.signature.signer).collect();
        if signers.len() >= threshold {
            pool_access
                .get_response_content_by_hash(&metadata.content_hash)
                .map(|content| {
                    (
                        aggregate_receipt_from_shares(metadata.clone(), shares),
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
/// If found, returns a [`CanisterHttpResponseReceipt`] carrying only the
/// designated node's receipt, the single signature, and the response body.
pub(crate) fn find_non_replicated_response(
    grouped_shares: &BTreeMap<CanisterHttpResponseMetadata, Vec<&CanisterHttpResponseShare>>,
    designated_node_id: &NodeId,
    pool_access: &dyn CanisterHttpPool,
) -> Option<(
    CanisterHttpResponseReceipt,
    BTreeSet<BasicSignature<CanisterHttpResponseReceiptShare>>,
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
                            aggregate_receipt_from_shares(metadata.clone(), &[correct_share]),
                            BTreeSet::from([correct_share.signature.clone()]),
                            content,
                        )
                    })
            })
    })
}

/// Builds the aggregated receipt from a slice of contributing shares:
/// the shared metadata together with a per-signer `payment_receipts`
/// map populated from each share's own payment receipt. In practice the
/// upstream code only feeds at most one share per signer.
pub(crate) fn aggregate_receipt_from_shares(
    metadata: CanisterHttpResponseMetadata,
    shares: &[&CanisterHttpResponseShare],
) -> CanisterHttpResponseReceipt {
    let payment_receipts = shares
        .iter()
        .map(|share| {
            (
                share.signature.signer,
                share.content.payment_receipt.clone(),
            )
        })
        .collect();
    CanisterHttpResponseReceipt {
        metadata,
        payment_receipts,
    }
}

/// Estimates the byte size of a [`CanisterHttpResponseWithConsensus`] before
/// the proof has been aggregated.
///
/// This function mirrors the implementation of
/// `CanisterHttpResponseWithConsensus::count_bytes()`:
///   proof.count_bytes()  → receipt.count_bytes() + Σ share.count_bytes()
///   content.count_bytes() → content.count_bytes()
pub(crate) fn estimate_response_with_consensus_size(
    receipt: &CanisterHttpResponseReceipt,
    shares: &BTreeSet<BasicSignature<CanisterHttpResponseReceiptShare>>,
    content: &CanisterHttpResponse,
) -> usize {
    receipt.count_bytes()
        + shares.iter().map(|s| s.count_bytes()).sum::<usize>()
        + content.count_bytes()
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
    pool_access: &dyn CanisterHttpPool,
) -> FlexibleFindResult {
    let mut entries_sorted_asc: Vec<_> = grouped_shares.iter().collect();
    entries_sorted_asc.sort_unstable_by_key(|(metadata, _)| metadata.content_size);

    let min_responses = min_responses as usize;
    let mut ok_responses: Vec<(CanisterHttpResponse, &CanisterHttpResponseShare)> = Vec::new();
    let mut ok_responses_size = size_of::<CallbackId>();
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
            },
            ok_responses_size,
        );
    }

    // 2. Too many nodes returned rejects (so that we can never reach min_responses OK responses)?
    if reject_responses.len() > committee.len().saturating_sub(min_responses) {
        let error = FlexibleCanisterHttpError::TooManyRejects {
            callback_id,
            reject_responses: reject_responses
                .into_iter()
                .map(|(response, share)| FlexibleCanisterHttpResponseWithProof {
                    response,
                    proof: share.clone(),
                })
                .collect(),
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
