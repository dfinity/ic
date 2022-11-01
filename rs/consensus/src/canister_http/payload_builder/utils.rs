use std::collections::HashSet;

use ic_interfaces::canister_http::CanisterHttpPermanentValidationError;
use ic_types::{
    batch::{CanisterHttpPayload, ValidationContext},
    canister_http::{CanisterHttpResponseShare, CanisterHttpResponseWithConsensus},
    crypto::crypto_hash,
    messages::CallbackId,
    RegistryVersion,
};

/// Checks whether the response is consistent
///
/// Consistency means:
/// - The signed metadata is the same as the metadata of the response
/// - The content_hash is the same as the hash of the content
///
/// **NOTE**: The signature is not checked
pub(crate) fn check_response_consistency(
    response: &CanisterHttpResponseWithConsensus,
) -> Result<(), CanisterHttpPermanentValidationError> {
    let content = &response.content;
    let metadata = &response.proof.content;

    // Check metadata field consistency
    match (
        metadata.id == content.id,
        metadata.timeout == content.timeout,
    ) {
        (true, true) => (),
        _ => {
            return Err(CanisterHttpPermanentValidationError::InvalidMetadata {
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
        return Err(CanisterHttpPermanentValidationError::ContentHashMismatch {
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
) -> Result<(), CanisterHttpPermanentValidationError> {
    // Check that response has not timed out
    if response.content.timeout < context.time {
        return Err(CanisterHttpPermanentValidationError::Timeout {
            timed_out_at: response.content.timeout,
            validation_time: context.time,
        });
    }

    // Check that registry version matched
    if response.proof.content.registry_version != registry_version {
        return Err(
            CanisterHttpPermanentValidationError::RegistryVersionMismatch {
                expected: registry_version,
                received: response.proof.content.registry_version,
            },
        );
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

/// Creates a [`HashSet`] of [`CallbackId`]s from `past_payloads`
pub(crate) fn get_past_payload_ids(past_payloads: &[&CanisterHttpPayload]) -> HashSet<CallbackId> {
    past_payloads
        .iter()
        .flat_map(|payload| {
            payload
                .responses
                .iter()
                .map(|response| response.content.id)
                .chain(payload.timeouts.iter().cloned())
        })
        .collect()
}
