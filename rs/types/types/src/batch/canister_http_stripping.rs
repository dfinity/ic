//! Stripping the content of canister HTTP responses from a canister HTTP payload,
//! as P2P does before it sends a block proposal to peers.
//!
//! The canister HTTP payload sits in a block as an opaque byte string: a sequence
//! of length-delimited [`pb::CanisterHttpResponseMessage`] protos (see
//! [`iterator_to_bytes`]). Some of those messages carry a full
//! [`CanisterHttpResponse`], each accompanied, in the very same message, by the
//! hash of its content: the `content_hash` of the metadata that the response's
//! signers signed over. That hash is all a receiver of the block needs to come up
//! with the content itself, so the block sent to peers does not need to carry it.
//!
//! Declaring a stripped response costs [`STRIPPED_RESPONSE_DECLARATION_BYTES`] in
//! the stripped block proposal, and a response is only stripped when its content
//! is at least [`MIN_STRIPPED_CONTENT_BYTES`], so stripping a response never adds
//! bytes.

use std::collections::BTreeSet;

use ic_protobuf::types::v1 as pb;
use prost::Message;

use super::{iterator_to_bytes, slice_to_messages};
use crate::{
    CountBytes, NumBytes,
    canister_http::{CanisterHttpReject, CanisterHttpResponse, CanisterHttpResponseContent},
    crypto::{CryptoHash, CryptoHashOf},
};

/// The smallest response content that is worth stripping.
pub const MIN_STRIPPED_CONTENT_BYTES: usize = 64;

/// The bytes that declaring one stripped response content costs in a stripped
/// block proposal.
pub const STRIPPED_RESPONSE_DECLARATION_BYTES: usize = 36;

/// A place in a message where the content of a response belongs, together with
/// the hash of that content.
pub type ResponseSlot<'a> = (
    CryptoHashOf<CanisterHttpResponse>,
    &'a mut Option<pb::CanisterHttpResponse>,
);

/// Returns the payload with the content of every response worth stripping removed,
/// together with the hashes of the contents that were removed, or `None` if the
/// payload is to be left as it is: if there is nothing worth stripping, or if it
/// could not be parsed.
///
/// Assumes that the payload is canonically encoded, i.e. exactly what prost encodes
/// its messages to, as payload validation requires. A receiver puts the payload back
/// together by encoding what it decodes, so stripping a payload that prost would
/// encode differently, e.g. one with an unknown field, would hand every peer that
/// gets the block a block that it has to reject.
///
/// Note that a payload this returns need not be free of response content: anything
/// smaller than [`MIN_STRIPPED_CONTENT_BYTES`] is deliberately left where it is. The
/// returned hashes name exactly the contents that were taken out, deduplicated: two
/// committee members of a flexible outcall that produced the very same response
/// occupy two slots of the payload, but there is only one piece of content to look
/// up for both of them.
pub fn strip_responses(
    payload_bytes: &[u8],
) -> Option<(Vec<u8>, BTreeSet<CryptoHashOf<CanisterHttpResponse>>)> {
    if payload_bytes.is_empty() {
        return None;
    }

    let mut messages: Vec<pb::CanisterHttpResponseMessage> =
        slice_to_messages(payload_bytes).ok()?;

    let mut stripped = BTreeSet::new();
    for message in &mut messages {
        stripped.append(&mut strip_message(message));
    }

    // Rather than pay for encoding the payload again, leave it as it is if there was
    // nothing worth stripping in it.
    if stripped.is_empty() {
        return None;
    }

    Some((
        iterator_to_bytes(messages.into_iter(), NumBytes::new(u64::MAX)),
        stripped,
    ))
}

/// The bytes that the message adds to a block proposal sent to peers: its
/// length-delimited encoding once stripped, plus the declarations of the contents
/// stripped from it.
///
/// Summed over the messages of a payload, this is at least what [`strip_responses`]
/// makes of the payload, which declares a content that several messages share only
/// once.
pub fn stripped_size(mut message: pb::CanisterHttpResponseMessage) -> usize {
    let declarations = strip_message(&mut message).len() * STRIPPED_RESPONSE_DECLARATION_BYTES;
    let len = message.encoded_len();
    prost::length_delimiter_len(len) + len + declarations
}

/// The bytes that stripping saves on a response with the given content, net of
/// declaring it: an estimate of what [`stripped_size`] measures exactly.
pub fn stripping_savings(content: &CanisterHttpResponseContent) -> usize {
    let size = content.count_bytes();
    if size >= MIN_STRIPPED_CONTENT_BYTES {
        size - STRIPPED_RESPONSE_DECLARATION_BYTES
    } else {
        0
    }
}

/// Removes the content of every response worth stripping from the message, and
/// returns the hashes of the contents removed.
fn strip_message(
    message: &mut pb::CanisterHttpResponseMessage,
) -> BTreeSet<CryptoHashOf<CanisterHttpResponse>> {
    let mut stripped = BTreeSet::new();
    for (content_hash, response) in response_slots(message) {
        if is_worth_stripping(response) {
            *response = None;
            stripped.insert(content_hash);
        }
    }
    stripped
}

/// Whether a slot holds a response whose content is worth stripping.
pub fn is_worth_stripping(response: &Option<pb::CanisterHttpResponse>) -> bool {
    response
        .as_ref()
        .is_some_and(|response| content_size(response) >= MIN_STRIPPED_CONTENT_BYTES)
}

/// The size of a response's content, the quantity its metadata reports as
/// `content_size`.
fn content_size(response: &pb::CanisterHttpResponse) -> usize {
    use pb::canister_http_response_content::Status;

    match response.content.as_ref().and_then(|c| c.status.as_ref()) {
        Some(Status::Success(payload)) => payload.len(),
        Some(Status::Reject(reject)) => {
            CanisterHttpReject::count_bytes_from_parts(reject.message.len())
        }
        None => 0,
    }
}

/// The response slots of the message, each with the hash of the content that
/// belongs in it.
///
/// The messages that carry no response have no slots: a timeout, a divergence
/// proof, an out-of-cycles error and an asynchronous receipt, as well as the errors
/// of a flexible outcall other than too many rejects, which carry shares at most.
///
/// A slot whose content hash cannot be read is skipped: such a message cannot be
/// part of a valid block, and there is nothing to identify its content by.
pub fn response_slots(message: &mut pb::CanisterHttpResponseMessage) -> Vec<ResponseSlot<'_>> {
    use pb::canister_http_response_message::MessageType;
    use pb::flexible_canister_http_error::ErrorDetails;

    match message.message_type.as_mut() {
        Some(MessageType::Response(response)) => {
            let content_hash = CryptoHashOf::new(CryptoHash(response.hash.clone()));
            vec![(content_hash, &mut response.response)]
        }
        Some(MessageType::FlexibleResponses(group)) => {
            flexible_response_slots(&mut group.responses)
        }
        Some(MessageType::FlexibleError(error)) => match error.error_details.as_mut() {
            Some(ErrorDetails::TooManyRejects(rejects)) => {
                flexible_response_slots(&mut rejects.reject_responses)
            }
            Some(
                ErrorDetails::Timeout(_)
                | ErrorDetails::ResponsesTooLarge(_)
                | ErrorDetails::OutOfCycles(_),
            )
            | None => vec![],
        },
        Some(
            MessageType::Timeout(_)
            | MessageType::DivergenceResponse(_)
            | MessageType::OutOfCycles(_)
            | MessageType::AsyncReceipt(_),
        )
        | None => vec![],
    }
}

/// The slots of a flexible outcall's responses, whose content hashes sit in their proofs.
fn flexible_response_slots(
    responses: &mut [pb::FlexibleCanisterHttpResponseWithProof],
) -> Vec<ResponseSlot<'_>> {
    responses
        .iter_mut()
        .filter_map(|response| {
            let content_hash = response
                .proof
                .as_ref()?
                .metadata
                .as_ref()?
                .content_hash
                .clone();
            Some((
                CryptoHashOf::new(CryptoHash(content_hash)),
                &mut response.response,
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::CallbackId;
    use ic_error_types::RejectCode;

    /// The threshold applies to the very quantity that a response's metadata reports
    /// as its `content_size`.
    #[test]
    fn content_size_is_the_metadata_content_size_test() {
        let reject = |message: &str| {
            CanisterHttpResponseContent::Reject(CanisterHttpReject {
                reject_code: RejectCode::SysTransient,
                message: message.to_string(),
            })
        };
        for content in [
            CanisterHttpResponseContent::Success(vec![42; 1024]),
            reject(&"x".repeat(MIN_STRIPPED_CONTENT_BYTES)),
            reject("short"),
        ] {
            let response = CanisterHttpResponse {
                id: CallbackId::new(1),
                content,
            };
            assert_eq!(
                content_size(&pb::CanisterHttpResponse::from(response.clone())),
                response.content.count_bytes()
            );
        }
    }
}
