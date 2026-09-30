//! The canister HTTP payload of a block.
//!
//! The canister HTTP payload sits in a block as an opaque byte string: a
//! sequence of length-delimited [`pb::CanisterHttpResponseMessage`] protos (see
//! [`ic_types::batch::iterator_to_bytes`]). Some of those messages carry a full
//! [`CanisterHttpResponse`], and a block does not need to repeat a response that
//! its own proof shows the peers to be holding already: see
//! [`for_each_response_slot`] for why that is the case for every one of them.
//!
//! Every such response is accompanied, in the very same message, by the hash of
//! its content: the `content_hash` of the metadata that the response's signers
//! signed over. That hash is all a receiver needs in order to look the content up
//! in its own canister HTTP pool, or to fetch it from a peer, which is why
//! stripping a response only ever *removes* bytes from a block, and never has to
//! add any.

use ic_protobuf::types::v1 as pb;
use ic_types::{
    batch::slice_to_messages,
    canister_http::CanisterHttpResponse,
    crypto::{CryptoHash, CryptoHashOf},
};
use thiserror::Error;

use super::types::CanisterHttpResponseContentHash;

/// The canister http payload of a block could not be read.
#[derive(Debug, PartialEq, Error)]
pub(crate) enum CanisterHttpPayloadError {
    #[error("The canister http payload could not be parsed: {0}")]
    DecodeError(String),
}

/// Returns the response with the given content hash, if the payload delivers it.
///
/// Used to serve a response that a peer is missing out of a block we still have,
/// for the case where it is no longer in our canister HTTP pool.
pub(crate) fn find_response(
    payload_bytes: &[u8],
    content_hash: &CanisterHttpResponseContentHash,
) -> Option<CanisterHttpResponse> {
    let mut messages = parse(payload_bytes).ok()?;

    let mut found = None;
    for_each_response_slot(&mut messages, |hash, response| {
        if found.is_none() && hash == *content_hash {
            found = response.take();
        }
    });

    found.and_then(|response| CanisterHttpResponse::try_from(response).ok())
}

fn parse(
    payload_bytes: &[u8],
) -> Result<Vec<pb::CanisterHttpResponseMessage>, CanisterHttpPayloadError> {
    slice_to_messages(payload_bytes)
        .map_err(|err| CanisterHttpPayloadError::DecodeError(err.to_string()))
}

/// Calls `f` once for every response slot of the payload, passing the hash of the
/// content that belongs in the slot together with the slot itself.
///
/// Every response a payload delivers may be stripped from it, because in every
/// case the replicas that signed for it already hold its content:
///
/// * A fully replicated response is proved by a quorum of `n - f` signatures, one
///   per replica that ran the outcall itself and signed this very content, so at
///   least that many replicas have it in their canister HTTP pool. They withhold
///   it from the gossip, on the grounds that their peers can produce it
///   themselves, but they will still serve it to a peer that asks for it by hash.
/// * A non-replicated or flexible response is produced by a single replica, which
///   therefore gossips it to everyone along with its share.
///
/// The messages that carry no response at all — a timeout, a divergence proof, an
/// out-of-cycles error or an asynchronous receipt — have no slot to visit.
///
/// A slot whose content hash cannot be read is skipped: such a message cannot be
/// part of a valid block, and there is nothing to identify its content by.
fn for_each_response_slot<F>(messages: &mut [pb::CanisterHttpResponseMessage], mut f: F)
where
    F: FnMut(CanisterHttpResponseContentHash, &mut Option<pb::CanisterHttpResponse>),
{
    use pb::canister_http_response_message::MessageType;
    use pb::flexible_canister_http_error::ErrorDetails;

    for message in messages {
        match message.message_type.as_mut() {
            Some(MessageType::Response(response)) => {
                let content_hash = CryptoHashOf::new(CryptoHash(response.hash.clone()));
                f(content_hash, &mut response.response);
            }
            Some(MessageType::FlexibleResponses(group)) => {
                for_each_response_with_proof(&mut group.responses, &mut f);
            }
            Some(MessageType::FlexibleError(error)) => {
                if let Some(ErrorDetails::TooManyRejects(rejects)) = error.error_details.as_mut() {
                    for_each_response_with_proof(&mut rejects.reject_responses, &mut f);
                }
            }
            Some(
                MessageType::Timeout(_)
                | MessageType::DivergenceResponse(_)
                | MessageType::OutOfCycles(_)
                | MessageType::AsyncReceipt(_),
            )
            | None => {}
        }
    }
}

fn for_each_response_with_proof<F>(
    responses: &mut [pb::FlexibleCanisterHttpResponseWithProof],
    f: &mut F,
) where
    F: FnMut(CanisterHttpResponseContentHash, &mut Option<pb::CanisterHttpResponse>),
{
    for response in responses {
        let Some(content_hash) = response
            .proof
            .as_ref()
            .and_then(|proof| proof.metadata.as_ref())
            .map(|metadata| CryptoHashOf::new(CryptoHash(metadata.content_hash.clone())))
        else {
            continue;
        };
        f(content_hash, &mut response.response);
    }
}

#[cfg(test)]
mod tests {
    use ic_types_test_utils::ids::{NODE_1, NODE_2};

    use crate::fetch_stripped_artifact::test_utils::{
        fake_canister_http_payload, fake_canister_http_response,
        fake_canister_http_response_message, fake_flexible_canister_http_responses_message,
        fake_stripped_canister_http_response_message,
    };

    use super::*;

    fn hash_of(response: &CanisterHttpResponse) -> CanisterHttpResponseContentHash {
        ic_types::crypto::crypto_hash(response)
    }

    #[test]
    fn find_response_test() {
        let response = fake_canister_http_response(1, 1024);
        let other = fake_canister_http_response(2, 1024);

        // Whichever kind of message delivers a response, its content can be found
        // by the hash the message carries alongside it.
        for payload in [
            fake_canister_http_payload(vec![fake_canister_http_response_message(
                &response,
                &[NODE_1],
            )]),
            fake_canister_http_payload(vec![fake_canister_http_response_message(
                &response,
                &[NODE_1, NODE_2],
            )]),
            fake_canister_http_payload(vec![fake_flexible_canister_http_responses_message(
                1,
                &[(response.clone(), NODE_1)],
            )]),
        ] {
            assert_eq!(
                find_response(&payload, &hash_of(&response)).as_ref(),
                Some(&response)
            );
            assert_eq!(find_response(&payload, &hash_of(&other)), None);
        }
    }

    /// A payload that no longer carries the content has nothing to serve.
    #[test]
    fn find_response_in_stripped_payload_test() {
        let response = fake_canister_http_response(1, 1024);
        let payload =
            fake_canister_http_payload(vec![fake_stripped_canister_http_response_message(
                &response,
                &[NODE_1],
            )]);

        assert_eq!(find_response(&payload, &hash_of(&response)), None);
    }

    #[test]
    fn malformed_payload_test() {
        let garbage = vec![0xff; 16];

        assert_eq!(
            find_response(&garbage, &hash_of(&fake_canister_http_response(1, 0))),
            None
        );
    }
}
