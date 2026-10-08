//! The canister HTTP payload of a block.
//!
//! The canister HTTP payload sits in a block as an opaque byte string: a
//! sequence of length-delimited [`pb::CanisterHttpResponseMessage`] protos (see
//! [`ic_types::batch::iterator_to_bytes`]). Some of those messages carry a full
//! [`CanisterHttpResponse`], each accompanied, in the very same message, by the
//! hash of its content: the `content_hash` of the metadata that the response's
//! signers signed over.
//!
//! That hash is all a receiver of the block needs to come up with the content
//! itself, whatever kind of outcall it answers, so the block does not need to carry
//! it. The receiver can always fetch it from the peers that advertise the block,
//! which serve it out of their canister HTTP pool or, once that has dropped it, out
//! of the block itself (see [`find_response`]). Its own canister HTTP pool usually
//! saves it that round trip, for as long as the outcall is in flight in its own
//! latest state:
//!
//! * A fully replicated response is withheld from the gossip, as every replica is
//!   expected to produce it itself, so the receiver holds it if its own adapter
//!   returned that very content.
//! * A non-replicated or flexible response is gossiped along with its share, as
//!   its peers cannot produce it themselves, so the receiver holds it once it has
//!   validated that share.

use ic_protobuf::types::v1 as pb;
use ic_types::{
    batch::slice_to_messages_iter,
    canister_http::CanisterHttpResponse,
    crypto::{CryptoHash, CryptoHashOf},
};

use super::types::CanisterHttpResponseContentHash;

/// A place in the payload where the content of a response belongs, together with
/// the hash of that content.
type ResponseSlot<'a> = (
    CanisterHttpResponseContentHash,
    &'a mut Option<pb::CanisterHttpResponse>,
);

/// Returns the response with the given content hash, if the payload delivers it.
///
/// Used to serve a response that a peer is missing out of a block we still have,
/// for the case where it is no longer in our canister HTTP pool. Decodes one
/// message at a time, so that it gets no further than the one delivering the
/// response.
pub(crate) fn find_response(
    payload_bytes: &[u8],
    content_hash: &CanisterHttpResponseContentHash,
) -> Option<CanisterHttpResponse> {
    slice_to_messages_iter::<pb::CanisterHttpResponseMessage>(payload_bytes)
        .map_while(Result::ok)
        .find_map(|mut message| {
            response_slots(&mut message)
                .into_iter()
                .filter(|(hash, _)| hash == content_hash)
                .find_map(|(_, response)| CanisterHttpResponse::try_from(response.take()?).ok())
        })
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
fn response_slots(message: &mut pb::CanisterHttpResponseMessage) -> Vec<ResponseSlot<'_>> {
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
    use ic_types_test_utils::ids::{NODE_1, NODE_2};

    use crate::fetch_stripped_artifact::test_utils::{
        fake_canister_http_payload, fake_canister_http_reject, fake_canister_http_response,
        fake_canister_http_response_message, fake_canister_http_timeout_message,
        fake_flexible_canister_http_responses_message,
        fake_flexible_canister_http_too_many_rejects_message,
        fake_stripped_canister_http_response_message,
    };

    use super::*;

    fn hash_of(response: &CanisterHttpResponse) -> CanisterHttpResponseContentHash {
        ic_types::crypto::crypto_hash(response)
    }

    #[test]
    fn find_response_test() {
        let other = fake_canister_http_response(2, 1024);

        // Whichever kind of message delivers a response, its content can be found
        // by the hash the message carries alongside it. Note that the rejects of a
        // failed flexible outcall are delivered too, by a `FlexibleError`.
        let success = fake_canister_http_response(1, 1024);
        let reject = fake_canister_http_reject(1);
        for (response, payload) in [
            (
                &success,
                fake_canister_http_payload(vec![fake_canister_http_response_message(
                    &success,
                    &[NODE_1],
                )]),
            ),
            (
                &success,
                fake_canister_http_payload(vec![fake_canister_http_response_message(
                    &success,
                    &[NODE_1, NODE_2],
                )]),
            ),
            (
                &success,
                fake_canister_http_payload(vec![fake_flexible_canister_http_responses_message(
                    1,
                    &[(success.clone(), NODE_1)],
                )]),
            ),
            (
                &reject,
                fake_canister_http_payload(vec![
                    fake_flexible_canister_http_too_many_rejects_message(
                        1,
                        &[(reject.clone(), NODE_1)],
                    ),
                ]),
            ),
            // A response that a later message than the first delivers.
            (
                &success,
                fake_canister_http_payload(vec![
                    fake_canister_http_timeout_message(3),
                    fake_canister_http_response_message(&success, &[NODE_1]),
                ]),
            ),
        ] {
            assert_eq!(
                find_response(&payload, &hash_of(response)).as_ref(),
                Some(response)
            );
            assert_eq!(find_response(&payload, &hash_of(&other)), None);
        }
    }

    /// A block that passed validation always carries every response, as a payload
    /// with an emptied slot does not even decode. Should one get here anyway, the
    /// emptied slot must not be served as if it held the response.
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

    /// A slot whose response does not decode cannot be part of a block that passed
    /// validation either. Should one get here anyway, it does not end the search: a
    /// later slot may deliver the very same content.
    #[test]
    fn find_response_skips_an_undecodable_response_test() {
        use pb::canister_http_response_message::MessageType;

        let response = fake_canister_http_response(1, 1024);
        let mut undecodable = fake_canister_http_response_message(&response, &[NODE_1]);
        let Some(MessageType::Response(with_consensus)) = undecodable.message_type.as_mut() else {
            panic!("Expected a response message");
        };
        with_consensus.response.as_mut().unwrap().content = None;
        let payload = fake_canister_http_payload(vec![
            undecodable,
            fake_canister_http_response_message(&response, &[NODE_2]),
        ]);

        assert_eq!(find_response(&payload, &hash_of(&response)), Some(response));
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
