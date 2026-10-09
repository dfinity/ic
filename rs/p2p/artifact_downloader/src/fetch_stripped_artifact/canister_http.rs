//! Stripping and reassembling the canister HTTP payload of a block.
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
//!
//! The block hash covers the payload's very bytes, so a receiver has to put them
//! back together exactly. It does so by encoding again what it decodes, which only
//! reproduces the bytes if they are prost's own encoding of the payload's messages.
//! This relies on payload validation, which rejects any canister HTTP payload that
//! is not canonically encoded (`canonical_bytes_to_payload` in
//! `ic-https-outcalls-consensus`): every block an honest node holds, and thus
//! strips, carries a canonically encoded payload.
//!
//! Declaring a stripped response costs 36 bytes in the stripped block proposal,
//! and a response is only stripped when its content is at least
//! [`MIN_STRIPPED_CONTENT_BYTES`], so stripping a response never adds bytes.

use std::collections::{BTreeMap, BTreeSet};

use ic_protobuf::types::v1 as pb;
use ic_types::{
    CountBytes, NumBytes,
    batch::{
        MAX_CANISTER_HTTP_PAYLOAD_SIZE, iterator_to_bytes, slice_to_messages,
        slice_to_messages_iter,
    },
    canister_http::{CanisterHttpReject, CanisterHttpResponse},
    crypto::{CryptoHash, CryptoHashOf},
};

use thiserror::Error;

use super::types::CanisterHttpResponseContentHash;

/// A place in the payload where the content of a response belongs, together with
/// the hash of that content.
type ResponseSlot<'a> = (
    CanisterHttpResponseContentHash,
    &'a mut Option<pb::CanisterHttpResponse>,
);

/// The canister http payload of a block could not be reassembled.
#[derive(Debug, PartialEq, Error)]
pub(crate) enum CanisterHttpPayloadError {
    #[error("The canister http payload could not be parsed: {0}")]
    DecodeError(String),
    #[error("The canister http payload is missing the response with content hash {0:?}")]
    MissingResponse(CanisterHttpResponseContentHash),
    #[error(
        "The reassembled canister http payload would exceed {} bytes",
        MAX_CANISTER_HTTP_PAYLOAD_SIZE
    )]
    TooLarge,
}

/// Returns the payload with the content of every response worth stripping removed,
/// together with the hashes of the contents that were removed, or `None` if the
/// payload is to be left as it is: if there is nothing worth stripping, or if it
/// could not be parsed (the block then fails validation later on).
///
/// Assumes that the payload is canonically encoded, i.e. exactly what prost encodes
/// its messages to, as payload validation requires. A receiver puts the payload back
/// together by encoding what it decodes, so stripping a payload that prost would
/// encode differently, e.g. one with an unknown field, would hand every peer that
/// gets the block from us a block that it has to reject.
///
/// Note that a payload this returns need not be free of response content: anything
/// smaller than [`MIN_STRIPPED_CONTENT_BYTES`] is deliberately left where it is. The
/// returned hashes name exactly the contents that were taken out, deduplicated: two
/// committee members of a flexible outcall that produced the very same response
/// occupy two slots of the payload, but there is only one piece of content to look
/// up for both of them.
pub(crate) fn strip_responses(
    payload_bytes: &[u8],
) -> Option<(Vec<u8>, BTreeSet<CanisterHttpResponseContentHash>)> {
    if payload_bytes.is_empty() {
        return None;
    }

    let mut messages = parse(payload_bytes).ok()?;

    let mut stripped = BTreeSet::new();
    for message in &mut messages {
        for (content_hash, response) in response_slots(message) {
            if is_worth_stripping(response) {
                *response = None;
                stripped.insert(content_hash);
            }
        }
    }

    // Rather than pay for encoding the payload again, leave it as it is if there was
    // nothing worth stripping in it.
    if stripped.is_empty() {
        return None;
    }

    Some((encode(messages), stripped))
}

/// The smallest response content that is worth stripping.
const MIN_STRIPPED_CONTENT_BYTES: usize = 64;

/// Whether a slot holds a response whose content is worth stripping.
fn is_worth_stripping(response: &Option<pb::CanisterHttpResponse>) -> bool {
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

/// Puts the given response contents back into the payload, in place of the ones
/// that [`strip_responses`] removed, and returns the reassembled payload.
///
/// Fails if the payload is missing a response whose content was not provided, or as
/// soon as it is clear that the reassembled payload would be bigger than any valid
/// block's.
pub(crate) fn reinsert_responses(
    payload_bytes: &[u8],
    responses: &BTreeMap<CanisterHttpResponseContentHash, Option<CanisterHttpResponse>>,
) -> Result<Vec<u8>, CanisterHttpPayloadError> {
    // Stripping never grows a payload, so one stripped from a valid block is within
    // the limit as well.
    if payload_bytes.len() > MAX_CANISTER_HTTP_PAYLOAD_SIZE {
        return Err(CanisterHttpPayloadError::TooLarge);
    }
    let mut messages = parse(payload_bytes)?;

    // Putting a content back grows the payload by more than the content itself, so
    // this is a lower bound on the size of the reassembled payload.
    let mut reassembled_size = payload_bytes.len();
    for message in &mut messages {
        for (content_hash, response) in response_slots(message) {
            if response.is_some() {
                continue;
            }
            let Some(Some(content)) = responses.get(&content_hash) else {
                return Err(CanisterHttpPayloadError::MissingResponse(content_hash));
            };
            reassembled_size = reassembled_size.saturating_add(content.content.count_bytes());
            if reassembled_size > MAX_CANISTER_HTTP_PAYLOAD_SIZE {
                return Err(CanisterHttpPayloadError::TooLarge);
            }
            *response = Some(pb::CanisterHttpResponse::from(content.clone()));
        }
    }

    Ok(encode(messages))
}

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
        // The messages after one that cannot be decoded can no longer be told
        // apart, so the search ends there rather than skipping it.
        .map_while(Result::ok)
        .find_map(|mut message| {
            response_slots(&mut message)
                .into_iter()
                .filter(|(hash, _)| hash == content_hash)
                .find_map(|(_, response)| CanisterHttpResponse::try_from(response.take()?).ok())
        })
}

fn parse(
    payload_bytes: &[u8],
) -> Result<Vec<pb::CanisterHttpResponseMessage>, CanisterHttpPayloadError> {
    slice_to_messages(payload_bytes)
        .map_err(|err| CanisterHttpPayloadError::DecodeError(err.to_string()))
}

/// Encodes the messages through the very function the canister HTTP payload builder
/// uses, [`iterator_to_bytes`], so that the result is exactly what it would write for
/// them. There is no limit, so that no message is ever dropped.
fn encode(messages: Vec<pb::CanisterHttpResponseMessage>) -> Vec<u8> {
    iterator_to_bytes(messages.into_iter(), NumBytes::new(u64::MAX))
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
    use assert_matches::assert_matches;
    use ic_types_test_utils::ids::{NODE_1, NODE_2};

    use crate::fetch_stripped_artifact::test_utils::{
        fake_canister_http_payload, fake_canister_http_payload_with_every_kind,
        fake_canister_http_reject, fake_canister_http_reject_of_size, fake_canister_http_response,
        fake_canister_http_response_message, fake_canister_http_timeout_message,
        fake_flexible_canister_http_responses_message,
        fake_flexible_canister_http_too_many_rejects_message,
        fake_stripped_canister_http_response_message,
    };

    use super::*;

    fn hash_of(response: &CanisterHttpResponse) -> CanisterHttpResponseContentHash {
        ic_types::crypto::crypto_hash(response)
    }

    /// The response contents that the payload still carries itself, in the order
    /// their messages appear in it.
    fn responses_left_in_payload(payload_bytes: &[u8]) -> Vec<CanisterHttpResponse> {
        use pb::canister_http_response_message::MessageType;
        use pb::flexible_canister_http_error::ErrorDetails;

        let mut found = Vec::new();
        let mut push = |response: &Option<pb::CanisterHttpResponse>| {
            if let Some(response) = response {
                found.push(CanisterHttpResponse::try_from(response.clone()).unwrap());
            }
        };
        for message in parse(payload_bytes).unwrap() {
            match message.message_type {
                Some(MessageType::Response(response)) => push(&response.response),
                Some(MessageType::FlexibleResponses(group)) => {
                    group.responses.iter().for_each(|r| push(&r.response));
                }
                Some(MessageType::FlexibleError(error)) => {
                    if let Some(ErrorDetails::TooManyRejects(rejects)) = error.error_details {
                        rejects
                            .reject_responses
                            .iter()
                            .for_each(|r| push(&r.response));
                    }
                }
                _ => {}
            }
        }
        found
    }

    #[test]
    fn strip_and_reinsert_roundtrip_test() {
        let (payload, all) = fake_canister_http_payload_with_every_kind();

        let (stripped, stripped_hashes) =
            strip_responses(&payload).expect("Should have stripped something");

        // Every response content is gone, whatever kind of outcall it answers, and
        // every one of them is named for the receiver to look it up by.
        assert_eq!(stripped_hashes, all.iter().map(hash_of).collect());
        assert_eq!(responses_left_in_payload(&stripped), Vec::new());

        // ...and the payload shrank by at least the contents that were removed.
        let stripped_bytes: usize = all
            .iter()
            .map(|response| response.content.count_bytes())
            .sum();
        assert!(
            stripped.len() + stripped_bytes <= payload.len(),
            "stripped: {}, removed: {stripped_bytes}, original: {}",
            stripped.len(),
            payload.len()
        );

        // Putting the contents back reproduces the original payload byte for byte,
        // which is what the block hash is computed over.
        let responses = all
            .into_iter()
            .map(|response| (hash_of(&response), Some(response)))
            .collect();
        assert_eq!(reinsert_responses(&stripped, &responses).unwrap(), payload);
    }

    /// Committee members of a flexible outcall that agree deliver the very same
    /// response, once each: every one of their slots is emptied, but the content is
    /// declared, and has to be looked up, only once.
    #[test]
    fn identical_responses_are_stripped_once_test() {
        let response = fake_canister_http_response(1, 1024);
        let reject = fake_canister_http_reject(2);
        let tiny = fake_canister_http_response(3, MIN_STRIPPED_CONTENT_BYTES - 1);

        let payload = fake_canister_http_payload(vec![
            fake_flexible_canister_http_responses_message(
                1,
                &[(response.clone(), NODE_1), (response.clone(), NODE_2)],
            ),
            fake_flexible_canister_http_too_many_rejects_message(
                2,
                &[(reject.clone(), NODE_1), (reject.clone(), NODE_2)],
            ),
            fake_canister_http_response_message(&tiny, &[NODE_1]),
        ]);

        let (stripped, stripped_hashes) =
            strip_responses(&payload).expect("Should have stripped something");

        assert_eq!(
            stripped_hashes,
            BTreeSet::from_iter([hash_of(&response), hash_of(&reject)])
        );
        assert_eq!(responses_left_in_payload(&stripped), vec![tiny]);

        let responses = [&response, &reject]
            .into_iter()
            .map(|response| (hash_of(response), Some(response.clone())))
            .collect();
        assert_eq!(reinsert_responses(&stripped, &responses).unwrap(), payload);
        assert_eq!(find_response(&payload, &hash_of(&response)), Some(response));
    }

    /// A response whose content is smaller than [`MIN_STRIPPED_CONTENT_BYTES`] is
    /// left in the block, as stripping it would save little or nothing.
    #[test]
    fn tiny_responses_are_not_stripped_test() {
        for (tiny, big) in [
            (
                fake_canister_http_response(1, MIN_STRIPPED_CONTENT_BYTES - 1),
                fake_canister_http_response(2, MIN_STRIPPED_CONTENT_BYTES),
            ),
            (
                fake_canister_http_reject_of_size(1, MIN_STRIPPED_CONTENT_BYTES - 1),
                fake_canister_http_reject_of_size(2, MIN_STRIPPED_CONTENT_BYTES),
            ),
        ] {
            // On its own there is nothing worth stripping, so the payload is untouched.
            let only_tiny = fake_canister_http_payload(vec![fake_canister_http_response_message(
                &tiny,
                &[NODE_1],
            )]);
            assert_eq!(strip_responses(&only_tiny), None);

            // Alongside one that is worth it, only the larger one goes.
            let both = fake_canister_http_payload(vec![
                fake_canister_http_response_message(&tiny, &[NODE_1]),
                fake_canister_http_response_message(&big, &[NODE_1]),
            ]);
            let (stripped, hashes) = strip_responses(&both).expect("Should strip the larger one");

            assert_eq!(hashes, BTreeSet::from_iter([hash_of(&big)]));
            assert_eq!(responses_left_in_payload(&stripped), vec![tiny]);
        }
    }

    /// The threshold applies to the very quantity that a response's metadata reports
    /// as its `content_size`.
    #[test]
    fn content_size_is_the_metadata_content_size_test() {
        for response in [
            fake_canister_http_response(1, 1024),
            fake_canister_http_reject(2),
            fake_canister_http_reject_of_size(3, 20),
        ] {
            assert_eq!(
                content_size(&pb::CanisterHttpResponse::from(response.clone())),
                response.content.count_bytes()
            );
        }
    }

    #[test]
    fn strip_is_idempotent_test() {
        for signers in [&[NODE_1][..], &[NODE_1, NODE_2][..]] {
            let payload = fake_canister_http_payload(vec![fake_canister_http_response_message(
                &fake_canister_http_response(1, 1024),
                signers,
            )]);

            let (stripped, _) = strip_responses(&payload).expect("Should have stripped something");

            assert_eq!(strip_responses(&stripped), None);
        }
    }

    #[test]
    fn nothing_to_strip_test() {
        for payload in [
            // A timeout carries no response at all.
            fake_canister_http_payload(vec![fake_canister_http_timeout_message(1)]),
            // An empty payload, i.e. a block with no outcall messages.
            Vec::new(),
        ] {
            assert_eq!(strip_responses(&payload), None);
        }
    }

    /// Reassembling a stripped payload has to reproduce the original byte for
    /// byte, because that is what the block hash is computed over.
    #[test]
    fn reinsert_responses_test() {
        let non_replicated = fake_canister_http_response(1, 1024);
        let fully_replicated = fake_canister_http_response(2, 1024);
        let flexible_1 = fake_canister_http_response(3, 1024);
        let flexible_2 = fake_canister_http_response(3, 2048);
        let all = [&non_replicated, &fully_replicated, &flexible_1, &flexible_2];

        let messages = |stripped: bool| {
            let response_message = if stripped {
                fake_stripped_canister_http_response_message
            } else {
                fake_canister_http_response_message
            };
            let mut flexible = fake_flexible_canister_http_responses_message(
                3,
                &[(flexible_1.clone(), NODE_1), (flexible_2.clone(), NODE_2)],
            );
            if stripped
                && let Some(pb::canister_http_response_message::MessageType::FlexibleResponses(
                    group,
                )) = flexible.message_type.as_mut()
            {
                for response in &mut group.responses {
                    response.response = None;
                }
            }
            vec![
                response_message(&non_replicated, &[NODE_1]),
                response_message(&fully_replicated, &[NODE_1, NODE_2]),
                flexible,
            ]
        };

        let unstripped = fake_canister_http_payload(messages(false));
        let stripped = fake_canister_http_payload(messages(true));
        assert!(stripped.len() < unstripped.len());

        let responses = all
            .into_iter()
            .map(|response| (hash_of(response), Some(response.clone())))
            .collect();

        assert_eq!(
            reinsert_responses(&stripped, &responses).unwrap(),
            unstripped
        );
    }

    /// A payload with nothing missing needs no contents to reassemble.
    #[test]
    fn reinsert_nothing_test() {
        let response = fake_canister_http_response(1, 1024);
        let payload = fake_canister_http_payload(vec![fake_canister_http_response_message(
            &response,
            &[NODE_1],
        )]);

        assert_eq!(
            reinsert_responses(&payload, &BTreeMap::new()).unwrap(),
            payload
        );
    }

    #[test]
    fn reinsert_without_the_content_fails_test() {
        let response = fake_canister_http_response(1, 1024);
        let stripped =
            fake_canister_http_payload(vec![fake_stripped_canister_http_response_message(
                &response,
                &[NODE_1],
            )]);

        for responses in [
            BTreeMap::new(),
            BTreeMap::from_iter([(hash_of(&response), None)]),
        ] {
            assert_matches!(
                reinsert_responses(&stripped, &responses),
                Err(CanisterHttpPayloadError::MissingResponse(hash))
                    if hash == hash_of(&response)
            );
        }
    }

    /// Empty slots are cheap, so a peer can make a great many of them name a single
    /// large content. Putting it back is refused as soon as the payload would exceed
    /// what any valid block can carry, rather than once the copies have added up.
    #[test]
    fn reinsert_refuses_to_exceed_the_payload_limit_test() {
        let response = fake_canister_http_response(1, MAX_CANISTER_HTTP_PAYLOAD_SIZE / 2);
        let slot = fake_stripped_canister_http_response_message(&response, &[NODE_1]);
        let stripped = fake_canister_http_payload(vec![slot; 3]);
        let responses = BTreeMap::from_iter([(hash_of(&response), Some(response))]);

        // Only the size of a payload that came back would be of any interest.
        assert_matches!(
            reinsert_responses(&stripped, &responses).map(|payload| payload.len()),
            Err(CanisterHttpPayloadError::TooLarge)
        );
    }

    /// No valid block carries a payload bigger than the limit, and stripping never
    /// grows one, so a stripped payload that big is refused before it is decoded.
    #[test]
    fn reinsert_refuses_an_oversized_payload_test() {
        let slot = fake_canister_http_payload(vec![fake_stripped_canister_http_response_message(
            &fake_canister_http_response(1, 1024),
            &[NODE_1],
        )]);
        let oversized = slot.repeat(MAX_CANISTER_HTTP_PAYLOAD_SIZE / slot.len() + 1);

        assert_matches!(
            reinsert_responses(&oversized, &BTreeMap::new()).map(|payload| payload.len()),
            Err(CanisterHttpPayloadError::TooLarge)
        );
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
        assert_eq!(strip_responses(&garbage), None);
        assert_matches!(
            reinsert_responses(&garbage, &BTreeMap::new()),
            Err(CanisterHttpPayloadError::DecodeError(_))
        );
    }
}
