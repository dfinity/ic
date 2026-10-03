//! Stripping and reassembling the canister HTTP payload of a block.
//!
//! The canister HTTP payload sits in a block as an opaque byte string: a
//! sequence of length-delimited [`pb::CanisterHttpResponseMessage`] protos (see
//! [`ic_types::batch::iterator_to_bytes`]). Some of those messages carry a full
//! [`CanisterHttpResponse`], and the block does not need to repeat a response
//! that its own proof shows the peers to be holding already: see
//! [`for_each_response_slot`] for why that is the case for every one of them.
//!
//! Every such response is accompanied, in the very same message, by the hash of
//! its content: the `content_hash` of the metadata that the response's signers
//! signed over. That hash is all a receiver needs in order to look the content up
//! in its own canister HTTP pool, or to fetch it from a peer.
//!
//! Replacing a response with its hash costs 34 bytes in the stripped block
//! proposal, so a response is only stripped when its content is larger than that
//! (see [`MIN_STRIPPED_CONTENT_BYTES`]). Stripping therefore never makes a block
//! proposal bigger than the one it was stripped from.

use std::collections::{BTreeMap, BTreeSet};

use ic_protobuf::types::v1 as pb;
use ic_types::{
    NumBytes,
    batch::{MAX_CANISTER_HTTP_PAYLOAD_SIZE, iterator_to_bytes, slice_to_messages},
    canister_http::CanisterHttpResponse,
    crypto::{CryptoHash, CryptoHashOf},
};

use thiserror::Error;

use super::types::CanisterHttpResponseContentHash;

/// The canister http payload of a block could not be reassembled.
#[derive(Debug, PartialEq, Error)]
pub(crate) enum CanisterHttpPayloadError {
    #[error("The canister http payload could not be parsed: {0}")]
    DecodeError(String),
    #[error("The canister http payload is missing the response with content hash {0:?}")]
    MissingResponse(CryptoHash),
}

/// Returns the payload with the content of every response worth stripping removed,
/// together with the hashes of the contents that were removed, or `None` if there
/// was nothing worth stripping (or the payload could not be parsed, in which case
/// the block is left untouched and will fail validation later on).
///
/// Note that a payload this returns is *not* free of response content: anything
/// smaller than [`MIN_STRIPPED_CONTENT_BYTES`] is deliberately left where it is,
/// because removing it would make the block proposal bigger. The returned hashes
/// are exactly the contents that were taken out, so they, rather than the payload's
/// empty slots, are what a receiver has to find.
///
/// The hashes are deduplicated: two committee members of a flexible outcall that
/// produced the very same response occupy two slots of the payload, but there is
/// only one piece of content to look up for both of them.
pub(crate) fn strip_responses(
    payload_bytes: &[u8],
) -> Option<(Vec<u8>, BTreeSet<CanisterHttpResponseContentHash>)> {
    if payload_bytes.is_empty() {
        return None;
    }

    let mut messages = parse(payload_bytes).ok()?;

    let mut stripped = BTreeSet::new();
    for_each_response_slot(&mut messages, |content_hash, response| {
        if response
            .as_ref()
            .is_none_or(|response| content_size(response) < MIN_STRIPPED_CONTENT_BYTES)
        {
            return;
        }

        if response.take().is_some() {
            stripped.insert(content_hash);
        }
    });

    (!stripped.is_empty()).then(|| (serialize(messages), stripped))
}

/// The smallest response content that is worth stripping.
///
/// A stripped response is replaced by its content hash in
/// [`pb::StrippedBlockProposal::stripped_canister_http_responses`], which costs 34
/// encoded bytes: the 32 byte hash, a tag and a length. Removing less content than
/// that would make the block proposal *bigger*, so the break-even point is where
/// this threshold belongs, with only enough slack above it to cover the framing
/// that the 34 bytes does not count.
///
/// It deliberately sits no higher. The declaration and the content it replaces are
/// both sent to every peer, so the comparison is 34 bytes against the content size
/// however large the subnet is, and anything above break-even is spending bandwidth
/// to save the per-response cost of reassembly. A block can carry up to
/// [`ic_types::canister_http::CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK`] responses, so
/// every byte of slack here is multiplied by five hundred.
///
/// In practice this keeps the replica's own terse rejects in the block, which are
/// the ones that cost more to strip than they save: "Deadline Exceeded",
/// "Insufficient cycles" and "Adapter returned empty result" are all under 32 bytes.
const MIN_STRIPPED_CONTENT_BYTES: usize = 64;

/// The size of a response's content, the quantity its metadata reports as
/// `content_size`.
fn content_size(response: &pb::CanisterHttpResponse) -> usize {
    use pb::canister_http_response_content::Status;

    match response.content.as_ref().and_then(|c| c.status.as_ref()) {
        Some(Status::Success(payload)) => payload.len(),
        Some(Status::Reject(reject)) => std::mem::size_of::<i32>() + reject.message.len(),
        None => 0,
    }
}

/// Puts the given response contents back into the payload, in place of the ones
/// that [`strip_responses`] removed, and returns the reassembled payload.
///
/// Fails if the payload is missing a response whose content was not provided.
pub(crate) fn reinsert_responses(
    payload_bytes: &[u8],
    responses: &BTreeMap<CanisterHttpResponseContentHash, Option<CanisterHttpResponse>>,
) -> Result<Vec<u8>, CanisterHttpPayloadError> {
    let mut messages = parse(payload_bytes)?;

    let mut error = None;
    for_each_response_slot(&mut messages, |content_hash, response| {
        if response.is_some() {
            return;
        }
        match responses.get(&content_hash) {
            Some(Some(content)) => {
                *response = Some(pb::CanisterHttpResponse::from(content.clone()));
            }
            Some(None) | None => {
                error.get_or_insert_with(|| {
                    CanisterHttpPayloadError::MissingResponse(content_hash.get())
                });
            }
        }
    });

    match error {
        Some(error) => Err(error),
        None => Ok(serialize(messages)),
    }
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

fn serialize(messages: Vec<pb::CanisterHttpResponseMessage>) -> Vec<u8> {
    // Stripping only ever removes bytes, and a payload that was reassembled from a
    // block that could pass validation is at most this big, so the limit truncates
    // nothing in either direction. Should a peer send a block whose payload exceeds
    // it, the truncated payload simply fails the block hash check in
    // `BlockProposalAssembler::try_assemble` and the block is dropped.
    iterator_to_bytes(
        messages.into_iter(),
        NumBytes::new(MAX_CANISTER_HTTP_PAYLOAD_SIZE as u64),
    )
}

/// Calls `f` once for every response slot of the payload, passing the hash of the
/// content that belongs in the slot together with the slot itself.
///
/// Every response a payload delivers can be stripped, because in every case the
/// replicas that signed for it already hold its content:
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
    use assert_matches::assert_matches;
    use ic_types_test_utils::ids::{NODE_1, NODE_2};

    use crate::fetch_stripped_artifact::test_utils::{
        fake_canister_http_payload, fake_canister_http_reject, fake_canister_http_response,
        fake_canister_http_response_message, fake_canister_http_timeout_message,
        fake_flexible_canister_http_responses_message,
        fake_flexible_canister_http_too_many_rejects_message,
        fake_stripped_canister_http_response_message,
    };
    use ic_types::CountBytes;

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
        let non_replicated = fake_canister_http_response(1, 1024);
        let fully_replicated = fake_canister_http_response(2, 1024);
        let flexible_1 = fake_canister_http_response(3, 1024);
        let flexible_2 = fake_canister_http_response(3, 2048);
        let reject = fake_canister_http_reject(4);

        let payload = fake_canister_http_payload(vec![
            fake_canister_http_response_message(&non_replicated, &[NODE_1]),
            fake_canister_http_response_message(&fully_replicated, &[NODE_1, NODE_2]),
            fake_flexible_canister_http_responses_message(
                3,
                &[(flexible_1.clone(), NODE_1), (flexible_2.clone(), NODE_2)],
            ),
            fake_flexible_canister_http_too_many_rejects_message(4, &[(reject.clone(), NODE_1)]),
            fake_canister_http_timeout_message(5),
        ]);

        let (stripped, stripped_hashes) =
            strip_responses(&payload).expect("Should have stripped something");

        // Every response content is gone, whatever kind of outcall it answers, and
        // every one of them is named for the receiver to look it up by.
        let all = [
            &non_replicated,
            &fully_replicated,
            &flexible_1,
            &flexible_2,
            &reject,
        ];
        assert_eq!(
            stripped_hashes,
            all.iter().map(|response| hash_of(response)).collect()
        );
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
            .map(|response| (hash_of(response), Some(response.clone())))
            .collect();
        assert_eq!(reinsert_responses(&stripped, &responses).unwrap(), payload);
    }

    /// A response whose content is smaller than the hash that would replace it is
    /// left in the block, because removing it would make the proposal bigger.
    #[test]
    fn tiny_responses_are_not_stripped_test() {
        let tiny = fake_canister_http_response(1, MIN_STRIPPED_CONTENT_BYTES - 1);
        let big = fake_canister_http_response(2, MIN_STRIPPED_CONTENT_BYTES);

        // On its own there is nothing worth stripping, so the payload is untouched.
        let only_tiny =
            fake_canister_http_payload(vec![fake_canister_http_response_message(&tiny, &[NODE_1])]);
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
                    if hash == hash_of(&response).get()
            );
        }
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
        ] {
            assert_eq!(
                find_response(&payload, &hash_of(response)).as_ref(),
                Some(response)
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
        assert_eq!(strip_responses(&garbage), None);
        assert_matches!(
            reinsert_responses(&garbage, &BTreeMap::new()),
            Err(CanisterHttpPayloadError::DecodeError(_))
        );
    }
}
