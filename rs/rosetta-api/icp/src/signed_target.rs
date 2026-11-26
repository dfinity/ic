//! Checks that the envelopes of a signed request are interchangeable.
//!
//! A signed request carries one envelope per ingress expiry, and
//! `/construction/submit` broadcasts whichever one is currently valid.
//! `/construction/parse`, `/construction/hash` and `/construction/submit` read
//! a signed request through [`representative_envelope`], so the envelope they
//! describe stands for the one that is sent.

use crate::{convert, errors::ApiError, models::EnvelopePair};
use ic_types::{
    Time,
    messages::{
        HttpCanisterUpdate, HttpReadStateContent, HttpRequest, ReadState, SignedIngressContent,
    },
};
use ic_validator_ingress_message::{HttpRequestVerifier, IngressMessageVerifier, TimeProvider};

/// Returns the update that stands for every envelope of a signed request.
///
/// The envelopes must carry the same update up to `ingress_expiry`, and each
/// must pair its update with the read-state call for that update's result.
/// `/construction/combine` builds envelopes exactly this way. Both calls must
/// also carry signatures that the IC accepts.
pub fn representative_envelope(
    envelopes: &[EnvelopePair],
) -> Result<&HttpCanisterUpdate, ApiError> {
    let representative = envelopes
        .first()
        .ok_or_else(|| ApiError::invalid_request("No request payload provided."))?
        .update_content();

    let expected = without_expiry(representative);
    for envelope in envelopes {
        if without_expiry(envelope.update_content()) != expected {
            return Err(ApiError::invalid_request(
                "The envelopes of a signed request must differ only in their ingress \
                 expiry. Refusing a request whose envelopes carry different payloads, \
                 since the one that gets submitted need not be the one described.",
            ));
        }
        verify_read_state(envelope)?;
        verify_signatures(envelope)?;
    }
    Ok(representative)
}

/// Compares whole updates, so fields added to `HttpCanisterUpdate` later are
/// covered too.
fn without_expiry(update: &HttpCanisterUpdate) -> HttpCanisterUpdate {
    let mut update = update.clone();
    update.ingress_expiry = 0;
    update
}

/// The read-state call is signed separately from the update. If it polled for
/// another request id, `/construction/submit` would report a failure for a call
/// that is in fact executing.
fn verify_read_state(envelope: &EnvelopePair) -> Result<(), ApiError> {
    let HttpReadStateContent::ReadState { read_state } = &envelope.read_state.content;
    if *read_state != convert::make_read_state_from_update(envelope.update_content()) {
        return Err(ApiError::invalid_request(
            "The read-state call of a signed request must read the result of that \
             request's own update. Refusing a request that would be reported as \
             having failed while it executes.",
        ));
    }
    Ok(())
}

/// The IC rejects a call that is not signed by the key its sender is derived
/// from. A rejected read-state call would make `/construction/submit` report a
/// failure for an update that executes. Expiry is checked on submission, so the
/// signatures are checked as of the envelope's own expiry.
fn verify_signatures(envelope: &EnvelopePair) -> Result<(), ApiError> {
    let invalid = |err: String| {
        ApiError::invalid_request(format!(
            "Refusing a signed request whose envelope the IC would reject: {err}"
        ))
    };
    let verifier = IngressMessageVerifier::builder()
        .with_time_provider(TimeProvider::Constant(Time::from_nanos_since_unix_epoch(
            envelope.update_content().ingress_expiry,
        )))
        .build();

    let update = HttpRequest::<SignedIngressContent>::try_from(envelope.update.clone())
        .map_err(|err| invalid(err.to_string()))?;
    verifier
        .validate_request(&update)
        .map_err(|err| invalid(err.to_string()))?;

    let read_state = HttpRequest::<ReadState>::try_from(envelope.read_state.clone())
        .map_err(|err| invalid(err.to_string()))?;
    verifier
        .validate_request(&read_state)
        .map_err(|err| invalid(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request_handler::make_sig_data;
    use ic_types::messages::{Blob, HttpCallContent, HttpRequestEnvelope};
    use rosetta_core::models::{Ed25519KeyPair, RosettaSupportedKeyPair};

    #[track_caller]
    fn assert_rejected<T: std::fmt::Debug>(result: Result<T, ApiError>, expected: &str) {
        let err = result.expect_err("expected the request to be rejected");
        assert!(
            format!("{err:?}").contains(expected),
            "expected an error containing {expected:?}, got {err:?}"
        );
    }

    fn update(arg: &[u8]) -> HttpCanisterUpdate {
        HttpCanisterUpdate {
            canister_id: Blob(vec![1]),
            method_name: "manage_neuron".to_string(),
            arg: Blob(arg.to_vec()),
            nonce: None,
            sender: Blob(signer().generate_principal_id().unwrap().into_vec()),
            ingress_expiry: 1_000,
            sender_info: None,
        }
    }

    fn signer() -> Ed25519KeyPair {
        Ed25519KeyPair::deserialize_raw(&[7; 32]).unwrap()
    }

    fn other_key() -> Ed25519KeyPair {
        Ed25519KeyPair::deserialize_raw(&[8; 32]).unwrap()
    }

    fn pair(update: HttpCanisterUpdate) -> EnvelopePair {
        signed_pair(update, &signer(), &signer())
    }

    fn signed_pair(
        update: HttpCanisterUpdate,
        update_key: &Ed25519KeyPair,
        read_state_key: &Ed25519KeyPair,
    ) -> EnvelopePair {
        let read_state = HttpReadStateContent::ReadState {
            read_state: convert::make_read_state_from_update(&update),
        };
        let update_sig = update_key.sign(&make_sig_data(&update.id()));
        let read_state_sig = read_state_key.sign(&make_sig_data(&read_state.id()));
        let pubkey = |key: &Ed25519KeyPair| {
            Some(Blob(
                Ed25519KeyPair::der_encode_pk(key.get_pb_key()).unwrap(),
            ))
        };
        EnvelopePair {
            update: HttpRequestEnvelope::<HttpCallContent> {
                content: HttpCallContent::Call { update },
                sender_pubkey: pubkey(update_key),
                sender_sig: Some(Blob(update_sig)),
                sender_delegation: None,
            },
            read_state: HttpRequestEnvelope::<HttpReadStateContent> {
                content: read_state,
                sender_pubkey: pubkey(read_state_key),
                sender_sig: Some(Blob(read_state_sig)),
                sender_delegation: None,
            },
        }
    }

    #[test]
    fn envelopes_must_differ_only_in_ingress_expiry() {
        let base = update(b"disburse neuron 7");
        let mut later = base.clone();
        later.ingress_expiry = base.ingress_expiry + 1_000;

        let envelopes = [pair(base.clone()), pair(later)];
        assert_eq!(representative_envelope(&envelopes).unwrap(), &base);

        assert_rejected(
            representative_envelope(&[pair(base), pair(update(b"disburse neuron 9"))]),
            "must differ only in their ingress",
        );
    }

    #[test]
    fn a_read_state_for_another_message_is_rejected() {
        let base = update(b"disburse neuron 7");
        let mut later = base.clone();
        later.ingress_expiry = base.ingress_expiry + 1_000;

        let mut spliced = pair(base.clone());
        spliced.read_state = pair(later).read_state;
        assert_rejected(
            representative_envelope(&[spliced]),
            "must read the result of that",
        );

        let mut spliced = pair(base);
        spliced.read_state = pair(update(b"disburse neuron 9")).read_state;
        assert_rejected(
            representative_envelope(&[spliced]),
            "must read the result of that",
        );
    }

    #[test]
    fn every_call_must_be_signed_by_its_sender() {
        let base = update(b"disburse neuron 7");
        let mut later = base.clone();
        later.ingress_expiry = base.ingress_expiry + 1_000;

        let mut corrupted = pair(later.clone());
        corrupted.read_state.sender_sig = Some(Blob(vec![0; 64]));
        let cases = [
            signed_pair(later.clone(), &signer(), &other_key()),
            signed_pair(later, &other_key(), &signer()),
            corrupted,
        ];
        for envelope in cases {
            assert_rejected(
                representative_envelope(&[pair(base.clone()), envelope]),
                "whose envelope the IC would reject",
            );
        }
    }

    #[test]
    fn a_request_without_envelopes_is_rejected() {
        assert_rejected(representative_envelope(&[]), "No request payload provided");
    }
}
