//! Verification that a signed transaction's envelopes all carry the same
//! message, and that each is paired with the read-state call that reads that
//! message's own result.
//!
//! A signed request carries one envelope per ingress expiry. The update half of
//! each envelope is covered by the caller's signature, but which envelope
//! `/construction/submit` broadcasts is decided at submit time, and the
//! read-state half is signed independently of the update it travels with.
//! Reading a request through [`representative_envelope`] gives the single
//! update that stands for all of them, or an error if they are not
//! interchangeable.
//!
//! `/construction/parse`, `/construction/hash` and the submit path's `Request`
//! reconstruction all read a signed request through this module, so the
//! envelope they describe is the envelope that gets sent.

use crate::{convert, errors::ApiError, models::EnvelopePair};
use ic_types::messages::{HttpCanisterUpdate, HttpReadStateContent};

/// Return the update that stands for every envelope of a signed request, or an
/// error if the envelopes are not interchangeable.
///
/// They are interchangeable when they all carry the same message and each is
/// paired with the read-state call that reads that message's own result.
///
/// Validating only one envelope would leave the displayed operations describing
/// a message that is not the one sent: `/construction/submit` broadcasts
/// whichever envelope is currently valid rather than the first, so a request
/// could pair an expired envelope matching the wrapper with a currently valid
/// envelope for a different neuron, amount or recipient. `/construction/combine`
/// builds these envelopes by cloning a single update and varying only
/// `ingress_expiry`, so requiring them to be identical in every other byte is
/// both what honest requests satisfy and enough to make the envelope that gets
/// broadcast interchangeable with the one described.
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
    }
    Ok(representative)
}

/// An update with its ingress expiry cleared, so that two of them compare equal
/// exactly when they are the same message sent in different ingress windows.
///
/// Compares whole updates rather than a field list, so a field added to
/// `HttpCanisterUpdate` later is covered without touching this.
fn without_expiry(update: &HttpCanisterUpdate) -> HttpCanisterUpdate {
    let mut update = update.clone();
    update.ingress_expiry = 0;
    update
}

/// Check that an envelope's read-state call is the one that reads the result of
/// that envelope's own update.
///
/// The two halves are signed independently, so a request can pair an update
/// with a read-state call belonging to some other message. The submit path
/// broadcasts the update and then polls with whatever read-state it was handed,
/// which never certifies the update's request id: the call is reported as
/// having failed while it is in fact executing, and a caller who believes that
/// report retries a transaction that has already gone through.
///
/// `/construction/combine` derives each read-state call from its own update, so
/// requiring exactly that is what honest requests already satisfy.
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

#[cfg(test)]
mod tests {
    use super::*;
    use ic_types::messages::{Blob, HttpCallContent, HttpRequestEnvelope};

    #[track_caller]
    fn assert_rejected<T: std::fmt::Debug>(result: Result<T, ApiError>, expected: &str) {
        let err = result.expect_err("expected the request to be rejected");
        assert!(
            format!("{err:?}").contains(expected),
            "expected an error containing {expected:?}, got {err:?}"
        );
    }

    /// An update distinguished only by its argument, which is enough: this
    /// module compares whole updates and does not interpret any field.
    fn update(arg: &[u8]) -> HttpCanisterUpdate {
        HttpCanisterUpdate {
            canister_id: Blob(vec![1]),
            method_name: "manage_neuron".to_string(),
            arg: Blob(arg.to_vec()),
            nonce: None,
            sender: Blob(vec![2]),
            ingress_expiry: 1_000,
            sender_info: None,
        }
    }

    /// An envelope pair as `/construction/combine` builds it: an update and the
    /// read-state call that reads that update's own result.
    fn pair(update: HttpCanisterUpdate) -> EnvelopePair {
        let read_state = convert::make_read_state_from_update(&update);
        EnvelopePair {
            update: HttpRequestEnvelope::<HttpCallContent> {
                content: HttpCallContent::Call { update },
                sender_pubkey: None,
                sender_sig: None,
                sender_delegation: None,
            },
            read_state: HttpRequestEnvelope::<HttpReadStateContent> {
                content: HttpReadStateContent::ReadState { read_state },
                sender_pubkey: None,
                sender_sig: None,
                sender_delegation: None,
            },
        }
    }

    #[test]
    fn envelopes_must_differ_only_in_ingress_expiry() {
        let base = update(b"disburse neuron 7");
        let mut later = base.clone();
        later.ingress_expiry = base.ingress_expiry + 1_000;

        // The same message in two ingress windows is what combine produces, and
        // either one stands for the other.
        let envelopes = [pair(base.clone()), pair(later)];
        assert_eq!(representative_envelope(&envelopes).unwrap(), &base);

        // An envelope carrying a different message alongside it is not, since
        // the submit path need not broadcast the one that was described.
        assert_rejected(
            representative_envelope(&[pair(base), pair(update(b"disburse neuron 9"))]),
            "must differ only in their ingress",
        );
    }

    /// The update and read-state halves are signed separately, so an envelope
    /// can pair an update with the read-state call of another message. Submit
    /// would broadcast the update and then poll for a request id the IC never
    /// certifies, reporting a failure for a call that is executing.
    #[test]
    fn a_read_state_for_another_message_is_rejected() {
        let base = update(b"disburse neuron 7");
        let mut later = base.clone();
        later.ingress_expiry = base.ingress_expiry + 1_000;

        // Both halves of a genuine pair, swapped between two envelopes of the
        // same transaction -- no extra signature needed to build this.
        let mut spliced = pair(base.clone());
        spliced.read_state = pair(later).read_state;
        assert_rejected(
            representative_envelope(&[spliced]),
            "must read the result of that",
        );

        // And the read-state call of an entirely different message.
        let mut spliced = pair(base);
        spliced.read_state = pair(update(b"disburse neuron 9")).read_state;
        assert_rejected(
            representative_envelope(&[spliced]),
            "must read the result of that",
        );
    }

    /// A signed transaction is attacker-supplied, and nothing requires a
    /// request in it to carry any envelope at all.
    #[test]
    fn a_request_without_envelopes_is_rejected() {
        assert_rejected(representative_envelope(&[]), "No request payload provided");
    }
}
