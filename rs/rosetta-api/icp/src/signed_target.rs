//! Checks that the envelopes of a signed request are interchangeable.
//!
//! A signed request carries one envelope per ingress expiry. The update half of
//! each envelope is covered by the caller's signature, but which envelope
//! `/construction/submit` broadcasts is decided at submit time, and the
//! read-state half is signed independently of the update it travels with.
//! Reading a request through [`representative_envelope`] gives the single
//! update that stands for all of them, or an error if they are not
//! interchangeable.
//!
//! It also checks that the metadata Rosetta displays for a request is
//! derivable from, and consistent with, the signed update. `UnsignedTransaction`
//! and `SignedTransaction` pair a [`RequestType`] -- plain CBOR metadata that no
//! signature covers -- with an [`HttpCanisterUpdate`], whose `canister_id`,
//! `method_name`, `arg`, `nonce` and `sender` are all covered by `update.id()`
//! and therefore by the caller's signature. A transfer must be addressed to the
//! ledger this instance serves, since its amount is displayed in that ledger's
//! token, and must debit the sender's default account, which is the account
//! displayed.
//!
//! `/construction/parse`, `/construction/hash` and the submit path's `Request`
//! reconstruction all read a signed request through this module, so the
//! envelope they describe is the envelope that gets sent, and the operations
//! shown before signing, after signing and after submission cannot disagree.

use crate::{convert, errors::ApiError, models::EnvelopePair, request_types::RequestType};
use ic_types::{
    CanisterId,
    messages::{HttpCanisterUpdate, HttpReadStateContent},
};

/// Ledger method behind `RequestType::Send`.
const SEND_PB: &str = "send_pb";

/// Check a signed request's envelopes as a whole: that they are
/// interchangeable, and that the message they carry is the one the displayed
/// metadata describes.
pub fn verify_signed_envelopes(
    request_type: &RequestType,
    envelopes: &[EnvelopePair],
    ledger_canister_id: &CanisterId,
    governance_canister_id: &CanisterId,
) -> Result<(), ApiError> {
    verify_signed_target(
        request_type,
        representative_envelope(envelopes)?,
        ledger_canister_id,
        governance_canister_id,
    )
}

/// Returns the update that stands for every envelope of a signed request.
///
/// The envelopes must carry the same update up to `ingress_expiry`, and each
/// must pair its update with the read-state call for that update's result.
/// `/construction/combine` builds envelopes exactly this way.
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

/// Check that every field of `request_type` that Rosetta will display is
/// derivable from, and consistent with, the signed `update`.
///
/// Fails closed: a request whose displayed metadata cannot be confirmed against
/// the signed payload is rejected rather than displayed with a warning.
///
/// `ledger_canister_id` and `governance_canister_id` are the canisters this
/// Rosetta instance is configured for, and the ones `/construction/payloads`
/// addresses. A transfer is denominated in that ledger's token and a neuron is
/// named under that governance canister, so a request addressed anywhere else
/// describes something this instance does not serve.
pub fn verify_signed_target(
    request_type: &RequestType,
    update: &HttpCanisterUpdate,
    ledger_canister_id: &CanisterId,
    _governance_canister_id: &CanisterId,
) -> Result<(), ApiError> {
    match request_type {
        RequestType::Send => {
            verify_canister(update, ledger_canister_id, "A transfer")?;
            verify_method_name(update, SEND_PB)?;
            // The ledger debits `AccountIdentifier::new(sender, from_subaccount)`,
            // but both reconstruction paths report the debit against the
            // sender's default account, so a transfer out of a subaccount would
            // be displayed as coming from somewhere it does not.
            // `/construction/payloads` only ever leaves this unset.
            let args = convert::from_arg(update.arg.0.clone())?;
            if args.from_subaccount.is_some() {
                return Err(ApiError::invalid_request(
                    "The signed transfer draws on a subaccount of the sender, but \
                     Rosetta would display it as debiting the sender's default \
                     account. Refusing to name an account other than the one being \
                     debited.",
                ));
            }
            Ok(())
        }

        // The neuron request types name a neuron, and sometimes a controller,
        // that the signed update also determines. Binding those is a separate
        // step; until then they are described from the wrapper, as before.
        // Listed rather than matched with a wildcard, so that a request type
        // added later has to be considered here.
        RequestType::Stake { .. }
        | RequestType::NeuronInfo { .. }
        | RequestType::ListNeurons { .. }
        | RequestType::SetDissolveTimestamp { .. }
        | RequestType::ChangeAutoStakeMaturity { .. }
        | RequestType::StartDissolve { .. }
        | RequestType::StopDissolve { .. }
        | RequestType::Disburse { .. }
        | RequestType::DisburseMaturity { .. }
        | RequestType::AddHotKey { .. }
        | RequestType::RemoveHotKey { .. }
        | RequestType::Spawn { .. }
        | RequestType::StakeMaturity { .. }
        | RequestType::RegisterVote { .. }
        | RequestType::Follow { .. }
        | RequestType::RefreshVotingPower { .. } => Ok(()),
    }
}

fn verify_canister(
    update: &HttpCanisterUpdate,
    expected: &CanisterId,
    what: &str,
) -> Result<(), ApiError> {
    if update.canister_id.0.as_slice() != expected.get().as_slice() {
        return Err(ApiError::invalid_request(format!(
            "{what} must be addressed to canister {expected}, but the signed update \
             is addressed elsewhere."
        )));
    }
    Ok(())
}

fn verify_method_name(update: &HttpCanisterUpdate, expected: &str) -> Result<(), ApiError> {
    if update.method_name != expected {
        return Err(ApiError::invalid_request(format!(
            "Expected the signed update to call '{expected}', but it calls '{}'.",
            update.method_name
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_types::{
        PrincipalId,
        messages::{Blob, HttpCallContent, HttpRequestEnvelope},
    };

    fn controller() -> PrincipalId {
        PrincipalId::new_user_test_id(1)
    }

    /// The canisters this Rosetta instance is configured for. Deliberately not
    /// the mainnet ids, so that a check against a hard-coded one would fail.
    fn ledger() -> CanisterId {
        CanisterId::from_u64(1)
    }

    fn governance() -> CanisterId {
        CanisterId::from_u64(2)
    }

    fn verify(request_type: &RequestType, update: &HttpCanisterUpdate) -> Result<(), ApiError> {
        verify_signed_target(request_type, update, &ledger(), &governance())
    }

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
            sender: Blob(vec![2]),
            ingress_expiry: 1_000,
            sender_info: None,
        }
    }

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
    fn a_request_without_envelopes_is_rejected() {
        assert_rejected(representative_envelope(&[]), "No request payload provided");
    }

    #[test]
    fn a_transfer_to_another_ledger_is_rejected() {
        let args = icp_ledger::SendArgs {
            memo: icp_ledger::Memo(0),
            amount: icp_ledger::Tokens::from_e8s(100_000_000),
            fee: icp_ledger::Tokens::from_e8s(10_000),
            from_subaccount: None,
            to: icp_ledger::AccountIdentifier::from(controller()),
            created_at_time: None,
        };
        let send = |canister_id: CanisterId| HttpCanisterUpdate {
            canister_id: Blob(canister_id.get().to_vec()),
            method_name: SEND_PB.to_string(),
            arg: Blob(convert::to_arg(args.clone())),
            nonce: None,
            sender: Blob(controller().into_vec()),
            ingress_expiry: 0,
            sender_info: None,
        };

        verify(&RequestType::Send, &send(ledger())).unwrap();
        // The amount and the recipient are signed, but the token they are
        // denominated in follows from the ledger being called.
        assert_rejected(
            verify(&RequestType::Send, &send(CanisterId::from_u64(99))),
            "A transfer must be addressed to canister",
        );
    }

    #[test]
    fn a_transfer_out_of_a_subaccount_is_rejected() {
        let send = |from_subaccount| HttpCanisterUpdate {
            canister_id: Blob(ledger().get().to_vec()),
            method_name: SEND_PB.to_string(),
            arg: Blob(convert::to_arg(icp_ledger::SendArgs {
                memo: icp_ledger::Memo(0),
                amount: icp_ledger::Tokens::from_e8s(100_000_000),
                fee: icp_ledger::Tokens::from_e8s(10_000),
                from_subaccount,
                to: icp_ledger::AccountIdentifier::from(PrincipalId::new_user_test_id(2)),
                created_at_time: None,
            })),
            nonce: None,
            sender: Blob(controller().into_vec()),
            ingress_expiry: 0,
            sender_info: None,
        };

        verify(&RequestType::Send, &send(None)).unwrap();
        // The ledger would debit a subaccount of the sender, but the operations
        // name the sender's default account.
        assert_rejected(
            verify(
                &RequestType::Send,
                &send(Some(icp_ledger::Subaccount([1; 32]))),
            ),
            "draws on a subaccount of the sender",
        );
    }

    /// A transfer that calls something other than the ledger's transfer method
    /// is not the transfer the operations describe.
    #[test]
    fn a_transfer_calling_another_method_is_rejected() {
        let update = HttpCanisterUpdate {
            canister_id: Blob(ledger().get().to_vec()),
            method_name: "notify_pb".to_string(),
            arg: Blob(convert::to_arg(icp_ledger::SendArgs {
                memo: icp_ledger::Memo(0),
                amount: icp_ledger::Tokens::from_e8s(1),
                fee: icp_ledger::Tokens::from_e8s(10_000),
                from_subaccount: None,
                to: icp_ledger::AccountIdentifier::from(controller()),
                created_at_time: None,
            })),
            nonce: None,
            sender: Blob(controller().into_vec()),
            ingress_expiry: 0,
            sender_info: None,
        };

        assert_rejected(
            verify(&RequestType::Send, &update),
            "Expected the signed update to call 'send_pb'",
        );
    }
}
