//! Checks that a signed request is described by the metadata Rosetta displays.
//!
//! A signed request carries one envelope per ingress expiry, and
//! `/construction/submit` broadcasts whichever one is currently valid. Its
//! [`RequestType`] is unsigned metadata, while the `canister_id`,
//! `method_name`, `arg`, `nonce` and `sender` of each update are signed.
//! `/construction/parse`, `/construction/hash` and `/construction/submit` read
//! a signed request through this module, so what they describe is what is
//! sent.

use crate::{convert, errors::ApiError, models::EnvelopePair, request_types::RequestType};
use ic_types::{
    CanisterId,
    messages::{HttpCanisterUpdate, HttpReadStateContent},
};

/// Ledger method behind `RequestType::Send`.
const SEND_PB: &str = "send_pb";

/// Returns the [`representative_envelope`] of a signed request after checking
/// it against `request_type` with [`verify_signed_target`].
pub fn verify_signed_envelopes<'a>(
    request_type: &RequestType,
    envelopes: &'a [EnvelopePair],
    ledger_canister_id: &CanisterId,
    governance_canister_id: &CanisterId,
) -> Result<&'a HttpCanisterUpdate, ApiError> {
    let update = representative_envelope(envelopes)?;
    verify_signed_target(
        request_type,
        update,
        ledger_canister_id,
        governance_canister_id,
    )?;
    Ok(update)
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

/// Checks that every field of `request_type` that Rosetta displays is
/// consistent with the signed `update`, which must be addressed to the
/// canisters this instance is configured for.
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
            // The debit is displayed against the sender's default account.
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

        // Not checked yet. Listed explicitly so that a new request type has to
        // be considered here.
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
        assert_rejected(
            verify(
                &RequestType::Send,
                &send(Some(icp_ledger::Subaccount([1; 32]))),
            ),
            "draws on a subaccount of the sender",
        );
    }

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
