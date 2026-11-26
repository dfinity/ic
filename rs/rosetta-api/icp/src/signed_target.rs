//! Checks that a signed request is described by the metadata Rosetta displays.
//!
//! A signed request carries one envelope per ingress expiry, and
//! `/construction/submit` broadcasts whichever one is currently valid. Its
//! [`RequestType`] is unsigned metadata, while the `canister_id`,
//! `method_name`, `arg`, `nonce` and `sender` of each update are signed.
//! `/construction/parse`, `/construction/hash` and `/construction/submit` read
//! a signed request through this module, so what they describe is what is
//! sent.

use crate::{
    convert,
    errors::ApiError,
    models::{EnvelopePair, SignedTransaction},
    request_types::RequestType,
};
use ic_crypto_standalone_sig_verifier::user_public_key_from_bytes;
use ic_types::{
    CanisterId, Time,
    crypto::AlgorithmId,
    messages::{HttpCanisterUpdate, HttpReadStateContent, HttpRequest, ReadState},
};
use ic_validator_ingress_message::{HttpRequestVerifier, IngressMessageVerifier, TimeProvider};

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

/// Returns the envelope that `/construction/submit` sends at `now`.
pub fn current_envelope(envelopes: &[EnvelopePair], now: Time) -> Option<&EnvelopePair> {
    envelopes.iter().find(|envelope| {
        let ingress_expiry =
            Time::from_nanos_since_unix_epoch(envelope.update.content.ingress_expiry());
        let ingress_start = ingress_expiry
            .saturating_sub(ic_limits::MAX_INGRESS_TTL.saturating_sub(ic_limits::PERMITTED_DRIFT));
        ingress_start <= now && ingress_expiry > now
    })
}

/// Checks the read-state signature of the envelope that each request of
/// `transaction` sends at `now`, before any of them is submitted.
///
/// `/construction/submit` polls for an update's result with its read-state
/// call, so a read-state call the IC rejects would report an update that
/// executes as failed. A read-state call that is anonymous, carries a
/// delegation or is signed with a canister signature is left to the IC, since
/// its validity depends on the IC's root key or clock.
pub fn verify_read_state_signatures(
    transaction: &SignedTransaction,
    now: Time,
) -> Result<(), ApiError> {
    let verifier = IngressMessageVerifier::builder()
        .with_time_provider(TimeProvider::Constant(now))
        .build();
    for (_, envelopes) in &transaction.requests {
        let Some(envelope) = current_envelope(envelopes, now) else {
            continue;
        };
        let read_state = &envelope.read_state;
        let Some(sender_pubkey) = &read_state.sender_pubkey else {
            continue;
        };
        let checkable = read_state.sender_delegation.is_none()
            && user_public_key_from_bytes(&sender_pubkey.0)
                .is_ok_and(|(key, _)| key.algorithm_id != AlgorithmId::IcCanisterSignature);
        if !checkable {
            continue;
        }
        HttpRequest::<ReadState>::try_from(read_state.clone())
            .map_err(|err| err.to_string())
            .and_then(|request| {
                verifier
                    .validate_request(&request)
                    .map_err(|err| err.to_string())
            })
            .map_err(|err| {
                ApiError::invalid_request(format!(
                    "Refusing to submit a request whose read-state call the IC would \
                     reject, since the outcome of its update could not be reported: {err}"
                ))
            })?;
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

    mod read_state_signatures {
        use super::*;
        use crate::{
            models::SignedTransaction, request_handler::make_sig_data, request_types::RequestType,
        };
        use rosetta_core::models::{Ed25519KeyPair, RosettaSupportedKeyPair};

        const NOW: u64 = 1_700_000_000_000_000_000;

        fn key(seed: u8) -> Ed25519KeyPair {
            Ed25519KeyPair::deserialize_raw(&[seed; 32]).unwrap()
        }

        fn signed(read_state_key: &Ed25519KeyPair, ingress_expiry: u64) -> EnvelopePair {
            let signer = key(1);
            let mut envelope = pair(HttpCanisterUpdate {
                sender: Blob(signer.generate_principal_id().unwrap().into_vec()),
                ingress_expiry,
                ..update(b"disburse neuron 7")
            });
            let read_state_id = envelope.read_state.content.id();
            envelope.read_state.sender_pubkey = Some(Blob(
                Ed25519KeyPair::der_encode_pk(read_state_key.get_pb_key()).unwrap(),
            ));
            envelope.read_state.sender_sig =
                Some(Blob(read_state_key.sign(&make_sig_data(&read_state_id))));
            envelope
        }

        fn current(read_state_key: &Ed25519KeyPair) -> EnvelopePair {
            signed(read_state_key, NOW + 60_000_000_000)
        }

        fn verify(requests: Vec<Vec<EnvelopePair>>) -> Result<(), ApiError> {
            let transaction = SignedTransaction {
                requests: requests
                    .into_iter()
                    .map(|envelopes| (RequestType::Send, envelopes))
                    .collect(),
            };
            verify_read_state_signatures(&transaction, Time::from_nanos_since_unix_epoch(NOW))
        }

        #[test]
        fn the_sent_read_state_call_of_every_request_must_be_signed_by_its_sender() {
            let mut corrupted = current(&key(1));
            corrupted.read_state.sender_sig = Some(Blob(vec![0; 64]));
            let expired = signed(&key(2), NOW);

            verify(vec![
                vec![current(&key(1))],
                vec![expired, current(&key(1))],
            ])
            .unwrap();
            for bad in [corrupted, current(&key(2))] {
                assert_rejected(
                    verify(vec![vec![current(&key(1))], vec![bad]]),
                    "whose read-state call the IC would reject",
                );
            }
        }

        #[test]
        fn read_state_calls_that_depend_on_the_ic_are_left_to_it() {
            let mut delegated = current(&key(2));
            delegated.read_state.sender_delegation = Some(vec![]);
            let mut anonymous = current(&key(2));
            anonymous.read_state.sender_pubkey = None;
            let mut unknown_key = current(&key(2));
            unknown_key.read_state.sender_pubkey = Some(Blob(vec![1, 2, 3]));

            verify(vec![vec![delegated], vec![anonymous], vec![unknown_key]]).unwrap();
        }
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
