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
    CanisterId, PrincipalId, Time,
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

/// Returns the envelope that `/construction/submit` sends at `now`: of those
/// valid at `now`, the one that expires last, so that its read-state call stays
/// valid while submit polls with it.
pub fn current_envelope(envelopes: &[EnvelopePair], now: Time) -> Option<&EnvelopePair> {
    envelopes
        .iter()
        .filter(|envelope| {
            let (ingress_start, ingress_expiry) = ingress_window(envelope);
            ingress_start <= now && ingress_expiry > now
        })
        .max_by_key(|envelope| envelope.update.content.ingress_expiry())
}

fn ingress_window(envelope: &EnvelopePair) -> (Time, Time) {
    let ingress_expiry =
        Time::from_nanos_since_unix_epoch(envelope.update.content.ingress_expiry());
    let ingress_start = ingress_expiry
        .saturating_sub(ic_limits::MAX_INGRESS_TTL.saturating_sub(ic_limits::PERMITTED_DRIFT));
    (ingress_start, ingress_expiry)
}

/// Checks the read-state signature of every envelope of `transaction` that has
/// not expired at `now`, before any request is submitted.
///
/// `/construction/submit` polls for an update's result with its read-state
/// call, so a read-state call the IC rejects would report an update that
/// executes as failed. Each request's envelope is picked when that request is
/// sent, so every unexpired envelope is checked, as of the start of its ingress
/// window or `now` if later. Of a read-state call that carries a delegation or
/// is signed with a canister signature, only that its sender is derived from
/// its public key is checked. Its signature and delegation chain are left to
/// the IC, so that no call the IC accepts is refused.
pub fn verify_read_state_signatures(
    transaction: &SignedTransaction,
    now: Time,
) -> Result<(), ApiError> {
    for (_, envelopes) in &transaction.requests {
        for envelope in envelopes {
            let (ingress_start, ingress_expiry) = ingress_window(envelope);
            if ingress_expiry > now {
                verify_read_state_signature(envelope, ingress_start.max(now))?;
            }
        }
    }
    Ok(())
}

fn verify_read_state_signature(envelope: &EnvelopePair, at: Time) -> Result<(), ApiError> {
    let refuse = |err: String| {
        ApiError::invalid_request(format!(
            "Refusing to submit a request whose read-state call the IC would \
             reject, since the outcome of its update could not be reported: {err}"
        ))
    };
    let read_state = &envelope.read_state;
    let delegated = read_state
        .sender_delegation
        .as_ref()
        .is_some_and(|delegations| !delegations.is_empty());
    let canister_signed = read_state.sender_pubkey.as_ref().is_some_and(|key| {
        user_public_key_from_bytes(&key.0)
            .is_ok_and(|(key, _)| key.algorithm_id == AlgorithmId::IcCanisterSignature)
    });
    if delegated || canister_signed {
        let HttpReadStateContent::ReadState {
            read_state: content,
        } = &read_state.content;
        let derived = read_state
            .sender_pubkey
            .as_ref()
            .map(|key| PrincipalId::new_self_authenticating(&key.0).into_vec());
        if derived.as_ref() != Some(&content.sender.0) {
            return Err(refuse(
                "its sender is not derived from its public key".to_string(),
            ));
        }
        return Ok(());
    }
    let verifier = IngressMessageVerifier::builder()
        .with_time_provider(TimeProvider::Constant(at))
        .build();
    HttpRequest::<ReadState>::try_from(read_state.clone())
        .map_err(|err| err.to_string())
        .and_then(|request| {
            verifier
                .validate_request(&request)
                .map_err(|err| err.to_string())
        })
        .map_err(refuse)
}

#[cfg(test)]
mod tests;
