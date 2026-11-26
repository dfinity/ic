//! Checks that a signed request is described by the metadata Rosetta displays.
//!
//! A request pairs a [`RequestType`], which is unsigned metadata, with an
//! [`HttpCanisterUpdate`], whose `canister_id`, `method_name`, `arg`, `nonce`
//! and `sender` are signed. Every field Rosetta displays must follow from the
//! signed update:
//!
//! * A transfer must call the configured ledger and debit the sender's default
//!   account.
//! * A neuron request must call the configured governance canister. A
//!   `manage_neuron` request names its neuron in the `nonce` and in the
//!   subaccount `H(controller, neuron_index)` of its `arg`, and its command
//!   must be the displayed operation.
//! * A signed request carries one envelope per ingress expiry, and
//!   `/construction/submit` broadcasts whichever one is currently valid, so all
//!   envelopes must carry the same update.
//!
//! `/construction/parse`, `/construction/hash` and `/construction/submit` all
//! read a signed request through this module.

use crate::{
    convert,
    errors::ApiError,
    models::{EnvelopePair, SignedTransaction},
    request_types::{PublicKeyOrPrincipal, RequestType},
};
use ic_crypto_standalone_sig_verifier::user_public_key_from_bytes;
use ic_nns_governance_api::{
    ClaimOrRefreshNeuronFromAccount, ListNeurons, ManageNeuronCommandRequest, ManageNeuronRequest,
    manage_neuron, manage_neuron::NeuronIdOrSubaccount,
};
use ic_types::{
    CanisterId, PrincipalId, Time,
    crypto::AlgorithmId,
    messages::{HttpCanisterUpdate, HttpReadStateContent, HttpRequest, ReadState},
};
use ic_validator_ingress_message::{HttpRequestVerifier, IngressMessageVerifier, TimeProvider};

const MANAGE_NEURON: &str = "manage_neuron";
const CLAIM_OR_REFRESH_NEURON_FROM_ACCOUNT: &str = "claim_or_refresh_neuron_from_account";
const GET_FULL_NEURON_BY_ID_OR_SUBACCOUNT: &str = "get_full_neuron_by_id_or_subaccount";
const LIST_NEURONS: &str = "list_neurons";
const SEND_PB: &str = "send_pb";

/// The `list_neurons` argument `/construction/payloads` builds for a page.
pub fn list_neurons_arg(page_number: Option<u64>) -> ListNeurons {
    ListNeurons {
        neuron_ids: vec![],
        include_neurons_readable_by_caller: true,
        include_empty_neurons_readable_by_caller: None,
        include_public_neurons_in_full_neurons: None,
        page_number,
        page_size: None,
        neuron_subaccounts: None,
    }
}

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
    governance_canister_id: &CanisterId,
) -> Result<(), ApiError> {
    let sender = PrincipalId::try_from(update.sender.0.as_slice()).map_err(|e| {
        ApiError::invalid_request(format!("Could not parse the signed update's sender: {e}"))
    })?;

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

        RequestType::Stake { neuron_index } => {
            verify_governance_canister(update, governance_canister_id)?;
            verify_method_name(update, CLAIM_OR_REFRESH_NEURON_FROM_ACCOUNT)?;
            verify_nonce_neuron_index(update, *neuron_index)?;
            // The neuron is `H(controller, memo)`, displayed against the signer.
            let args: ClaimOrRefreshNeuronFromAccount = decode_arg(update, "stake")?;
            if args.memo != *neuron_index {
                return Err(mismatch(
                    "neuron_index",
                    *neuron_index,
                    args.memo,
                    "the signed claim_or_refresh_neuron_from_account memo",
                ));
            }
            match args.controller {
                None => Ok(()),
                Some(controller) if controller == sender => Ok(()),
                Some(controller) => Err(ApiError::invalid_request(format!(
                    "The signed stake request names controller {controller}, but Rosetta \
                     would display it against the signer {sender}."
                ))),
            }
        }

        RequestType::NeuronInfo {
            neuron_index,
            controller,
        } => {
            verify_governance_canister(update, governance_canister_id)?;
            verify_method_name(update, GET_FULL_NEURON_BY_ID_OR_SUBACCOUNT)?;
            let id_or_subaccount: NeuronIdOrSubaccount = decode_arg(update, "neuron info")?;
            verify_neuron_subaccount(
                &id_or_subaccount,
                controller.as_ref(),
                sender,
                *neuron_index,
            )
        }

        RequestType::ListNeurons { page_number } => {
            verify_governance_canister(update, governance_canister_id)?;
            verify_method_name(update, LIST_NEURONS)?;
            let args: ListNeurons = decode_arg(update, "list neurons")?;
            let signed_page_number = args.page_number.unwrap_or_default();
            if signed_page_number != *page_number {
                return Err(mismatch(
                    "page_number",
                    *page_number,
                    signed_page_number,
                    "the signed list_neurons argument",
                ));
            }
            if args != list_neurons_arg(args.page_number) {
                return Err(ApiError::invalid_request(
                    "The signed list_neurons argument sets fields other than the page \
                     number, which Rosetta would not display.",
                ));
            }
            Ok(())
        }

        RequestType::SetDissolveTimestamp { neuron_index }
        | RequestType::ChangeAutoStakeMaturity { neuron_index }
        | RequestType::StartDissolve { neuron_index }
        | RequestType::StopDissolve { neuron_index }
        | RequestType::Disburse { neuron_index }
        | RequestType::DisburseMaturity { neuron_index }
        | RequestType::AddHotKey { neuron_index }
        | RequestType::RemoveHotKey { neuron_index }
        | RequestType::Spawn { neuron_index }
        | RequestType::StakeMaturity { neuron_index }
        | RequestType::RegisterVote { neuron_index } => verify_manage_neuron(
            request_type,
            update,
            *neuron_index,
            None,
            sender,
            governance_canister_id,
        ),

        RequestType::Follow {
            neuron_index,
            controller,
        }
        | RequestType::RefreshVotingPower {
            neuron_index,
            controller,
        } => verify_manage_neuron(
            request_type,
            update,
            *neuron_index,
            controller.as_ref(),
            sender,
            governance_canister_id,
        ),
    }
}

fn verify_manage_neuron(
    request_type: &RequestType,
    update: &HttpCanisterUpdate,
    neuron_index: u64,
    controller: Option<&PublicKeyOrPrincipal>,
    sender: PrincipalId,
    governance_canister_id: &CanisterId,
) -> Result<(), ApiError> {
    verify_governance_canister(update, governance_canister_id)?;
    verify_method_name(update, MANAGE_NEURON)?;
    verify_nonce_neuron_index(update, neuron_index)?;

    let manage: ManageNeuronRequest = decode_arg(update, "manage_neuron")?;

    verify_command_matches(request_type, manage.command.as_ref())?;

    // `/construction/payloads` identifies the neuron by subaccount only.
    if manage.id.is_some() {
        return Err(ApiError::invalid_request(
            "The signed manage_neuron request sets the legacy `id` field, whose \
             target cannot be verified against the displayed neuron_index.",
        ));
    }

    let id_or_subaccount = manage.neuron_id_or_subaccount.ok_or_else(|| {
        ApiError::invalid_request(
            "The signed manage_neuron request does not identify a neuron, so the \
             displayed neuron_index cannot be verified.",
        )
    })?;

    verify_neuron_subaccount(&id_or_subaccount, controller, sender, neuron_index)
}

/// Checks that the signed `manage_neuron` command is the displayed operation.
fn verify_command_matches(
    request_type: &RequestType,
    command: Option<&ManageNeuronCommandRequest>,
) -> Result<(), ApiError> {
    use ManageNeuronCommandRequest as Cmd;
    use manage_neuron::configure::Operation as Op;

    let operation = match command {
        Some(Cmd::Configure(manage_neuron::Configure { operation })) => operation.as_ref(),
        _ => None,
    };

    let bound = match request_type {
        RequestType::SetDissolveTimestamp { .. } => {
            matches!(operation, Some(Op::SetDissolveTimestamp(_)))
        }
        RequestType::ChangeAutoStakeMaturity { .. } => {
            matches!(operation, Some(Op::ChangeAutoStakeMaturity(_)))
        }
        RequestType::StartDissolve { .. } => matches!(operation, Some(Op::StartDissolving(_))),
        RequestType::StopDissolve { .. } => matches!(operation, Some(Op::StopDissolving(_))),
        RequestType::AddHotKey { .. } => matches!(operation, Some(Op::AddHotKey(_))),
        RequestType::RemoveHotKey { .. } => matches!(operation, Some(Op::RemoveHotKey(_))),
        RequestType::Disburse { .. } => matches!(command, Some(Cmd::Disburse(_))),
        RequestType::DisburseMaturity { .. } => matches!(command, Some(Cmd::DisburseMaturity(_))),
        RequestType::Spawn { .. } => matches!(command, Some(Cmd::Spawn(_))),
        RequestType::StakeMaturity { .. } => matches!(command, Some(Cmd::StakeMaturity(_))),
        RequestType::RegisterVote { .. } => matches!(command, Some(Cmd::RegisterVote(_))),
        RequestType::Follow { .. } => matches!(command, Some(Cmd::Follow(_))),
        RequestType::RefreshVotingPower { .. } => {
            matches!(command, Some(Cmd::RefreshVotingPower(_)))
        }
        RequestType::Send
        | RequestType::Stake { .. }
        | RequestType::NeuronInfo { .. }
        | RequestType::ListNeurons { .. } => false,
    };

    if !bound {
        return Err(ApiError::invalid_request(format!(
            "The signed manage_neuron command is not the {} operation Rosetta would \
             display. Refusing to name an operation other than the one being signed.",
            request_type.clone().into_str()
        )));
    }
    Ok(())
}

/// Checks that the signed subaccount is `H(controller, neuron_index)` for the
/// displayed controller, or the signer if none is displayed.
fn verify_neuron_subaccount(
    id_or_subaccount: &NeuronIdOrSubaccount,
    controller: Option<&PublicKeyOrPrincipal>,
    sender: PrincipalId,
    neuron_index: u64,
) -> Result<(), ApiError> {
    let signed_subaccount = match id_or_subaccount {
        NeuronIdOrSubaccount::Subaccount(subaccount) => subaccount,
        NeuronIdOrSubaccount::NeuronId(_) => {
            return Err(ApiError::invalid_request(
                "The signed request identifies the neuron by id, whose target cannot \
                 be verified against the displayed neuron_index.",
            ));
        }
    };

    let controller = match controller {
        Some(controller) => convert::principal_id_from_public_key_or_principal(controller.clone())?,
        None => sender,
    };

    let expected = convert::neuron_subaccount_bytes_from_principal(&controller, neuron_index);
    if signed_subaccount.as_slice() != expected.as_slice() {
        return Err(ApiError::invalid_request(format!(
            "The signed neuron subaccount does not belong to the neuron Rosetta would \
             display (controller {controller}, neuron_index {neuron_index}). Refusing to \
             describe a request that targets a different neuron than it appears to."
        )));
    }
    Ok(())
}

fn verify_nonce_neuron_index(
    update: &HttpCanisterUpdate,
    neuron_index: u64,
) -> Result<(), ApiError> {
    let nonce = update.nonce.as_ref().ok_or_else(|| {
        ApiError::invalid_request(
            "The signed update carries no nonce, so the displayed neuron_index \
             cannot be verified against it.",
        )
    })?;
    let signed_neuron_index: u64 = crate::convert::decode_canister_method_arg(nonce.0.as_ref())
        .map_err(|e| {
            ApiError::invalid_request(format!(
                "Could not decode the neuron index from the signed nonce: {e:#}"
            ))
        })?;
    if signed_neuron_index != neuron_index {
        return Err(mismatch(
            "neuron_index",
            neuron_index,
            signed_neuron_index,
            "the signed nonce",
        ));
    }
    Ok(())
}

fn verify_governance_canister(
    update: &HttpCanisterUpdate,
    governance_canister_id: &CanisterId,
) -> Result<(), ApiError> {
    verify_canister(update, governance_canister_id, "A neuron request")
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

fn decode_arg<T>(update: &HttpCanisterUpdate, what: &str) -> Result<T, ApiError>
where
    T: candid::CandidType + serde::de::DeserializeOwned,
{
    crate::convert::decode_canister_method_arg(update.arg.0.as_ref())
        .map_err(|e| ApiError::invalid_request(format!("Could not decode {what} argument: {e:#}")))
}

fn mismatch(field: &str, displayed: u64, signed: u64, source: &str) -> ApiError {
    ApiError::invalid_request(format!(
        "Rosetta would display {field} {displayed}, but {source} says {signed}. Refusing \
         to describe a request that differs from the payload being signed."
    ))
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
mod tests;
