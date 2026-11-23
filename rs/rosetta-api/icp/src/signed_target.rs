//! Verification that the request metadata Rosetta displays for a transaction is
//! bound to the bytes the caller actually signs.
//!
//! `UnsignedTransaction` and `SignedTransaction` pair a [`RequestType`] -- plain
//! CBOR metadata that no signature covers -- with an [`HttpCanisterUpdate`],
//! whose `canister_id`, `method_name`, `arg`, `nonce` and `sender` are all
//! covered by `update.id()` and therefore by the caller's signature. Every field
//! Rosetta displays must therefore be derivable from, and consistent with, the
//! signed update:
//!
//! * A neuron management request names its neuron twice in signed data: in the
//!   `nonce`, and in the neuron subaccount `H(controller, neuron_index)` inside
//!   the `arg`. Both must match the displayed neuron index and controller, and
//!   the signed command must be the displayed operation.
//! * A transfer must be addressed to the ledger this instance serves, since its
//!   amount is displayed in that ledger's token, and must debit the sender's
//!   default account, which is the account displayed.
//! * Each signed update travels with a separately signed read-state call, which
//!   must read that update's own result.
//!
//! [`verify_signed_target`] and [`verify_signed_envelopes`] enforce this. They
//! are shared by `/construction/parse`, `/construction/hash` and the submit
//! path's `Request` reconstruction, so the operations shown before and after
//! signing, the expected transaction hash, and the operations reported after
//! submission all describe the signed update.

use crate::{
    convert,
    errors::ApiError,
    models::EnvelopePair,
    request_types::{PublicKeyOrPrincipal, RequestType},
};
use ic_nns_governance_api::{
    ClaimOrRefreshNeuronFromAccount, ManageNeuronCommandRequest, ManageNeuronRequest,
    manage_neuron, manage_neuron::NeuronIdOrSubaccount,
};
use ic_types::{
    CanisterId, PrincipalId,
    messages::{HttpCanisterUpdate, HttpReadStateContent},
};

/// Governance method that every neuron management command is submitted through.
const MANAGE_NEURON: &str = "manage_neuron";
/// Governance method behind `RequestType::Stake`.
const CLAIM_OR_REFRESH_NEURON_FROM_ACCOUNT: &str = "claim_or_refresh_neuron_from_account";
/// Governance method behind `RequestType::NeuronInfo`.
const GET_FULL_NEURON_BY_ID_OR_SUBACCOUNT: &str = "get_full_neuron_by_id_or_subaccount";
/// Governance method behind `RequestType::ListNeurons`.
const LIST_NEURONS: &str = "list_neurons";
/// Ledger method behind `RequestType::Send`.
const SEND_PB: &str = "send_pb";

/// Check a signed request's envelopes as a whole.
///
/// A signed request carries one envelope per ingress expiry, each with its own
/// signature, and `/construction/submit` broadcasts whichever one is currently
/// valid rather than the first. Validating only one envelope would therefore
/// leave the displayed operations describing a message that is not the one sent:
/// a request could pair an expired envelope matching the wrapper with a
/// currently valid envelope for a different neuron, amount or recipient.
///
/// `/construction/combine` builds these envelopes by cloning a single update and
/// varying only `ingress_expiry`, so requiring them to be identical in every
/// other byte is both what honest requests satisfy and enough to make the
/// envelope that gets broadcast interchangeable with the one described.
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

/// Return the update that stands for every envelope of a signed request, or an
/// error if the envelopes are not interchangeable.
///
/// They are interchangeable when they all carry the same message -- see
/// [`verify_signed_envelopes`] for why they have to -- and each is paired with
/// the read-state call that reads that message's own result. Callers that go on
/// to check the returned update against the displayed metadata themselves use
/// this directly, rather than having it checked twice.
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
    governance_canister_id: &CanisterId,
) -> Result<(), ApiError> {
    let sender = PrincipalId::try_from(update.sender.0.as_slice()).map_err(|e| {
        ApiError::invalid_request(format!("Could not parse the signed update's sender: {e}"))
    })?;

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

        RequestType::Stake { neuron_index } => {
            verify_governance_canister(update, governance_canister_id)?;
            verify_method_name(update, CLAIM_OR_REFRESH_NEURON_FROM_ACCOUNT)?;
            verify_nonce_neuron_index(update, *neuron_index)?;
            // `claim_or_refresh_neuron_from_account` identifies the neuron by
            // `memo` rather than by subaccount, so that is what binds the
            // displayed index here.
            let args: ClaimOrRefreshNeuronFromAccount = decode_arg(update, "stake")?;
            if args.memo != *neuron_index {
                return Err(mismatch(
                    "neuron_index",
                    *neuron_index,
                    args.memo,
                    "the signed claim_or_refresh_neuron_from_account memo",
                ));
            }
            // The signed argument may name the controller explicitly, in which
            // case the neuron claimed is `H(controller, memo)` rather than the
            // signer's. Rosetta displays the request against the signer, so
            // anything else would describe the wrong neuron's owner.
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
            // This request type carries no nonce; the subaccount in the signed
            // argument is the only authenticated neuron identifier.
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
            let args: ic_nns_governance_api::ListNeurons = decode_arg(update, "list neurons")?;
            let signed_page_number = args.page_number.unwrap_or_default();
            if signed_page_number != *page_number {
                return Err(mismatch(
                    "page_number",
                    *page_number,
                    signed_page_number,
                    "the signed list_neurons argument",
                ));
            }
            Ok(())
        }

        // Everything below is a `manage_neuron` command. The neuron is
        // identified by the subaccount in the signed argument, and the index
        // used to derive that subaccount is repeated in the signed nonce, so
        // both are checked against what will be displayed.
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

/// Shared body for the `manage_neuron` request types.
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

    // `/construction/payloads` always identifies the neuron by subaccount and
    // leaves the legacy `id` field unset. A request that sets `id` carries a
    // neuron identifier that cannot be checked against the displayed index, so
    // it is rejected rather than displayed unverified.
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

/// Check that the signed `manage_neuron` command is the operation the displayed
/// request type names.
///
/// Binding the neuron alone is not enough: the submit path does not re-derive
/// the command for every request type (`START_DISSOLVE` and `STOP_DISSOLVE`
/// report the wrapper variant without decoding the payload at all), so
/// rewriting only that variant would make Rosetta name one operation while a
/// different one executes.
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
        // Not submitted through `manage_neuron`; their own arms bind them.
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

/// Check that the signed neuron subaccount is the one derived from the
/// controller and neuron index that will be displayed.
///
/// Because the subaccount is `H(controller, neuron_index)`, this also
/// authenticates the displayed `controller` on the request types that carry one
/// as wrapper metadata: a wrapper naming a different controller no longer
/// reproduces the signed subaccount.
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

    // With no explicit controller the neuron belongs to the signer; with one,
    // the signer is a hotkey acting for that controller. `/construction/payloads`
    // derives the subaccount the same way.
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

/// Check the signed nonce, which `/construction/payloads` uses to carry the
/// neuron index, against the index that will be displayed.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::EnvelopePair;
    use candid::Encode;
    use ic_nns_governance_api::{ManageNeuronCommandRequest, manage_neuron};
    use ic_types::messages::{Blob, HttpCallContent, HttpRequestEnvelope};

    const NEURON_INDEX: u64 = 7;

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

    #[track_caller]
    fn assert_rejected(result: Result<(), ApiError>, expected: &str) {
        let err = result.expect_err("expected the request to be rejected");
        assert!(
            format!("{err:?}").contains(expected),
            "expected an error containing {expected:?}, got {err:?}"
        );
    }

    fn verify(request_type: &RequestType, update: &HttpCanisterUpdate) -> Result<(), ApiError> {
        verify_signed_target(request_type, update, &ledger(), &governance())
    }

    fn verify_envelopes(
        request_type: &RequestType,
        envelopes: &[EnvelopePair],
    ) -> Result<(), ApiError> {
        verify_signed_envelopes(request_type, envelopes, &ledger(), &governance())
    }

    /// Builds the update that `add_neuron_management_payload` would build for a
    /// complete-stake disburse of `neuron_index`, controlled by `sender`.
    fn manage_neuron_update(sender: PrincipalId, neuron_index: u64) -> HttpCanisterUpdate {
        let manage = ManageNeuronRequest {
            id: None,
            neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::Subaccount(
                convert::neuron_subaccount_bytes_from_principal(&sender, neuron_index).to_vec(),
            )),
            command: Some(ManageNeuronCommandRequest::Disburse(
                manage_neuron::Disburse {
                    amount: None,
                    to_account: None,
                },
            )),
        };
        HttpCanisterUpdate {
            canister_id: Blob(governance().get().to_vec()),
            method_name: MANAGE_NEURON.to_string(),
            arg: Blob(Encode!(&manage).unwrap()),
            nonce: Some(Blob(Encode!(&neuron_index).unwrap())),
            sender: Blob(sender.into_vec()),
            ingress_expiry: 0,
            sender_info: None,
        }
    }

    fn disburse(neuron_index: u64) -> RequestType {
        RequestType::Disburse { neuron_index }
    }

    #[test]
    fn faithful_update_is_accepted() {
        let update = manage_neuron_update(controller(), NEURON_INDEX);
        verify(&disburse(NEURON_INDEX), &update).unwrap();
    }

    #[test]
    fn rewritten_neuron_index_is_rejected() {
        let update = manage_neuron_update(controller(), NEURON_INDEX);
        // The wrapper claims a different, less valuable neuron than the one the
        // signed subaccount and nonce identify.
        assert_rejected(
            verify(&disburse(0), &update),
            "neuron_index 0, but the signed nonce says 7",
        );
    }

    #[test]
    fn missing_nonce_is_rejected() {
        let mut update = manage_neuron_update(controller(), NEURON_INDEX);
        update.nonce = None;
        // Fail closed: an absent nonce leaves the displayed index unverifiable
        // rather than verified.
        assert_rejected(verify(&disburse(NEURON_INDEX), &update), "carries no nonce");
    }

    #[test]
    fn nonce_agreeing_with_a_foreign_subaccount_is_rejected() {
        let mut update = manage_neuron_update(controller(), NEURON_INDEX);
        // Both the wrapper and the nonce say NEURON_INDEX, but the subaccount
        // belongs to someone else's neuron, so the nonce alone is not enough.
        let manage = ManageNeuronRequest {
            id: None,
            neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::Subaccount(
                convert::neuron_subaccount_bytes_from_principal(
                    &PrincipalId::new_user_test_id(2),
                    NEURON_INDEX,
                )
                .to_vec(),
            )),
            command: Some(ManageNeuronCommandRequest::Disburse(
                manage_neuron::Disburse {
                    amount: None,
                    to_account: None,
                },
            )),
        };
        update.arg = Blob(Encode!(&manage).unwrap());
        assert_rejected(
            verify(&disburse(NEURON_INDEX), &update),
            "signed neuron subaccount does not belong",
        );
    }

    #[test]
    fn legacy_neuron_id_field_is_rejected() {
        let mut update = manage_neuron_update(controller(), NEURON_INDEX);
        let manage = ManageNeuronRequest {
            id: Some(ic_nns_common::pb::v1::NeuronId { id: 99 }),
            neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::Subaccount(
                convert::neuron_subaccount_bytes_from_principal(&controller(), NEURON_INDEX)
                    .to_vec(),
            )),
            command: Some(ManageNeuronCommandRequest::Disburse(
                manage_neuron::Disburse {
                    amount: None,
                    to_account: None,
                },
            )),
        };
        update.arg = Blob(Encode!(&manage).unwrap());
        assert_rejected(
            verify(&disburse(NEURON_INDEX), &update),
            "legacy `id` field",
        );
    }

    #[test]
    fn neuron_id_instead_of_subaccount_is_rejected() {
        let mut update = manage_neuron_update(controller(), NEURON_INDEX);
        let manage = ManageNeuronRequest {
            id: None,
            neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(
                ic_nns_common::pb::v1::NeuronId { id: 99 },
            )),
            command: Some(ManageNeuronCommandRequest::Disburse(
                manage_neuron::Disburse {
                    amount: None,
                    to_account: None,
                },
            )),
        };
        update.arg = Blob(Encode!(&manage).unwrap());
        assert_rejected(
            verify(&disburse(NEURON_INDEX), &update),
            "identifies the neuron by id",
        );
    }

    #[test]
    fn foreign_canister_is_rejected() {
        let mut update = manage_neuron_update(controller(), NEURON_INDEX);
        update.canister_id = Blob(PrincipalId::new_user_test_id(3).to_vec());
        assert_rejected(
            verify(&disburse(NEURON_INDEX), &update),
            "must be addressed to canister",
        );

        // Including the mainnet governance canister, when that is not the one
        // this instance was configured with. `/construction/derive` names
        // neurons under the configured canister, so a request against any
        // other one describes a neuron this instance does not serve.
        let mut update = manage_neuron_update(controller(), NEURON_INDEX);
        update.canister_id = Blob(ic_nns_constants::GOVERNANCE_CANISTER_ID.get().to_vec());
        assert_rejected(
            verify(&disburse(NEURON_INDEX), &update),
            "must be addressed to canister",
        );
    }

    #[test]
    fn unexpected_method_name_is_rejected() {
        let mut update = manage_neuron_update(controller(), NEURON_INDEX);
        update.method_name = "some_other_method".to_string();
        assert_rejected(
            verify(&disburse(NEURON_INDEX), &update),
            "Expected the signed update to call 'manage_neuron'",
        );
    }

    #[test]
    fn substituted_controller_is_rejected() {
        // `FOLLOW` carries the controller as wrapper metadata so a hotkey can
        // act for it. Because the subaccount is `H(controller, neuron_index)`,
        // naming a different controller no longer reproduces it.
        let hotkey = PrincipalId::new_user_test_id(9);
        let manage = ManageNeuronRequest {
            id: None,
            neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::Subaccount(
                convert::neuron_subaccount_bytes_from_principal(&controller(), NEURON_INDEX)
                    .to_vec(),
            )),
            command: Some(ManageNeuronCommandRequest::Follow(manage_neuron::Follow {
                topic: 0,
                followees: vec![],
            })),
        };
        let mut update = manage_neuron_update(hotkey, NEURON_INDEX);
        update.arg = Blob(Encode!(&manage).unwrap());

        let honest = RequestType::Follow {
            neuron_index: NEURON_INDEX,
            controller: Some(PublicKeyOrPrincipal::Principal(controller())),
        };
        verify(&honest, &update).unwrap();

        let substituted = RequestType::Follow {
            neuron_index: NEURON_INDEX,
            controller: Some(PublicKeyOrPrincipal::Principal(
                PrincipalId::new_user_test_id(4),
            )),
        };
        assert_rejected(
            verify(&substituted, &update),
            "signed neuron subaccount does not belong",
        );
    }

    #[test]
    fn stake_is_bound_to_the_signed_memo() {
        let sender = controller();
        let args = ClaimOrRefreshNeuronFromAccount {
            controller: None,
            memo: NEURON_INDEX,
        };
        let update = HttpCanisterUpdate {
            canister_id: Blob(governance().get().to_vec()),
            method_name: CLAIM_OR_REFRESH_NEURON_FROM_ACCOUNT.to_string(),
            arg: Blob(Encode!(&args).unwrap()),
            nonce: Some(Blob(Encode!(&NEURON_INDEX).unwrap())),
            sender: Blob(sender.into_vec()),
            ingress_expiry: 0,
            sender_info: None,
        };

        verify(
            &RequestType::Stake {
                neuron_index: NEURON_INDEX,
            },
            &update,
        )
        .unwrap();
        assert_rejected(
            verify(&RequestType::Stake { neuron_index: 0 }, &update),
            "neuron_index 0, but the signed nonce says 7",
        );
    }

    #[test]
    fn list_neurons_page_number_is_bound_to_the_signed_argument() {
        let args = ic_nns_governance_api::ListNeurons {
            neuron_ids: vec![],
            include_neurons_readable_by_caller: true,
            include_empty_neurons_readable_by_caller: None,
            include_public_neurons_in_full_neurons: None,
            page_number: Some(3),
            page_size: None,
            neuron_subaccounts: None,
        };
        let update = HttpCanisterUpdate {
            canister_id: Blob(governance().get().to_vec()),
            method_name: LIST_NEURONS.to_string(),
            arg: Blob(Encode!(&args).unwrap()),
            nonce: None,
            sender: Blob(controller().into_vec()),
            ingress_expiry: 0,
            sender_info: None,
        };

        verify(&RequestType::ListNeurons { page_number: 3 }, &update).unwrap();
        assert_rejected(
            verify(&RequestType::ListNeurons { page_number: 0 }, &update),
            "page_number 0, but the signed list_neurons argument says 3",
        );
    }

    #[test]
    fn neuron_info_is_bound_to_the_signed_subaccount() {
        let sender = controller();
        let args = NeuronIdOrSubaccount::Subaccount(
            convert::neuron_subaccount_bytes_from_principal(&sender, NEURON_INDEX).to_vec(),
        );
        let update = HttpCanisterUpdate {
            canister_id: Blob(governance().get().to_vec()),
            method_name: GET_FULL_NEURON_BY_ID_OR_SUBACCOUNT.to_string(),
            arg: Blob(Encode!(&args).unwrap()),
            nonce: None,
            sender: Blob(sender.into_vec()),
            ingress_expiry: 0,
            sender_info: None,
        };

        verify(
            &RequestType::NeuronInfo {
                neuron_index: NEURON_INDEX,
                controller: None,
            },
            &update,
        )
        .unwrap();
        assert_rejected(
            verify(
                &RequestType::NeuronInfo {
                    neuron_index: 0,
                    controller: None,
                },
                &update,
            ),
            "signed neuron subaccount does not belong",
        );
    }

    #[test]
    fn substituted_command_is_rejected() {
        // The signed command is a disburse of this neuron; the wrapper names a
        // different operation on the same neuron, so nonce, subaccount,
        // canister and method all still agree.
        let update = manage_neuron_update(controller(), NEURON_INDEX);
        assert_rejected(
            verify(
                &RequestType::StartDissolve {
                    neuron_index: NEURON_INDEX,
                },
                &update,
            ),
            "The signed manage_neuron command is not the",
        );
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

    #[test]
    fn stake_with_foreign_controller_is_rejected() {
        let sender = controller();
        let signed_stake = |controller: Option<PrincipalId>| {
            let args = ClaimOrRefreshNeuronFromAccount {
                controller,
                memo: NEURON_INDEX,
            };
            HttpCanisterUpdate {
                canister_id: Blob(governance().get().to_vec()),
                method_name: CLAIM_OR_REFRESH_NEURON_FROM_ACCOUNT.to_string(),
                arg: Blob(Encode!(&args).unwrap()),
                nonce: Some(Blob(Encode!(&NEURON_INDEX).unwrap())),
                sender: Blob(sender.into_vec()),
                ingress_expiry: 0,
                sender_info: None,
            }
        };
        let stake = RequestType::Stake {
            neuron_index: NEURON_INDEX,
        };

        // Absent, or naming the signer: the neuron displayed is the one claimed.
        verify(&stake, &signed_stake(None)).unwrap();
        verify(&stake, &signed_stake(Some(sender))).unwrap();
        // Naming someone else claims `H(other, memo)`, not the signer's neuron.
        assert_rejected(
            verify(
                &stake,
                &signed_stake(Some(PrincipalId::new_user_test_id(77))),
            ),
            "names controller",
        );
    }

    /// Every `manage_neuron` request type, paired with the command
    /// `/construction/payloads` signs for it.
    fn manage_neuron_requests(neuron_index: u64) -> Vec<(RequestType, ManageNeuronCommandRequest)> {
        use ManageNeuronCommandRequest as Cmd;
        use manage_neuron::configure::Operation as Op;
        let configure = |operation| {
            Cmd::Configure(manage_neuron::Configure {
                operation: Some(operation),
            })
        };
        let hot_key = Some(PrincipalId::new_user_test_id(5));
        vec![
            (
                RequestType::Disburse { neuron_index },
                Cmd::Disburse(manage_neuron::Disburse {
                    amount: None,
                    to_account: None,
                }),
            ),
            (
                RequestType::DisburseMaturity { neuron_index },
                Cmd::DisburseMaturity(manage_neuron::DisburseMaturity {
                    percentage_to_disburse: 100,
                    to_account_identifier: None,
                    to_account: None,
                }),
            ),
            (
                RequestType::SetDissolveTimestamp { neuron_index },
                configure(Op::SetDissolveTimestamp(
                    manage_neuron::SetDissolveTimestamp {
                        dissolve_timestamp_seconds: 1_000,
                    },
                )),
            ),
            (
                RequestType::ChangeAutoStakeMaturity { neuron_index },
                configure(Op::ChangeAutoStakeMaturity(
                    manage_neuron::ChangeAutoStakeMaturity {
                        requested_setting_for_auto_stake_maturity: true,
                    },
                )),
            ),
            (
                RequestType::StartDissolve { neuron_index },
                configure(Op::StartDissolving(manage_neuron::StartDissolving {})),
            ),
            (
                RequestType::StopDissolve { neuron_index },
                configure(Op::StopDissolving(manage_neuron::StopDissolving {})),
            ),
            (
                RequestType::AddHotKey { neuron_index },
                configure(Op::AddHotKey(manage_neuron::AddHotKey {
                    new_hot_key: hot_key,
                })),
            ),
            (
                RequestType::RemoveHotKey { neuron_index },
                configure(Op::RemoveHotKey(manage_neuron::RemoveHotKey {
                    hot_key_to_remove: hot_key,
                })),
            ),
            (
                RequestType::Spawn { neuron_index },
                Cmd::Spawn(manage_neuron::Spawn {
                    new_controller: None,
                    percentage_to_spawn: None,
                    nonce: Some(neuron_index + 1),
                }),
            ),
            (
                RequestType::StakeMaturity { neuron_index },
                Cmd::StakeMaturity(manage_neuron::StakeMaturity {
                    percentage_to_stake: None,
                }),
            ),
            (
                RequestType::RegisterVote { neuron_index },
                Cmd::RegisterVote(manage_neuron::RegisterVote {
                    proposal: Some(ic_nns_common::pb::v1::ProposalId { id: 1 }),
                    vote: 1,
                }),
            ),
            (
                RequestType::Follow {
                    neuron_index,
                    controller: None,
                },
                Cmd::Follow(manage_neuron::Follow {
                    topic: 0,
                    followees: vec![ic_nns_common::pb::v1::NeuronId { id: 1 }],
                }),
            ),
            (
                RequestType::RefreshVotingPower {
                    neuron_index,
                    controller: None,
                },
                Cmd::RefreshVotingPower(manage_neuron::RefreshVotingPower {}),
            ),
        ]
    }

    /// Builds the update `add_neuron_management_payload` builds for `command`
    /// on the signer's own neuron `neuron_index`.
    fn manage_neuron_update_with(
        sender: PrincipalId,
        neuron_index: u64,
        command: ManageNeuronCommandRequest,
    ) -> HttpCanisterUpdate {
        let manage = ManageNeuronRequest {
            id: None,
            neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::Subaccount(
                convert::neuron_subaccount_bytes_from_principal(&sender, neuron_index).to_vec(),
            )),
            command: Some(command),
        };
        HttpCanisterUpdate {
            arg: Blob(Encode!(&manage).unwrap()),
            ..manage_neuron_update(sender, neuron_index)
        }
    }

    #[test]
    fn every_manage_neuron_request_is_bound_to_the_signed_neuron() {
        for (request_type, command) in manage_neuron_requests(NEURON_INDEX) {
            let update = manage_neuron_update_with(controller(), NEURON_INDEX, command);
            let name = request_type.clone().into_str();

            if let Err(err) = verify(&request_type, &update) {
                panic!("{name}: the genuine update was rejected: {err:?}");
            }

            // The same signed update, displayed as acting on another neuron.
            let (rewritten, _) = manage_neuron_requests(0)
                .into_iter()
                .find(|(other, _)| other.clone().into_str() == name)
                .unwrap();
            let err = verify(&rewritten, &update).expect_err(name);
            assert!(
                format!("{err:?}").contains("neuron_index 0, but the signed nonce says 7"),
                "{name}: unexpected error {err:?}"
            );
        }
    }

    /// Builds the envelope pair `/construction/combine` would build for
    /// `update`: the update itself, and the read-state call that reads its
    /// result.
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
        let base = manage_neuron_update(controller(), NEURON_INDEX);
        let mut later = base.clone();
        later.ingress_expiry = base.ingress_expiry + 1_000;

        // The same message in two ingress windows is what combine produces.
        verify_envelopes(&disburse(NEURON_INDEX), &[pair(base.clone()), pair(later)]).unwrap();

        // An envelope for another neuron alongside it is not.
        let other = manage_neuron_update(controller(), 9);
        assert_rejected(
            verify_envelopes(&disburse(NEURON_INDEX), &[pair(base), pair(other)]),
            "must differ only in their ingress",
        );

        // And an empty request has nothing to describe.
        assert_rejected(
            verify_envelopes(&disburse(NEURON_INDEX), &[]),
            "No request payload provided",
        );
    }

    /// The update and read-state halves are signed separately, so an envelope
    /// can pair an update with the read-state call of another message. Submit
    /// would broadcast the update and then poll for a request id the IC never
    /// certifies, reporting a failure for a call that is executing.
    #[test]
    fn a_read_state_for_another_message_is_rejected() {
        let base = manage_neuron_update(controller(), NEURON_INDEX);
        let mut later = base.clone();
        later.ingress_expiry = base.ingress_expiry + 1_000;

        // Both halves of a genuine pair, swapped between two envelopes of the
        // same transaction -- no extra signature needed to build this.
        let mut spliced = pair(base.clone());
        spliced.read_state = pair(later).read_state;
        assert_rejected(
            verify_envelopes(&disburse(NEURON_INDEX), &[spliced]),
            "must read the result of that",
        );

        // And the read-state call of an entirely different neuron's request.
        let mut spliced = pair(base);
        spliced.read_state = pair(manage_neuron_update(controller(), 9)).read_state;
        assert_rejected(
            verify_envelopes(&disburse(NEURON_INDEX), &[spliced]),
            "must read the result of that",
        );
    }
}
