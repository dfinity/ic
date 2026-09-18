//! Verification that the request metadata Rosetta displays for a transaction is
//! bound to the bytes the caller actually signs.
//!
//! `UnsignedTransaction` and `SignedTransaction` pair a [`RequestType`] — plain
//! CBOR metadata, covered by no signature — with an [`HttpCanisterUpdate`],
//! whose `canister_id`, `method_name`, `arg`, `nonce` and `sender` are all
//! covered by `update.id()` and therefore by the caller's signature.
//!
//! `/construction/payloads` always emits the two consistently, and every neuron
//! management payload it builds carries the neuron index twice over: once in the
//! signed `nonce`, and once in the neuron subaccount inside the signed `arg`
//! (as `H(controller, neuron_index)`). Nothing downstream used to require the
//! two representations to agree, so an actor able to rewrite the wrapper could
//! make `/construction/parse` describe one neuron while the signed update
//! targeted another — and for a full-stake `DISBURSE` or a 100%
//! `DISBURSE_MATURITY` the neuron index is the only field indicating how much
//! value moves.
//!
//! [`verify_signed_target`] closes that gap. It is shared by
//! `/construction/parse` and by the submit path's `Request` reconstruction, so
//! the operations shown before signing, the operations shown after signing, and
//! the operations reported back after submission cannot diverge.

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
use ic_types::{PrincipalId, messages::HttpCanisterUpdate};

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
) -> Result<(), ApiError> {
    let representative = envelopes
        .first()
        .ok_or_else(|| ApiError::invalid_request("No request payload provided."))?
        .update_content();

    verify_signed_target(request_type, representative)?;

    for envelope in &envelopes[1..] {
        if !same_update_modulo_expiry(representative, envelope.update_content()) {
            return Err(ApiError::invalid_request(
                "The envelopes of a signed request must differ only in their ingress \
                 expiry. Refusing a request whose envelopes carry different payloads, \
                 since the one that gets submitted need not be the one described.",
            ));
        }
    }
    Ok(())
}

/// Whether two updates are the same message sent in different ingress windows.
fn same_update_modulo_expiry(a: &HttpCanisterUpdate, b: &HttpCanisterUpdate) -> bool {
    // Compare whole updates rather than a field list, so a field added to
    // `HttpCanisterUpdate` later is covered without touching this.
    let normalize = |update: &HttpCanisterUpdate| {
        let mut update = update.clone();
        update.ingress_expiry = 0;
        update
    };
    normalize(a) == normalize(b)
}

/// Check that every field of `request_type` that Rosetta will display is
/// derivable from, and consistent with, the signed `update`.
///
/// Fails closed: a request whose displayed metadata cannot be confirmed against
/// the signed payload is rejected rather than displayed with a warning.
///
/// The one field this does not cover is the `canister_id` of a
/// `RequestType::Send`, which requires knowing the ledger canister this Rosetta
/// instance is configured for. Every governance-bound request type does have its
/// `canister_id` checked here.
pub fn verify_signed_target(
    request_type: &RequestType,
    update: &HttpCanisterUpdate,
) -> Result<(), ApiError> {
    let sender = PrincipalId::try_from(update.sender.0.as_slice()).map_err(|e| {
        ApiError::invalid_request(format!("Could not parse the signed update's sender: {e}"))
    })?;

    match request_type {
        RequestType::Send => verify_method_name(update, SEND_PB),

        RequestType::Stake { neuron_index } => {
            verify_governance_canister(update)?;
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
            verify_governance_canister(update)?;
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
            verify_governance_canister(update)?;
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
        | RequestType::RegisterVote { neuron_index } => {
            verify_manage_neuron(request_type, update, *neuron_index, None, sender)
        }

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
) -> Result<(), ApiError> {
    verify_governance_canister(update)?;
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
    let signed_neuron_index: u64 = candid::decode_one(nonce.0.as_ref()).map_err(|e| {
        ApiError::invalid_request(format!(
            "Could not decode the neuron index from the signed nonce: {e:?}"
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

fn verify_governance_canister(update: &HttpCanisterUpdate) -> Result<(), ApiError> {
    let expected = ic_nns_constants::GOVERNANCE_CANISTER_ID.get();
    if update.canister_id.0.as_slice() != expected.as_slice() {
        return Err(ApiError::invalid_request(format!(
            "A neuron request must be addressed to the governance canister {expected}, \
             but the signed update is addressed elsewhere."
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
    T: for<'a> candid::Deserialize<'a> + candid::CandidType,
{
    candid::decode_one(update.arg.0.as_ref())
        .map_err(|e| ApiError::invalid_request(format!("Could not decode {what} argument: {e:?}")))
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
    use candid::Encode;
    use ic_nns_governance_api::{ManageNeuronCommandRequest, manage_neuron};
    use ic_types::messages::Blob;

    const NEURON_INDEX: u64 = 7;

    fn controller() -> PrincipalId {
        PrincipalId::new_user_test_id(1)
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
            canister_id: Blob(ic_nns_constants::GOVERNANCE_CANISTER_ID.get().to_vec()),
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
        verify_signed_target(&disburse(NEURON_INDEX), &update).unwrap();
    }

    #[test]
    fn rewritten_neuron_index_is_rejected() {
        let update = manage_neuron_update(controller(), NEURON_INDEX);
        // The wrapper claims a different, less valuable neuron than the one the
        // signed subaccount and nonce identify.
        verify_signed_target(&disburse(0), &update).unwrap_err();
    }

    #[test]
    fn missing_nonce_is_rejected() {
        let mut update = manage_neuron_update(controller(), NEURON_INDEX);
        update.nonce = None;
        // Fail closed: an absent nonce leaves the displayed index unverifiable
        // rather than verified.
        verify_signed_target(&disburse(NEURON_INDEX), &update).unwrap_err();
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
        verify_signed_target(&disburse(NEURON_INDEX), &update).unwrap_err();
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
        verify_signed_target(&disburse(NEURON_INDEX), &update).unwrap_err();
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
        verify_signed_target(&disburse(NEURON_INDEX), &update).unwrap_err();
    }

    #[test]
    fn foreign_canister_is_rejected() {
        let mut update = manage_neuron_update(controller(), NEURON_INDEX);
        update.canister_id = Blob(PrincipalId::new_user_test_id(3).to_vec());
        verify_signed_target(&disburse(NEURON_INDEX), &update).unwrap_err();
    }

    #[test]
    fn unexpected_method_name_is_rejected() {
        let mut update = manage_neuron_update(controller(), NEURON_INDEX);
        update.method_name = "some_other_method".to_string();
        verify_signed_target(&disburse(NEURON_INDEX), &update).unwrap_err();
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
        verify_signed_target(&honest, &update).unwrap();

        let substituted = RequestType::Follow {
            neuron_index: NEURON_INDEX,
            controller: Some(PublicKeyOrPrincipal::Principal(
                PrincipalId::new_user_test_id(4),
            )),
        };
        verify_signed_target(&substituted, &update).unwrap_err();
    }

    #[test]
    fn stake_is_bound_to_the_signed_memo() {
        let sender = controller();
        let args = ClaimOrRefreshNeuronFromAccount {
            controller: None,
            memo: NEURON_INDEX,
        };
        let update = HttpCanisterUpdate {
            canister_id: Blob(ic_nns_constants::GOVERNANCE_CANISTER_ID.get().to_vec()),
            method_name: CLAIM_OR_REFRESH_NEURON_FROM_ACCOUNT.to_string(),
            arg: Blob(Encode!(&args).unwrap()),
            nonce: Some(Blob(Encode!(&NEURON_INDEX).unwrap())),
            sender: Blob(sender.into_vec()),
            ingress_expiry: 0,
            sender_info: None,
        };

        verify_signed_target(
            &RequestType::Stake {
                neuron_index: NEURON_INDEX,
            },
            &update,
        )
        .unwrap();
        verify_signed_target(&RequestType::Stake { neuron_index: 0 }, &update).unwrap_err();
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
            canister_id: Blob(ic_nns_constants::GOVERNANCE_CANISTER_ID.get().to_vec()),
            method_name: LIST_NEURONS.to_string(),
            arg: Blob(Encode!(&args).unwrap()),
            nonce: None,
            sender: Blob(controller().into_vec()),
            ingress_expiry: 0,
            sender_info: None,
        };

        verify_signed_target(&RequestType::ListNeurons { page_number: 3 }, &update).unwrap();
        verify_signed_target(&RequestType::ListNeurons { page_number: 0 }, &update).unwrap_err();
    }

    #[test]
    fn neuron_info_is_bound_to_the_signed_subaccount() {
        let sender = controller();
        let args = NeuronIdOrSubaccount::Subaccount(
            convert::neuron_subaccount_bytes_from_principal(&sender, NEURON_INDEX).to_vec(),
        );
        let update = HttpCanisterUpdate {
            canister_id: Blob(ic_nns_constants::GOVERNANCE_CANISTER_ID.get().to_vec()),
            method_name: GET_FULL_NEURON_BY_ID_OR_SUBACCOUNT.to_string(),
            arg: Blob(Encode!(&args).unwrap()),
            nonce: None,
            sender: Blob(sender.into_vec()),
            ingress_expiry: 0,
            sender_info: None,
        };

        verify_signed_target(
            &RequestType::NeuronInfo {
                neuron_index: NEURON_INDEX,
                controller: None,
            },
            &update,
        )
        .unwrap();
        verify_signed_target(
            &RequestType::NeuronInfo {
                neuron_index: 0,
                controller: None,
            },
            &update,
        )
        .unwrap_err();
    }
    #[test]
    fn substituted_command_is_rejected() {
        // The signed command is a disburse of this neuron; the wrapper names a
        // different operation on the same neuron, so nonce, subaccount,
        // canister and method all still agree.
        let update = manage_neuron_update(controller(), NEURON_INDEX);
        verify_signed_target(
            &RequestType::StartDissolve {
                neuron_index: NEURON_INDEX,
            },
            &update,
        )
        .unwrap_err();
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
                canister_id: Blob(ic_nns_constants::GOVERNANCE_CANISTER_ID.get().to_vec()),
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
        verify_signed_target(&stake, &signed_stake(None)).unwrap();
        verify_signed_target(&stake, &signed_stake(Some(sender))).unwrap();
        // Naming someone else claims `H(other, memo)`, not the signer's neuron.
        verify_signed_target(
            &stake,
            &signed_stake(Some(PrincipalId::new_user_test_id(77))),
        )
        .unwrap_err();
    }

    #[test]
    fn envelopes_must_differ_only_in_ingress_expiry() {
        use crate::models::EnvelopePair;
        use ic_types::messages::{
            HttpCallContent, HttpReadState, HttpReadStateContent, HttpRequestEnvelope,
        };

        let pair = |update: HttpCanisterUpdate| EnvelopePair {
            update: HttpRequestEnvelope::<HttpCallContent> {
                content: HttpCallContent::Call { update },
                sender_pubkey: None,
                sender_sig: None,
                sender_delegation: None,
            },
            read_state: HttpRequestEnvelope::<HttpReadStateContent> {
                content: HttpReadStateContent::ReadState {
                    read_state: HttpReadState {
                        sender: Blob(controller().into_vec()),
                        paths: vec![],
                        nonce: None,
                        ingress_expiry: 0,
                    },
                },
                sender_pubkey: None,
                sender_sig: None,
                sender_delegation: None,
            },
        };

        let base = manage_neuron_update(controller(), NEURON_INDEX);
        let mut later = base.clone();
        later.ingress_expiry = base.ingress_expiry + 1_000;

        // The same message in two ingress windows is what combine produces.
        verify_signed_envelopes(&disburse(NEURON_INDEX), &[pair(base.clone()), pair(later)])
            .unwrap();

        // An envelope for another neuron alongside it is not.
        let other = manage_neuron_update(controller(), 9);
        verify_signed_envelopes(&disburse(NEURON_INDEX), &[pair(base), pair(other)]).unwrap_err();

        // And an empty request has nothing to describe.
        verify_signed_envelopes(&disburse(NEURON_INDEX), &[]).unwrap_err();
    }
}
