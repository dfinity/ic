use crate::{
    convert::{self, from_account_or_account_identifier, from_arg, to_model_account_identifier},
    errors::ApiError,
    models::{ConstructionParseRequest, ConstructionParseResponse, ParsedTransaction},
    request_handler::{RosettaRequestHandler, verify_network_id},
    request_types::{
        AddHotKey, ChangeAutoStakeMaturity, Disburse, DisburseMaturity, Follow, ListNeurons,
        NeuronInfo, PublicKeyOrPrincipal, RefreshVotingPower, RegisterVote, RemoveHotKey,
        RequestType, SetDissolveTimestamp, Spawn, Stake, StakeMaturity, StartDissolve,
        StopDissolve,
    },
    signed_target::{representative_envelope, verify_signed_target},
};
use rosetta_core::objects::ObjectMap;

use ic_nns_governance_api::{
    ClaimOrRefreshNeuronFromAccount, ManageNeuronCommandRequest, ManageNeuronRequest,
    manage_neuron::{self, NeuronIdOrSubaccount},
};

use crate::{models::seconds::Seconds, request::Request};
use ic_types::{
    PrincipalId,
    messages::{Blob, HttpCanisterUpdate},
};
use icp_ledger::{AccountIdentifier, Operation, SendArgs};
use std::convert::TryFrom;

impl RosettaRequestHandler {
    /// Parse a Transaction.
    /// See https://www.rosetta-api.org/docs/ConstructionApi.html#constructionparse
    pub fn construction_parse(
        &self,
        msg: ConstructionParseRequest,
    ) -> Result<ConstructionParseResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;

        let updates: Vec<_> = match ParsedTransaction::try_from(msg.clone())? {
            ParsedTransaction::Signed(signed_transaction) => signed_transaction
                .requests
                .iter()
                .map(|(request_type, envelopes)| {
                    Ok((
                        request_type.clone(),
                        representative_envelope(envelopes)?.clone(),
                    ))
                })
                .collect::<Result<Vec<_>, ApiError>>()?,
            ParsedTransaction::Unsigned(unsigned_transaction) => unsigned_transaction.updates,
        };

        let mut requests = vec![];
        let mut from_ai = vec![];
        let mut metadata = serde_json::Map::new();

        for (request_type, update) in updates {
            verify_signed_target(
                &request_type,
                &update,
                self.ledger.ledger_canister_id(),
                self.ledger.governance_canister_id(),
            )?;

            let HttpCanisterUpdate { arg, sender, .. } = update;
            let from = PrincipalId::try_from(sender.0)
                .map_err(|e| ApiError::internal_error(e.to_string()))?
                .into();
            if msg.signed {
                from_ai.push(from);
            }

            match request_type {
                RequestType::Send => send(&mut requests, &mut metadata, arg, from)?,
                RequestType::Stake { neuron_index } => {
                    stake(&mut requests, arg, from, neuron_index)?
                }
                RequestType::SetDissolveTimestamp { neuron_index } => {
                    set_dissolve_timestamp(&mut requests, arg, from, neuron_index)?
                }
                RequestType::ChangeAutoStakeMaturity { neuron_index } => {
                    change_auto_stake_maturity(&mut requests, arg, from, neuron_index)?
                }
                RequestType::StartDissolve { neuron_index } => {
                    start_dissolve(&mut requests, arg, from, neuron_index)?
                }
                RequestType::StopDissolve { neuron_index } => {
                    stop_dissolve(&mut requests, arg, from, neuron_index)?
                }
                RequestType::Disburse { neuron_index } => {
                    disburse(&mut requests, arg, from, neuron_index)?
                }
                RequestType::DisburseMaturity { neuron_index } => {
                    disburse_maturity(&mut requests, arg, from, neuron_index)?
                }
                RequestType::AddHotKey { neuron_index } => {
                    add_hotkey(&mut requests, arg, from, neuron_index)?
                }
                RequestType::RemoveHotKey { neuron_index } => {
                    remove_hotkey(&mut requests, arg, from, neuron_index)?
                }
                RequestType::Spawn { neuron_index } => {
                    spawn(&mut requests, arg, from, neuron_index)?
                }
                RequestType::RegisterVote { neuron_index } => {
                    register_vote(&mut requests, arg, from, neuron_index)?
                }
                RequestType::StakeMaturity { neuron_index } => {
                    stake_maturity(&mut requests, arg, from, neuron_index)?
                }
                RequestType::ListNeurons { page_number } => {
                    list_neurons(&mut requests, arg, from, Some(page_number))?
                }
                RequestType::NeuronInfo {
                    neuron_index,
                    controller,
                } => neuron_info(&mut requests, arg, from, neuron_index, controller)?,
                RequestType::Follow {
                    neuron_index,
                    controller,
                } => follow(&mut requests, arg, from, neuron_index, controller)?,
                RequestType::RefreshVotingPower {
                    neuron_index,
                    controller,
                } => refresh_voting_power(&mut requests, arg, from, neuron_index, controller)?,
            }
        }

        from_ai.sort();
        from_ai.dedup();
        let from_ai = from_ai.iter().map(to_model_account_identifier).collect();

        Ok(ConstructionParseResponse {
            operations: Request::requests_to_operations(&requests, self.ledger.token_symbol())?,
            account_identifier_signers: Some(from_ai),
            metadata: Some(metadata),
        })
    }
}

/// Handle SEND.
fn send(
    requests: &mut Vec<Request>,
    metadata: &mut ObjectMap,
    arg: Blob,
    from: AccountIdentifier,
) -> Result<(), ApiError> {
    let SendArgs {
        amount,
        fee,
        to,
        memo,
        created_at_time,
        ..
    } = from_arg(arg.0)?;
    requests.push(Request::Transfer(Operation::Transfer {
        from,
        to,
        spender: None,
        amount,
        fee,
    }));
    metadata.insert("memo".into(), serde_json::to_value(memo).unwrap());
    if let Some(created_at_time) = created_at_time {
        metadata.insert(
            "created_at_time".into(),
            serde_json::to_value(created_at_time.as_nanos_since_unix_epoch()).unwrap(),
        );
    }
    Ok(())
}

/// Handle STAKE.
fn stake(
    requests: &mut Vec<Request>,
    arg: Blob,
    from: AccountIdentifier,
    neuron_index: u64,
) -> Result<(), ApiError> {
    let _: ClaimOrRefreshNeuronFromAccount = convert::decode_canister_method_arg(arg.0.as_ref())
        .map_err(|e| {
            ApiError::internal_error(format!("Could not decode Create Stake argument: {e:#}"))
        })?;
    requests.push(Request::Stake(Stake {
        account: from,
        neuron_index,
    }));
    Ok(())
}

fn change_auto_stake_maturity(
    requests: &mut Vec<Request>,
    arg: Blob,
    from: AccountIdentifier,
    neuron_index: u64,
) -> Result<(), ApiError> {
    let manage: ManageNeuronRequest =
        convert::decode_canister_method_arg(arg.0.as_ref()).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not decode Change Auto Stake Maturity argument: {e:#}"
            ))
        })?;
    let requested_setting_for_auto_stake_maturity = match manage.command {
        Some(ManageNeuronCommandRequest::Configure(manage_neuron::Configure {
            operation: Some(manage_neuron::configure::Operation::ChangeAutoStakeMaturity(d)),
        })) => Ok(d.requested_setting_for_auto_stake_maturity),
        Some(e) => Err(ApiError::internal_error(format!(
            "Incompatible manage_neuron command: {e:?}"
        ))),
        None => Err(ApiError::internal_error(
            "Missing manage_neuron command".to_string(),
        )),
    }?;
    requests.push(Request::ChangeAutoStakeMaturity(ChangeAutoStakeMaturity {
        account: from,
        neuron_index,
        requested_setting_for_auto_stake_maturity,
    }));
    Ok(())
}

/// Handle SET_DISSOLVE_TIMESTAMP.
fn set_dissolve_timestamp(
    requests: &mut Vec<Request>,
    arg: Blob,
    from: AccountIdentifier,
    neuron_index: u64,
) -> Result<(), ApiError> {
    let manage: ManageNeuronRequest =
        convert::decode_canister_method_arg(arg.0.as_ref()).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not decode Set Dissolve Timestamp argument: {e:#}"
            ))
        })?;
    let timestamp = Seconds(match manage.command {
        Some(ManageNeuronCommandRequest::Configure(manage_neuron::Configure {
            operation: Some(manage_neuron::configure::Operation::SetDissolveTimestamp(d)),
        })) => Ok(d.dissolve_timestamp_seconds),
        Some(e) => Err(ApiError::internal_error(format!(
            "Incompatible manage_neuron command: {e:?}"
        ))),
        None => Err(ApiError::internal_error(
            "Missing manage_neuron command".to_string(),
        )),
    }?);
    requests.push(Request::SetDissolveTimestamp(SetDissolveTimestamp {
        account: from,
        neuron_index,
        timestamp,
    }));
    Ok(())
}

/// Handle START_DISSOLVE.
fn start_dissolve(
    requests: &mut Vec<Request>,
    arg: Blob,
    from: AccountIdentifier,
    neuron_index: u64,
) -> Result<(), ApiError> {
    let manage: ManageNeuronRequest =
        convert::decode_canister_method_arg(arg.0.as_ref()).map_err(|e| {
            ApiError::internal_error(format!("Could not decode Start Dissolve argument: {e:#}"))
        })?;
    if !matches!(
        manage.command,
        Some(ManageNeuronCommandRequest::Configure(
            manage_neuron::Configure {
                operation: Some(manage_neuron::configure::Operation::StartDissolving(
                    manage_neuron::StartDissolving {},
                )),
            }
        ))
    ) {
        return Err(ApiError::internal_error(
            "Incompatible manage_neuron command".to_string(),
        ));
    };
    requests.push(Request::StartDissolve(StartDissolve {
        account: from,
        neuron_index,
    }));
    Ok(())
}

/// Handle STOP_DISSOLVE.
fn stop_dissolve(
    requests: &mut Vec<Request>,
    arg: Blob,
    from: AccountIdentifier,
    neuron_index: u64,
) -> Result<(), ApiError> {
    let manage: ManageNeuronRequest =
        convert::decode_canister_method_arg(arg.0.as_ref()).map_err(|e| {
            ApiError::internal_error(format!("Could not decode Stop Dissolve argument: {e:#}"))
        })?;
    if !matches!(
        manage.command,
        Some(ManageNeuronCommandRequest::Configure(
            manage_neuron::Configure {
                operation: Some(manage_neuron::configure::Operation::StopDissolving(
                    manage_neuron::StopDissolving {},
                )),
            }
        ))
    ) {
        return Err(ApiError::internal_error(
            "Incompatible manage_neuron command".to_string(),
        ));
    };
    requests.push(Request::StopDissolve(StopDissolve {
        account: from,
        neuron_index,
    }));
    Ok(())
}

/// Handle DISBURSE.
fn disburse(
    requests: &mut Vec<Request>,
    arg: Blob,
    from: AccountIdentifier,
    neuron_index: u64,
) -> Result<(), ApiError> {
    let manage: ManageNeuronRequest =
        convert::decode_canister_method_arg(arg.0.as_ref()).map_err(|e| {
            ApiError::internal_error(format!("Could not decode ManageNeuron argument: {e:#}"))
        })?;
    if let ManageNeuronRequest {
        command:
            Some(ManageNeuronCommandRequest::Disburse(manage_neuron::Disburse { to_account, amount })),
        ..
    } = manage
    {
        requests.push(Request::Disburse(Disburse {
            account: from,
            amount: amount.map(|a| icp_ledger::Tokens::from_e8s(a.e8s)),
            recipient: to_account.map_or(Ok(None), |a| {
                AccountIdentifier::try_from(&a)
                    .map_err(|e| {
                        ApiError::internal_error(format!(
                            "Could not parse recipient AccountIdentifier {e:?}"
                        ))
                    })
                    .map(Some)
            })?,
            neuron_index,
        }));
    } else {
        return Err(ApiError::internal_error(
            "Incompatible manage_neuron command".to_string(),
        ));
    };
    Ok(())
}

/// Handle DISBURSE_MATURITY.
fn disburse_maturity(
    requests: &mut Vec<Request>,
    arg: Blob,
    from: AccountIdentifier,
    neuron_index: u64,
) -> Result<(), ApiError> {
    let manage: ManageNeuronRequest =
        convert::decode_canister_method_arg(arg.0.as_ref()).map_err(|e| {
            ApiError::internal_error(format!("Could not decode ManageNeuron argument: {e:#}"))
        })?;
    if let ManageNeuronRequest {
        command:
            Some(ManageNeuronCommandRequest::DisburseMaturity(manage_neuron::DisburseMaturity {
                to_account,
                percentage_to_disburse,
                to_account_identifier,
            })),
        ..
    } = manage
    {
        let recipient = from_account_or_account_identifier(to_account, to_account_identifier)?;

        requests.push(Request::DisburseMaturity(DisburseMaturity {
            account: from,
            percentage_to_disburse,
            recipient,
            neuron_index,
        }));
    } else {
        return Err(ApiError::internal_error(
            "Incompatible manage_neuron command".to_string(),
        ));
    };
    Ok(())
}

/// Handle ADD_HOTKEY.
fn add_hotkey(
    requests: &mut Vec<Request>,
    arg: Blob,
    from: AccountIdentifier,
    neuron_index: u64,
) -> Result<(), ApiError> {
    let manage: ManageNeuronRequest =
        convert::decode_canister_method_arg(arg.0.as_ref()).map_err(|e| {
            ApiError::internal_error(format!("Could not decode ManageNeuron argument: {e:#}"))
        })?;
    if let Some(ManageNeuronCommandRequest::Configure(manage_neuron::Configure {
        operation:
            Some(manage_neuron::configure::Operation::AddHotKey(manage_neuron::AddHotKey {
                new_hot_key: Some(pid),
            })),
    })) = manage.command
    {
        requests.push(Request::AddHotKey(AddHotKey {
            account: from,
            neuron_index,
            key: PublicKeyOrPrincipal::Principal(pid),
        }));
    } else {
        return Err(ApiError::internal_error(
            "Incompatible manage_neuron command".to_string(),
        ));
    };
    Ok(())
}

/// Handle REMOVE_HOTKEY.
fn remove_hotkey(
    requests: &mut Vec<Request>,
    arg: Blob,
    from: AccountIdentifier,
    neuron_index: u64,
) -> Result<(), ApiError> {
    let manage: ManageNeuronRequest =
        convert::decode_canister_method_arg(arg.0.as_ref()).map_err(|e| {
            ApiError::internal_error(format!("Could not decode ManageNeuron argument: {e:#}"))
        })?;
    if let Some(ManageNeuronCommandRequest::Configure(manage_neuron::Configure {
        operation:
            Some(manage_neuron::configure::Operation::RemoveHotKey(manage_neuron::RemoveHotKey {
                hot_key_to_remove: Some(pid),
            })),
    })) = manage.command
    {
        requests.push(Request::RemoveHotKey(RemoveHotKey {
            account: from,
            neuron_index,
            key: PublicKeyOrPrincipal::Principal(pid),
        }));
    } else {
        return Err(ApiError::internal_error(
            "Incompatible manage_neuron command".to_string(),
        ));
    };
    Ok(())
}

/// Handle SPAWN.
fn spawn(
    requests: &mut Vec<Request>,
    arg: Blob,
    from: AccountIdentifier,
    neuron_index: u64,
) -> Result<(), ApiError> {
    let manage: ManageNeuronRequest =
        convert::decode_canister_method_arg(arg.0.as_ref()).map_err(|e| {
            ApiError::internal_error(format!("Could not decode ManageNeuron argument: {e:#}"))
        })?;
    if let Some(ManageNeuronCommandRequest::Spawn(manage_neuron::Spawn {
        new_controller,
        nonce,
        percentage_to_spawn,
    })) = manage.command
    {
        if let Some(spawned_neuron_index) = nonce {
            requests.push(Request::Spawn(Spawn {
                account: from,
                spawned_neuron_index,
                controller: new_controller,
                percentage_to_spawn,
                neuron_index,
            }));
        } else {
            return Err(ApiError::internal_error(
                "Incompatible manage_neuron command (spawned neuron index is required).",
            ));
        }
    } else {
        return Err(ApiError::internal_error(
            "Incompatible manage_neuron command".to_string(),
        ));
    }
    Ok(())
}

fn register_vote(
    requests: &mut Vec<Request>,
    arg: Blob,
    from: AccountIdentifier,
    neuron_index: u64,
) -> Result<(), ApiError> {
    let manage: ManageNeuronRequest =
        convert::decode_canister_method_arg(arg.0.as_ref()).map_err(|e| {
            ApiError::internal_error(format!("Could not decode ManageNeuron argument: {e:#}"))
        })?;
    if let Some(ManageNeuronCommandRequest::RegisterVote(manage_neuron::RegisterVote {
        proposal,
        vote,
    })) = manage.command
    {
        requests.push(Request::RegisterVote(RegisterVote {
            account: from,
            proposal: proposal.map(|p| p.id),
            vote,
            neuron_index,
        }));
    } else {
        return Err(ApiError::internal_error(
            "Incompatible manage_neuron command".to_string(),
        ));
    }
    Ok(())
}

/// Handle STAKE_MATURITY.
fn stake_maturity(
    requests: &mut Vec<Request>,
    arg: Blob,
    from: AccountIdentifier,
    neuron_index: u64,
) -> Result<(), ApiError> {
    let manage: ManageNeuronRequest =
        convert::decode_canister_method_arg(arg.0.as_ref()).map_err(|e| {
            ApiError::internal_error(format!("Could not decode ManageNeuron argument: {e:#}"))
        })?;
    if let Some(ManageNeuronCommandRequest::StakeMaturity(manage_neuron::StakeMaturity {
        percentage_to_stake,
    })) = manage.command
    {
        requests.push(Request::StakeMaturity(StakeMaturity {
            account: from,
            percentage_to_stake,
            neuron_index,
        }));
    } else {
        return Err(ApiError::internal_error(
            "Incompatible manage_neuron command".to_string(),
        ));
    }
    Ok(())
}

/// Handle NEURON_INFO.
fn neuron_info(
    requests: &mut Vec<Request>,
    arg: Blob,
    from: AccountIdentifier,
    neuron_index: u64,
    controller: Option<PublicKeyOrPrincipal>,
) -> Result<(), ApiError> {
    let _: NeuronIdOrSubaccount =
        convert::decode_canister_method_arg(arg.0.as_ref()).map_err(|e| {
            ApiError::internal_error(format!("Could not decode neuron info argument: {e:#}"))
        })?;

    match controller.map(convert::principal_id_from_public_key_or_principal) {
        None => {
            requests.push(Request::NeuronInfo(NeuronInfo {
                account: from,
                controller: None,
                neuron_index,
            }));
        }
        Some(Ok(pid)) => {
            requests.push(Request::NeuronInfo(NeuronInfo {
                account: from,
                controller: Some(pid),
                neuron_index,
            }));
        }
        _ => {
            return Err(ApiError::invalid_request("Invalid neuron info request."));
        }
    }
    Ok(())
}

/// Handle LIST_NEURONS.
fn list_neurons(
    requests: &mut Vec<Request>,
    _arg: Blob,
    from: AccountIdentifier,
    page_number: Option<u64>,
) -> Result<(), ApiError> {
    requests.push(Request::ListNeurons(ListNeurons {
        account: from,
        page_number,
    }));
    Ok(())
}

/// Handle FOLLOW.
fn follow(
    requests: &mut Vec<Request>,
    arg: Blob,
    from: AccountIdentifier,
    neuron_index: u64,
    controller: Option<PublicKeyOrPrincipal>,
) -> Result<(), ApiError> {
    let manage: ManageNeuronRequest =
        convert::decode_canister_method_arg(arg.0.as_ref()).map_err(|e| {
            ApiError::internal_error(format!("Could not decode ManageNeuron argument: {e:#}"))
        })?;
    if let Some(ManageNeuronCommandRequest::Follow(manage_neuron::Follow { topic, followees })) =
        manage.command
    {
        let ids = followees.iter().map(|x| x.id).collect();
        match controller.map(convert::principal_id_from_public_key_or_principal) {
            None => {
                requests.push(Request::Follow(Follow {
                    account: from,
                    topic,
                    followees: ids,
                    controller: None,
                    neuron_index,
                }));
            }
            Some(Ok(pid)) => {
                requests.push(Request::Follow(Follow {
                    account: from,
                    topic,
                    followees: ids,
                    controller: Some(pid),
                    neuron_index,
                }));
            }
            _ => {
                return Err(ApiError::invalid_request("Invalid follow request."));
            }
        }
    } else {
        return Err(ApiError::internal_error(
            "Incompatible manage_neuron command".to_string(),
        ));
    }
    Ok(())
}

fn refresh_voting_power(
    requests: &mut Vec<Request>,
    arg: Blob,
    from: AccountIdentifier,
    neuron_index: u64,
    controller: Option<PublicKeyOrPrincipal>,
) -> Result<(), ApiError> {
    let manage: ManageNeuronRequest =
        convert::decode_canister_method_arg(arg.0.as_ref()).map_err(|e| {
            ApiError::internal_error(format!("Could not decode ManageNeuron argument: {e:#}"))
        })?;
    if let Some(ManageNeuronCommandRequest::RefreshVotingPower(
        manage_neuron::RefreshVotingPower {},
    )) = manage.command
    {
        let pid = match controller.map(convert::principal_id_from_public_key_or_principal) {
            None => None,
            Some(Ok(pid)) => Some(pid),
            _ => {
                return Err(ApiError::invalid_request(
                    "Invalid refresh voting power request.",
                ));
            }
        };
        requests.push(Request::RefreshVotingPower(RefreshVotingPower {
            neuron_index,
            account: from,
            controller: pid,
        }));
    } else {
        return Err(ApiError::internal_error(
            "Incompatible manage_neuron command".to_string(),
        ));
    }
    Ok(())
}
#[cfg(test)]
mod tests;
