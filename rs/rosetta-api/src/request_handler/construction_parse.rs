use crate::convert::{self, from_arg, to_model_account_identifier};
use crate::errors::ApiError;
use crate::models::{ConstructionParseRequest, ConstructionParseResponse, ParsedTransaction};
use crate::request_handler::{verify_network_id, RosettaRequestHandler};
use crate::request_types::{
    AddHotKey, Disburse, Follow, MergeMaturity, NeuronInfo, PublicKeyOrPrincipal, RemoveHotKey,
    RequestType, SetDissolveTimestamp, Spawn, Stake, StartDissolve, StopDissolve,
};

use ic_nns_governance::pb::v1::{
    manage_neuron::{self, Command, NeuronIdOrSubaccount},
    ClaimOrRefreshNeuronFromAccount, ManageNeuron,
};

use crate::models::seconds::Seconds;
use crate::request::Request;
use ic_types::messages::{Blob, HttpCallContent, HttpCanisterUpdate};
use ic_types::PrincipalId;
use ledger_canister::{AccountIdentifier, Operation, SendArgs};
use std::convert::TryFrom;

impl RosettaRequestHandler {
    /// Parse a Transaction.
    /// See https://www.rosetta-api.org/docs/ConstructionApi.html#constructionparse
    pub fn construction_parse(
        &self,
        msg: ConstructionParseRequest,
    ) -> Result<ConstructionParseResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;

        let updates: Vec<_> = match msg.transaction()? {
            ParsedTransaction::Signed(envelopes) => envelopes
                .iter()
                .map(
                    |(request_type, updates)| match updates[0].update.content.clone() {
                        HttpCallContent::Call { update } => (request_type.clone(), update),
                    },
                )
                .collect(),
            ParsedTransaction::Unsigned(unsigned_transaction) => unsigned_transaction.updates,
        };

        let mut requests = vec![];
        let mut from_ai = vec![];

        for (request_type, HttpCanisterUpdate { arg, sender, .. }) in updates {
            let from = PrincipalId::try_from(sender.0)
                .map_err(|e| ApiError::internal_error(e.to_string()))?
                .into();
            if msg.signed {
                from_ai.push(from);
            }

            match request_type {
                RequestType::Send => send(&mut requests, arg, from)?,
                RequestType::Stake { neuron_index } => {
                    stake(&mut requests, arg, from, neuron_index)?
                }
                RequestType::SetDissolveTimestamp { neuron_index } => {
                    set_dissolve_timestamp(&mut requests, arg, from, neuron_index)?
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
                RequestType::AddHotKey { neuron_index } => {
                    add_hotkey(&mut requests, arg, from, neuron_index)?
                }
                RequestType::RemoveHotKey { neuron_index } => {
                    remove_hotkey(&mut requests, arg, from, neuron_index)?
                }
                RequestType::Spawn { neuron_index } => {
                    spawn(&mut requests, arg, from, neuron_index)?
                }
                RequestType::MergeMaturity { neuron_index } => {
                    merge_maturity(&mut requests, arg, from, neuron_index)?
                }
                RequestType::NeuronInfo {
                    neuron_index,
                    controller,
                } => neuron_info(&mut requests, arg, from, neuron_index, controller)?,
                RequestType::Follow {
                    neuron_index,
                    controller,
                } => follow(&mut requests, arg, from, neuron_index, controller)?,
            }
        }

        from_ai.sort();
        from_ai.dedup();
        let from_ai = from_ai.iter().map(to_model_account_identifier).collect();

        Ok(ConstructionParseResponse {
            operations: Request::requests_to_operations(&requests, self.ledger.token_symbol())?,
            signers: None,
            account_identifier_signers: Some(from_ai),
            metadata: None,
        })
    }
}

/// Handle SEND.
fn send(requests: &mut Vec<Request>, arg: Blob, from: AccountIdentifier) -> Result<(), ApiError> {
    let SendArgs {
        amount, fee, to, ..
    } = from_arg(arg.0)?;
    requests.push(Request::Transfer(Operation::Transfer {
        from,
        to,
        amount,
        fee,
    }));
    Ok(())
}

/// Handle STAKE.
fn stake(
    requests: &mut Vec<Request>,
    arg: Blob,
    from: AccountIdentifier,
    neuron_index: u64,
) -> Result<(), ApiError> {
    let _: ClaimOrRefreshNeuronFromAccount = candid::decode_one(arg.0.as_ref()).map_err(|e| {
        ApiError::internal_error(format!("Could not decode Create Stake argument: {:?}", e))
    })?;
    requests.push(Request::Stake(Stake {
        account: from,
        neuron_index,
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
    let manage: ManageNeuron = candid::decode_one(arg.0.as_ref()).map_err(|e| {
        ApiError::internal_error(format!(
            "Could not decode Set Dissolve Timestamp argument: {:?}",
            e
        ))
    })?;
    let timestamp = Seconds(match manage.command {
        Some(Command::Configure(manage_neuron::Configure {
            operation: Some(manage_neuron::configure::Operation::SetDissolveTimestamp(d)),
        })) => Ok(d.dissolve_timestamp_seconds),
        Some(e) => Err(ApiError::internal_error(format!(
            "Incompatible manage_neuron command: {:?}",
            e
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
    let manage: ManageNeuron = candid::decode_one(arg.0.as_ref()).map_err(|e| {
        ApiError::internal_error(format!("Could not decode Start Dissolve argument: {:?}", e))
    })?;
    if !matches!(
        manage.command,
        Some(Command::Configure(manage_neuron::Configure {
            operation: Some(manage_neuron::configure::Operation::StartDissolving(
                manage_neuron::StartDissolving {},
            )),
        }))
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
    let manage: ManageNeuron = candid::decode_one(arg.0.as_ref()).map_err(|e| {
        ApiError::internal_error(format!("Could not decode Stop Dissolve argument: {:?}", e))
    })?;
    if !matches!(
        manage.command,
        Some(Command::Configure(manage_neuron::Configure {
            operation: Some(manage_neuron::configure::Operation::StopDissolving(
                manage_neuron::StopDissolving {},
            )),
        }))
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
    let manage: ManageNeuron = candid::decode_one(arg.0.as_ref()).map_err(|e| {
        ApiError::internal_error(format!("Could not decode ManageNeuron argument: {:?}", e))
    })?;
    if let ManageNeuron {
        command: Some(Command::Disburse(manage_neuron::Disburse { to_account, amount })),
        ..
    } = manage
    {
        requests.push(Request::Disburse(Disburse {
            account: from,
            amount: amount.map(|a| ledger_canister::Tokens::from_e8s(a.e8s)),
            recipient: to_account.map_or(Ok(None), |a| {
                AccountIdentifier::try_from(&a)
                    .map_err(|e| {
                        ApiError::internal_error(format!(
                            "Could not parse recipient AccountIdentifier {:?}",
                            e
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

/// Handle ADD_HOTKEY.
fn add_hotkey(
    requests: &mut Vec<Request>,
    arg: Blob,
    from: AccountIdentifier,
    neuron_index: u64,
) -> Result<(), ApiError> {
    let manage: ManageNeuron = candid::decode_one(arg.0.as_ref()).map_err(|e| {
        ApiError::internal_error(format!("Could not decode ManageNeuron argument: {:?}", e))
    })?;
    if let Some(Command::Configure(manage_neuron::Configure {
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
    let manage: ManageNeuron = candid::decode_one(arg.0.as_ref()).map_err(|e| {
        ApiError::internal_error(format!("Could not decode ManageNeuron argument: {:?}", e))
    })?;
    if let Some(Command::Configure(manage_neuron::Configure {
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
    let manage: ManageNeuron = candid::decode_one(arg.0.as_ref()).map_err(|e| {
        ApiError::internal_error(format!("Could not decode ManageNeuron argument: {:?}", e))
    })?;
    if let Some(Command::Spawn(manage_neuron::Spawn {
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

/// Handle MERGE_MATURITY.
fn merge_maturity(
    requests: &mut Vec<Request>,
    arg: Blob,
    from: AccountIdentifier,
    neuron_index: u64,
) -> Result<(), ApiError> {
    let manage: ManageNeuron = candid::decode_one(arg.0.as_ref()).map_err(|e| {
        ApiError::internal_error(format!("Could not decode ManageNeuron argument: {:?}", e))
    })?;
    if let Some(Command::MergeMaturity(manage_neuron::MergeMaturity {
        percentage_to_merge,
    })) = manage.command
    {
        requests.push(Request::MergeMaturity(MergeMaturity {
            account: from,
            percentage_to_merge,
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
    let _: NeuronIdOrSubaccount = candid::decode_one(arg.0.as_ref()).map_err(|e| {
        ApiError::internal_error(format!("Could not decode neuron info argument: {:?}", e))
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

/// Handle FOLLOW.
fn follow(
    requests: &mut Vec<Request>,
    arg: Blob,
    from: AccountIdentifier,
    neuron_index: u64,
    controller: Option<PublicKeyOrPrincipal>,
) -> Result<(), ApiError> {
    let manage: ManageNeuron = candid::decode_one(arg.0.as_ref()).map_err(|e| {
        ApiError::internal_error(format!("Could not decode ManageNeuron argument: {:?}", e))
    })?;
    if let Some(Command::Follow(manage_neuron::Follow { topic, followees })) = manage.command {
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
