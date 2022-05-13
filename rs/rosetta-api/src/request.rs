use crate::convert::principal_id_from_public_key_or_principal;
use crate::errors::ApiError;
use crate::models::seconds::Seconds;
use crate::request_types::*;
use crate::{convert, models};
use dfn_candid::CandidOne;
use ic_nns_governance::pb::v1::manage_neuron::{self, configure, Command, Configure};
use ic_types::PrincipalId;
use ledger_canister::Tokens;
use on_wire::FromWire;
use std::convert::{TryFrom, TryInto};

use crate::models::operation::Operation;
use serde::{Deserialize, Serialize};

pub mod request_result;
mod serde_transfer;
pub mod transaction_operation_results;
pub mod transaction_results;

/// A `Request` is the deserialized representation of an `Operation`,
/// sans the `operation_identifier`, and `FEE` Operations.
/// Multiple `Request`s can be converted to `Operation`s via the
/// `TransactionBuilder`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum Request {
    /// Contains `Send`, `Mint`, and `Burn` operations.
    /// Attempting to serialize or deserialize any Mint, or Burn will error.
    #[serde(rename = "TRANSACTION")]
    #[serde(with = "serde_transfer")]
    Transfer(ledger_canister::Operation),
    #[serde(rename = "STAKE")]
    Stake(Stake),
    #[serde(rename = "SET_DISSOLVE_TIMESTAMP")]
    SetDissolveTimestamp(SetDissolveTimestamp),
    #[serde(rename = "START_DISSOLVE")]
    StartDissolve(StartDissolve),
    #[serde(rename = "STOP_DISSOLVE")]
    StopDissolve(StopDissolve),
    #[serde(rename = "DISBURSE")]
    Disburse(Disburse),
    #[serde(rename = "ADD_HOT_KEY")]
    AddHotKey(AddHotKey),
    #[serde(rename = "REMOVE_HOTKEY")]
    RemoveHotKey(RemoveHotKey),
    #[serde(rename = "SPAWN")]
    Spawn(Spawn),
    #[serde(rename = "MERGE_MATURITY")]
    MergeMaturity(MergeMaturity),
    #[serde(rename = "NEURON_INFO")]
    NeuronInfo(NeuronInfo),
    #[serde(rename = "FOLLOW")]
    Follow(Follow),
}

impl Request {
    /// Return the request type of a request.
    pub fn request_type(&self) -> Result<RequestType, ApiError> {
        match self {
            Request::Stake(Stake { neuron_index, .. }) => Ok(RequestType::Stake {
                neuron_index: *neuron_index,
            }),
            Request::SetDissolveTimestamp(SetDissolveTimestamp { neuron_index, .. }) => {
                Ok(RequestType::SetDissolveTimestamp {
                    neuron_index: *neuron_index,
                })
            }
            Request::StartDissolve(StartDissolve { neuron_index, .. }) => {
                Ok(RequestType::StartDissolve {
                    neuron_index: *neuron_index,
                })
            }
            Request::StopDissolve(StopDissolve { neuron_index, .. }) => {
                Ok(RequestType::StopDissolve {
                    neuron_index: *neuron_index,
                })
            }
            Request::Disburse(Disburse { neuron_index, .. }) => Ok(RequestType::Disburse {
                neuron_index: *neuron_index,
            }),
            Request::AddHotKey(AddHotKey { neuron_index, .. }) => Ok(RequestType::AddHotKey {
                neuron_index: *neuron_index,
            }),
            Request::RemoveHotKey(RemoveHotKey { neuron_index, .. }) => {
                Ok(RequestType::RemoveHotKey {
                    neuron_index: *neuron_index,
                })
            }
            Request::Transfer(ledger_canister::Operation::Transfer { .. }) => Ok(RequestType::Send),
            Request::Transfer(ledger_canister::Operation::Burn { .. }) => Err(
                ApiError::invalid_request("Burn operations are not supported through Rosetta"),
            ),
            Request::Transfer(ledger_canister::Operation::Mint { .. }) => Err(
                ApiError::invalid_request("Mint operations are not supported through Rosetta"),
            ),
            Request::Spawn(Spawn { neuron_index, .. }) => Ok(RequestType::Spawn {
                neuron_index: *neuron_index,
            }),
            Request::MergeMaturity(MergeMaturity { neuron_index, .. }) => {
                Ok(RequestType::MergeMaturity {
                    neuron_index: *neuron_index,
                })
            }
            Request::NeuronInfo(NeuronInfo {
                neuron_index,
                controller,
                ..
            }) => Ok(RequestType::NeuronInfo {
                neuron_index: *neuron_index,
                controller: controller.map(PublicKeyOrPrincipal::Principal),
            }),
            Request::Follow(Follow {
                neuron_index,
                controller,
                ..
            }) => Ok(RequestType::Follow {
                neuron_index: *neuron_index,
                controller: controller.map(PublicKeyOrPrincipal::Principal),
            }),
        }
    }

    /// Builds a Transaction from a sequence of `Request`s.
    /// This is a thin wrapper over the `TransactionBuilder`.
    ///
    /// TODO We should capture the concept of a Transaction in a type.
    pub fn requests_to_operations(
        requests: &[Request],
        token_name: &str,
    ) -> Result<Vec<Operation>, ApiError> {
        let mut builder = TransactionBuilder::default();
        for request in requests {
            match request {
                Request::Transfer(o) => builder.transfer(o, token_name)?,
                Request::Stake(o) => builder.stake(o),
                Request::SetDissolveTimestamp(o) => builder.set_dissolve_timestamp(o),
                Request::StartDissolve(o) => builder.start_dissolve(o),
                Request::StopDissolve(o) => builder.stop_dissolve(o),
                Request::Disburse(o) => builder.disburse(o, token_name),
                Request::AddHotKey(o) => builder.add_hot_key(o),
                Request::RemoveHotKey(o) => builder.remove_hotkey(o),
                Request::Spawn(o) => builder.spawn(o),
                Request::MergeMaturity(o) => builder.merge_maturity(o),
                Request::NeuronInfo(o) => builder.neuron_info(o),
                Request::Follow(o) => builder.follow(o),
            };
        }
        Ok(builder.build())
    }

    pub fn is_transfer(&self) -> bool {
        matches!(self, Request::Transfer(_))
    }

    pub fn is_neuron_management(&self) -> bool {
        matches!(
            self,
            Request::Stake(_)
                | Request::SetDissolveTimestamp(_)
                | Request::StartDissolve(_)
                | Request::StopDissolve(_)
                | Request::Disburse(_)
                | Request::AddHotKey(_)
                | Request::RemoveHotKey(_)
                | Request::Spawn(_)
                | Request::MergeMaturity(_)
                | Request::NeuronInfo(_) // not neuron management but we need it signed.
                | Request::Follow(_)
        )
    }
}

/// Sort of the inverse of `construction_payloads`.
impl TryFrom<&models::Request> for Request {
    type Error = ApiError;

    fn try_from(req: &models::Request) -> Result<Self, Self::Error> {
        let (request_type, calls) = req;
        let payload: &models::EnvelopePair = calls
            .first()
            .ok_or_else(|| ApiError::invalid_request("No request payload provided."))?;

        let pid =
            PrincipalId::try_from(payload.update_content().sender.clone().0).map_err(|e| {
                ApiError::internal_error(format!(
                    "Could not parse envelope sender's public key: {}",
                    e
                ))
            })?;

        let account = ledger_canister::account_identifier::AccountIdentifier::from(pid);

        let manage_neuron = || {
            {
                CandidOne::<ic_nns_governance::pb::v1::ManageNeuron>::from_bytes(
                    payload.update_content().arg.0.clone(),
                )
                .map_err(|e| {
                    ApiError::invalid_request(format!("Could not parse manage_neuron: {}", e))
                })
            }
            .map(|m| m.0.command)
        };

        match request_type {
            RequestType::Send => {
                let ledger_canister::SendArgs {
                    to, amount, fee, ..
                } = convert::from_arg(payload.update_content().arg.0.clone())?;
                Ok(Request::Transfer(ledger_canister::Operation::Transfer {
                    from: account,
                    to,
                    amount,
                    fee,
                }))
            }
            RequestType::Stake { neuron_index } => Ok(Request::Stake(Stake {
                account,
                neuron_index: *neuron_index,
            })),
            RequestType::SetDissolveTimestamp { neuron_index } => {
                let command = manage_neuron()?;
                if let Some(Command::Configure(Configure {
                    operation:
                        Some(configure::Operation::SetDissolveTimestamp(
                            manage_neuron::SetDissolveTimestamp {
                                dissolve_timestamp_seconds,
                                ..
                            },
                        )),
                })) = command
                {
                    Ok(Request::SetDissolveTimestamp(SetDissolveTimestamp {
                        account,
                        neuron_index: *neuron_index,
                        timestamp: Seconds(dissolve_timestamp_seconds),
                    }))
                } else {
                    Err(ApiError::invalid_request(
                        "Request is missing set dissolve timestamp operation.",
                    ))
                }
            }
            RequestType::StartDissolve { neuron_index } => {
                Ok(Request::StartDissolve(StartDissolve {
                    account,
                    neuron_index: *neuron_index,
                }))
            }
            RequestType::StopDissolve { neuron_index } => Ok(Request::StopDissolve(StopDissolve {
                account,
                neuron_index: *neuron_index,
            })),
            RequestType::Disburse { neuron_index } => {
                let command = manage_neuron()?;
                if let Some(Command::Disburse(manage_neuron::Disburse { to_account, amount })) =
                    command
                {
                    let recipient = if let Some(a) = to_account {
                        Some((&a).try_into().map_err(|e| {
                            ApiError::invalid_request(format!(
                                "Could not parse recipient account identifier: {}",
                                e
                            ))
                        })?)
                    } else {
                        None
                    };

                    Ok(Request::Disburse(Disburse {
                        account,
                        amount: amount.map(|amount| Tokens::from_e8s(amount.e8s)),
                        recipient,
                        neuron_index: *neuron_index,
                    }))
                } else {
                    Err(ApiError::invalid_request("Request is missing recipient"))
                }
            }
            RequestType::AddHotKey { neuron_index } => {
                if let Some(Command::Configure(Configure {
                    operation:
                        Some(configure::Operation::AddHotKey(manage_neuron::AddHotKey {
                            new_hot_key: Some(pid),
                            ..
                        })),
                })) = manage_neuron()?
                {
                    Ok(Request::AddHotKey(AddHotKey {
                        account,
                        neuron_index: *neuron_index,
                        key: PublicKeyOrPrincipal::Principal(pid),
                    }))
                } else {
                    Err(ApiError::invalid_request("Request is missing set hotkey."))
                }
            }
            RequestType::RemoveHotKey { neuron_index } => {
                if let Some(Command::Configure(Configure {
                    operation:
                        Some(configure::Operation::RemoveHotKey(manage_neuron::RemoveHotKey {
                            hot_key_to_remove: Some(pid),
                            ..
                        })),
                })) = manage_neuron()?
                {
                    Ok(Request::RemoveHotKey(RemoveHotKey {
                        account,
                        neuron_index: *neuron_index,
                        key: PublicKeyOrPrincipal::Principal(pid),
                    }))
                } else {
                    Err(ApiError::invalid_request(
                        "Request is missing hotkey to remove.",
                    ))
                }
            }
            RequestType::Spawn { neuron_index } => {
                if let Some(Command::Spawn(manage_neuron::Spawn {
                    new_controller,
                    nonce,
                    percentage_to_spawn,
                })) = manage_neuron()?
                {
                    if let Some(spawned_neuron_index) = nonce {
                        Ok(Request::Spawn(Spawn {
                            account,
                            spawned_neuron_index,
                            controller: new_controller,
                            percentage_to_spawn,
                            neuron_index: *neuron_index,
                        }))
                    } else {
                        Err(ApiError::invalid_request(
                            "Spawned neuron index is required.",
                        ))
                    }
                } else {
                    Err(ApiError::invalid_request("Invalid spawn request."))
                }
            }
            RequestType::MergeMaturity { neuron_index } => {
                if let Some(Command::MergeMaturity(manage_neuron::MergeMaturity {
                    percentage_to_merge,
                })) = manage_neuron()?
                {
                    Ok(Request::MergeMaturity(MergeMaturity {
                        account,
                        percentage_to_merge,
                        neuron_index: *neuron_index,
                    }))
                } else {
                    Err(ApiError::invalid_request("Invalid merge maturity request."))
                }
            }
            RequestType::NeuronInfo {
                neuron_index,
                controller,
                ..
            } => {
                match controller
                    .clone()
                    .map(principal_id_from_public_key_or_principal)
                {
                    None => Ok(Request::NeuronInfo(NeuronInfo {
                        account,
                        controller: None,
                        neuron_index: *neuron_index,
                    })),
                    Some(Ok(pid)) => Ok(Request::NeuronInfo(NeuronInfo {
                        account,
                        controller: Some(pid),
                        neuron_index: *neuron_index,
                    })),
                    Some(Err(e)) => Err(e),
                }
            }
            RequestType::Follow {
                neuron_index,
                controller,
            } => {
                if let Some(Command::Follow(manage_neuron::Follow { topic, followees })) =
                    manage_neuron()?
                {
                    let ids = followees.iter().map(|n| n.id).collect();
                    match controller
                        .clone()
                        .map(principal_id_from_public_key_or_principal)
                    {
                        None => Ok(Request::Follow(Follow {
                            account,
                            topic,
                            followees: ids,
                            controller: None,
                            neuron_index: *neuron_index,
                        })),
                        Some(Ok(pid)) => Ok(Request::Follow(Follow {
                            account,
                            topic,
                            followees: ids,
                            controller: Some(pid),
                            neuron_index: *neuron_index,
                        })),
                        Some(Err(e)) => Err(e),
                    }
                } else {
                    Err(ApiError::invalid_request("Invalid follow request."))
                }
            }
        }
    }
}
