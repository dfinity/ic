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
                    // Each envelope carries its own signature and the submit
                    // path broadcasts whichever one is currently valid, not the
                    // first, so one of them stands for the rest only once they
                    // all agree. The loop below then checks that one against
                    // the metadata about to be displayed.
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
            // Every field of `request_type` reaching the caller below must be
            // bound to the signed payload; otherwise the operations we return
            // would not describe the bytes the caller signs and broadcasts.
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
    let _: ClaimOrRefreshNeuronFromAccount = candid::decode_one(arg.0.as_ref()).map_err(|e| {
        ApiError::internal_error(format!("Could not decode Create Stake argument: {e:?}"))
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
    let manage: ManageNeuronRequest = candid::decode_one(arg.0.as_ref()).map_err(|e| {
        ApiError::internal_error(format!(
            "Could not decode Change Auto Stake Maturity argument: {e:?}"
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
    let manage: ManageNeuronRequest = candid::decode_one(arg.0.as_ref()).map_err(|e| {
        ApiError::internal_error(format!(
            "Could not decode Set Dissolve Timestamp argument: {e:?}"
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
    let manage: ManageNeuronRequest = candid::decode_one(arg.0.as_ref()).map_err(|e| {
        ApiError::internal_error(format!("Could not decode Start Dissolve argument: {e:?}"))
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
    let manage: ManageNeuronRequest = candid::decode_one(arg.0.as_ref()).map_err(|e| {
        ApiError::internal_error(format!("Could not decode Stop Dissolve argument: {e:?}"))
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
    let manage: ManageNeuronRequest = candid::decode_one(arg.0.as_ref()).map_err(|e| {
        ApiError::internal_error(format!("Could not decode ManageNeuron argument: {e:?}"))
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
    let manage: ManageNeuronRequest = candid::decode_one(arg.0.as_ref()).map_err(|e| {
        ApiError::internal_error(format!("Could not decode ManageNeuron argument: {e:?}"))
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
    let manage: ManageNeuronRequest = candid::decode_one(arg.0.as_ref()).map_err(|e| {
        ApiError::internal_error(format!("Could not decode ManageNeuron argument: {e:?}"))
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
    let manage: ManageNeuronRequest = candid::decode_one(arg.0.as_ref()).map_err(|e| {
        ApiError::internal_error(format!("Could not decode ManageNeuron argument: {e:?}"))
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
    let manage: ManageNeuronRequest = candid::decode_one(arg.0.as_ref()).map_err(|e| {
        ApiError::internal_error(format!("Could not decode ManageNeuron argument: {e:?}"))
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
    let manage: ManageNeuronRequest = candid::decode_one(arg.0.as_ref()).map_err(|e| {
        ApiError::internal_error(format!("Could not decode ManageNeuron argument: {e:?}"))
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
    let manage: ManageNeuronRequest = candid::decode_one(arg.0.as_ref()).map_err(|e| {
        ApiError::internal_error(format!("Could not decode ManageNeuron argument: {e:?}"))
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
    let _: NeuronIdOrSubaccount = candid::decode_one(arg.0.as_ref()).map_err(|e| {
        ApiError::internal_error(format!("Could not decode neuron info argument: {e:?}"))
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
    let manage: ManageNeuronRequest = candid::decode_one(arg.0.as_ref()).map_err(|e| {
        ApiError::internal_error(format!("Could not decode ManageNeuron argument: {e:?}"))
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
    let manage: ManageNeuronRequest = candid::decode_one(arg.0.as_ref()).map_err(|e| {
        ApiError::internal_error(format!("Could not decode ManageNeuron argument: {e:?}"))
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
mod tests {
    use proptest::{
        prop_assert, prop_assert_eq, proptest, strategy::Strategy, test_runner::TestCaseError,
    };
    use std::{str::FromStr, time::SystemTime};

    use crate::{
        models::{
            ConstructionCombineRequest, ConstructionParseRequest, ConstructionPayloadsRequest,
            ConstructionPayloadsRequestMetadata, CurveType, PublicKey, Signature, SignatureType,
        },
        request_handler::tests::construction::{
            setup_handler, setup_transfer_test, sign_and_combine, signed_disburse,
        },
    };
    use rosetta_core::objects::ObjectMap;

    #[test]
    fn test_payloads_parse_identity() {
        let (handler, network_identifier, operations, pub_key, key) = setup_transfer_test();

        let gen_opt_u64 = proptest::option::of(proptest::prelude::any::<u64>());
        const ONE_HOUR_NANOS: u64 = 60 * 60 * 1_000_000_000;
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Could not get system time")
            .as_nanos() as u64;
        // `ingress_start` is kept within a realistic window around `now`: the
        // ingress window is now bounded to 24h, and this
        // also avoids overflowing `ingress_start + ingress_interval` below.
        let gen_ingress_start = proptest::option::of(now..(now + ONE_HOUR_NANOS));
        let gen_metadata = proptest::option::of(
            (gen_opt_u64.clone(), gen_ingress_start, gen_opt_u64).prop_flat_map(
                |(created_at_time, ingress_start, memo)| {
                    proptest::option::of(1..ONE_HOUR_NANOS).prop_map(move |ingress_interval| {
                        let ingress_end = ingress_interval.map(|ingress_interval| {
                            ingress_start.unwrap_or(now) + ingress_interval
                        });
                        ConstructionPayloadsRequestMetadata {
                            created_at_time,
                            ingress_start,
                            ingress_end,
                            memo,
                        }
                    })
                },
            ),
        );

        fn check_metadata(
            expected_metadata: Option<ConstructionPayloadsRequestMetadata>,
            actual_metadata: ObjectMap,
        ) -> std::result::Result<(), TestCaseError> {
            match expected_metadata {
                None => {
                    // memo and created_at_time are always populated by construction_payloads
                    // (memo defaults to 0, created_at_time to the current time)
                    prop_assert!(
                        actual_metadata.contains_key("memo"),
                        "Metadata should always contain a memo"
                    );
                    prop_assert!(
                        actual_metadata.contains_key("created_at_time"),
                        "Metadata should always contain a created_at_time"
                    );
                }
                Some(expected_metadata) => {
                    let expected_metadata = serde_json::to_value(expected_metadata).unwrap();
                    let expected_metadata = expected_metadata.as_object().unwrap();
                    if let Some(memo) = expected_metadata.get("memo") {
                        prop_assert_eq!(Some(memo), actual_metadata.get("memo"));
                    } else {
                        prop_assert!(
                            actual_metadata.contains_key("memo"),
                            "Metadata should always contain a memo"
                        );
                    }
                    if let Some(created_at_time) = expected_metadata.get("created_at_time") {
                        prop_assert_eq!(
                            Some(created_at_time),
                            actual_metadata.get("created_at_time")
                        );
                    } else {
                        prop_assert!(
                            actual_metadata.contains_key("created_at_time"),
                            "Metadata should always contain a created_at_time"
                        );
                    }
                }
            }
            Ok(())
        }

        // check parse unsigned transaction
        proptest!(|(metadata in gen_metadata.clone())| {
            let handler = handler.clone();
            let construction_payloads_result = handler.construction_payloads(ConstructionPayloadsRequest {
                network_identifier: network_identifier.clone(),
                operations: operations.clone(),
                metadata: metadata.clone().map(|m|m.try_into().unwrap()),
                public_keys: Some(vec![pub_key.clone()]),
            }).unwrap();
            let unsigned_transaction = construction_payloads_result.unsigned_transaction;

            // parse the unsigned transaction and check the result
            let parsed = handler.construction_parse(ConstructionParseRequest {
                network_identifier: network_identifier.clone(),
                signed: false,
                transaction: unsigned_transaction,
            }).unwrap();

            prop_assert_eq!(operations.clone(), parsed.operations);

            // metadata must always be present
            prop_assert!(parsed.metadata.is_some(), "Metadata should always be returned");

            check_metadata(metadata, parsed.metadata.unwrap()).unwrap()
        });

        // check parse signed transaction
        // signing is slow => use less test cases
        let conf = proptest::test_runner::Config {
            cases: 32,
            ..Default::default()
        };
        proptest!(conf, |(metadata in gen_metadata.clone())| {
            let construction_payloads_result = handler.construction_payloads(ConstructionPayloadsRequest {
                network_identifier: network_identifier.clone(),
                operations: operations.clone(),
                metadata: metadata.clone().map(|m|m.try_into().unwrap()),
                public_keys: Some(vec![pub_key.clone()]),
            }).unwrap();
            let unsigned_transaction = construction_payloads_result.unsigned_transaction;

            // create the signed transaction
            let mut signatures = vec![];
            for payload in construction_payloads_result.payloads {
                let bytes = hex::decode(payload.clone().hex_bytes).unwrap();
                let signature = key.sign_message(&bytes);
                let signature = Signature {
                    signing_payload: payload,
                    public_key: PublicKey::new(hex::encode(key.public_key().serialize_raw()), CurveType::Edwards25519),
                    signature_type: SignatureType::Ed25519,
                    hex_bytes: hex::encode(signature),
                };
                signatures.push(signature);
            }

            let signed_transaction = handler.construction_combine(ConstructionCombineRequest {
                network_identifier:network_identifier.clone(),
                unsigned_transaction,
                signatures,
            }).unwrap().signed_transaction;

            // parse the signed transaction and check the result
            let parsed = handler.construction_parse(ConstructionParseRequest {
                network_identifier:network_identifier.clone(),
                signed: true,
                transaction: signed_transaction,
            }).unwrap();

            prop_assert_eq!(operations.clone(), parsed.operations);

            // metadata must always be present
            prop_assert!(parsed.metadata.is_some(), "Metadata should always be returned");

            check_metadata(metadata, parsed.metadata.unwrap()).unwrap()
        });
    }

    // When the caller does not specify a memo, `construction_payloads` uses a
    // deterministic memo of 0 instead of a random one. With the time-based
    // inputs pinned, reconstructing
    // the same transfer must therefore produce a byte-identical unsigned
    // transaction every time -- and hence the same transaction hash -- so that
    // the ledger's `created_at_time` based deduplication can catch a retried
    // transfer. This test reconstructs the same transfer three times and checks
    // both that the unsigned transactions are identical and that the embedded
    // memo is 0.
    #[test]
    fn test_payloads_without_memo_is_deterministic() {
        let (handler, network_identifier, operations, pub_key, _key) = setup_transfer_test();

        // Pin all time-based inputs so that the only thing that could vary
        // across reconstructions is the (previously random) memo.
        const NANOS: u64 = 1_000_000_000;
        let created_at_time = 1_700_000_000 * NANOS;
        let metadata = ConstructionPayloadsRequestMetadata {
            memo: None,
            created_at_time: Some(created_at_time),
            ingress_start: Some(created_at_time),
            ingress_end: Some(created_at_time + 600 * NANOS),
        };

        let reconstruct = || {
            handler
                .construction_payloads(ConstructionPayloadsRequest {
                    network_identifier: network_identifier.clone(),
                    operations: operations.clone(),
                    metadata: Some(metadata.clone().try_into().unwrap()),
                    public_keys: Some(vec![pub_key.clone()]),
                })
                .unwrap()
                .unsigned_transaction
        };

        let unsigned_transactions: Vec<String> = (0..3).map(|_| reconstruct()).collect();

        // Reconstruction must be deterministic: identical bytes => identical
        // transaction hash, which is what lets the ledger deduplicate retries.
        assert!(
            unsigned_transactions
                .iter()
                .all(|tx| *tx == unsigned_transactions[0]),
            "expected identical unsigned transactions across reconstructions, got {unsigned_transactions:?}"
        );

        // And the memo embedded in the (memo-less) transfer must be 0.
        let parsed = handler
            .construction_parse(ConstructionParseRequest {
                network_identifier: network_identifier.clone(),
                signed: false,
                transaction: unsigned_transactions[0].clone(),
            })
            .unwrap();
        let memo = parsed
            .metadata
            .expect("metadata should always be returned")
            .get("memo")
            .expect("memo should always be present")
            .clone();
        assert_eq!(memo, serde_json::json!(0), "expected a memo of 0");
    }

    /// Everything below rejects a tampered transaction, so the negative
    /// control belongs with them: what `/construction/combine` genuinely
    /// produces must still parse, and must describe the same operations it was
    /// built from -- including over an ingress window wide enough to need
    /// several independently signed envelopes, which is the shape
    /// `verify_signed_envelopes` is strictest about.
    #[test]
    fn test_parse_accepts_a_genuine_signed_transaction() {
        use crate::{models::SignedTransaction, request::Request, request_types::Disburse};
        use rosetta_core::convert::principal_id_from_public_key;

        const NEURON_INDEX: u64 = 7;
        const NANOS: u64 = 1_000_000_000;

        let (handler, network_identifier, pub_key, key) = setup_handler();

        // A single envelope, as the default ingress window produces.
        let (operations, _unsigned, signed) =
            signed_disburse(&handler, &network_identifier, &pub_key, &key, NEURON_INDEX);
        let parsed = handler
            .construction_parse(ConstructionParseRequest {
                network_identifier: network_identifier.clone(),
                signed: true,
                transaction: signed.clone(),
            })
            .expect("a genuine signed transaction must parse");
        assert_eq!(operations, parsed.operations);
        Request::from_signed_request(
            &SignedTransaction::from_str(&signed).unwrap().requests[0],
            handler.ledger.ledger_canister_id(),
            handler.ledger.governance_canister_id(),
        )
        .expect("the submit path must accept a genuine signed transaction");

        // And several envelopes, as a wider ingress window produces.
        let account =
            icp_ledger::AccountIdentifier::from(principal_id_from_public_key(&pub_key).unwrap());
        let operations = Request::requests_to_operations(
            &[Request::Disburse(Disburse {
                account,
                amount: None,
                recipient: None,
                neuron_index: NEURON_INDEX,
            })],
            "TKN",
        )
        .unwrap();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let payloads = handler
            .construction_payloads(ConstructionPayloadsRequest {
                network_identifier: network_identifier.clone(),
                operations: operations.clone(),
                metadata: Some(
                    ConstructionPayloadsRequestMetadata {
                        memo: None,
                        created_at_time: Some(now),
                        ingress_start: Some(now),
                        ingress_end: Some(now + 600 * NANOS),
                    }
                    .try_into()
                    .unwrap(),
                ),
                public_keys: Some(vec![pub_key.clone()]),
            })
            .unwrap();
        let signed = sign_and_combine(&handler, &network_identifier, &pub_key, &key, payloads);

        let envelopes = SignedTransaction::from_str(&signed).unwrap().requests[0]
            .1
            .len();
        assert!(
            envelopes > 1,
            "expected a multi-envelope transaction, got {envelopes}"
        );

        let parsed = handler
            .construction_parse(ConstructionParseRequest {
                network_identifier,
                signed: true,
                transaction: signed.clone(),
            })
            .expect("a genuine multi-envelope transaction must parse");
        assert_eq!(operations, parsed.operations);
        Request::from_signed_request(
            &SignedTransaction::from_str(&signed).unwrap().requests[0],
            handler.ledger.ledger_canister_id(),
            handler.ledger.governance_canister_id(),
        )
        .expect("the submit path must accept a genuine multi-envelope transaction");
    }

    /// Regression test for the construction flow's authenticated-data
    /// confusion: the outer `RequestType` is plain CBOR metadata that no
    /// signature covers, so rewriting its `neuron_index` used to make
    /// `/construction/parse` describe one neuron while the signed
    /// `manage_neuron` update targeted another. For a full-stake `DISBURSE`
    /// (`amount: None`) the index is the only field that says how much value
    /// moves, so the operations shown to the signer must be bound to the signed
    /// payload.
    #[test]
    fn test_parse_rejects_rewritten_neuron_index() {
        use crate::{
            models::{SignedTransaction, UnsignedTransaction},
            request::Request,
            request_types::{Disburse, RequestType},
        };
        use rosetta_core::convert::principal_id_from_public_key;

        const DISPLAYED_INDEX: u64 = 0;
        const SIGNED_INDEX: u64 = 7;

        let (handler, network_identifier, pub_key, key) = setup_handler();
        let signer = principal_id_from_public_key(&pub_key).unwrap();
        let account = icp_ledger::AccountIdentifier::from(signer);

        // A complete-stake disburse of the valuable neuron to a third party.
        let operations = Request::requests_to_operations(
            &[Request::Disburse(Disburse {
                account,
                amount: None,
                recipient: Some(icp_ledger::AccountIdentifier::from(
                    ic_types::PrincipalId::new_user_test_id(42),
                )),
                neuron_index: SIGNED_INDEX,
            })],
            "TKN",
        )
        .unwrap();

        let payloads = handler
            .construction_payloads(ConstructionPayloadsRequest {
                network_identifier: network_identifier.clone(),
                operations: operations.clone(),
                metadata: None,
                public_keys: Some(vec![pub_key.clone()]),
            })
            .unwrap();

        // The untampered transaction parses, and reports the neuron actually
        // targeted by the signed update.
        let parsed = handler
            .construction_parse(ConstructionParseRequest {
                network_identifier: network_identifier.clone(),
                signed: false,
                transaction: payloads.unsigned_transaction.clone(),
            })
            .unwrap();
        assert_eq!(operations, parsed.operations);

        // Rewrite only the unsigned wrapper, leaving every signable byte of the
        // update -- and therefore the message id and the signature -- untouched.
        let mut unsigned = UnsignedTransaction::from_str(&payloads.unsigned_transaction).unwrap();
        for (request_type, _) in unsigned.updates.iter_mut() {
            assert_eq!(
                *request_type,
                RequestType::Disburse {
                    neuron_index: SIGNED_INDEX
                }
            );
            *request_type = RequestType::Disburse {
                neuron_index: DISPLAYED_INDEX,
            };
        }

        let err = handler
            .construction_parse(ConstructionParseRequest {
                network_identifier: network_identifier.clone(),
                signed: false,
                transaction: unsigned.to_string(),
            })
            .expect_err("parse must reject a wrapper that disagrees with the signed payload");
        assert!(
            format!("{err:?}").contains("neuron_index"),
            "unexpected error: {err:?}"
        );

        // The same must hold once the (genuine) signatures are attached: the
        // signed transaction carries the same unauthenticated wrapper.
        let mut signatures = vec![];
        for payload in payloads.payloads {
            let bytes = hex::decode(payload.clone().hex_bytes).unwrap();
            let signature = key.sign_message(&bytes);
            signatures.push(Signature {
                signing_payload: payload,
                public_key: pub_key.clone(),
                signature_type: SignatureType::Ed25519,
                hex_bytes: hex::encode(signature),
            });
        }
        let signed_transaction = handler
            .construction_combine(ConstructionCombineRequest {
                network_identifier: network_identifier.clone(),
                unsigned_transaction: payloads.unsigned_transaction,
                signatures,
            })
            .unwrap()
            .signed_transaction;

        let mut signed = SignedTransaction::from_str(&signed_transaction).unwrap();
        for (request_type, _) in signed.requests.iter_mut() {
            *request_type = RequestType::Disburse {
                neuron_index: DISPLAYED_INDEX,
            };
        }
        let tampered_signed = hex::encode(serde_cbor::to_vec(&signed).unwrap());

        let err = handler
            .construction_parse(ConstructionParseRequest {
                network_identifier,
                signed: true,
                transaction: tampered_signed,
            })
            .expect_err("signed parse must reject a wrapper that disagrees with the payload");
        assert!(
            format!("{err:?}").contains("neuron_index"),
            "unexpected error: {err:?}"
        );

        // And the submit path, which reconstructs the same operations for the
        // `/construction/submit` response, must reject it too.
        let err = Request::from_signed_request(
            &signed.requests[0],
            handler.ledger.ledger_canister_id(),
            handler.ledger.governance_canister_id(),
        )
        .expect_err("the submit path must reject the same mismatch");
        assert!(
            format!("{err:?}").contains("neuron_index"),
            "unexpected error: {err:?}"
        );
    }

    /// Binding the neuron is not enough on its own: the submit path does not
    /// re-derive the command for every request type, so rewriting only the
    /// wrapper's variant used to make `/construction/submit` report one
    /// operation while a different signed command executed. `/construction/parse`
    /// happened to catch this because each of its per-operation handlers
    /// re-decodes the command, but submit is reachable without parsing at all.
    #[test]
    fn test_submit_path_rejects_substituted_command() {
        use crate::{models::SignedTransaction, request::Request, request_types::RequestType};

        const NEURON_INDEX: u64 = 7;

        let (handler, network_identifier, pub_key, key) = setup_handler();
        let (_, _, signed_transaction) =
            signed_disburse(&handler, &network_identifier, &pub_key, &key, NEURON_INDEX);

        // Same neuron, same signed disburse command -- only the wrapper's
        // operation name is swapped, for one whose submit branch never looks at
        // the payload.
        let mut signed = SignedTransaction::from_str(&signed_transaction).unwrap();
        for (request_type, _) in signed.requests.iter_mut() {
            *request_type = RequestType::StartDissolve {
                neuron_index: NEURON_INDEX,
            };
        }

        let err = Request::from_signed_request(
            &signed.requests[0],
            handler.ledger.ledger_canister_id(),
            handler.ledger.governance_canister_id(),
        )
        .expect_err("the submit path must reject a substituted operation");
        assert!(
            format!("{err:?}").contains("manage_neuron command"),
            "unexpected error: {err:?}"
        );

        // Parse must reject it as well.
        handler
            .construction_parse(ConstructionParseRequest {
                network_identifier,
                signed: true,
                transaction: hex::encode(serde_cbor::to_vec(&signed).unwrap()),
            })
            .expect_err("parse must reject a substituted operation");
    }

    /// A signed request carries one envelope per ingress expiry, and the submit
    /// path broadcasts whichever is currently valid rather than the first.
    /// Validating a single envelope therefore used to leave room for a request
    /// that pairs an expired envelope matching the wrapper with a currently
    /// valid envelope for a different neuron: parse would describe the first
    /// while submit sent the second. Both envelopes here carry genuine
    /// signatures.
    #[test]
    fn test_rejects_divergent_envelopes() {
        use crate::{models::SignedTransaction, request::Request, request_types::RequestType};

        let (handler, network_identifier, pub_key, key) = setup_handler();
        let (_, _, displayed) = signed_disburse(&handler, &network_identifier, &pub_key, &key, 0);
        let (_, _, hidden) = signed_disburse(&handler, &network_identifier, &pub_key, &key, 7);

        let displayed = SignedTransaction::from_str(&displayed).unwrap();
        let hidden = SignedTransaction::from_str(&hidden).unwrap();

        // Wrapper and first envelope describe the worthless neuron; a later
        // envelope targets the valuable one.
        let mut envelopes = vec![displayed.requests[0].1[0].clone()];
        envelopes.push(hidden.requests[0].1[0].clone());
        let spliced = SignedTransaction {
            requests: vec![(RequestType::Disburse { neuron_index: 0 }, envelopes)],
        };

        let err = Request::from_signed_request(
            &spliced.requests[0],
            handler.ledger.ledger_canister_id(),
            handler.ledger.governance_canister_id(),
        )
        .expect_err("the submit path must reject envelopes that disagree");
        assert!(
            format!("{err:?}").contains("ingress"),
            "unexpected error: {err:?}"
        );

        let err = handler
            .construction_parse(ConstructionParseRequest {
                network_identifier,
                signed: true,
                transaction: hex::encode(serde_cbor::to_vec(&spliced).unwrap()),
            })
            .expect_err("parse must reject envelopes that disagree");
        assert!(
            format!("{err:?}").contains("ingress"),
            "unexpected error: {err:?}"
        );
    }
}
