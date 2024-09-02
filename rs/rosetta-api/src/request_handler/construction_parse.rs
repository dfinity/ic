use crate::{
    convert::{self, from_arg, to_model_account_identifier},
    errors::ApiError,
    models::{ConstructionParseRequest, ConstructionParseResponse, ParsedTransaction},
    request_handler::{verify_network_id, RosettaRequestHandler},
    request_types::{
        AddHotKey, ChangeAutoStakeMaturity, Disburse, Follow, ListNeurons, MergeMaturity,
        NeuronInfo, PublicKeyOrPrincipal, RegisterVote, RemoveHotKey, RequestType,
        SetDissolveTimestamp, Spawn, Stake, StakeMaturity, StartDissolve, StopDissolve,
    },
};
use rosetta_core::objects::ObjectMap;

use ic_nns_governance_api::pb::v1::{
    manage_neuron::{self, Command, NeuronIdOrSubaccount},
    ClaimOrRefreshNeuronFromAccount, ManageNeuron,
};

use crate::{models::seconds::Seconds, request::Request};
use ic_types::{
    messages::{Blob, HttpCallContent, HttpCanisterUpdate},
    PrincipalId,
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
        let mut metadata = serde_json::Map::new();

        for (request_type, HttpCanisterUpdate { arg, sender, .. }) in updates {
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
                RequestType::MergeMaturity { neuron_index } => {
                    merge_maturity(&mut requests, arg, from, neuron_index)?
                }
                RequestType::StakeMaturity { neuron_index } => {
                    stake_maturity(&mut requests, arg, from, neuron_index)?
                }
                RequestType::ListNeurons => list_neurons(&mut requests, arg, from)?,
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
        ApiError::internal_error(format!("Could not decode Create Stake argument: {:?}", e))
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
    let manage: ManageNeuron = candid::decode_one(arg.0.as_ref()).map_err(|e| {
        ApiError::internal_error(format!(
            "Could not decode Change Auto Stake Maturity argument: {:?}",
            e
        ))
    })?;
    let requested_setting_for_auto_stake_maturity = match manage.command {
        Some(Command::Configure(manage_neuron::Configure {
            operation: Some(manage_neuron::configure::Operation::ChangeAutoStakeMaturity(d)),
        })) => Ok(d.requested_setting_for_auto_stake_maturity),
        Some(e) => Err(ApiError::internal_error(format!(
            "Incompatible manage_neuron command: {:?}",
            e
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
            amount: amount.map(|a| icp_ledger::Tokens::from_e8s(a.e8s)),
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

fn register_vote(
    requests: &mut Vec<Request>,
    arg: Blob,
    from: AccountIdentifier,
    neuron_index: u64,
) -> Result<(), ApiError> {
    let manage: ManageNeuron = candid::decode_one(arg.0.as_ref()).map_err(|e| {
        ApiError::internal_error(format!("Could not decode ManageNeuron argument: {:?}", e))
    })?;
    if let Some(Command::RegisterVote(manage_neuron::RegisterVote { proposal, vote })) =
        manage.command
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

/// Handle STAKE_MATURITY.
fn stake_maturity(
    requests: &mut Vec<Request>,
    arg: Blob,
    from: AccountIdentifier,
    neuron_index: u64,
) -> Result<(), ApiError> {
    let manage: ManageNeuron = candid::decode_one(arg.0.as_ref()).map_err(|e| {
        ApiError::internal_error(format!("Could not decode ManageNeuron argument: {:?}", e))
    })?;
    if let Some(Command::StakeMaturity(manage_neuron::StakeMaturity {
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

/// Handle LIST_NEURONS.
fn list_neurons(
    requests: &mut Vec<Request>,
    _arg: Blob,
    from: AccountIdentifier,
) -> Result<(), ApiError> {
    requests.push(Request::ListNeurons(ListNeurons { account: from }));
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

#[cfg(test)]
mod tests {
    use ic_base_types::CanisterId;
    use proptest::{
        prop_assert, prop_assert_eq, proptest, strategy::Strategy, test_runner::TestCaseError,
    };
    use rand_chacha::rand_core::OsRng;
    use std::{str::FromStr, time::SystemTime};
    use url::Url;

    use crate::{
        ledger_client::LedgerClient,
        models::{
            operation::OperationType, Amount, ConstructionCombineRequest,
            ConstructionDeriveRequest, ConstructionParseRequest, ConstructionPayloadsRequest,
            ConstructionPayloadsRequestMetadata, Currency, CurveType, Operation,
            OperationIdentifier, PublicKey, Signature, SignatureType,
        },
        request_handler::RosettaRequestHandler,
    };
    use rosetta_core::objects::ObjectMap;

    #[test]
    fn test_payloads_parse_identity() {
        let key = ic_crypto_ed25519::PrivateKey::generate_using_rng(&mut OsRng);
        let ledger_client = futures::executor::block_on(LedgerClient::new(
            Url::from_str("http://localhost:1234").unwrap(),
            CanisterId::from_u64(1),
            "TKN".into(),
            CanisterId::from_u64(2),
            None,
            None,
            true,
            None,
            false,
        ))
        .unwrap();
        let handler = RosettaRequestHandler::new("Internet Computer".into(), ledger_client.into());

        // get the nextwork identifier
        let network_identifier = handler.network_id();
        let currency = Currency {
            symbol: "TKN".into(),
            decimals: 8,
            metadata: None,
        };

        // get the account from the public key
        let pub_key = crate::models::PublicKey {
            hex_bytes: hex::encode(key.public_key().serialize_raw()),
            curve_type: CurveType::Edwards25519,
        };
        let account = handler
            .construction_derive(ConstructionDeriveRequest {
                network_identifier: network_identifier.clone(),
                public_key: pub_key.clone(),
                metadata: None,
            })
            .unwrap()
            .account_identifier;

        // create the unsigned transaction
        let operations = vec![
            Operation {
                operation_identifier: OperationIdentifier {
                    index: 0,
                    network_index: None,
                },
                related_operations: None,
                type_: OperationType::Transaction.to_string(),
                status: None,
                account: account.clone(),
                amount: Some(Amount {
                    value: "-100000000".into(),
                    currency: currency.clone(),
                    metadata: None,
                }),
                coin_change: None,
                metadata: None,
            },
            Operation {
                operation_identifier: OperationIdentifier {
                    index: 1,
                    network_index: None,
                },
                related_operations: None,
                type_: OperationType::Transaction.to_string(),
                status: None,
                account: account.clone(),
                amount: Some(Amount {
                    value: "100000000".into(),
                    currency: currency.clone(),
                    metadata: None,
                }),
                coin_change: None,
                metadata: None,
            },
            Operation {
                operation_identifier: OperationIdentifier {
                    index: 2,
                    network_index: None,
                },
                related_operations: None,
                type_: OperationType::Fee.to_string(),
                status: None,
                account,
                amount: Some(Amount {
                    value: "-1000000".into(),
                    currency,
                    metadata: None,
                }),
                coin_change: None,
                metadata: None,
            },
        ];
        let gen_opt_u64 = proptest::option::of(proptest::prelude::any::<u64>());
        const ONE_HOUR_NANOS: u64 = 60 * 60 * 1_000_000_000;
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Could not get system time")
            .as_nanos() as u64;
        let gen_metadata = proptest::option::of(
            (gen_opt_u64.clone(), gen_opt_u64.clone(), gen_opt_u64).prop_flat_map(
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
                    // memo and created_at_time should always be set but the value is random
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
            prop_assert!(parsed.metadata.is_some(), "Metatada should always be returned");

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
            prop_assert!(parsed.metadata.is_some(), "Metatada should always be returned");

            check_metadata(metadata, parsed.metadata.unwrap()).unwrap()
        });
    }
}
