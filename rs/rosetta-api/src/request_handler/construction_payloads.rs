use dfn_candid::CandidOne;
use ic_nns_common::pb::v1::NeuronId;
use ic_types::messages::{Blob, HttpCanisterUpdate, MessageId};
use ic_types::PrincipalId;
use ledger_canister::{Memo, Operation, SendArgs, Tokens};
use on_wire::IntoWire;
use rand::Rng;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use ic_nns_governance::pb::v1::{
    manage_neuron::{self, configure, Command, NeuronIdOrSubaccount},
    ClaimOrRefreshNeuronFromAccount, ManageNeuron,
};

use crate::convert::{make_read_state_from_update, to_arg, to_model_account_identifier};
use crate::errors::ApiError;
use crate::ledger_client::LedgerAccess;
use crate::models::{
    AccountIdentifier, ConstructionPayloadsRequest, ConstructionPayloadsResponse, PublicKey,
    SignatureType, SigningPayload, UnsignedTransaction,
};
use crate::request_handler::{make_sig_data, verify_network_id, RosettaRequestHandler};
use crate::request_types::{
    AddHotKey, Disburse, Follow, MergeMaturity, NeuronInfo, PublicKeyOrPrincipal, RemoveHotKey,
    Request, RequestType, SetDissolveTimestamp, Spawn, Stake, StartDissolve, StopDissolve,
};
use crate::{convert, models};

impl RosettaRequestHandler {
    /// Generate an Unsigned Transaction and Signing Payloads.
    /// See https://www.rosetta-api.org/docs/ConstructionApi.html#constructionpayloads
    /// The unsigned_transaction returned from this function is a CBOR
    /// serialized UnsignedTransaction. The data to be signed is a
    /// single hex encoded MessageId.
    pub fn construction_payloads(
        &self,
        msg: ConstructionPayloadsRequest,
    ) -> Result<ConstructionPayloadsResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;

        let ops = msg.operations.clone();

        let pks = msg.public_keys.clone().ok_or_else(|| {
            ApiError::internal_error("Expected field 'public_keys' to be populated")
        })?;
        let transactions = convert::from_operations(&ops, false, self.ledger.token_symbol())?;

        let interval = ic_constants::MAX_INGRESS_TTL
            - ic_constants::PERMITTED_DRIFT
            - Duration::from_secs(120);

        let meta = msg.metadata.as_ref();

        let ingress_start = meta
            .and_then(|meta| meta.ingress_start)
            .map(ic_types::time::Time::from_nanos_since_unix_epoch)
            .unwrap_or_else(ic_types::time::current_time);

        let ingress_end = meta
            .and_then(|meta| meta.ingress_end)
            .map(ic_types::time::Time::from_nanos_since_unix_epoch)
            .unwrap_or_else(|| ingress_start + interval);

        let created_at_time: ledger_canister::TimeStamp = meta
            .and_then(|meta| meta.created_at_time)
            .map(ledger_canister::TimeStamp::from_nanos_since_unix_epoch)
            .unwrap_or_else(|| std::time::SystemTime::now().into());

        // FIXME: the memo field needs to be associated with the operation
        let memo: Memo = meta
            .and_then(|meta| meta.memo)
            .map(Memo)
            .unwrap_or_else(|| Memo(rand::thread_rng().gen()));

        let mut ingress_expiries = vec![];
        let mut now = ingress_start;
        while now < ingress_end {
            let ingress_expiry = (now + ic_constants::MAX_INGRESS_TTL
                - ic_constants::PERMITTED_DRIFT)
                .as_nanos_since_unix_epoch();
            ingress_expiries.push(ingress_expiry);
            now += interval;
        }

        let mut updates = vec![];
        let mut payloads = vec![];

        let pks_map = pks
            .iter()
            .map(|pk| {
                let pid: PrincipalId = convert::principal_id_from_public_key(pk)?;
                let account: ledger_canister::AccountIdentifier = pid.into();
                Ok((account, pk))
            })
            .collect::<Result<HashMap<_, _>, ApiError>>()?;

        for t in transactions {
            match t {
                Request::Transfer(req) => handle_transfer(
                    req,
                    memo,
                    created_at_time,
                    &self.ledger,
                    &mut payloads,
                    &mut updates,
                    &pks_map,
                    &ingress_expiries,
                )?,
                Request::NeuronInfo(req) => handle_neuron_info(
                    req,
                    &mut payloads,
                    &mut updates,
                    &pks_map,
                    &ingress_expiries,
                )?,
                Request::Stake(req) => handle_stake(
                    req,
                    &mut payloads,
                    &mut updates,
                    &pks_map,
                    &ingress_expiries,
                )?,
                Request::StartDissolve(req) => handle_start_dissolve(
                    req,
                    &mut payloads,
                    &mut updates,
                    &pks_map,
                    &ingress_expiries,
                )?,
                Request::StopDissolve(req) => handle_stop_dissolve(
                    req,
                    &mut payloads,
                    &mut updates,
                    &pks_map,
                    &ingress_expiries,
                )?,
                Request::SetDissolveTimestamp(req) => handle_set_dissolve_timestamp(
                    req,
                    &mut payloads,
                    &mut updates,
                    &pks_map,
                    &ingress_expiries,
                )?,
                Request::AddHotKey(req) => handle_add_hotkey(
                    req,
                    &mut payloads,
                    &mut updates,
                    &pks_map,
                    &ingress_expiries,
                )?,
                Request::RemoveHotKey(req) => handle_remove_hotkey(
                    req,
                    &mut payloads,
                    &mut updates,
                    &pks_map,
                    &ingress_expiries,
                )?,
                Request::Disburse(req) => handle_disburse(
                    req,
                    &mut payloads,
                    &mut updates,
                    &pks_map,
                    &ingress_expiries,
                )?,
                Request::Spawn(req) => handle_spawn(
                    req,
                    &mut payloads,
                    &mut updates,
                    &pks_map,
                    &ingress_expiries,
                )?,
                Request::MergeMaturity(req) => handle_merge_maturity(
                    req,
                    &mut payloads,
                    &mut updates,
                    &pks_map,
                    &ingress_expiries,
                )?,
                Request::Follow(req) => handle_follow(
                    req,
                    &mut payloads,
                    &mut updates,
                    &pks_map,
                    &ingress_expiries,
                )?,
            }
        }

        Ok(models::ConstructionPayloadsResponse::new(
            &UnsignedTransaction {
                updates,
                ingress_expiries,
            },
            payloads,
        ))
    }
}

/// Handle TRANSFER.
fn handle_transfer(
    req: Operation,
    memo: Memo,
    created_at_time: ledger_canister::TimeStamp,
    ledger: &Arc<dyn LedgerAccess + Send + Sync>,
    payloads: &mut Vec<SigningPayload>,
    updates: &mut Vec<(RequestType, HttpCanisterUpdate)>,
    pks_map: &HashMap<ledger_canister::AccountIdentifier, &PublicKey>,
    ingress_expiries: &[u64],
) -> Result<(), ApiError> {
    match req {
        Operation::Burn { .. } => Err(ApiError::invalid_request(
            "Burn operations are not supported through Rosetta.",
        )),
        Operation::Mint { .. } => Err(ApiError::invalid_request(
            "Mint operations are not supported through Rosetta.",
        )),
        Operation::Transfer {
            from,
            to,
            amount,
            fee,
        } => handle_transfer_operation(
            from,
            to,
            amount,
            fee,
            memo,
            created_at_time,
            ledger,
            payloads,
            updates,
            pks_map,
            ingress_expiries,
        ),
    }
}

fn handle_transfer_operation(
    from: ledger_canister::AccountIdentifier,
    to: ledger_canister::AccountIdentifier,
    amount: Tokens,
    fee: Tokens,
    memo: Memo,
    created_at_time: ledger_canister::TimeStamp,
    ledger: &Arc<dyn LedgerAccess + Send + Sync>,
    payloads: &mut Vec<SigningPayload>,
    updates: &mut Vec<(RequestType, HttpCanisterUpdate)>,
    pks_map: &HashMap<ledger_canister::AccountIdentifier, &PublicKey>,
    ingress_expiries: &[u64],
) -> Result<(), ApiError> {
    let pk = pks_map.get(&from).ok_or_else(|| {
        ApiError::internal_error(format!(
            "Cannot find public key for account identifier {}",
            from,
        ))
    })?;

    // The argument we send to the canister
    let send_args = SendArgs {
        memo,
        amount,
        fee,
        from_subaccount: None,
        to,
        created_at_time: Some(created_at_time),
    };

    let update = HttpCanisterUpdate {
        canister_id: Blob(ledger.ledger_canister_id().get().to_vec()),
        method_name: "send_pb".to_string(),
        arg: Blob(to_arg(send_args)),
        // This nonce allows you to send two otherwise identical requests to the IC.
        // We don't use a it here because we never want two transactions with
        // identical tx IDs to both land on chain.
        nonce: None,
        sender: Blob(convert::principal_id_from_public_key(pk)?.into_vec()),
        ingress_expiry: 0,
    };

    add_payloads(
        payloads,
        ingress_expiries,
        &convert::to_model_account_identifier(&from),
        &update,
    );
    updates.push((RequestType::Send, update));
    Ok(())
}

/// Handle NEURON_INFO.
fn handle_neuron_info(
    req: NeuronInfo,
    payloads: &mut Vec<SigningPayload>,
    updates: &mut Vec<(RequestType, HttpCanisterUpdate)>,
    pks_map: &HashMap<ledger_canister::AccountIdentifier, &PublicKey>,
    ingress_expiries: &[u64],
) -> Result<(), ApiError> {
    let account = req.account;
    let controller = req.controller;
    let neuron_index = req.neuron_index;
    let neuron_subaccount = neuron_subaccount(account, controller, neuron_index, pks_map);

    // In the case of an hotkey, account will be derived from the hotkey so
    // we can use the same logic for controller or hotkey.
    let pk = pks_map.get(&account).ok_or_else(|| {
        ApiError::internal_error(format!(
            "NeuronInfo - Cannot find public key for account {}",
            account,
        ))
    })?;
    let sender = convert::principal_id_from_public_key(pk)?;

    // Argument for the method called on the governance canister.
    let args = NeuronIdOrSubaccount::Subaccount(neuron_subaccount.to_vec());
    let update = HttpCanisterUpdate {
        canister_id: Blob(ic_nns_constants::GOVERNANCE_CANISTER_ID.get().to_vec()),
        method_name: "get_full_neuron_by_id_or_subaccount".to_string(),
        arg: Blob(CandidOne(args).into_bytes().expect("Serialization failed")),
        nonce: None,
        sender: Blob(sender.into_vec()), // Sender is controller or hotkey.
        ingress_expiry: 0,
    };
    add_payloads(
        payloads,
        ingress_expiries,
        &convert::to_model_account_identifier(&account),
        &update,
    );
    updates.push((
        RequestType::NeuronInfo {
            neuron_index,
            controller: controller.map(PublicKeyOrPrincipal::Principal),
        },
        update,
    ));
    Ok(())
}

/// Handle DISBURSE.
fn handle_disburse(
    req: Disburse,
    payloads: &mut Vec<SigningPayload>,
    updates: &mut Vec<(RequestType, HttpCanisterUpdate)>,
    pks_map: &HashMap<ledger_canister::AccountIdentifier, &PublicKey>,
    ingress_expiries: &[u64],
) -> Result<(), ApiError> {
    let account = req.account;
    let neuron_index = req.neuron_index;
    let amount = req.amount;
    let command = Command::Disburse(manage_neuron::Disburse {
        amount: amount.map(|amount| manage_neuron::disburse::Amount {
            e8s: amount.get_e8s(),
        }),
        to_account: req.recipient.map(From::from),
    });

    add_neuron_management_payload(
        RequestType::Disburse { neuron_index },
        account,
        None,
        neuron_index,
        command,
        payloads,
        updates,
        pks_map,
        ingress_expiries,
    )?;
    Ok(())
}

/// Handle STAKE.
fn handle_stake(
    req: Stake,
    payloads: &mut Vec<SigningPayload>,
    updates: &mut Vec<(RequestType, HttpCanisterUpdate)>,
    pks_map: &HashMap<ledger_canister::AccountIdentifier, &PublicKey>,
    ingress_expiries: &[u64],
) -> Result<(), ApiError> {
    let account = req.account;
    let neuron_index = req.neuron_index;
    let pk = pks_map.get(&account).ok_or_else(|| {
        ApiError::internal_error(format!(
            "Cannot find public key for account identifier {}",
            account,
        ))
    })?;

    // What we send to the governance canister
    let args = ClaimOrRefreshNeuronFromAccount {
        controller: None,
        memo: neuron_index,
    };

    let update = HttpCanisterUpdate {
        canister_id: Blob(ic_nns_constants::GOVERNANCE_CANISTER_ID.get().to_vec()),
        method_name: "claim_or_refresh_neuron_from_account".to_string(),
        arg: Blob(CandidOne(args).into_bytes().expect("Serialization failed")),
        // TODO work out whether Rosetta will accept us generating a nonce here
        // If we don't have a nonce it could cause one of those nasty bugs that
        // doesn't show it's face until you try to do two
        // identical transactions at the same time

        // We reuse the nonce field for neuron_index,
        // since neuron management commands lack an equivalent to the ledgers memo.
        // If we also need a real nonce, we'll concatenate it to the
        // neuron_index.
        nonce: Some(Blob(
            CandidOne(neuron_index)
                .into_bytes()
                .expect("Serialization of neuron_index failed"),
        )),
        sender: Blob(convert::principal_id_from_public_key(pk)?.into_vec()),
        ingress_expiry: 0,
    };

    add_payloads(
        payloads,
        ingress_expiries,
        &to_model_account_identifier(&account),
        &update,
    );
    updates.push((RequestType::Stake { neuron_index }, update));
    Ok(())
}

/// Handle START_DISSOLVE.
fn handle_start_dissolve(
    req: StartDissolve,
    payloads: &mut Vec<SigningPayload>,
    updates: &mut Vec<(RequestType, HttpCanisterUpdate)>,
    pks_map: &HashMap<ledger_canister::AccountIdentifier, &PublicKey>,
    ingress_expiries: &[u64],
) -> Result<(), ApiError> {
    let account = req.account;
    let neuron_index = req.neuron_index;
    let command = Command::Configure(manage_neuron::Configure {
        operation: Some(manage_neuron::configure::Operation::StartDissolving(
            manage_neuron::StartDissolving {},
        )),
    });
    add_neuron_management_payload(
        RequestType::StartDissolve { neuron_index },
        account,
        None,
        neuron_index,
        command,
        payloads,
        updates,
        pks_map,
        ingress_expiries,
    )?;
    Ok(())
}

/// Handle STOP_DISSOLVE.
fn handle_stop_dissolve(
    req: StopDissolve,
    payloads: &mut Vec<SigningPayload>,
    updates: &mut Vec<(RequestType, HttpCanisterUpdate)>,
    pks_map: &HashMap<ledger_canister::AccountIdentifier, &PublicKey>,
    ingress_expiries: &[u64],
) -> Result<(), ApiError> {
    let account = req.account;
    let neuron_index = req.neuron_index;
    let command = Command::Configure(manage_neuron::Configure {
        operation: Some(manage_neuron::configure::Operation::StopDissolving(
            manage_neuron::StopDissolving {},
        )),
    });
    add_neuron_management_payload(
        RequestType::StopDissolve { neuron_index },
        account,
        None,
        neuron_index,
        command,
        payloads,
        updates,
        pks_map,
        ingress_expiries,
    )?;
    Ok(())
}

/// Handle SET_DISSOLVE_TIMESTAMP.
fn handle_set_dissolve_timestamp(
    req: SetDissolveTimestamp,
    payloads: &mut Vec<SigningPayload>,
    updates: &mut Vec<(RequestType, HttpCanisterUpdate)>,
    pks_map: &HashMap<ledger_canister::AccountIdentifier, &PublicKey>,
    ingress_expiries: &[u64],
) -> Result<(), ApiError> {
    let account = req.account;
    let neuron_index = req.neuron_index;
    let timestamp = req.timestamp;
    let command = Command::Configure(manage_neuron::Configure {
        operation: Some(configure::Operation::SetDissolveTimestamp(
            manage_neuron::SetDissolveTimestamp {
                dissolve_timestamp_seconds: Duration::from(timestamp).as_secs(),
            },
        )),
    });
    add_neuron_management_payload(
        RequestType::SetDissolveTimestamp { neuron_index },
        account,
        None,
        neuron_index,
        command,
        payloads,
        updates,
        pks_map,
        ingress_expiries,
    )?;
    Ok(())
}

/// Handle ADD_HOTKEY.
fn handle_add_hotkey(
    req: AddHotKey,
    payloads: &mut Vec<SigningPayload>,
    updates: &mut Vec<(RequestType, HttpCanisterUpdate)>,
    pks_map: &HashMap<ledger_canister::AccountIdentifier, &PublicKey>,
    ingress_expiries: &[u64],
) -> Result<(), ApiError> {
    let account = req.account;
    let neuron_index = req.neuron_index;
    let key = req.key;
    let pid = match key {
        PublicKeyOrPrincipal::Principal(p) => p,
        PublicKeyOrPrincipal::PublicKey(pk) => convert::principal_id_from_public_key(&pk)?,
    };
    let command = Command::Configure(manage_neuron::Configure {
        operation: Some(configure::Operation::AddHotKey(manage_neuron::AddHotKey {
            new_hot_key: Some(pid),
        })),
    });
    add_neuron_management_payload(
        RequestType::AddHotKey { neuron_index },
        account,
        None,
        neuron_index,
        command,
        payloads,
        updates,
        pks_map,
        ingress_expiries,
    )?;
    Ok(())
}

/// Handle REMOVE_HOTKEY.
fn handle_remove_hotkey(
    req: RemoveHotKey,
    payloads: &mut Vec<SigningPayload>,
    updates: &mut Vec<(RequestType, HttpCanisterUpdate)>,
    pks_map: &HashMap<ledger_canister::AccountIdentifier, &PublicKey>,
    ingress_expiries: &[u64],
) -> Result<(), ApiError> {
    let account = req.account;
    let neuron_index = req.neuron_index;
    let key = req.key;
    let pid = match key {
        PublicKeyOrPrincipal::Principal(p) => p,
        PublicKeyOrPrincipal::PublicKey(pk) => convert::principal_id_from_public_key(&pk)?,
    };
    let command = Command::Configure(manage_neuron::Configure {
        operation: Some(configure::Operation::RemoveHotKey(
            manage_neuron::RemoveHotKey {
                hot_key_to_remove: Some(pid),
            },
        )),
    });
    add_neuron_management_payload(
        RequestType::RemoveHotKey { neuron_index },
        account,
        None,
        neuron_index,
        command,
        payloads,
        updates,
        pks_map,
        ingress_expiries,
    )?;
    Ok(())
}

/// Handle SPAWN.
fn handle_spawn(
    req: Spawn,
    payloads: &mut Vec<SigningPayload>,
    updates: &mut Vec<(RequestType, HttpCanisterUpdate)>,
    pks_map: &HashMap<ledger_canister::AccountIdentifier, &PublicKey>,
    ingress_expiries: &[u64],
) -> Result<(), ApiError> {
    let neuron_index = req.neuron_index;
    let command = Command::Spawn(manage_neuron::Spawn {
        new_controller: req.controller,
        percentage_to_spawn: req.percentage_to_spawn,
        nonce: Some(req.spawned_neuron_index),
    });
    add_neuron_management_payload(
        RequestType::Spawn { neuron_index },
        req.account,
        None,
        neuron_index,
        command,
        payloads,
        updates,
        pks_map,
        ingress_expiries,
    )?;
    Ok(())
}

/// Handle MERGE_MATURITY.
fn handle_merge_maturity(
    req: MergeMaturity,
    payloads: &mut Vec<SigningPayload>,
    updates: &mut Vec<(RequestType, HttpCanisterUpdate)>,
    pks_map: &HashMap<ledger_canister::AccountIdentifier, &PublicKey>,
    ingress_expiries: &[u64],
) -> Result<(), ApiError> {
    let account = req.account;
    let neuron_index = req.neuron_index;
    let percentage_to_merge = req.percentage_to_merge;
    let command = Command::MergeMaturity(manage_neuron::MergeMaturity {
        percentage_to_merge,
    });
    add_neuron_management_payload(
        RequestType::MergeMaturity { neuron_index },
        account,
        None,
        neuron_index,
        command,
        payloads,
        updates,
        pks_map,
        ingress_expiries,
    )?;
    Ok(())
}

/// Handle FOLLOW.
fn handle_follow(
    req: Follow,
    payloads: &mut Vec<SigningPayload>,
    updates: &mut Vec<(RequestType, HttpCanisterUpdate)>,
    pks_map: &HashMap<ledger_canister::AccountIdentifier, &PublicKey>,
    ingress_expiries: &[u64],
) -> Result<(), ApiError> {
    let account = req.account;
    let topic = req.topic;
    let controller = req.controller;
    let neuron_index = req.neuron_index;
    let nids = req
        .followees
        .iter()
        .map(|id| NeuronId { id: *id })
        .collect();
    let command = Command::Follow(manage_neuron::Follow {
        topic,
        followees: nids,
    });
    add_neuron_management_payload(
        RequestType::Follow {
            neuron_index,
            controller: controller.map(PublicKeyOrPrincipal::Principal),
        },
        account,
        controller,
        neuron_index,
        command,
        payloads,
        updates,
        pks_map,
        ingress_expiries,
    )?;
    Ok(())
}

fn add_neuron_management_payload(
    request_type: RequestType,
    account: ledger_canister::AccountIdentifier,
    controller: Option<PrincipalId>, // specify with hotkey.
    neuron_index: u64,
    command: ic_nns_governance::pb::v1::manage_neuron::Command,
    payloads: &mut Vec<SigningPayload>,
    updates: &mut Vec<(RequestType, HttpCanisterUpdate)>,
    pks_map: &HashMap<ledger_canister::AccountIdentifier, &PublicKey>,
    ingress_expiries: &[u64],
) -> Result<(), ApiError> {
    let neuron_subaccount = neuron_subaccount(account, controller, neuron_index, pks_map);

    // In the case of an hotkey, account will be derived from the hotkey so
    // we can use the same logic for controller or hotkey.
    let pk = pks_map.get(&account).ok_or_else(|| {
        ApiError::internal_error(format!(
            "Neuron management - Cannot find public key for account {}",
            account,
        ))
    })?;

    let manage_neuron = ManageNeuron {
        id: None,
        neuron_id_or_subaccount: Some(manage_neuron::NeuronIdOrSubaccount::Subaccount(
            neuron_subaccount.to_vec(),
        )),
        command: Some(command),
    };

    let update = HttpCanisterUpdate {
        canister_id: Blob(ic_nns_constants::GOVERNANCE_CANISTER_ID.get().to_vec()),
        method_name: "manage_neuron".to_string(),
        arg: Blob(
            CandidOne(manage_neuron)
                .into_bytes()
                .expect("Serialization failed"),
        ),
        nonce: Some(Blob(
            CandidOne(neuron_index)
                .into_bytes()
                .expect("Serialization of neuron_index failed"),
        )),
        sender: Blob(convert::principal_id_from_public_key(pk)?.into_vec()),
        ingress_expiry: 0,
    };

    add_payloads(
        payloads,
        ingress_expiries,
        &convert::to_model_account_identifier(&account),
        &update,
    );

    updates.push((request_type, update));
    Ok(())
}

/// Add transaction and read state messages for a given update to the payloads vector.
/// Payloads are added for each ingress expiries.
fn add_payloads(
    payloads: &mut Vec<SigningPayload>,
    ingress_expiries: &[u64],
    account_identifier: &AccountIdentifier,
    update: &HttpCanisterUpdate,
) {
    for ingress_expiry in ingress_expiries {
        let mut update = update.clone();
        update.ingress_expiry = *ingress_expiry;
        let message_id = update.id();
        let transaction_payload = SigningPayload {
            address: None,
            account_identifier: Some(account_identifier.clone()),
            hex_bytes: hex::encode(make_sig_data(&message_id)),
            signature_type: Some(SignatureType::Ed25519),
        };
        payloads.push(transaction_payload);
        let read_state = make_read_state_from_update(&update);
        let read_state_message_id = MessageId::from(read_state.representation_independent_hash());
        let read_state_payload = SigningPayload {
            address: None,
            account_identifier: Some(account_identifier.clone()),
            hex_bytes: hex::encode(make_sig_data(&read_state_message_id)),
            signature_type: Some(SignatureType::Ed25519),
        };
        payloads.push(read_state_payload);
    }
}

// Process the neuron subaccount from controller or hotkey.
fn neuron_subaccount(
    account: ledger_canister::AccountIdentifier,
    controller: Option<PrincipalId>,
    neuron_index: u64,
    pks_map: &HashMap<ledger_canister::AccountIdentifier, &PublicKey>,
) -> [u8; 32] {
    match controller {
        Some(neuron_controller) => {
            // Hotkey (or any explicit controller).
            crate::convert::neuron_subaccount_bytes_from_principal(&neuron_controller, neuron_index)
        }
        None => {
            // Default controller.
            let pk = pks_map
                .get(&account)
                .ok_or_else(|| {
                    ApiError::internal_error(format!(
                        "Cannot find public key for account {}",
                        account,
                    ))
                })
                .unwrap();
            crate::convert::neuron_subaccount_bytes_from_public_key(pk, neuron_index)
                .expect("Error while processing neuron subaccount")
        }
    }
}
