mod state;

use crate::convert::state::State;
use crate::errors::ApiError;
use crate::models::amount::{from_amount, ledgeramount_from_amount};
use crate::models::operation::OperationType;
use crate::models::{self, AccountIdentifier, BlockIdentifier, Operation};
use crate::request::request_result::RequestResult;
use crate::request::transaction_operation_results::TransactionOperationResults;
use crate::request::transaction_results::TransactionResults;
use crate::request::Request;
use crate::request_types::{
    ChangeAutoStakeMaturityMetadata, DisburseMetadata, FollowMetadata, KeyMetadata,
    MergeMaturityMetadata, NeuronIdentifierMetadata, NeuronInfoMetadata, PublicKeyOrPrincipal,
    RegisterVoteMetadata, RequestResultMetadata, SetDissolveTimestampMetadata, SpawnMetadata,
    StakeMaturityMetadata, Status, STATUS_COMPLETED,
};
use crate::transaction_id::TransactionIdentifier;
use crate::{convert, errors};
use dfn_protobuf::ProtoBuf;
use ic_crypto_tree_hash::Path;
use ic_ledger_canister_blocks_synchronizer::blocks::HashedBlock;
use ic_ledger_core::block::BlockType;
use ic_ledger_hash_of::HashOf;
use ic_types::messages::{HttpCanisterUpdate, HttpReadState};
use ic_types::{CanisterId, PrincipalId};
use icp_ledger::{
    Block, BlockIndex, Operation as LedgerOperation, SendArgs, Subaccount, TimeStamp, Tokens,
    Transaction,
};
use on_wire::{FromWire, IntoWire};
use rosetta_core::convert::principal_id_from_public_key;
use serde_json::map::Map;
use serde_json::{from_value, Number, Value};
use std::convert::{TryFrom, TryInto};

/// This module converts from ledger_canister data structures to Rosetta data
/// structures

pub fn to_rosetta_core_transaction(
    transaction_index: BlockIndex,
    transaction: Transaction,
    timestamp: TimeStamp,
    token_symbol: &str,
) -> Result<rosetta_core::objects::Transaction, ApiError> {
    let transaction_identifier = TransactionIdentifier::from(&transaction).into();
    let operation = transaction.operation;
    let operations = {
        let mut ops =
            Request::requests_to_operations(&[Request::Transfer(operation)], token_symbol)?;
        for op in ops.iter_mut() {
            op.status = Some(STATUS_COMPLETED.to_string());
        }
        ops
    };
    let mut metadata = Map::new();
    metadata.insert(
        "memo".to_string(),
        Value::Number(Number::from(transaction.memo.0)),
    );
    metadata.insert(
        "block_height".to_string(),
        Value::Number(Number::from(transaction_index)),
    );
    metadata.insert(
        "timestamp".to_string(),
        Value::Number(Number::from(timestamp.as_nanos_since_unix_epoch())),
    );
    Ok(rosetta_core::objects::Transaction {
        transaction_identifier,
        operations,
        metadata: Some(metadata),
    })
}

pub fn hashed_block_to_rosetta_core_transaction(
    hb: &HashedBlock,
    token_symbol: &str,
) -> Result<models::Transaction, ApiError> {
    let block = Block::decode(hb.block.clone())
        .map_err(|err| ApiError::internal_error(format!("Cannot decode block: {:?}", err)))?;
    let transaction = block.transaction;
    to_rosetta_core_transaction(hb.index, transaction, block.timestamp, token_symbol)
}

/// Convert from operations to requests.
pub fn operations_to_requests(
    ops: &[Operation],
    preprocessing: bool,
    token_name: &str,
) -> Result<Vec<Request>, ApiError> {
    let op_error = |op: &Operation, e| {
        let msg = format!("In operation '{:?}': {}", op, e);
        ApiError::InvalidTransaction(false, msg.into())
    };

    let mut state = State::new(preprocessing, vec![], None, None, None);

    for o in ops {
        if o.account.is_none() {
            return Err(op_error(o, "Account must be populated".into()));
        }
        if o.coin_change.is_some() {
            return Err(op_error(o, "Coin changes are not permitted".into()));
        }
        let account = from_model_account_identifier(o.account.as_ref().unwrap())
            .map_err(|e| op_error(o, e))?;

        let validate_neuron_management_op = || {
            if o.amount.is_some() && o.type_.parse::<OperationType>()? != OperationType::Disburse {
                Err(op_error(
                    o,
                    format!(
                        "neuron management {:?} operation cannot have an amount",
                        o.type_
                    ),
                ))
            } else if o.coin_change.is_some() {
                Err(op_error(
                    o,
                    format!(
                        "neuron management {:?} operation cannot have a coin change",
                        o.type_
                    ),
                ))
            } else {
                Ok(())
            }
        };

        match o.type_.parse::<OperationType>()? {
            OperationType::Transaction => {
                let amount = o
                    .amount
                    .as_ref()
                    .ok_or_else(|| op_error(o, "Amount must be populated".into()))?;
                let amount = from_amount(amount, token_name).map_err(|e| op_error(o, e))?;
                state.transaction(account, amount)?;
            }
            OperationType::Approve => {
                return Err(ApiError::InvalidRequest(
                    false,
                    "OperationType Approve is not supported for Requests".into(),
                ))
            }
            OperationType::Fee => {
                let amount = o
                    .amount
                    .as_ref()
                    .ok_or_else(|| op_error(o, "Amount must be populated".into()))?;
                let amount = from_amount(amount, token_name).map_err(|e| op_error(o, e))?;
                state.fee(account, Tokens::from_e8s((-amount) as u64))?;
            }
            OperationType::Stake => {
                validate_neuron_management_op()?;
                let NeuronIdentifierMetadata { neuron_index } = o.metadata.clone().try_into()?;
                state.stake(account, neuron_index)?;
            }
            OperationType::SetDissolveTimestamp => {
                validate_neuron_management_op()?;
                let SetDissolveTimestampMetadata {
                    neuron_index,
                    timestamp,
                } = o.metadata.clone().try_into()?;
                state.set_dissolve_timestamp(account, neuron_index, timestamp)?;
            }
            OperationType::ChangeAutoStakeMaturity => {
                validate_neuron_management_op()?;
                let ChangeAutoStakeMaturityMetadata {
                    neuron_index,
                    requested_setting_for_auto_stake_maturity,
                } = o.metadata.clone().try_into()?;
                state.change_auto_stake_maturity(
                    account,
                    neuron_index,
                    requested_setting_for_auto_stake_maturity,
                )?;
            }

            OperationType::StartDissolving => {
                validate_neuron_management_op()?;
                let NeuronIdentifierMetadata { neuron_index } = o.metadata.clone().try_into()?;
                state.start_dissolve(account, neuron_index)?;
            }
            OperationType::StopDissolving => {
                validate_neuron_management_op()?;
                let NeuronIdentifierMetadata { neuron_index } = o.metadata.clone().try_into()?;
                state.stop_dissolve(account, neuron_index)?;
            }
            OperationType::AddHotkey => {
                let KeyMetadata { key, neuron_index } = o.metadata.clone().try_into()?;
                validate_neuron_management_op()?;
                state.add_hot_key(account, neuron_index, key)?;
            }
            OperationType::RemoveHotkey => {
                let KeyMetadata { key, neuron_index } = o.metadata.clone().try_into()?;
                validate_neuron_management_op()?;
                state.remove_hotkey(account, neuron_index, key)?;
            }
            OperationType::Disburse => {
                let DisburseMetadata {
                    neuron_index,
                    recipient,
                } = o.metadata.clone().try_into()?;
                validate_neuron_management_op()?;
                let amount = if let Some(ref amount) = o.amount {
                    Some(ledgeramount_from_amount(amount, token_name).map_err(|e| {
                        ApiError::internal_error(format!("Could not convert Amount {:?}", e))
                    })?)
                } else {
                    None
                };
                state.disburse(account, neuron_index, amount, recipient)?;
            }
            OperationType::Spawn => {
                let SpawnMetadata {
                    neuron_index,
                    controller,
                    percentage_to_spawn,
                    spawned_neuron_index,
                } = o.metadata.clone().try_into()?;
                validate_neuron_management_op()?;
                state.spawn(
                    account,
                    neuron_index,
                    spawned_neuron_index,
                    percentage_to_spawn,
                    controller
                        .map(principal_id_from_public_key_or_principal)
                        .transpose()?,
                )?;
            }
            OperationType::MergeMaturity => {
                let MergeMaturityMetadata {
                    neuron_index,
                    percentage_to_merge,
                } = o.metadata.clone().try_into()?;
                validate_neuron_management_op()?;
                state.merge_maturity(account, neuron_index, percentage_to_merge)?;
            }
            OperationType::RegisterVote => {
                let RegisterVoteMetadata {
                    neuron_index,
                    proposal,
                    vote,
                } = o.metadata.clone().try_into()?;
                validate_neuron_management_op()?;
                state.register_vote(account, neuron_index, proposal, vote)?;
            }
            OperationType::StakeMaturity => {
                let StakeMaturityMetadata {
                    neuron_index,
                    percentage_to_stake,
                } = o.metadata.clone().try_into()?;
                validate_neuron_management_op()?;
                state.stake_maturity(account, neuron_index, percentage_to_stake)?;
            }
            OperationType::NeuronInfo => {
                let NeuronInfoMetadata {
                    controller,
                    neuron_index,
                } = o.metadata.clone().try_into()?;
                validate_neuron_management_op()?;
                // The governance canister expects a principal. If the caller
                // provided a public key, we compute the corresponding principal.
                let principal = match controller {
                    None => None,
                    Some(p) => Some(principal_id_from_public_key_or_principal(p)?),
                };
                state.neuron_info(account, principal, neuron_index)?;
            }
            OperationType::ListNeurons => {
                validate_neuron_management_op()?;
                state.list_neurons(account)?;
            }
            OperationType::Burn | OperationType::Mint => {
                let msg = format!("Unsupported operation type: {:?}", o.type_);
                return Err(op_error(o, msg));
            }
            OperationType::Follow => {
                let FollowMetadata {
                    topic,
                    followees,
                    controller,
                    neuron_index,
                } = o.metadata.clone().try_into()?;
                validate_neuron_management_op()?;
                // convert from pkp in operation to principal in request.
                let pid = match controller {
                    None => None,
                    Some(p) => Some(principal_id_from_public_key_or_principal(p)?),
                };
                state.follow(account, pid, neuron_index, topic, followees)?;
            }
        }
    }

    state.flush()?;

    if state.actions.is_empty() {
        return Err(ApiError::InvalidTransaction(
            false,
            "Operations don't contain any actions.".into(),
        ));
    }

    Ok(state.actions)
}

pub fn block_id(block: &HashedBlock) -> Result<BlockIdentifier, ApiError> {
    let idx = block.index;
    Ok(BlockIdentifier::new(idx, from_hash(&block.hash)))
}

pub fn to_model_account_identifier(aid: &icp_ledger::AccountIdentifier) -> AccountIdentifier {
    AccountIdentifier {
        address: aid.to_hex(),
        sub_account: None,
        metadata: None,
    }
}

pub fn from_model_account_identifier(
    aid: &AccountIdentifier,
) -> Result<icp_ledger::AccountIdentifier, String> {
    icp_ledger::AccountIdentifier::from_hex(&aid.address)
}

const LAST_HEIGHT: &str = "last_height";

// Last hash is an option because there may be no blocks on the system
pub fn from_metadata(mut ob: rosetta_core::objects::ObjectMap) -> Result<BlockIndex, ApiError> {
    let v = ob
        .remove(LAST_HEIGHT)
        .ok_or_else(|| ApiError::internal_error("No value `LAST_HEIGHT` in object"))?;
    from_value(v).map_err(|e| ApiError::internal_error(e.to_string()))
}

pub fn from_public_key(pk: &models::PublicKey) -> Result<Vec<u8>, ApiError> {
    from_hex(&pk.hex_bytes)
}

pub fn from_hex(hex: &str) -> Result<Vec<u8>, ApiError> {
    hex::decode(hex)
        .map_err(|e| ApiError::invalid_request(format!("Hex could not be decoded {:?}", e)))
}

pub fn to_hex(v: &[u8]) -> String {
    hex::encode(v)
}

pub fn account_from_public_key(pk: &models::PublicKey) -> Result<AccountIdentifier, ApiError> {
    let pid = principal_id_from_public_key(pk)
        .map_err(|err| ApiError::InvalidPublicKey(false, err.into()))?;
    Ok(to_model_account_identifier(&pid.into()))
}

/// `neuron_index` must also be the `nonce` of neuron management commands.
pub fn neuron_subaccount_bytes_from_public_key(
    pk: &models::PublicKey,
    neuron_index: u64,
) -> Result<[u8; 32], ApiError> {
    let controller = principal_id_from_public_key(pk)
        .map_err(|err| ApiError::InvalidPublicKey(false, err.into()))?;
    Ok(neuron_subaccount_hash(&controller, neuron_index))
}

/// `neuron_index` must also be the `nonce` of neuron management commands.
pub fn neuron_subaccount_bytes_from_principal(
    controller: &PrincipalId,
    neuron_index: u64,
) -> [u8; 32] {
    neuron_subaccount_hash(controller, neuron_index)
}

fn neuron_subaccount_hash(principal: &PrincipalId, nonce: u64) -> [u8; 32] {
    let mut state = ic_crypto_sha2::Sha256::new();
    state.write(&[0x0c]);
    state.write(b"neuron-stake");
    state.write(principal.as_slice());
    state.write(&nonce.to_be_bytes());
    state.finish()
}

/// `neuron_index` must also be the `nonce` of neuron management commands.
pub fn neuron_account_from_public_key(
    governance_canister_id: &CanisterId,
    pk: &models::PublicKey,
    neuron_index: u64,
) -> Result<AccountIdentifier, ApiError> {
    let subaccount_bytes = neuron_subaccount_bytes_from_public_key(pk, neuron_index)?;
    Ok(to_model_account_identifier(
        &icp_ledger::AccountIdentifier::new(
            governance_canister_id.get(),
            Some(Subaccount(subaccount_bytes)),
        ),
    ))
}

pub fn principal_id_from_public_key_or_principal(
    pkp: PublicKeyOrPrincipal,
) -> Result<PrincipalId, ApiError> {
    match pkp {
        PublicKeyOrPrincipal::Principal(p) => Ok(p),
        PublicKeyOrPrincipal::PublicKey(pk) => principal_id_from_public_key(&pk)
            .map_err(|err| ApiError::InvalidPublicKey(false, err.into())),
    }
}

// This is so I can keep track of where this conversion is done
pub fn from_arg(encoded: Vec<u8>) -> Result<SendArgs, ApiError> {
    ProtoBuf::from_bytes(encoded)
        .map_err(ApiError::internal_error)
        .map(|ProtoBuf(c)| c)
}

pub fn to_arg(args: SendArgs) -> Vec<u8> {
    ProtoBuf(args).into_bytes().expect("Serialization failed")
}

pub fn from_hash<T>(hash: &HashOf<T>) -> String {
    format!("{}", *hash)
}

pub fn to_hash<T>(s: &str) -> Result<HashOf<T>, ApiError> {
    s.parse().map_err(ApiError::internal_error)
}

pub fn make_read_state_from_update(update: &HttpCanisterUpdate) -> HttpReadState {
    let path = Path::new(vec!["request_status".into(), update.id().into()]);
    HttpReadState {
        sender: update.sender.clone(),
        paths: vec![path],
        nonce: None,
        ingress_expiry: update.ingress_expiry,
    }
}

/// Convert TransactionOperationResults to ApiError.
pub fn transaction_operation_result_to_api_error(
    e: TransactionOperationResults,
    token_name: &str,
) -> ApiError {
    match from_transaction_operation_results(e, token_name) {
        Ok(e) => ApiError::OperationsErrors(e, token_name.to_string()),
        Err(e) => e,
    }
}

/// Convert TransactionOperationResults to TransactionResults.
pub fn from_transaction_operation_results(
    t: TransactionOperationResults,
    token_name: &str,
) -> Result<TransactionResults, ApiError> {
    let requests = convert::operations_to_requests(&t.operations, false, token_name)?;

    let mut operations = Vec::with_capacity(requests.len());
    let mut op_idx = 0;
    for _type in requests.into_iter() {
        let o = match (&_type, &t.operations[op_idx..]) {
            (Request::Transfer(LedgerOperation::Transfer { .. }), [withdraw, deposit, fee, ..])
                if withdraw.type_.parse::<OperationType>()? == OperationType::Transaction
                    && deposit.type_.parse::<OperationType>()? == OperationType::Transaction
                    && fee.type_.parse::<OperationType>()? == OperationType::Fee =>
            {
                op_idx += 3;
                fee
            }
            (_, [o, ..]) => {
                op_idx += 1;
                o
            }
            (_, []) => {
                return Err(ApiError::internal_error(
                    "Too few Operations, could not match Operations with Requests",
                ))
            }
        };

        let status = o.status.clone().and_then(|n| Status::from_name(n.as_str()));

        let RequestResultMetadata {
            block_index,
            neuron_id,
            transaction_identifier,
            response,
        } = RequestResultMetadata::try_from(o.metadata.clone())?;
        let status = response
            .map(|e| Status::Failed(errors::convert_to_api_error(e, token_name)))
            .or(status)
            .ok_or_else(|| ApiError::internal_error("Could not decode Status from Operation"))?;

        operations.push(RequestResult {
            _type,
            block_index,
            neuron_id,
            transaction_identifier,
            status,
            response: None,
        });
    }

    Ok(TransactionResults { operations })
}

pub fn transaction_results_to_api_error(tr: TransactionResults, token_name: &str) -> ApiError {
    ApiError::OperationsErrors(tr, token_name.to_string())
}

#[cfg(test)]
mod tests;
