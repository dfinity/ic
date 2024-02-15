use super::types::{CanisterMethodName, EnvelopePair, SignedTransaction, UnsignedTransaction};
use crate::common::storage::types::RosettaToken;
use anyhow::anyhow;
use anyhow::{bail, Context};
use candid::{Decode, Nat, Principal};
use ic_agent::agent::{Envelope, EnvelopeContent};
use ic_ledger_canister_core::ledger::LedgerTransaction;
use icrc_ledger_agent::Icrc1Agent;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::{TransferArg, TransferError};
use icrc_ledger_types::icrc2::approve::ApproveArgs;
use icrc_ledger_types::icrc2::transfer_from::TransferFromArgs;
use rosetta_core::objects::Signature;
use rosetta_core::response_types::ConstructionCombineResponse;
use rosetta_core::response_types::ConstructionHashResponse;
use rosetta_core::{
    identifiers::TransactionIdentifier, response_types::ConstructionSubmitResponse,
};
use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::Arc;

fn build_serialized_bytes<T: serde::Serialize + std::fmt::Debug>(
    object: &T,
) -> anyhow::Result<Vec<u8>> {
    let mut buf = vec![];
    ciborium::ser::into_writer(&object, &mut buf)
        .with_context(|| format!("Failed to serialize object {:?}", object))?;
    Ok(buf)
}

// The Request id is linked to the EnvelopeContent and is the actual content of the request to the IC that needs to be signed to authenticate the caller
fn build_signable_request_id_from_envelope_content(envelope_content: &EnvelopeContent) -> String {
    hex::encode(envelope_content.to_request_id().signable())
}

fn build_envelope_from_signature_and_envelope_content<'a>(
    signature: &Signature,
    envelope_content: EnvelopeContent,
) -> anyhow::Result<Envelope<'a>> {
    let envelope = Envelope {
        content: Cow::Owned(envelope_content),
        sender_pubkey: Some(signature.public_key.get_der_encoding()?),
        sender_sig: Some(hex::decode(&signature.hex_bytes)?),
        sender_delegation: None,
    };
    Ok(envelope)
}

pub async fn handle_construction_submit(
    signed_transaction: SignedTransaction<'_>,
    canister_id: Principal,
    icrc1_agent: Arc<Icrc1Agent>,
) -> anyhow::Result<ConstructionSubmitResponse> {
    if signed_transaction.envelope_pairs.is_empty() {
        bail!("No valid envelopes found in the signed transaction");
    }

    if signed_transaction.envelope_pairs.len() > 1 {
        // TODO: support more than one transaction per submit request
        // TODO: support various ingress intervals
        bail!("Only one envelope pair is supported per submit request. Found more than one envelope pair.");
    }

    let envelope_pair = &signed_transaction.envelope_pairs[0];

    // Forward the call envelope to the IC
    let call_envelope = &envelope_pair.call_envelope;
    let call_envelope_serialized = build_serialized_bytes(call_envelope)?;
    icrc1_agent
        .agent
        .update_signed(canister_id, call_envelope_serialized)
        .await
        .context("Failed to send EnvelopeContent::Call.")?;

    // Take the request id from the previous call envelope and wait until the IC has processes the content of the call envelope
    let read_state_envelope = &envelope_pair.read_state_envelope;
    let read_state_envelope_serialized = build_serialized_bytes(read_state_envelope)?;

    // TODO: support all operation types during parsing
    Decode!(&icrc1_agent
        .agent
        .wait_signed(
            &call_envelope.content.to_request_id(),
            canister_id,
            read_state_envelope_serialized,
        )
        .await?,Result<Nat, TransferError>)
    .context("Failed to wait for read state envelope")?
    .map_err(|err| anyhow!("Failed to decode transfer result: {:?}", err))?;

    Ok(ConstructionSubmitResponse {
        transaction_identifier: TransactionIdentifier {
            hash: build_transaction_hash_from_envelope_content(&call_envelope.content)?,
        },
        metadata: None,
    })
}

// Tries to convert a CanisterMethodArg into an icrc1::Transaction
// Fails if the underlying method is not supported by icrc1 ledgers
pub fn build_icrc1_transaction_from_canister_method_args(
    canister_method_name: &CanisterMethodName,
    caller: &Principal,
    candid_bytes: Vec<u8>,
) -> anyhow::Result<ic_icrc1::Transaction<RosettaToken>> {
    Ok(match canister_method_name {
        CanisterMethodName::Icrc2Approve => {
            let ApproveArgs {
                spender,
                amount,
                from_subaccount,
                fee,
                expected_allowance,
                expires_at,
                memo,
                created_at_time,
            } = Decode!(&candid_bytes, ApproveArgs).with_context(|| {
                format!("Could not decode approve args from: {:?} ", candid_bytes)
            })?;

            let operation = ic_icrc1::Operation::Approve {
                spender,
                amount: RosettaToken::try_from(amount).map_err(|err| anyhow!("{:?}", err))?,
                from: Account {
                    owner: *caller,
                    subaccount: from_subaccount,
                },
                fee: fee
                    .map(|fee| RosettaToken::try_from(fee).map_err(|err| anyhow!("{:?}", err)))
                    .transpose()?,
                expected_allowance: expected_allowance
                    .map(|fee| RosettaToken::try_from(fee).map_err(|err| anyhow!("{:?}", err)))
                    .transpose()?,
                expires_at,
            };
            ic_icrc1::Transaction {
                operation,
                memo,
                created_at_time,
            }
        }
        CanisterMethodName::Icrc2TransferFrom => {
            let TransferFromArgs {
                to,
                amount,
                from,
                spender_subaccount,
                fee,
                memo,
                created_at_time,
            } = Decode!(&candid_bytes, TransferFromArgs).with_context(|| {
                format!(
                    "Could not decode transfer from args from: {:?} ",
                    candid_bytes
                )
            })?;

            let operation = ic_icrc1::Operation::Transfer {
                to,
                amount: RosettaToken::try_from(amount).map_err(|err| anyhow!("{:?}", err))?,
                from,
                spender: Some(Account {
                    owner: *caller,
                    subaccount: spender_subaccount,
                }),
                fee: fee
                    .map(|fee| RosettaToken::try_from(fee).map_err(|err| anyhow!("{:?}", err)))
                    .transpose()?,
            };
            ic_icrc1::Transaction {
                operation,
                memo,
                created_at_time,
            }
        }
        CanisterMethodName::Icrc1Transfer => {
            let TransferArg {
                to,
                amount,
                from_subaccount,
                fee,
                memo,
                created_at_time,
            } = Decode!(&candid_bytes, TransferArg).with_context(|| {
                format!("Could not decode transfer args from: {:?} ", candid_bytes)
            })?;

            let operation = ic_icrc1::Operation::Transfer {
                to,
                amount: RosettaToken::try_from(amount).map_err(|err| anyhow!("{:?}", err))?,
                from: Account {
                    owner: *caller,
                    subaccount: from_subaccount,
                },
                spender: None,
                fee: fee
                    .map(|fee| RosettaToken::try_from(fee).map_err(|err| anyhow!("{:?}", err)))
                    .transpose()?,
            };
            ic_icrc1::Transaction {
                operation,
                memo,
                created_at_time,
            }
        }
    })
}

pub fn build_transaction_hash_from_envelope_content(
    envelope_content: &EnvelopeContent,
) -> anyhow::Result<String> {
    // First we can derive the canister method args and the caller of the function from the envelope content
    let canister_method_name = CanisterMethodName::new_from_envelope_content(envelope_content)?;

    let candid_encoded_bytes = match envelope_content {
        EnvelopeContent::Call { arg, .. } => arg.clone(),
        _ => bail!(
            "Wrong EnvelopeContent type, expected EnvelopeContent::Call, got {:?}",
            envelope_content
        ),
    };

    // Then we can derive the icrc1 transaction from the canister method args and the caller
    let icrc1_transaction = build_icrc1_transaction_from_canister_method_args(
        &canister_method_name,
        envelope_content.sender(),
        candid_encoded_bytes,
    )?;

    // TODO Transaction hash may not match up due to incoherence of RosettaToken and U64/U256: https://dfinity.atlassian.net/browse/FI-1154?atlOrigin=eyJpIjoiOWMwNWEwOGI3ZTZmNDFiZDlhMjc0YTQ0YmFmZmY1MmEiLCJwIjoiaiJ9
    Ok(icrc1_transaction.hash().to_string())
}

pub fn handle_construction_hash(
    signed_transaction: SignedTransaction,
) -> anyhow::Result<ConstructionHashResponse> {
    if signed_transaction.envelope_pairs.is_empty() {
        bail!("No valid envelopes found in the signed transaction");
    }

    // There are multiple envelopes in the signed transaction, but we only support one icrc1 ledger transaction per signed transaction
    // If there are multiple different icrc1 ledger transactions in the signed transaction, we return an error
    let mut tx_hashes = HashSet::new();
    for envelope_pair in signed_transaction.envelope_pairs {
        let transaction_hash =
            build_transaction_hash_from_envelope_content(&envelope_pair.call_envelope.content)?;
        tx_hashes.insert(transaction_hash);
    }

    // We expect only one icrc1 ledger transaction in the signed transaction
    if tx_hashes.len() > 1 {
        bail!("Only one icrc1 ledger transaction is supported per signed transaction. Found more than one icrc1 ledger transaction.");
    }

    Ok(ConstructionHashResponse {
        transaction_identifier: TransactionIdentifier {
            hash: tx_hashes.into_iter().next().unwrap(),
        },
        metadata: serde_json::map::Map::new(),
    })
}

pub fn handle_construction_combine(
    unsigned_transaction: UnsignedTransaction,
    signatures: Vec<Signature>,
) -> anyhow::Result<ConstructionCombineResponse> {
    if unsigned_transaction.envelope_contents.len() != signatures.len() {
        bail!("Number of signatures does not match number of envelopes");
    }

    // TODO: Support multiple envelope contents
    if unsigned_transaction.envelope_contents.len() != 2 {
        bail!("Only one envelope pair is supported per combine request. Found more than one envelope pair.");
    }

    // TODO: Support arbitrary order of envelope contents
    let envelope_call = &unsigned_transaction.envelope_contents[0];
    if !matches!(envelope_call, EnvelopeContent::Call { .. }) {
        bail!("First envelope content must be a Call envelope");
    };

    let envelope_read_state = &unsigned_transaction.envelope_contents[1];
    if !matches!(envelope_read_state, EnvelopeContent::ReadState { .. }) {
        bail!("Second envelope content must be a ReadState envelope");
    };

    // TODO: support arbitrary order of signatures
    let envelope_call_signature = &signatures[0];
    if envelope_call_signature.signing_payload.hex_bytes
        != build_signable_request_id_from_envelope_content(envelope_call)
    {
        bail!("First entry should be signature of call envelope");
    }

    let envelope_read_state_signature = &signatures[1];
    if envelope_read_state_signature.signing_payload.hex_bytes
        != build_signable_request_id_from_envelope_content(envelope_read_state)
    {
        bail!("Second entry should be signature of read state envelope");
    }

    let envelope_pairs = vec![EnvelopePair {
        call_envelope: build_envelope_from_signature_and_envelope_content(
            envelope_call_signature,
            envelope_call.clone(),
        )?,
        read_state_envelope: build_envelope_from_signature_and_envelope_content(
            envelope_read_state_signature,
            envelope_read_state.clone(),
        )?,
    }];

    Ok(ConstructionCombineResponse {
        signed_transaction: hex::encode(serde_cbor::to_vec(&SignedTransaction { envelope_pairs })?),
    })
}
