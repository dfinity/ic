use super::types::{EnvelopePair, SignedTransaction, UnsignedTransaction};
use anyhow::anyhow;
use anyhow::{bail, Context};
use candid::{Decode, Nat, Principal};
use ic_agent::agent::{Envelope, EnvelopeContent};
use icrc_ledger_agent::Icrc1Agent;
use icrc_ledger_types::icrc1::transfer::TransferError;
use rosetta_core::objects::Signature;
use rosetta_core::response_types::ConstructionCombineResponse;
use rosetta_core::{
    identifiers::TransactionIdentifier, response_types::ConstructionSubmitResponse,
};
use std::borrow::Cow;
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
        // TODO: Building the transaction hash is not yet supported by construction submit
        transaction_identifier: TransactionIdentifier {
            hash: "0".to_string(),
        },
        metadata: None,
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
