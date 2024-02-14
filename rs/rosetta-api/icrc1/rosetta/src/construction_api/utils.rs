use super::types::SignedTransaction;
use anyhow::anyhow;
use anyhow::{bail, Context};
use candid::{Decode, Nat, Principal};
use icrc_ledger_agent::Icrc1Agent;
use icrc_ledger_types::icrc1::transfer::TransferError;
use rosetta_core::{
    identifiers::TransactionIdentifier, response_types::ConstructionSubmitResponse,
};
use std::sync::Arc;

fn build_serialized_bytes<T: serde::Serialize + std::fmt::Debug>(
    object: &T,
) -> anyhow::Result<Vec<u8>> {
    let mut buf = vec![];
    ciborium::ser::into_writer(&object, &mut buf)
        .with_context(|| format!("Failed to serialize object {:?}", object))?;
    Ok(buf)
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
