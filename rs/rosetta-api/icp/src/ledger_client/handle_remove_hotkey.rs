use crate::{errors::ApiError, ledger_client::OperationOutput};
use ic_nns_governance_api::{ManageNeuronResponse, manage_neuron_response::Command};

pub fn handle_remove_hotkey(
    bytes: Vec<u8>,
) -> Result<Result<Option<OperationOutput>, ApiError>, String> {
    let response: ManageNeuronResponse = candid::decode_one(bytes.as_ref())
        .map_err(|err| format!("Could not decode REMOVE_HOTKEY response: {err}"))?;
    match &response.command {
        Some(Command::Configure(_)) => Ok(Ok(None)),
        Some(Command::Error(err)) => Ok(Err(ApiError::TransactionRejected(
            false,
            format!("Could not remove hotkey: {err}").into(),
        ))),
        _ => panic!("Unexpected remove hot key result: {:?}", response.command),
    }
}
