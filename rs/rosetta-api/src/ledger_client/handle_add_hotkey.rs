use crate::errors::ApiError;
use crate::ledger_client::OperationOutput;
use ic_nns_governance::pb::v1::manage_neuron_response::Command;
use ic_nns_governance::pb::v1::ManageNeuronResponse;

pub fn handle_add_hotkey(
    bytes: Vec<u8>,
) -> Result<Result<Option<OperationOutput>, ApiError>, String> {
    let response: ManageNeuronResponse = candid::decode_one(bytes.as_ref())
        .map_err(|err| format!("Could not decode ADD_HOTKEY response: {}", err))?;
    match &response.command {
        Some(Command::Configure(_)) => Ok(Ok(None)),
        Some(Command::Error(err)) => {
            if err.error_message.contains("Hot key duplicated") {
                Ok(Ok(None))
            } else {
                Ok(Err(ApiError::TransactionRejected(
                    false,
                    format!("Could not add hot key: {}", err).into(),
                )))
            }
        }
        _ => panic!("Unexpected add hot key result: {:?}", response.command),
    }
}
