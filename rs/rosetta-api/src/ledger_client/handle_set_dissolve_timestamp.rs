use crate::errors::ApiError;
use crate::ledger_client::OperationOutput;
use ic_nns_governance::pb::v1::manage_neuron_response::Command;
use ic_nns_governance::pb::v1::ManageNeuronResponse;

pub fn handle_set_dissolve_timestamp(
    bytes: Vec<u8>,
) -> Result<Result<Option<OperationOutput>, ApiError>, String> {
    let response: ManageNeuronResponse = candid::decode_one(bytes.as_ref())
        .map_err(|err| format!("Could not decode dissolve timestamp response: {}", err))?;
    match &response.command {
        Some(Command::Configure(_)) => Ok(Ok(None)),
        Some(Command::Error(err)) => {
            if err.error_message
                == "Can't set a dissolve delay that is smaller than the current dissolve delay."
            {
                Ok(Ok(None))
            } else {
                Ok(Err(ApiError::TransactionRejected(
                    false,
                    format!("Could not set dissolve delay timestamp: {}", err).into(),
                )))
            }
        }
        _ => panic!(
            "unexpected set dissolve delay timestamp result: {:?}",
            response.command
        ),
    }
}
