use crate::{
    errors::ApiError,
    ledger_client::OperationOutput,
    request_types::{RequestType, START_DISSOLVE},
};
use ic_nns_governance_api::pb::v1::{
    governance_error, manage_neuron_response::Command, ManageNeuronResponse,
};

pub fn handle_start_dissolve(
    bytes: Vec<u8>,
    request_type: &RequestType,
) -> Result<Result<Option<OperationOutput>, ApiError>, String> {
    let response: ManageNeuronResponse = candid::decode_one(bytes.as_ref())
        .map_err(|err| format!("Could not decode start disburse response: {}", err))?;
    match &response.command {
        Some(Command::Configure(_)) => Ok(Ok(None)),
        Some(Command::Error(err)) => {
            let req_str = request_type.clone().into_str();
            if req_str == START_DISSOLVE
                && err.error_type == governance_error::ErrorType::RequiresNotDissolving as i32
            {
                Ok(Ok(None))
            } else {
                Ok(Err(ApiError::TransactionRejected(
                    false,
                    format!("Could not start dissolving: {}", err).into(),
                )))
            }
        }
        _ => panic!("unexpected start dissolve result: {:?}", response.command),
    }
}
