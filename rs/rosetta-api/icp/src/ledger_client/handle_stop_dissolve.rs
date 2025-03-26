use crate::{
    errors::ApiError,
    ledger_client::OperationOutput,
    request_types::{RequestType, STOP_DISSOLVE},
};
use ic_nns_governance_api::pb::v1::{
    governance_error, manage_neuron_response::Command, ManageNeuronResponse,
};

pub fn handle_stop_dissolve(
    bytes: Vec<u8>,
    request_type: &RequestType,
) -> Result<Result<Option<OperationOutput>, ApiError>, String> {
    let response: ManageNeuronResponse = candid::decode_one(bytes.as_ref())
        .map_err(|err| format!("Could not decode start/stop disburse response: {}", err))?;
    match &response.command {
        Some(Command::Configure(_)) => Ok(Ok(None)),
        Some(Command::Error(err)) => {
            let req_str = request_type.clone().into_str();
            if req_str == STOP_DISSOLVE
                && err.error_type == governance_error::ErrorType::RequiresDissolving as i32
            {
                Ok(Ok(None))
            } else {
                Ok(Err(ApiError::TransactionRejected(
                    false,
                    format!("Could not stop dissolving: {}", err).into(),
                )))
            }
        }
        _ => panic!("unexpected stop dissolve result: {:?}", response.command),
    }
}
