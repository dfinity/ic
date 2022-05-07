use crate::errors::ApiError;
use crate::ledger_client::OperationOutput;
use ic_nns_governance::pb::v1::manage_neuron_response::{Command, DisburseResponse};
use ic_nns_governance::pb::v1::ManageNeuronResponse;

pub fn handle_disburse(
    bytes: Vec<u8>,
) -> Result<Result<Option<OperationOutput>, ApiError>, String> {
    let response: ManageNeuronResponse = candid::decode_one(bytes.as_ref())
        .map_err(|err| format!("Could not decode DISBURSE response : {}", err))?;
    match &response.command {
        Some(Command::Disburse(DisburseResponse {
            transfer_block_height,
        })) => Ok(Ok(Some(OperationOutput::BlockIndex(
            *transfer_block_height,
        )))),
        Some(Command::Error(err)) => Ok(Err(ApiError::TransactionRejected(
            false,
            format!("Could not disburse: {}", err).into(),
        ))),
        _ => panic!("Unexpected disburse result: {:?}", response.command),
    }
}
