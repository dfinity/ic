use crate::errors::ApiError;
use crate::ledger_client::OperationOutput;
use ic_nns_governance::pb::v1::manage_neuron_response::{Command, MergeMaturityResponse};
use ic_nns_governance::pb::v1::ManageNeuronResponse;

pub fn handle_merge_maturity(
    bytes: Vec<u8>,
) -> Result<Result<Option<OperationOutput>, ApiError>, String> {
    let response: ManageNeuronResponse = candid::decode_one(bytes.as_ref())
        .map_err(|err| format!("Could not decode MERGE_MATURITY response: {}", err))?;
    match &response.command {
        Some(Command::MergeMaturity(MergeMaturityResponse { .. })) => Ok(Ok(None)),
        Some(Command::Error(err)) => Ok(Err(ApiError::TransactionRejected(
            false,
            format!("Could not merge maturity: {}", err).into(),
        ))),
        _ => panic!("Unexpected merge maturity result: {:?}", response.command),
    }
}
