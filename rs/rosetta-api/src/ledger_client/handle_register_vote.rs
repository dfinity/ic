use crate::errors::ApiError;
use crate::ledger_client::OperationOutput;
use ic_nns_governance::pb::v1::manage_neuron_response::{Command, RegisterVoteResponse};
use ic_nns_governance::pb::v1::ManageNeuronResponse;

pub fn handle_register_vote(
    bytes: Vec<u8>,
) -> Result<Result<Option<OperationOutput>, ApiError>, String> {
    let response: ManageNeuronResponse = candid::decode_one(bytes.as_ref())
        .map_err(|err| format!("Could not decode REGISTER_VOTE response: {}", err))?;
    match &response.command {
        Some(Command::RegisterVote(RegisterVoteResponse { .. })) => Ok(Ok(None)),
        Some(Command::Error(err)) => Ok(Err(ApiError::TransactionRejected(
            false,
            format!("Could not register vote: {}", err).into(),
        ))),
        _ => panic!("Unexpected register vote result: {:?}", response.command),
    }
}
