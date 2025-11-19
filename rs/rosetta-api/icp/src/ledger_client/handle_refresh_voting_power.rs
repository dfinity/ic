use crate::{errors::ApiError, ledger_client::OperationOutput};
use ic_nns_governance_api::{
    ManageNeuronResponse,
    manage_neuron_response::{Command, RefreshVotingPowerResponse},
};

pub fn handle_refresh_voting_power(
    bytes: Vec<u8>,
) -> Result<Result<Option<OperationOutput>, ApiError>, String> {
    let response: ManageNeuronResponse = candid::decode_one(bytes.as_ref())
        .map_err(|err| format!("Could not decode REFRESH_VOTING_POWER response: {err}"))?;
    match &response.command {
        Some(Command::RefreshVotingPower(RefreshVotingPowerResponse { .. })) => Ok(Ok(None)),
        Some(Command::Error(err)) => Ok(Err(ApiError::TransactionRejected(
            false,
            format!("Could not register vote: {err}").into(),
        ))),
        _ => panic!("Unexpected register vote result: {:?}", response.command),
    }
}
