use crate::{errors::ApiError, ledger_client::OperationOutput};
use ic_nns_governance_api::{
    ManageNeuronResponse,
    manage_neuron_response::{Command, StakeMaturityResponse},
};

pub fn handle_stake_maturity(
    bytes: Vec<u8>,
) -> Result<Result<Option<OperationOutput>, ApiError>, String> {
    let response: ManageNeuronResponse = candid::decode_one(bytes.as_ref())
        .map_err(|err| format!("Could not decode STAKE_MATURITY response: {err}"))?;
    match &response.command {
        Some(Command::StakeMaturity(StakeMaturityResponse { .. })) => Ok(Ok(None)),
        Some(Command::Error(err)) => Ok(Err(ApiError::TransactionRejected(
            false,
            format!("Could not stake maturity: {err}").into(),
        ))),
        _ => panic!("Unexpected stake maturity result: {:?}", response.command),
    }
}
