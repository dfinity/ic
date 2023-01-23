use crate::errors::ApiError;
use crate::ledger_client::OperationOutput;
use ic_nns_governance::pb::v1::manage_neuron_response::Command;
use ic_nns_governance::pb::v1::ManageNeuronResponse;

pub fn handle_change_auto_stake_maturity(
    bytes: Vec<u8>,
) -> Result<Result<Option<OperationOutput>, ApiError>, String> {
    let response: ManageNeuronResponse = candid::decode_one(bytes.as_ref()).map_err(|err| {
        format!(
            "Could not decode change auto stake maturity response: {}",
            err
        )
    })?;
    match &response.command {
        Some(Command::Configure(_)) => Ok(Ok(None)),
        Some(Command::Error(err)) => Ok(Err(ApiError::TransactionRejected(
            false,
            format!("Could change auto staking maturity: {}", err).into(),
        ))),
        _ => panic!(
            "Unexpected change auto staking maturity result: {:?}",
            response.command
        ),
    }
}
